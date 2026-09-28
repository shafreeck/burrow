package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"

	"github.com/shafreeck/muser/internal/proto"
	"github.com/shafreeck/muser/internal/vless"
)

// handleMuxConn handles multiplexed MUX (mux.cool) sessions over a single
// client connection. Each MUX session (sid) maps to an independent tunnel
// stream through the agent. Used by VLESS (CommandMux).
func (s *Server) handleMuxConn(c net.Conn, r io.Reader, ac *agentConn, protoName string) {
	s.log("%s: mux session from %s", protoName, c.RemoteAddr())

	// sid -> streamID mapping
	type muxSession struct {
		sid        uint16
		streamID   string
		directConn net.Conn // non-nil for Cloudflare edge bypass (direct dial, no agent)
	}
	sessions := make(map[uint16]*muxSession)
	var sessMu sync.Mutex

	// Write mutex for the client connection (multiple goroutines write MUX frames)
	var writeMu sync.Mutex

	// Cleanup: close all streams on exit
	defer func() {
		sessMu.Lock()
		for _, sess := range sessions {
			if sess.directConn != nil {
				sess.directConn.Close()
			} else {
				s.closeStream(sess.streamID)
				msg, _ := json.Marshal(map[string]string{"type": proto.TypeClose, "id": sess.streamID})
				ac.ws.WriteText(msg)
			}
		}
		sessMu.Unlock()
	}()

	// Helper: create a tunnel stream for a MUX New frame
	// Returns (streamID, directConn). directConn is non-nil for Cloudflare edge
	// bypass (direct dial, no agent). streamID is "" on failure.
	openStream := func(sid uint16, addr string) (string, net.Conn) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			s.log("%s mux: bad addr %q: %v", protoName, addr, err)
			return "", nil
		}

		// Cloudflare edge bypass: dial directly instead of via agent tunnel.
		if isCloudflareEdge(host) {
			port := atoi(portStr)
			s.log("%s mux: cloudflare edge %s:%d detected, dialing direct (bypass tunnel)", protoName, host, port)
			target, derr := dialDirect(host, port)
			if derr != nil {
				s.log("%s mux: direct dial %s:%d failed: %v", protoName, host, port, derr)
				return "", nil
			}
			// Spawn relay: target -> client (wrapped in MUX frames)
			go func() {
				defer target.Close()
				buf := make([]byte, 32*1024)
				for {
					n, rerr := target.Read(buf)
					if n > 0 {
						writeMu.Lock()
						werr := vless.WriteMuxFrame(c, sid, vless.MuxKeep, vless.MuxOptData, buf[:n])
						writeMu.Unlock()
						if werr != nil {
							return
						}
					}
					if rerr != nil {
						// Target closed, send MUX End
						writeMu.Lock()
						vless.WriteMuxFrame(c, sid, vless.MuxEnd, 0, nil)
						writeMu.Unlock()
						return
					}
				}
			}()
			// Return empty streamID with the direct conn; caller stores it in session
			return "", target
		}

		streamID := newID()
		ch := make(chan map[string]interface{}, 1)
		s.pendingMu.Lock()
		s.pending[streamID] = ch
		s.pendingMu.Unlock()

		creq := map[string]interface{}{
			"type": proto.TypeConnect,
			"id":   streamID,
			"host": host,
			"port": atoi(portStr),
		}
		b, _ := json.Marshal(creq)
		if err := ac.ws.WriteText(b); err != nil {
			s.pendingMu.Lock()
			delete(s.pending, streamID)
			s.pendingMu.Unlock()
			return "", nil
		}

		var res map[string]interface{}
		select {
		case res = <-ch:
		case <-time.After(15 * time.Second):
			s.pendingMu.Lock()
			delete(s.pending, streamID)
			s.pendingMu.Unlock()
			s.log("%s mux: agent timeout for %s", protoName, addr)
			return "", nil
		}
		if ok, _ := res["ok"].(bool); !ok {
			msg, _ := res["error"].(string)
			s.log("%s mux: connect %s failed: %s", protoName, addr, msg)
			return "", nil
		}

		// Register stream
		st := &stream{
			id:    streamID,
			agent: ac,
			toNet: make(chan []byte, 64),
			done:  make(chan struct{}),
		}
		s.streamsMu.Lock()
		s.streams[streamID] = st
		s.streamsMu.Unlock()

		// Forward agent -> client: wrap in MUX frames
		go func() {
			defer s.closeStream(streamID)
			for {
				select {
				case data := <-st.toNet:
					writeMu.Lock()
					werr := vless.WriteMuxFrame(c, sid, vless.MuxKeep, vless.MuxOptData, data)
					writeMu.Unlock()
					if werr != nil {
						return
					}
				case <-st.done:
					// Send MUX End frame
					writeMu.Lock()
					vless.WriteMuxFrame(c, sid, vless.MuxEnd, 0, nil)
					writeMu.Unlock()
					return
				}
			}
		}()

		return streamID, nil
	}

	// Read MUX frames from client
	for {
		frame, err := vless.ReadMuxFrame(r)
		if err != nil {
			// Connection closed or error
			return
		}

		switch frame.Status {
		case vless.MuxNew:
			sessMu.Lock()
			if _, exists := sessions[frame.SessionID]; exists {
				sessMu.Unlock()
				continue
			}
			sessMu.Unlock()

			streamID, directConn := openStream(frame.SessionID, frame.Addr)
			if streamID == "" && directConn == nil {
				// Failed to open, send End frame
				writeMu.Lock()
				vless.WriteMuxFrame(c, frame.SessionID, vless.MuxEnd, vless.MuxOptError, nil)
				writeMu.Unlock()
				continue
			}

			sessMu.Lock()
			sessions[frame.SessionID] = &muxSession{sid: frame.SessionID, streamID: streamID, directConn: directConn}
			sessMu.Unlock()

			// If New frame also has data, forward it
			if frame.Option&vless.MuxOptData != 0 && len(frame.Payload) > 0 {
				d := proto.Data{ID: streamID, Payload: base64.StdEncoding.EncodeToString(frame.Payload)}
				b, _ := json.Marshal(d)
				ac.ws.WriteText(b)
			}

		case vless.MuxKeep:
			// Data frame (Keep with Data option) or keepalive
			if frame.Option&vless.MuxOptData != 0 && len(frame.Payload) > 0 {
				sessMu.Lock()
				sess, ok := sessions[frame.SessionID]
				sessMu.Unlock()
				if !ok {
					continue
				}
				// Direct bypass session: write straight to the TCP connection
				if sess.directConn != nil {
					if _, werr := sess.directConn.Write(frame.Payload); werr != nil {
						// Target write failed, close session
						sessMu.Lock()
						delete(sessions, frame.SessionID)
						sessMu.Unlock()
						sess.directConn.Close()
						writeMu.Lock()
						vless.WriteMuxFrame(c, frame.SessionID, vless.MuxEnd, vless.MuxOptError, nil)
						writeMu.Unlock()
					}
					continue
				}
				// Forward to agent via text frame (base64)
				d := map[string]interface{}{
					"type":    proto.TypeData,
					"id":      sess.streamID,
					"payload": base64.StdEncoding.EncodeToString(frame.Payload),
				}
				b, _ := json.Marshal(d)
				if err := ac.ws.WriteText(b); err != nil {
					return
				}
			}
			// KeepAlive (sid=0) or Keep without data: ignore

		case vless.MuxEnd:
			sessMu.Lock()
			sess, ok := sessions[frame.SessionID]
			if ok {
				delete(sessions, frame.SessionID)
			}
			sessMu.Unlock()
			if ok {
				if sess.directConn != nil {
					// Direct bypass: just close the TCP connection
					sess.directConn.Close()
				} else {
					s.closeStream(sess.streamID)
					msg, _ := json.Marshal(map[string]string{"type": proto.TypeClose, "id": sess.streamID})
					ac.ws.WriteText(msg)
				}
			}

		case vless.MuxKeepAlive:
			// Ignore
		}
	}
}
