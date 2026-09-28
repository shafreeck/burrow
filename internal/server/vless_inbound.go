package server

import (
	"encoding/json"
	"net"
	"time"

	"github.com/shafreeck/muser/internal/proto"
	"github.com/shafreeck/muser/internal/vless"
)

// ServeVLESS runs a blocking VLESS TCP inbound on addr.
// Each client connection is parsed as VLESS, then relayed through
// the tunnel via the existing stream mechanism.
func (s *Server) ServeVLESS(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.log("vless listening on %s", addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleVLESS(c)
	}
}

func (s *Server) handleVLESS(c net.Conn) {
	defer c.Close()

	// Parse VLESS header with a deadline so dead clients don't hang us.
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	req, err := vless.Parse(c)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		s.log("vless parse failed: %v", err)
		return
	}

	// UUID check. If VLESSUUID is set, the client UUID must match.
	if s.cfg.VLESSUUID != "" {
		uuidHex := make([]byte, 32)
		hexChars := "0123456789abcdef"
		for i, b := range req.UUID {
			uuidHex[i*2] = hexChars[b>>4]
			uuidHex[i*2+1] = hexChars[b&0x0f]
		}
		if string(uuidHex) != s.cfg.VLESSUUID {
			s.log("vless rejected: bad uuid")
			return
		}
	}

	host, portStr, err := net.SplitHostPort(req.Addr)
	if err != nil && req.Command != vless.CmdMux {
		s.log("vless bad addr %q: %v", req.Addr, err)
		return
	}

	// Cloudflare edge bypass: if the target is cloudflared's control plane
	// (and TUN is looping it back into us), dial directly via the physical
	// interface instead of forwarding through the agent tunnel.
	// This breaks the TUN loop without requiring sudo or user configuration.
	if req.Command != vless.CmdMux && isCloudflareEdge(host) {
		port := atoi(portStr)
		s.log("vless: cloudflare edge %s:%d detected, dialing direct (bypass tunnel)", host, port)
		target, derr := dialDirect(host, port)
		if derr != nil {
			s.log("vless: direct dial %s:%d failed: %v", host, port, derr)
			return
		}
		// VLESS handshake OK.
		if err := vless.WriteResponse(c); err != nil {
			target.Close()
			return
		}
		s.relayDirect(c, target)
		return
	}

	ac := s.waitAgent(10 * time.Second)
	if ac == nil {
		s.log("vless: no agent connected")
		return
	}

	// MUX: multiplexed sessions over a single VLESS connection.
	if req.Command == vless.CmdMux {
		s.handleVLESSMux(c, ac)
		return
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
		return
	}
	var res map[string]interface{}
	select {
	case res = <-ch:
	case <-time.After(15 * time.Second):
		s.pendingMu.Lock()
		delete(s.pending, streamID)
		s.pendingMu.Unlock()
		s.log("vless: agent timeout for %s", req.Addr)
		return
	}
	if ok, _ := res["ok"].(bool); !ok {
		msg, _ := res["error"].(string)
		s.log("vless: connect %s failed: %s", req.Addr, msg)
		return
	}

	// VLESS handshake OK.
	if err := vless.WriteResponse(c); err != nil {
		s.closeStream(streamID)
		return
	}
	s.log("vless: %s -> %s stream=%s", c.RemoteAddr(), req.Addr, streamID)

	st := &stream{
		id:    streamID,
		agent: ac,
		toNet: make(chan []byte, 64),
		done:  make(chan struct{}),
	}
	s.streamsMu.Lock()
	s.streams[streamID] = st
	s.streamsMu.Unlock()

	defer func() {
		s.closeStream(streamID)
		msg, _ := json.Marshal(map[string]string{"type": proto.TypeClose, "id": streamID})
		ac.ws.WriteText(msg)
	}()

	// client -> agent
	go func() {
		defer s.closeStream(streamID)
		buf := make([]byte, 32*1024)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				frame := proto.EncodeDataFrame(streamID, buf[:n])
				if werr := ac.ws.WriteBinary(frame); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// agent -> client
	for {
		select {
		case data := <-st.toNet:
			if _, err := c.Write(data); err != nil {
				return
			}
		case <-st.done:
			return
		}
	}
}

// handleVLESSMux handles a VLESS MUX (mux.cool) connection.
// Multiple logical TCP streams are multiplexed over the single client connection.
// Each MUX session (sid) maps to an independent tunnel stream through the agent.
// handleVLESSMux handles a VLESS MUX (mux.cool) connection.
func (s *Server) handleVLESSMux(c net.Conn, ac *agentConn) {
	// VLESS handshake OK.
	if err := vless.WriteResponse(c); err != nil {
		return
	}
	s.handleMuxConn(c, c, ac, "vless")
}
