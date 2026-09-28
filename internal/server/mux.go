package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"

	"github.com/shafreeck/burrow/internal/proto"
	"github.com/shafreeck/burrow/internal/vless"
)

// handleMuxConn handles TCP Mux.Cool sessions. UDP/XUDP is not implemented.
func (s *Server) handleMuxConn(c net.Conn, r io.Reader, ac *agentConn, protoName string) {
	type muxSession struct {
		sid    uint16
		stream *stream
		direct net.Conn
		once   sync.Once
	}
	var mu, writeMu sync.Mutex
	sessions := make(map[uint16]*muxSession)
	write := func(sid uint16, status, option byte, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return vless.WriteMuxFrame(c, sid, status, option, payload)
	}
	closeSession := func(sess *muxSession, notify bool) {
		sess.once.Do(func() {
			mu.Lock()
			if sessions[sess.sid] == sess {
				delete(sessions, sess.sid)
			}
			mu.Unlock()
			if sess.direct != nil {
				sess.direct.Close()
			} else if sess.stream != nil {
				s.endAgentStream(sess.stream)
			}
			if notify {
				write(sess.sid, vless.MuxEnd, 0, nil)
			}
		})
	}
	defer func() {
		c.Close()
		mu.Lock()
		all := make([]*muxSession, 0, len(sessions))
		for _, sess := range sessions {
			all = append(all, sess)
		}
		mu.Unlock()
		for _, sess := range all {
			closeSession(sess, false)
		}
	}()
	forward := func(sess *muxSession, payload []byte) error {
		if sess.direct != nil {
			sess.direct.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, err := sess.direct.Write(payload)
			return err
		}
		data := proto.Data{Type: proto.TypeData, ID: sess.stream.id, Payload: base64.StdEncoding.EncodeToString(payload)}
		raw, _ := json.Marshal(data)
		return ac.ws.WriteText(raw)
	}
	for {
		frame, err := vless.ReadMuxFrame(r)
		if err != nil {
			return
		}
		mu.Lock()
		sess := sessions[frame.SessionID]
		mu.Unlock()
		switch frame.Status {
		case vless.MuxNew:
			if sess != nil {
				return
			} // Duplicate live session IDs are a protocol error.
			host, port, err := net.SplitHostPort(frame.Addr)
			if err != nil {
				return
			}
			sess = &muxSession{sid: frame.SessionID}
			if isCloudflareEdge(host) {
				sess.direct, err = dialDirect(host, atoi(port))
			} else {
				sess.stream, err = s.openAgentStream(ac, host, atoi(port))
			}
			if err != nil {
				s.log("%s mux: %v", protoName, err)
				if write(frame.SessionID, vless.MuxEnd, vless.MuxOptError, nil) != nil {
					return
				}
				continue
			}
			mu.Lock()
			sessions[sess.sid] = sess
			mu.Unlock()
			go func(sess *muxSession) {
				defer closeSession(sess, true)
				if sess.direct != nil {
					buf := make([]byte, 32*1024)
					for {
						n, err := sess.direct.Read(buf)
						if n > 0 && write(sess.sid, vless.MuxKeep, vless.MuxOptData, buf[:n]) != nil {
							return
						}
						if err != nil {
							return
						}
					}
				}
				for {
					data, ok := sess.stream.receive()
					if !ok {
						return
					}
					if write(sess.sid, vless.MuxKeep, vless.MuxOptData, data) != nil {
						return
					}
				}
			}(sess)
			if len(frame.Payload) > 0 {
				if err := forward(sess, frame.Payload); err != nil {
					closeSession(sess, true)
				}
			}
		case vless.MuxKeep:
			if sess != nil && len(frame.Payload) > 0 {
				if err := forward(sess, frame.Payload); err != nil {
					closeSession(sess, true)
				}
			}
		case vless.MuxEnd:
			if sess != nil {
				closeSession(sess, false)
			}
		case vless.MuxKeepAlive:
		default:
			return
		}
	}
}
