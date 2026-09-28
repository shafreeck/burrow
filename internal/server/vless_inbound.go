package server

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/shafreeck/burrow/internal/proto"
	"github.com/shafreeck/burrow/internal/vless"
)

// ServeVLESS runs a blocking VLESS TCP inbound on addr.
// Each client connection is parsed as VLESS, then relayed through
// the tunnel via the existing stream mechanism.
func (s *Server) ServeVLESS(addr string) error {
	ln, err := s.listenInbound(addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	return s.ServeVLESSListener(ln)
}

// ServeVLESSListener serves an already-bound listener, including its TLS setup.
func (s *Server) ServeVLESSListener(ln net.Listener) error {
	s.log("vless listening on %s", ln.Addr())
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
	if req.Command == vless.CmdTCP && isCloudflareEdge(host) {
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

	// UDP: the VM sandbox blocks all UDP, so the agent can never relay it.
	// Dial directly from the server. For cloudflared QUIC (TUN loop case)
	// this is the bypass; for everything else it's the only way UDP works.
	// No need to wait for an agent.
	if req.Command == vless.CmdUDP {
		s.log("vless: udp %s, dialing direct (agent cannot do UDP)", req.Addr)
		if err := vless.WriteResponse(c); err != nil {
			return
		}
		s.relayUDP(c, req.Addr)
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

	st, err := s.openAgentStream(ac, host, atoi(portStr))
	if err != nil {
		s.log("vless: %v", err)
		return
	}
	streamID := st.id
	defer s.endAgentStream(st)

	// VLESS handshake OK.
	if err := vless.WriteResponse(c); err != nil {
		s.closeStream(streamID)
		return
	}
	s.log("vless: %s -> %s stream=%s", c.RemoteAddr(), req.Addr, streamID)

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
		data, ok := st.receive()
		if !ok {
			return
		}
		if _, err := c.Write(data); err != nil {
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

// relayUDP relays VLESS UDP between the client TCP connection and a direct
// UDP dial to the target. VLESS UDP datagrams are length-prefixed:
// [len(2, big-endian)][payload] in both directions.
// Used for cloudflared QUIC under TUN (bypass) and any other UDP,
// since the VM agent cannot do UDP at all.
func (s *Server) relayUDP(c net.Conn, addr string) {
	udpConn, err := dialDirectNetwork("udp", addr)
	if err != nil {
		s.log("vless: udp dial %s failed: %v", addr, err)
		return
	}
	defer udpConn.Close()

	done := make(chan struct{})
	defer close(done)

	// Client -> UDP target.
	go func() {
		defer func() {
			select {
			case <-done:
			default:
				c.Close()
			}
		}()
		hdr := make([]byte, 2)
		for {
			if _, err := io.ReadFull(c, hdr); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(hdr))
			if n <= 0 || n > 65535 {
				s.log("vless: udp bad packet len %d", n)
				return
			}
			payload := make([]byte, n)
			if _, err := io.ReadFull(c, payload); err != nil {
				return
			}
			udpConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := udpConn.Write(payload); err != nil {
				return
			}
		}
	}()

	// UDP target -> client.
	buf := make([]byte, 65535)
	hdr := make([]byte, 2)
	for {
		udpConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := udpConn.Read(buf)
		if err != nil {
			return
		}
		binary.BigEndian.PutUint16(hdr, uint16(n))
		c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write(hdr); err != nil {
			return
		}
		if _, err := c.Write(buf[:n]); err != nil {
			return
		}
	}
}
