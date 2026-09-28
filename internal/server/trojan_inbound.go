package server

import (
	"net"
	"time"

	"github.com/shafreeck/burrow/internal/proto"
	"github.com/shafreeck/burrow/internal/trojan"
)

// ServeTrojan runs a blocking Trojan inbound on addr.
// If the server has TLS cert configured, the listener uses TLS (standard
// Trojan deployment). Otherwise plain TCP (testing only).
// Each client connection verifies the password, parses the request,
// then relays through the tunnel via the existing stream mechanism.
func (s *Server) ServeTrojan(addr, password string) error {
	ln, err := s.listenInbound(addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	return s.ServeTrojanListener(ln, password)
}

// ServeTrojanListener serves an already-bound listener, including its TLS setup.
func (s *Server) ServeTrojanListener(ln net.Listener, password string) error {
	s.log("trojan listening on %s (TLS=%t)", ln.Addr(), s.cfg.TLSCert != "")
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleTrojan(c, password)
	}
}

func (s *Server) handleTrojan(c net.Conn, password string) {
	defer c.Close()

	// Parse Trojan header with a deadline so dead clients don't hang us.
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := trojan.VerifyPassword(c, password); err != nil {
		s.log("trojan auth failed: %v", err)
		return
	}
	req, err := trojan.ParseRequest(c)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		s.log("trojan parse failed: %v", err)
		return
	}

	host, portStr, err := net.SplitHostPort(req.Addr)
	if err != nil {
		s.log("trojan bad addr %q: %v", req.Addr, err)
		return
	}

	// Cloudflare edge bypass (TUN loop fix)
	if isCloudflareEdge(host, atoi(portStr)) {
		port := atoi(portStr)
		s.log("trojan: cloudflare edge %s:%d, dialing direct", host, port)
		target, derr := s.directDial(host, port)
		if derr != nil {
			s.log("trojan: direct dial failed: %v", derr)
			return
		}
		s.relayDirect(c, target)
		return
	}

	ac := s.waitAgent(10 * time.Second)
	if ac == nil {
		s.log("trojan: no agent connected")
		return
	}

	st, err := s.openAgentStream(ac, host, atoi(portStr))
	if err != nil {
		s.log("trojan: %v", err)
		return
	}
	streamID := st.id
	defer s.endAgentStream(st)

	// Trojan has no server response header; payload follows directly.
	s.log("trojan: %s -> %s stream=%s", c.RemoteAddr(), req.Addr, streamID)

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
