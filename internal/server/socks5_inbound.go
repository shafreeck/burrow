package server

import (
	"net"
	"time"

	"github.com/shafreeck/burrow/internal/proto"
	"github.com/shafreeck/burrow/internal/socks5"
)

// ServeSOCKS5 runs a blocking SOCKS5 TCP inbound on addr.
func (s *Server) ServeSOCKS5(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	return s.ServeSOCKS5Listener(ln)
}

// ServeSOCKS5Listener serves an already-bound SOCKS5 listener.
func (s *Server) ServeSOCKS5Listener(ln net.Listener) error {
	s.log("socks5 listening on %s", ln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleSOCKS5(c)
	}
}

func (s *Server) handleSOCKS5(c net.Conn) {
	defer c.Close()

	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := socks5.Handshake(c); err != nil {
		s.log("socks5 handshake failed: %v", err)
		return
	}
	req, err := socks5.ParseRequest(c)
	c.SetReadDeadline(time.Time{})
	if err != nil {
		s.log("socks5 parse failed: %v", err)
		socks5.WriteReply(c, socks5.RepFailure)
		return
	}

	host, portStr, err := net.SplitHostPort(req.Addr)
	if err != nil {
		socks5.WriteReply(c, socks5.RepFailure)
		return
	}

	// Cloudflare edge bypass (TUN loop fix)
	if isCloudflareEdge(host) {
		port := atoi(portStr)
		s.log("socks5: cloudflare edge %s:%d, dialing direct", host, port)
		target, derr := dialDirect(host, port)
		if derr != nil {
			socks5.WriteReply(c, socks5.RepFailure)
			return
		}
		socks5.WriteReply(c, socks5.RepSuccess)
		s.relayDirect(c, target)
		return
	}

	ac := s.waitAgent(10 * time.Second)
	if ac == nil {
		s.log("socks5: no agent connected")
		socks5.WriteReply(c, socks5.RepFailure)
		return
	}

	st, err := s.openAgentStream(ac, host, atoi(portStr))
	if err != nil {
		s.log("socks5: %v", err)
		socks5.WriteReply(c, socks5.RepFailure)
		return
	}
	streamID := st.id
	defer s.endAgentStream(st)

	if err := socks5.WriteReply(c, socks5.RepSuccess); err != nil {
		s.closeStream(streamID)
		return
	}
	s.log("socks5: %s -> %s stream=%s", c.RemoteAddr(), req.Addr, streamID)

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
