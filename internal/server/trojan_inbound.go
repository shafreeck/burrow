package server

import (
	"crypto/tls"
	"encoding/json"
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
	var ln net.Listener
	var err error
	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
		if err != nil {
			return err
		}
		ln, err = tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			return err
		}
		s.log("trojan listening on %s (TLS)", addr)
	} else {
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		s.log("trojan listening on %s (plain TCP, testing only)", addr)
	}
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
	if isCloudflareEdge(host) {
		port := atoi(portStr)
		s.log("trojan: cloudflare edge %s:%d, dialing direct", host, port)
		target, derr := dialDirect(host, port)
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
		s.log("trojan: agent timeout for %s", req.Addr)
		return
	}
	if ok, _ := res["ok"].(bool); !ok {
		msg, _ := res["error"].(string)
		s.log("trojan: connect %s failed: %s", req.Addr, msg)
		return
	}

	// Trojan has no server response header; payload follows directly.
	s.log("trojan: %s -> %s stream=%s", c.RemoteAddr(), req.Addr, streamID)

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
