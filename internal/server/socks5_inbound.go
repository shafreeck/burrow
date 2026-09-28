package server

import (
	"encoding/json"
	"net"
	"time"

	"github.com/shafreeck/muser/internal/proto"
	"github.com/shafreeck/muser/internal/socks5"
)

// ServeSOCKS5 runs a blocking SOCKS5 TCP inbound on addr.
func (s *Server) ServeSOCKS5(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.log("socks5 listening on %s", addr)
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
		socks5.WriteReply(c, socks5.RepFailure)
		return
	}
	var res map[string]interface{}
	select {
	case res = <-ch:
	case <-time.After(15 * time.Second):
		s.pendingMu.Lock()
		delete(s.pending, streamID)
		s.pendingMu.Unlock()
		s.log("socks5: agent timeout for %s", req.Addr)
		socks5.WriteReply(c, socks5.RepFailure)
		return
	}
	if ok, _ := res["ok"].(bool); !ok {
		socks5.WriteReply(c, socks5.RepFailure)
		return
	}

	if err := socks5.WriteReply(c, socks5.RepSuccess); err != nil {
		s.closeStream(streamID)
		return
	}
	s.log("socks5: %s -> %s stream=%s", c.RemoteAddr(), req.Addr, streamID)

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
