package server

import (
	"crypto/tls"
	"fmt"
	"net"
)

func (s *Server) listenInbound(addr string) (net.Listener, error) {
	if (s.cfg.TLSCert == "") != (s.cfg.TLSKey == "") {
		return nil, fmt.Errorf("certificate and key must be supplied together")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if s.cfg.TLSCert == "" {
		return ln, nil
	}
	cert, err := tls.LoadX509KeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
	if err != nil {
		ln.Close()
		return nil, err
	}
	return tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}), nil
}
