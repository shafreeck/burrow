package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shafreeck/burrow/internal/trojan"
	"github.com/shafreeck/burrow/internal/vless"
)

func TestTLSInbounds(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	fixture.Close()
	cert := fixture.TLS.Certificates[0]
	root := x509.NewCertPool()
	root.AddCert(fixture.Certificate())
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []string{"vless", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			s := connectedServer(t)
			s.cfg.TLSCert = certFile
			s.cfg.TLSKey = keyFile
			addr := target(t, func(c net.Conn) { io.WriteString(c, "TLS relay works") })
			ln, err := s.listenInbound("127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := ln.Accept()
				if err != nil {
					return
				}
				if protocol == "vless" {
					s.handleVLESS(c)
				} else {
					s.handleTrojan(c, "password")
				}
			}()
			c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: root, ServerName: "example.com"})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			if protocol == "vless" {
				c.Write(vlessHeader(vless.CmdTCP, addr))
				var header [2]byte
				if _, err := io.ReadFull(c, header[:]); err != nil {
					t.Fatal(err)
				}
			} else {
				header := []byte(trojan.PasswordHash("password") + "\r\n")
				header = append(header, trojan.CmdTCP, trojan.ATypeIPv4, 127, 0, 0, 1)
				header = append(header, portBytes(addr)...)
				header = append(header, '\r', '\n')
				c.Write(header)
			}
			body, err := io.ReadAll(c)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != "TLS relay works" {
				t.Fatalf("TLS body=%q", body)
			}
			<-done
		})
	}
}
