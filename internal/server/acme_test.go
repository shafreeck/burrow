package server

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/shafreeck/burrow/internal/acme/acmetest"
)

func TestACMEListenerLifecycle(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			ca := acmetest.New(t)
			var addr string
			ca.ChallengeURL = func(token string) string {
				if fail {
					token = "wrong-token"
				}
				return "http://" + addr + "/.well-known/acme-challenge/" + token
			}
			logf := func(format string, args ...interface{}) {
				if format == "acme: HTTP-01 listening on %s" {
					addr = args[0].(net.Addr).String()
				}
			}
			dir := t.TempDir()
			cert, key, err := obtainCertViaACME("example.com", "", dir, "127.0.0.1:0", ca.URL+"/directory", logf)
			if fail && err == nil {
				t.Fatal("expected validation error")
			}
			if !fail {
				if err != nil {
					t.Fatal(err)
				}
				if cert != filepath.Join(dir, "cert.pem") {
					t.Fatal(cert)
				}
				if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
					t.Fatal(err)
				}
			}
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			ln.Close()
			r := httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/test-token", nil)
			w := httptest.NewRecorder()
			handleACMEChallenge(w, r)
			if w.Code != 404 {
				t.Fatalf("challenge leaked after issuance: %d", w.Code)
			}
		})
	}
}

func TestACMEFailsBeforeIssuanceWhenPortIsOccupied(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, _, err = obtainCertViaACME("example.com", "", t.TempDir(), ln.Addr().String(), "http://invalid.test/directory", func(string, ...interface{}) {})
	if err == nil {
		t.Fatal("occupied challenge port accepted")
	}
}
