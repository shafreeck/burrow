package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shafreeck/burrow/internal/acme/acmetest"
)

func TestJWKCoordinatesHaveFixedWidth(t *testing.T) {
	curve := elliptic.P256()
	for i := int64(1); i < 4096; i++ {
		d := big.NewInt(i)
		x, y := curve.ScalarBaseMult(d.Bytes())
		if len(x.Bytes()) == 32 && len(y.Bytes()) == 32 {
			continue
		}
		c, err := New("unused", &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d})
		if err != nil {
			t.Fatal(err)
		}
		jwk, err := c.jwk()
		if err != nil {
			t.Fatal(err)
		}
		for _, axis := range []string{"x", "y"} {
			raw, err := base64.RawURLEncoding.DecodeString(jwk[axis])
			if err != nil || len(raw) != 32 {
				t.Fatalf("%s coordinate length=%d: %v", axis, len(raw), err)
			}
		}
		return
	}
	t.Fatal("did not find a leading-zero coordinate")
}

func TestObtainCert(t *testing.T) {
	for _, scenario := range []string{"success", "invalid", "pending", "order error"} {
		t.Run(scenario, func(t *testing.T) {
			ca := acmetest.New(t)
			var mu sync.Mutex
			var keyAuth string
			challenge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if scenario == "invalid" {
					http.Error(w, "origin unavailable", 502)
					return
				}
				if r.URL.Path != "/.well-known/acme-challenge/test-token" || keyAuth == "" {
					http.NotFound(w, r)
					return
				}
				w.Write([]byte(keyAuth))
			}))
			defer challenge.Close()
			ca.ChallengeURL = func(token string) string { return challenge.URL + "/.well-known/acme-challenge/" + token }
			ca.KeepPending = scenario == "pending"
			ca.FailOrder = scenario == "order error"
			client, err := New(ca.URL+"/directory", nil)
			if err != nil {
				t.Fatal(err)
			}
			client.pollInterval = time.Millisecond
			client.pollAttempts = 3
			if err := client.Register(""); err != nil {
				t.Fatal(err)
			}
			cert, key, err := client.ObtainCert("example.com", func(token, auth string) { mu.Lock(); keyAuth = auth; mu.Unlock() })
			if scenario == "success" {
				if err != nil {
					t.Fatal(err)
				}
				pair, err := tls.X509KeyPair(cert, key)
				if err != nil {
					t.Fatal(err)
				}
				leaf, err := x509.ParseCertificate(pair.Certificate[0])
				if err != nil {
					t.Fatal(err)
				}
				if err := leaf.VerifyHostname("example.com"); err != nil {
					t.Fatal(err)
				}
				return
			}
			want := map[string]string{"invalid": "HTTP-01 returned status 502", "pending": "did not become valid", "order error": "domain not allowed"}[scenario]
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("error=%v want %q", err, want)
			}
			if ca.Finalized.Load() {
				t.Fatal("finalized an order without valid authorization")
			}
		})
	}
}
