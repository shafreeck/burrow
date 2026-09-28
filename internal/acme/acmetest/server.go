// Package acmetest provides a local CA that checks HTTP-01 over TCP.
package acmetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type CA struct {
	*httptest.Server
	ChallengeURL               func(string) string
	KeepPending                bool
	FailOrder                  bool
	Finalized                  atomic.Bool
	mu                         sync.Mutex
	status, detail, thumbprint string
	cert                       []byte
}

func New(t *testing.T) *CA {
	t.Helper()
	ca := &CA{status: "pending"}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ca.mu.Lock()
		defer ca.mu.Unlock()
		base := "http://" + r.Host
		w.Header().Set("Replay-Nonce", "local-test-nonce")
		var jws struct{ Protected, Payload string }
		if r.Method == "POST" {
			json.NewDecoder(r.Body).Decode(&jws)
		}
		write := func(v interface{}) { json.NewEncoder(w).Encode(v) }
		switch r.URL.Path {
		case "/directory":
			write(map[string]interface{}{"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/order", "meta": map[string]string{"website": "https://example.test"}})
		case "/nonce":
		case "/account":
			raw, _ := base64.RawURLEncoding.DecodeString(jws.Protected)
			var header struct {
				JWK map[string]string `json:"jwk"`
			}
			json.Unmarshal(raw, &header)
			canonical, _ := json.Marshal(header.JWK)
			hash := sha256.Sum256(canonical)
			ca.thumbprint = base64.RawURLEncoding.EncodeToString(hash[:])
			w.Header().Set("Location", base+"/account/1")
			w.WriteHeader(http.StatusCreated)
			write(map[string]string{"status": "valid"})
		case "/order":
			if ca.FailOrder {
				w.WriteHeader(400)
				write(map[string]interface{}{"type": "urn:ietf:params:acme:error:malformed", "detail": "domain not allowed", "status": 400})
				return
			}
			w.Header().Set("Location", base+"/order/1")
			w.WriteHeader(http.StatusCreated)
			write(map[string]interface{}{"status": "pending", "authorizations": []string{base + "/authz"}, "finalize": base + "/finalize"})
		case "/authz":
			challenge := map[string]interface{}{"type": "http-01", "url": base + "/challenge", "token": "test-token", "status": ca.status}
			if ca.detail != "" {
				challenge["error"] = map[string]string{"type": "urn:ietf:params:acme:error:unauthorized", "detail": ca.detail}
			}
			write(map[string]interface{}{"status": ca.status, "challenges": []interface{}{challenge}})
		case "/challenge":
			if ca.KeepPending {
				write(map[string]string{"status": "pending"})
				return
			}
			ca.status = "invalid"
			if ca.ChallengeURL == nil {
				ca.detail = "no challenge endpoint"
			} else {
				client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
				defer client.CloseIdleConnections()
				resp, err := client.Get(ca.ChallengeURL("test-token"))
				if err != nil {
					ca.detail = err.Error()
				} else {
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					if resp.StatusCode == 200 && string(body) == "test-token."+ca.thumbprint {
						ca.status = "valid"
					} else {
						ca.detail = fmt.Sprintf("HTTP-01 returned status %d or incorrect key authorization", resp.StatusCode)
					}
				}
			}
			write(map[string]string{"status": ca.status})
		case "/finalize":
			ca.Finalized.Store(true)
			if ca.status != "valid" {
				w.WriteHeader(403)
				write(map[string]string{"detail": "authorization is not valid"})
				return
			}
			raw, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
			var body struct {
				CSR string `json:"csr"`
			}
			json.Unmarshal(raw, &body)
			der, _ := base64.RawURLEncoding.DecodeString(body.CSR)
			csr, err := x509.ParseCertificateRequest(der)
			if err != nil || csr.CheckSignature() != nil {
				http.Error(w, "bad CSR", 400)
				return
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: csr.Subject, DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, err = x509.CreateCertificate(rand.Reader, template, template, csr.PublicKey, key)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			ca.cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			write(map[string]string{"status": "valid"})
		case "/order/1":
			write(map[string]string{"status": "valid", "certificate": base + "/cert"})
		case "/cert":
			w.Write(ca.cert)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ca.Close)
	return ca
}
