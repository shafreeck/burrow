package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockACMEServer simulates Let's Encrypt's ACME v2 API.
func mockACMEServer(t *testing.T, failWithError bool) *httptest.Server {
	var serverURL string
	mux := http.NewServeMux()

	// Directory (with meta object, like real LE)
	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"newAccount": "http://" + r.Host + "/newAccount",
			"newOrder":   "http://" + r.Host + "/newOrder",
			"newNonce":   "http://" + r.Host + "/newNonce",
			"meta": map[string]interface{}{
				"termsOfService": "https://example.com/tos",
				"website":        "https://example.com",
			},
		})
	})

	mux.HandleFunc("/newNonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce-123")
		w.WriteHeader(200)
	})

	mux.HandleFunc("/newAccount", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce-456")
		w.Header().Set("Location", "http://"+r.Host+"/account/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]string{"status": "valid"})
	})

	mux.HandleFunc("/newOrder", func(w http.ResponseWriter, r *http.Request) {
		if failWithError {
			// Simulate LE error response with numeric status
			w.Header().Set("Replay-Nonce", "test-nonce-789")
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"type":   "urn:ietf:params:acme:error:malformed",
				"detail": "test error: domain not allowed",
				"status": 400,
			})
			return
		}
		w.Header().Set("Replay-Nonce", "test-nonce-789")
		w.Header().Set("Location", "http://"+r.Host+"/order/1")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":         "pending",
			"authorizations": []string{"http://" + r.Host + "/authz/1"},
			"finalize":       "http://" + r.Host + "/finalize/1",
		})
	})

	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce-abc")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "pending",
			"challenges": []map[string]string{
				{"type": "http-01", "url": "http://" + r.Host + "/chall/1", "token": "test-token", "status": "pending"},
				{"type": "dns-01", "url": "http://" + r.Host + "/chall/2", "token": "test-token2", "status": "pending"},
			},
		})
	})

	mux.HandleFunc("/chall/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce-def")
		json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
	})

	mux.HandleFunc("/finalize/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce-ghi")
		json.NewEncoder(w).Encode(map[string]string{"status": "processing"})
	})

	mux.HandleFunc("/order/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce-jkl")
		json.NewEncoder(w).Encode(map[string]string{
			"status":      "valid",
			"certificate": "http://" + r.Host + "/cert/1",
		})
	})

	mux.HandleFunc("/cert/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce-mno")
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Write([]byte("-----BEGIN CERTIFICATE-----\nMOCKCERT\n-----END CERTIFICATE-----\n"))
	})

	srv := httptest.NewServer(mux)
	serverURL = srv.URL
	_ = serverURL
	return srv
}

func TestObtainCertSuccess(t *testing.T) {
	srv := mockACMEServer(t, false)
	defer srv.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, err := New(srv.URL+"/directory", key)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := client.Register(""); err != nil {
		t.Fatalf("Register: %v", err)
	}

	challengeSrv := func(token, keyAuth string) {
		if token != "test-token" {
			t.Errorf("unexpected token: %s", token)
		}
		if !strings.Contains(keyAuth, "test-token.") {
			t.Errorf("keyAuth doesn't start with token: %s", keyAuth)
		}
	}

	cert, keyPEM, err := client.ObtainCert("example.com", challengeSrv)
	if err != nil {
		t.Fatalf("ObtainCert: %v", err)
	}
	if !strings.Contains(string(cert), "MOCKCERT") {
		t.Errorf("cert doesn't contain expected content")
	}
	if !strings.Contains(string(keyPEM), "PRIVATE KEY") {
		t.Errorf("key doesn't look like PEM")
	}
	t.Log("ObtainCert success path works")
}

func TestObtainCertACMEError(t *testing.T) {
	srv := mockACMEServer(t, true) // failWithError=true
	defer srv.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client, err := New(srv.URL+"/directory", key)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := client.Register(""); err != nil {
		t.Fatalf("Register: %v", err)
	}

	_, _, err = client.ObtainCert("example.com", func(t, k string) {})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Should contain the ACME error detail, not a JSON unmarshal error
	if strings.Contains(err.Error(), "cannot unmarshal") {
		t.Errorf("got JSON unmarshal error instead of proper ACME error: %v", err)
	}
	if !strings.Contains(err.Error(), "domain not allowed") {
		t.Errorf("error doesn't contain ACME detail: %v", err)
	}
	t.Logf("ACME error properly surfaced: %v", err)
}
