package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/shafreeck/burrow/internal/acme"
)

// acmeChallenges holds in-progress HTTP-01 challenge tokens.
var acmeChallenges = struct {
	sync.Mutex
	m map[string]string
}{m: make(map[string]string)}

// handleACMEChallenge serves /.well-known/acme-challenge/<token>.
func handleACMEChallenge(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Path[len("/.well-known/acme-challenge/"):]
	acmeChallenges.Lock()
	keyAuth, ok := acmeChallenges.m[token]
	acmeChallenges.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(keyAuth))
}

// ObtainCertViaACME obtains a TLS cert for domain via Let's Encrypt HTTP-01.
// It saves cert.pem and key.pem to certDir, and returns their paths.
// It serves HTTP-01 on listenAddr for the duration of issuance; public port 80
// must reach that listener. email can be empty. Use staging=true for testing.
func ObtainCertViaACME(domain, email, certDir, listenAddr string, staging bool, logf func(string, ...interface{})) (certPath, keyPath string, err error) {
	dir := acme.DirectoryURL
	if staging {
		dir = acme.StagingDirectoryURL
	}
	return obtainCertViaACME(domain, email, certDir, listenAddr, dir, logf)
}

func obtainCertViaACME(domain, email, certDir, listenAddr, directoryURL string, logf func(string, ...interface{})) (certPath, keyPath string, err error) {
	// Bind synchronously before creating an order. Otherwise the CA can attempt
	// validation while no HTTP server is listening.
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return "", "", fmt.Errorf("acme HTTP-01 listen %s: %w", listenAddr, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/acme-challenge/", handleACMEChallenge)
	httpServer := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		if err := httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			logf("acme: challenge server: %v", err)
		}
	}()
	defer func() {
		httpServer.Close()
		<-stopped
	}()
	var tokens []string
	defer func() {
		acmeChallenges.Lock()
		defer acmeChallenges.Unlock()
		for _, token := range tokens {
			delete(acmeChallenges.m, token)
		}
	}()
	logf("acme: HTTP-01 listening on %s", ln.Addr())
	logf("acme: obtaining cert for %s via %s...", domain, directoryURL)

	client, err := acme.New(directoryURL, nil)
	if err != nil {
		return "", "", err
	}
	if err := client.Register(email); err != nil {
		return "", "", fmt.Errorf("acme register: %w", err)
	}

	certPEM, keyPEM, err := client.ObtainCert(domain, func(token, keyAuth string) {
		acmeChallenges.Lock()
		acmeChallenges.m[token] = keyAuth
		acmeChallenges.Unlock()
		tokens = append(tokens, token)
		logf("acme: challenge ready at /.well-known/acme-challenge/%s", token)
	})
	if err != nil {
		return "", "", fmt.Errorf("acme obtain: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return "", "", fmt.Errorf("acme returned an invalid certificate/key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", "", err
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return "", "", err
	}

	if err := os.MkdirAll(certDir, 0700); err != nil {
		return "", "", err
	}
	certPath = filepath.Join(certDir, "cert.pem")
	keyPath = filepath.Join(certDir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return "", "", err
	}
	logf("acme: cert saved to %s (expires %s)", certPath, leaf.NotAfter.Format(time.RFC3339))
	return certPath, keyPath, nil
}
