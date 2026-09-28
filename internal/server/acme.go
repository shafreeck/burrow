package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/shafreeck/muser/internal/acme"
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
// email is for the ACME account (can be empty). Use staging=true for testing.
func ObtainCertViaACME(domain, email, certDir string, staging bool, logf func(string, ...interface{})) (certPath, keyPath string, err error) {
	dir := acme.DirectoryURL
	if staging {
		dir = acme.StagingDirectoryURL
	}
	logf("acme: obtaining cert for %s (staging=%v)...", domain, staging)

	client, err := acme.New(dir, nil)
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
		logf("acme: challenge ready at /.well-known/acme-challenge/%s", token)
	})
	if err != nil {
		return "", "", fmt.Errorf("acme obtain: %w", err)
	}

	// Clean up challenge.
	acmeChallenges.Lock()
	acmeChallenges.m = make(map[string]string)
	acmeChallenges.Unlock()

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
	logf("acme: cert saved to %s (renew before %s)", certPath,
		time.Now().Add(90*24*time.Hour).Format("2006-01-02"))
	return certPath, keyPath, nil
}
