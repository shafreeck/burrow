// Package acme implements a minimal ACME client (RFC 8555) for Let's Encrypt
// HTTP-01 challenges. Only what we need: obtain a cert for a single domain.
//
// Flow:
//  1. Get directory, create account (or load existing key)
//  2. Create order for domain
//  3. Solve http-01 challenge (caller must serve the token)
//  4. Finalize with CSR, download cert
//
// Pure Go stdlib, no external dependencies.
package acme

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

const (
	// Let's Encrypt production directory.
	DirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"
	// Staging for testing (rate limits are relaxed).
	StagingDirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Client is an ACME client.
type Client struct {
	dir          string
	http         *http.Client
	accountKey   crypto.Signer
	accountURL   string
	nonce        string
	pollInterval time.Duration
	pollAttempts int
}

// New creates a client. If accountKey is nil, a new ECDSA P-256 key is generated.
func New(dir string, accountKey crypto.Signer) (*Client, error) {
	if accountKey == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		accountKey = k
	}
	return &Client{
		dir:          dir,
		http:         &http.Client{Timeout: 30 * time.Second},
		accountKey:   accountKey,
		pollInterval: 2 * time.Second,
		pollAttempts: 30,
	}, nil
}

// directory fetches the ACME directory.
func (c *Client) directory() (map[string]string, error) {
	resp, err := c.http.Get(c.dir)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// The directory contains a "meta" object; decode leniently and
	// extract only the string endpoints we need.
	var raw map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	dir := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			dir[k] = s
		}
	}
	return dir, nil
}

// jwk returns the JWK for the account key.
func (c *Client) jwk() (map[string]string, error) {
	switch k := c.accountKey.(type) {
	case *ecdsa.PrivateKey:
		// P-256
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("acme: only P-256 ECDSA keys are supported")
		}
		x := base64.RawURLEncoding.EncodeToString(k.X.FillBytes(make([]byte, 32)))
		y := base64.RawURLEncoding.EncodeToString(k.Y.FillBytes(make([]byte, 32)))
		return map[string]string{"kty": "EC", "crv": "P-256", "x": x, "y": y}, nil
	case *rsa.PrivateKey:
		n := base64.RawURLEncoding.EncodeToString(k.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())
		return map[string]string{"kty": "RSA", "n": n, "e": e}, nil
	default:
		return nil, fmt.Errorf("acme: unsupported key type %T", c.accountKey)
	}
}

// post sends a signed POST to url with payload.
func (c *Client) post(url string, payload interface{}) (*http.Response, error) {
	dir, err := c.directory()
	if err != nil {
		return nil, err
	}
	// Get fresh nonce if needed.
	if c.nonce == "" {
		resp, err := c.http.Head(dir["newNonce"])
		if err != nil {
			return nil, err
		}
		resp.Body.Close()
		c.nonce = resp.Header.Get("Replay-Nonce")
	}

	// Build JWS.
	protected := map[string]interface{}{
		"alg":   "ES256",
		"nonce": c.nonce,
		"url":   url,
	}
	if c.accountURL == "" {
		jwk, err := c.jwk()
		if err != nil {
			return nil, err
		}
		protected["jwk"] = jwk
	} else {
		protected["kid"] = c.accountURL
	}
	// Adjust alg for RSA.
	if _, ok := c.accountKey.(*rsa.PrivateKey); ok {
		protected["alg"] = "RS256"
	}

	protJSON, _ := json.Marshal(protected)
	// POST-as-GET (RFC 8555 §7.3): empty payload, not "null".
	var payloadB64 string
	if payload != nil {
		payloadJSON, _ := json.Marshal(payload)
		payloadB64 = base64.RawURLEncoding.EncodeToString(payloadJSON)
	}
	protB64 := base64.RawURLEncoding.EncodeToString(protJSON)
	signingInput := protB64 + "." + payloadB64

	var sig []byte
	switch k := c.accountKey.(type) {
	case *ecdsa.PrivateKey:
		h := sha256.Sum256([]byte(signingInput))
		r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
		if err != nil {
			return nil, err
		}
		// JWS requires raw R||S, each 32 bytes for P-256.
		sig = make([]byte, 64)
		rb := r.Bytes()
		sb := s.Bytes()
		copy(sig[32-len(rb):32], rb)
		copy(sig[64-len(sb):], sb)
	case *rsa.PrivateKey:
		h := sha256.Sum256([]byte(signingInput))
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
		if err != nil {
			return nil, err
		}
	}

	jws := map[string]string{
		"protected": protB64,
		"payload":   payloadB64,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	}
	body, _ := json.Marshal(jws)

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	// Save nonce for next request.
	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		c.nonce = n
	}
	return resp, nil
}

// checkResponse verifies the HTTP status and returns a descriptive error
// if the ACME server rejected the request. ACME errors have a numeric
// "status" field, so we must check before decoding into our structs.
func checkResponse(resp *http.Response, op string) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	defer resp.Body.Close()
	var acmeErr struct {
		Type   string `json:"type"`
		Detail string `json:"detail"`
		Status int    `json:"status"`
	}
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &acmeErr); err == nil && acmeErr.Detail != "" {
		return fmt.Errorf("acme %s: %s (type=%s, status=%d)", op, acmeErr.Detail, acmeErr.Type, acmeErr.Status)
	}
	return fmt.Errorf("acme %s: http %d: %s", op, resp.StatusCode, b)
}

// Register creates a new ACME account.
func (c *Client) Register(email string) error {
	dir, err := c.directory()
	if err != nil {
		return err
	}
	payload := map[string]interface{}{
		"termsOfServiceAgreed": true,
	}
	if email != "" {
		payload["contact"] = []string{"mailto:" + email}
	}
	resp, err := c.post(dir["newAccount"], payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("acme: register status %d: %s", resp.StatusCode, b)
	}
	c.accountURL = resp.Header.Get("Location")
	return nil
}

// ChallengeInfo holds the http-01 challenge details.
type ChallengeInfo struct {
	Token         string
	KeyAuth       string
	ChallengeURL  string
	Authorization string
}

type problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

type authorization struct {
	Status     string `json:"status"`
	Challenges []struct {
		Type   string   `json:"type"`
		URL    string   `json:"url"`
		Token  string   `json:"token"`
		Status string   `json:"status"`
		Error  *problem `json:"error"`
	} `json:"challenges"`
}

func (a authorization) failure() error {
	for _, ch := range a.Challenges {
		if ch.Type == "http-01" && ch.Error != nil {
			return fmt.Errorf("acme: HTTP-01 challenge %s: %s (type=%s)", a.Status, ch.Error.Detail, ch.Error.Type)
		}
	}
	return fmt.Errorf("acme: authorization %s", a.Status)
}

func (c *Client) waitAuthorization(url string) error {
	var lastErr error
	var status string
	for i := 0; i < c.pollAttempts; i++ {
		if i > 0 {
			time.Sleep(c.pollInterval)
		}
		resp, err := c.post(url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		if err := checkResponse(resp, "pollAuthorization"); err != nil {
			lastErr = err
			continue
		}
		var auth authorization
		err = json.NewDecoder(resp.Body).Decode(&auth)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("acme: decode authorization: %w", err)
		}
		status = auth.Status
		lastErr = nil
		switch status {
		case "valid":
			return nil
		case "pending", "processing":
			// The CA is still checking the challenge.
		default:
			return auth.failure()
		}
	}
	if lastErr != nil {
		return fmt.Errorf("acme: authorization polling exhausted: %w", lastErr)
	}
	return fmt.Errorf("acme: authorization did not become valid (status=%s)", status)
}

// ObtainCert obtains a certificate for domain via http-01.
// challengeSrv must serve KeyAuth at /.well-known/acme-challenge/<Token>.
// Returns PEM-encoded cert chain and private key.
func (c *Client) ObtainCert(domain string, challengeSrv func(token, keyAuth string)) ([]byte, []byte, error) {
	dir, err := c.directory()
	if err != nil {
		return nil, nil, err
	}

	// 1. Create order.
	orderPayload := map[string]interface{}{
		"identifiers": []map[string]string{{"type": "dns", "value": domain}},
	}
	resp, err := c.post(dir["newOrder"], orderPayload)
	if err != nil {
		return nil, nil, err
	}
	if err := checkResponse(resp, "newOrder"); err != nil {
		return nil, nil, err
	}
	var order struct {
		Authorizations []string `json:"authorizations"`
		Finalize       string   `json:"finalize"`
		Status         string   `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&order); err != nil {
		resp.Body.Close()
		return nil, nil, err
	}
	orderURL := resp.Header.Get("Location")
	resp.Body.Close()

	if len(order.Authorizations) == 0 {
		return nil, nil, fmt.Errorf("acme: no authorizations")
	}

	// 2. Get challenge from first authorization.
	resp, err = c.post(order.Authorizations[0], nil)
	if err != nil {
		return nil, nil, err
	}
	if err := checkResponse(resp, "getAuthorization"); err != nil {
		return nil, nil, err
	}
	var auth authorization
	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		resp.Body.Close()
		return nil, nil, err
	}
	resp.Body.Close()

	// If already valid (e.g. cached from a previous run), skip the challenge.
	if auth.Status != "valid" {
		if auth.Status != "pending" {
			return nil, nil, auth.failure()
		}
		var challURL, token string
		for _, ch := range auth.Challenges {
			if ch.Type == "http-01" {
				challURL = ch.URL
				token = ch.Token
				break
			}
		}
		if challURL == "" {
			types := make([]string, 0, len(auth.Challenges))
			for _, ch := range auth.Challenges {
				types = append(types, ch.Type+":"+ch.Status)
			}
			return nil, nil, fmt.Errorf("acme: no http-01 challenge (auth status=%s, challenges=%v)", auth.Status, types)
		}

		// 3. Compute key authorization.
		jwk, err := c.jwk()
		if err != nil {
			return nil, nil, err
		}
		jwkJSON, _ := json.Marshal(jwk)
		jwkHash := sha256.Sum256(jwkJSON)
		thumbprint := base64.RawURLEncoding.EncodeToString(jwkHash[:])
		keyAuth := token + "." + thumbprint

		// 4. Serve challenge and notify ACME server.
		challengeSrv(token, keyAuth)

		cresp, err := c.post(challURL, map[string]interface{}{})
		if err != nil {
			return nil, nil, err
		}
		if err := checkResponse(cresp, "triggerChallenge"); err != nil {
			return nil, nil, err
		}
		cresp.Body.Close()

		// 5. Poll authorization until valid.
		if err := c.waitAuthorization(order.Authorizations[0]); err != nil {
			return nil, nil, err
		}
	}

	// 6. Generate key and CSR.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		return nil, nil, err
	}
	csrB64 := base64.RawURLEncoding.EncodeToString(csrDER)

	// 7. Finalize order.
	resp, err = c.post(order.Finalize, map[string]string{"csr": csrB64})
	if err != nil {
		return nil, nil, err
	}
	if err := checkResponse(resp, "finalizeOrder"); err != nil {
		return nil, nil, err
	}
	resp.Body.Close()

	// 8. Poll order until valid, get certificate URL.
	var certURL string
	for i := 0; i < c.pollAttempts; i++ {
		if i > 0 {
			time.Sleep(c.pollInterval)
		}
		resp, err := c.post(orderURL, nil)
		if err != nil {
			continue
		}
		if err := checkResponse(resp, "pollOrder"); err != nil {
			// (checkResponse already closed the body on error)
			continue
		}
		var o struct {
			Status      string `json:"status"`
			Certificate string `json:"certificate"`
		}
		json.NewDecoder(resp.Body).Decode(&o)
		resp.Body.Close()
		if o.Status == "valid" {
			certURL = o.Certificate
			break
		}
		if o.Status == "invalid" {
			return nil, nil, fmt.Errorf("acme: order invalid")
		}
	}
	if certURL == "" {
		return nil, nil, fmt.Errorf("acme: order not valid")
	}

	// 9. Download certificate.
	resp, err = c.post(certURL, nil)
	if err != nil {
		return nil, nil, err
	}
	if err := checkResponse(resp, "downloadCert"); err != nil {
		return nil, nil, err
	}
	certPEM, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, nil, err
	}

	// Encode private key as PEM.
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pemEncode("EC PRIVATE KEY", keyDER)

	return certPEM, keyPEM, nil
}

func pemEncode(blockType string, der []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("-----BEGIN " + blockType + "-----\n")
	b64 := base64.StdEncoding.EncodeToString(der)
	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) {
			end = len(b64)
		}
		buf.WriteString(b64[i:end] + "\n")
	}
	buf.WriteString("-----END " + blockType + "-----\n")
	return buf.Bytes()
}
