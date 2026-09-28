package main

import (
	"fmt"
	"strings"
)

// validateTransport keeps public hostname, tunnel management, and certificate
// issuance separate. In particular, a hostname never silently requests a cert.
func validateTransport(tunnel, noTunnel bool, domain string, acme bool, cert, key string) (string, error) {
	mode := "none"
	if tunnel {
		mode = "quick"
		if domain != "" {
			mode = "external"
		}
	}
	if noTunnel && tunnel {
		return "", fmt.Errorf("--no-tunnel conflicts with --tunnel")
	}
	if domain != "" {
		if len(domain) > 253 || !strings.Contains(domain, ".") {
			return "", fmt.Errorf("--domain must be a DNS hostname, such as burrow.example.com")
		}
		for _, label := range strings.Split(domain, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", fmt.Errorf("invalid --domain %q: use a DNS hostname without a scheme, port, path, or backslash", domain)
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return "", fmt.Errorf("invalid --domain %q: use a DNS hostname without a scheme, port, path, or backslash", domain)
				}
			}
		}
	}
	if (cert == "") != (key == "") {
		return "", fmt.Errorf("--tls-cert and --tls-key must be supplied together")
	}
	if mode != "none" && (acme || cert != "") {
		return "", fmt.Errorf("tunnel mode %s uses local HTTP and Cloudflare's public TLS; remove --acme, --tls-cert, and --tls-key", mode)
	}
	if acme && domain == "" {
		return "", fmt.Errorf("--acme requires --domain")
	}
	if acme && cert != "" {
		return "", fmt.Errorf("choose either --acme or --tls-cert/--tls-key")
	}
	if mode == "none" && domain != "" && !acme && cert == "" {
		return "", fmt.Errorf("--domain no longer implicitly enables ACME; add --acme for direct TLS, supply --tls-cert/--tls-key, or add --tunnel for a fixed Cloudflare hostname")
	}
	return mode, nil
}
