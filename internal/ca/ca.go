package ca

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

//go:embed hatch-egress-ca.crt
var hatchEgressCA []byte

// PEM returns the embedded Hatch sandbox egress CA certificate in PEM format.
func PEM() []byte {
	return hatchEgressCA
}

// Install installs a caller-supplied root CA, or the bundled CA snapshot
// when path is empty. Callers must verify a new root with the VM administrator;
// a certificate received from an untrusted TLS connection is not proof of identity.
// On macOS it uses `security add-trusted-cert` (requires sudo for System keychain).
// On Linux it copies to /usr/local/share/ca-certificates and runs update-ca-certificates.
func Install(path string) error {
	data := hatchEgressCA
	if path != "" {
		var err error
		data, err = os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read CA: %w", err)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Using the bundled CA snapshot; verify its SHA-256 fingerprint against your current VM. Use --ca-cert if that VM uses a different root.")
	}
	cert, err := validateRoot(data)
	if err != nil {
		return err
	}
	fmt.Printf("CA subject: %s\nSHA-256: %X\n", cert.Subject, sha256.Sum256(cert.Raw))
	switch runtime.GOOS {
	case "darwin":
		// Write to temp file, then add to System keychain
		tmp, err := os.CreateTemp("", "hatch-egress-ca-*.crt")
		if err != nil {
			return fmt.Errorf("create temp file: %w", err)
		}
		tmpPath := tmp.Name()
		if _, err := tmp.Write(data); err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("write temp cert: %w", err)
		}
		tmp.Close()
		defer os.Remove(tmpPath)

		cmd := exec.Command("sudo", "security", "add-trusted-cert",
			"-d", "-r", "trustRoot",
			"-k", "/Library/Keychains/System.keychain",
			tmpPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("security add-trusted-cert failed: %w", err)
		}
		fmt.Println("CA installed to System keychain as trusted root.")
		return nil

	case "linux":
		dst := "/usr/local/share/ca-certificates/hatch-egress-ca.crt"
		if err := os.WriteFile(dst, data, 0644); err != nil {
			return fmt.Errorf("write %s (need sudo): %w", dst, err)
		}
		cmd := exec.Command("update-ca-certificates")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("update-ca-certificates failed: %w", err)
		}
		fmt.Println("CA installed to system trust store.")
		return nil

	default:
		// Fallback: write to current directory
		dst := filepath.Join(".", "hatch-egress-ca.crt")
		if err := os.WriteFile(dst, data, 0644); err != nil {
			return fmt.Errorf("write %s: %w", dst, err)
		}
		fmt.Printf("CA written to %s (manual install required on %s)\n", dst, runtime.GOOS)
		return nil
	}
}

func validateRoot(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(bytes.TrimSpace(data))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("CA file must contain exactly one PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA: %w", err)
	}
	if !cert.IsCA || !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return nil, fmt.Errorf("CA file must contain a self-signed root CA, not a website or intermediate certificate")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return nil, fmt.Errorf("invalid root CA signature: %w", err)
	}
	if now := time.Now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("root CA is outside its validity period (%s to %s)", cert.NotBefore, cert.NotAfter)
	}
	return cert, nil
}
