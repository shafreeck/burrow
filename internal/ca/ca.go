package ca

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

//go:embed hatch-egress-ca.crt
var hatchEgressCA []byte

// PEM returns the embedded Hatch sandbox egress CA certificate in PEM format.
func PEM() []byte {
	return hatchEgressCA
}

// Install installs the embedded CA certificate into the system trust store.
// On macOS it uses `security add-trusted-cert` (requires sudo for System keychain).
// On Linux it copies to /usr/local/share/ca-certificates and runs update-ca-certificates.
func Install() error {
	switch runtime.GOOS {
	case "darwin":
		// Write to temp file, then add to System keychain
		tmp, err := os.CreateTemp("", "hatch-egress-ca-*.crt")
		if err != nil {
			return fmt.Errorf("create temp file: %w", err)
		}
		tmpPath := tmp.Name()
		if _, err := tmp.Write(hatchEgressCA); err != nil {
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
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("security add-trusted-cert failed: %w", err)
		}
		fmt.Println("CA installed to System keychain as trusted root.")
		return nil

	case "linux":
		dst := "/usr/local/share/ca-certificates/hatch-egress-ca.crt"
		if err := os.WriteFile(dst, hatchEgressCA, 0644); err != nil {
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
		if err := os.WriteFile(dst, hatchEgressCA, 0644); err != nil {
			return fmt.Errorf("write %s: %w", dst, err)
		}
		fmt.Printf("CA written to %s (manual install required on %s)\n", dst, runtime.GOOS)
		return nil
	}
}
