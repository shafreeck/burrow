// Package trojan implements the Trojan protocol request parsing.
// Trojan: https://trojan-gfw.github.io/trojan/developer/protocol
//
// Client sends (over TLS):
//
//	hex(SHA224(password)) + "\r\n"
//	+ CMD(1) + ATYP(1) + ADDR + PORT(2) + "\r\n"
//	+ payload...
//
// CMD: 0x01 = TCP CONNECT, 0x03 = UDP ASSOCIATE
// ATYP: 0x01 = IPv4, 0x03 = Domain, 0x04 = IPv6
//
// We only support TCP CONNECT. UDP is rejected.
package trojan

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net"
)

const (
	CmdTCP = 0x01
	CmdUDP = 0x03

	ATypeIPv4   = 0x01
	ATypeDomain = 0x03
	ATypeIPv6   = 0x04
)

// PasswordHash returns hex(SHA224(password)) as used by Trojan.
func PasswordHash(password string) string {
	h := sha256.Sum224([]byte(password))
	return hex.EncodeToString(h[:])
}

// Request is a parsed Trojan request.
type Request struct {
	Addr string // host:port
}

// VerifyPassword reads the 56-char hex hash + CRLF and compares.
func VerifyPassword(r io.Reader, password string) error {
	buf := make([]byte, 58) // 56 hex + \r\n
	if _, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("trojan: read password: %w", err)
	}
	if buf[56] != '\r' || buf[57] != '\n' {
		return fmt.Errorf("trojan: bad password line ending")
	}
	got := string(buf[:56])
	want := PasswordHash(password)
	// Constant-time compare to avoid timing leaks.
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return fmt.Errorf("trojan: bad password")
	}
	return nil
}

// ParseRequest reads CMD + ATYP + ADDR + PORT + CRLF after password verification.
func ParseRequest(r io.Reader) (*Request, error) {
	hdr := make([]byte, 2) // CMD + ATYP
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("trojan: read cmd/atyp: %w", err)
	}
	if hdr[0] != CmdTCP {
		return nil, fmt.Errorf("trojan: unsupported cmd %d", hdr[0])
	}

	var host string
	switch hdr[1] {
	case ATypeIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, fmt.Errorf("trojan: read ipv4: %w", err)
		}
		host = net.IP(b).String()
	case ATypeDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return nil, fmt.Errorf("trojan: read domain len: %w", err)
		}
		if lb[0] == 0 {
			return nil, fmt.Errorf("trojan: empty domain")
		}
		b := make([]byte, lb[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, fmt.Errorf("trojan: read domain: %w", err)
		}
		host = string(b)
	case ATypeIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, fmt.Errorf("trojan: read ipv6: %w", err)
		}
		host = net.IP(b).String()
	default:
		return nil, fmt.Errorf("trojan: bad atyp %d", hdr[1])
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, portBytes); err != nil {
		return nil, fmt.Errorf("trojan: read port: %w", err)
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])
	if port == 0 {
		return nil, fmt.Errorf("trojan: port must be nonzero")
	}

	crlf := make([]byte, 2)
	if _, err := io.ReadFull(r, crlf); err != nil {
		return nil, fmt.Errorf("trojan: read crlf: %w", err)
	}
	if crlf[0] != '\r' || crlf[1] != '\n' {
		return nil, fmt.Errorf("trojan: bad crlf")
	}

	return &Request{Addr: net.JoinHostPort(host, fmt.Sprint(port))}, nil
}
