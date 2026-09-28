// Package socks5 implements a minimal SOCKS5 TCP inbound (RFC 1928).
// Only CONNECT command with no authentication is supported.
package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const Version = 0x05

// Commands.
const (
	CmdConnect = 0x01
)

// Address types.
const (
	ATypeIPv4   = 0x01
	ATypeDomain = 0x03
	ATypeIPv6   = 0x04
)

// Reply codes.
const (
	RepSuccess = 0x00
	RepFailure = 0x01
)

// Handshake performs the SOCKS5 greeting (no-auth only).
// Returns nil on success, error otherwise.
func Handshake(rw io.ReadWriter) error {
	// Client: VER NMETHODS METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(rw, hdr); err != nil {
		return fmt.Errorf("socks5: read greeting: %w", err)
	}
	if hdr[0] != Version {
		return fmt.Errorf("socks5: bad version %d", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(rw, methods); err != nil {
		return fmt.Errorf("socks5: read methods: %w", err)
	}
	// Server: VER METHOD (0x00 = no auth)
	if _, err := rw.Write([]byte{Version, 0x00}); err != nil {
		return fmt.Errorf("socks5: write method: %w", err)
	}
	return nil
}

// Request is a parsed SOCKS5 CONNECT request.
type Request struct {
	Addr string // "host:port"
}

// ParseRequest reads a SOCKS5 request after the handshake.
func ParseRequest(r io.Reader) (*Request, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("socks5: read request: %w", err)
	}
	if hdr[0] != Version {
		return nil, fmt.Errorf("socks5: bad version %d", hdr[0])
	}
	if hdr[1] != CmdConnect {
		return nil, fmt.Errorf("socks5: unsupported cmd %d", hdr[1])
	}
	atype := hdr[3]
	var host string
	switch atype {
	case ATypeIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		host = net.IP(b).String()
	case ATypeDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return nil, err
		}
		b := make([]byte, lb[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		host = string(b)
	case ATypeIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		host = net.IP(b).String()
	default:
		return nil, fmt.Errorf("socks5: bad atype %d", atype)
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, portBytes); err != nil {
		return nil, err
	}
	port := binary.BigEndian.Uint16(portBytes)
	return &Request{Addr: net.JoinHostPort(host, fmt.Sprint(port))}, nil
}

// WriteReply writes a SOCKS5 response. rep is RepSuccess or RepFailure.
func WriteReply(w io.Writer, rep byte) error {
	// VER REP RSV ATYP(IPv4) BND.ADDR(0.0.0.0) BND.PORT(0)
	_, err := w.Write([]byte{Version, rep, 0x00, ATypeIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
