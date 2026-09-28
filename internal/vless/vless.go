// Package vless implements the VLESS proxy protocol (TCP).
// See https://github.com/XTLS/Xray-core for the reference implementation.
//
// VLESS request header (client -> server):
//
//	+------+--------+-------+---------+----------+--------+--------+
//	| Ver  | UUID   | Addon | Command | Port    | AType  | Addr   |
//	+------+--------+-------+---------+----------+--------+--------+
//	|  1   | 16     | 1 (M) | 1       | 2 (BE)  | 1      | var    |
//	+------+--------+-------+---------+----------+--------+--------+
//
// VLESS response header (server -> client, TCP only):
//
//	+-----+-------+
//	| Ver | Addon |
//	+-----+-------+
//	|  1  | 1 (0) |
//	+-----+-------+
package vless

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// Commands.
const (
	CmdTCP = 0x01
	CmdUDP = 0x02
	CmdMux = 0x03
)

// Address types.
const (
	ATypeIPv4   = 0x01
	ATypeDomain = 0x02
	ATypeIPv6   = 0x03
)

// Version.
const Version = 0x00

var (
	ErrBadVersion = errors.New("vless: bad version")
	ErrBadCommand = errors.New("vless: unsupported command")
	ErrBadAType   = errors.New("vless: bad address type")
)

// Request is a parsed VLESS client header.
type Request struct {
	UUID    [16]byte
	Command byte
	Addr    string // "host:port"
}

// Parse reads and parses a VLESS request header from r.
// It returns the request and any bytes already read beyond the header
// (there should be none; VLESS header is followed immediately by payload).
func Parse(r io.Reader) (*Request, error) {
	// Fixed part: ver(1) + uuid(16) + addonLen(1)
	hdr := make([]byte, 18)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("vless: read header: %w", err)
	}
	if hdr[0] != Version {
		return nil, ErrBadVersion
	}
	var req Request
	copy(req.UUID[:], hdr[1:17])
	addonLen := int(hdr[17])
	if addonLen > 0 {
		// Skip addon data (rarely used).
		if _, err := io.CopyN(io.Discard, r, int64(addonLen)); err != nil {
			return nil, fmt.Errorf("vless: read addon: %w", err)
		}
	}

	// Command(1) + Port(2) + AType(1)
	cmd := make([]byte, 4)
	if _, err := io.ReadFull(r, cmd); err != nil {
		return nil, fmt.Errorf("vless: read cmd: %w", err)
	}
	req.Command = cmd[0]
	if req.Command != CmdTCP && req.Command != CmdMux && req.Command != CmdUDP {
		return nil, ErrBadCommand
	}
	if req.Command == CmdMux {
		// MUX: the VLESS request header omits port/address.
		// The address for each sub-stream comes inside MUX frames.
		req.Addr = "mux"
		return &req, nil
	}
	port := binary.BigEndian.Uint16(cmd[1:3])
	atype := cmd[3]

	var host string
	switch atype {
	case ATypeIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, fmt.Errorf("vless: read ipv4: %w", err)
		}
		host = net.IP(b).String()
	case ATypeDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return nil, fmt.Errorf("vless: read domain len: %w", err)
		}
		b := make([]byte, lb[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, fmt.Errorf("vless: read domain: %w", err)
		}
		host = string(b)
	case ATypeIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, fmt.Errorf("vless: read ipv6: %w", err)
		}
		host = net.IP(b).String()
	default:
		return nil, ErrBadAType
	}
	req.Addr = net.JoinHostPort(host, fmt.Sprint(port))
	return &req, nil
}

// WriteResponse writes the VLESS TCP response header (ver=0, addonLen=0).
func WriteResponse(w io.Writer) error {
	_, err := w.Write([]byte{Version, 0x00})
	return err
}
