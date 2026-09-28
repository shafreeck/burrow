// Package vless implements the VLESS proxy protocol (TCP).
// This file implements Mux.Cool frame parsing (Xray's multiplexing protocol).
//
// Mux.Cool frame format (xray common/mux/frame.go, all big-endian):
//
//	meta_len   u16 BE    length of the meta block
//	meta:
//	    session_id u16 BE  stream id — client-allocated, echoed back by server
//	    status     u8      1=New 2=Keep 3=End 4=KeepAlive
//	    option     u8      bit1=Data, bit2=Error
//	    (New frames:)
//	      network u8       1=TCP 2=UDP
//	      port    u16 BE
//	      atype   u8       0x01 IPv4 | 0x02 domain | 0x03 IPv6
//	      address ...      (port first, then address)
//	payload_len u16 BE   present only when option&Data
//	payload             payload_len bytes
package vless

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// MUX session statuses.
const (
	MuxNew       = 0x01
	MuxKeep      = 0x02
	MuxEnd       = 0x03
	MuxKeepAlive = 0x04
)

// MUX option bits.
const (
	MuxOptData  = 0x01
	MuxOptError = 0x02
)

// MUX network types.
const (
	MuxNetTCP = 0x01
	MuxNetUDP = 0x02
)

// MuxFrame is a parsed Mux.Cool frame.
type MuxFrame struct {
	SessionID uint16
	Status    byte
	Option    byte
	Network   byte   // only for New frames
	Addr      string // only for New frames, "host:port"
	Payload   []byte // only when Option&MuxOptData != 0
}

// ReadMuxFrame reads one Mux.Cool frame from r.
func ReadMuxFrame(r io.Reader) (*MuxFrame, error) {
	// meta_len (2 bytes)
	var metaLenBuf [2]byte
	if _, err := io.ReadFull(r, metaLenBuf[:]); err != nil {
		return nil, fmt.Errorf("mux: read meta_len: %w", err)
	}
	metaLen := binary.BigEndian.Uint16(metaLenBuf[:])
	if metaLen < 4 {
		return nil, fmt.Errorf("mux: meta_len too small: %d", metaLen)
	}
	if metaLen > 512 {
		return nil, fmt.Errorf("mux: meta_len too large: %d", metaLen)
	}

	// meta block
	meta := make([]byte, metaLen)
	if _, err := io.ReadFull(r, meta); err != nil {
		return nil, fmt.Errorf("mux: read meta: %w", err)
	}

	f := &MuxFrame{
		SessionID: binary.BigEndian.Uint16(meta[0:2]),
		Status:    meta[2],
		Option:    meta[3],
	}

	// Parse New frame address
	if f.Status == MuxNew {
		if metaLen < 4+1+2+1 {
			return nil, fmt.Errorf("mux: New frame meta too short")
		}
		f.Network = meta[4]
		if f.Network != MuxNetTCP {
			return nil, fmt.Errorf("mux: unsupported network %d (only TCP)", f.Network)
		}
		port := binary.BigEndian.Uint16(meta[5:7])
		atype := meta[7]
		var host string
		switch atype {
		case ATypeIPv4:
			if metaLen < 8+4 {
				return nil, fmt.Errorf("mux: New frame IPv4 too short")
			}
			host = net.IP(meta[8:12]).String()
		case ATypeDomain:
			if metaLen < 8+1 {
				return nil, fmt.Errorf("mux: New frame domain len missing")
			}
			dlen := int(meta[8])
			if int(metaLen) < 8+1+dlen {
				return nil, fmt.Errorf("mux: New frame domain too short")
			}
			host = string(meta[9 : 9+dlen])
		case ATypeIPv6:
			if metaLen < 8+16 {
				return nil, fmt.Errorf("mux: New frame IPv6 too short")
			}
			host = net.IP(meta[8:24]).String()
		default:
			return nil, fmt.Errorf("mux: bad atype %d", atype)
		}
		f.Addr = net.JoinHostPort(host, fmt.Sprint(port))
	}

	// Payload (only when option has Data bit)
	if f.Option&MuxOptData != 0 {
		var plenBuf [2]byte
		if _, err := io.ReadFull(r, plenBuf[:]); err != nil {
			return nil, fmt.Errorf("mux: read payload_len: %w", err)
		}
		plen := binary.BigEndian.Uint16(plenBuf[:])
		if plen > 0 {
			f.Payload = make([]byte, plen)
			if _, err := io.ReadFull(r, f.Payload); err != nil {
				return nil, fmt.Errorf("mux: read payload: %w", err)
			}
		}
	}

	return f, nil
}

// WriteMuxFrame writes a Mux.Cool frame to w.
// For server -> client, we typically send Data frames (status=Keep, option=Data)
// or End frames (status=End).
func WriteMuxFrame(w io.Writer, sessionID uint16, status, option byte, payload []byte) error {
	// Build meta: session_id(2) + status(1) + option(1) = 4 bytes
	meta := make([]byte, 4)
	binary.BigEndian.PutUint16(meta[0:2], sessionID)
	meta[2] = status
	meta[3] = option

	// meta_len
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(meta)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.Write(meta); err != nil {
		return err
	}

	// payload
	if option&MuxOptData != 0 {
		var plen [2]byte
		binary.BigEndian.PutUint16(plen[:], uint16(len(payload)))
		if _, err := w.Write(plen[:]); err != nil {
			return err
		}
		if len(payload) > 0 {
			if _, err := w.Write(payload); err != nil {
				return err
			}
		}
	}
	return nil
}
