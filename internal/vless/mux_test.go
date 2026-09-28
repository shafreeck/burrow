package vless

import (
	"bytes"
	"testing"
)

func TestMuxFrameRoundTrip(t *testing.T) {
	// Build a New frame manually: meta_len(2) + meta + payload
	// meta: sid(2) + status(1) + option(1) + network(1) + port(2) + atype(1) + domain_len(1) + domain
	domain := "example.com"
	meta := new(bytes.Buffer)
	meta.Write([]byte{0x00, 0x01}) // sid=1
	meta.WriteByte(MuxNew)         // status=New
	meta.WriteByte(MuxOptData)     // option=Data
	meta.WriteByte(MuxNetTCP)      // network=TCP
	meta.Write([]byte{0x00, 0x50}) // port=80
	meta.WriteByte(ATypeDomain)
	meta.WriteByte(byte(len(domain)))
	meta.WriteString(domain)

	payload := []byte("GET / HTTP/1.0\r\n\r\n")

	buf := new(bytes.Buffer)
	ml := uint16(meta.Len())
	buf.WriteByte(byte(ml >> 8))
	buf.WriteByte(byte(ml))
	buf.Write(meta.Bytes())
	pl := uint16(len(payload))
	buf.WriteByte(byte(pl >> 8))
	buf.WriteByte(byte(pl))
	buf.Write(payload)

	// Parse it
	f, err := ReadMuxFrame(buf)
	if err != nil {
		t.Fatalf("ReadMuxFrame: %v", err)
	}
	if f.SessionID != 1 {
		t.Errorf("SessionID = %d, want 1", f.SessionID)
	}
	if f.Status != MuxNew {
		t.Errorf("Status = %d, want %d", f.Status, MuxNew)
	}
	if f.Addr != "example.com:80" {
		t.Errorf("Addr = %q, want example.com:80", f.Addr)
	}
	if string(f.Payload) != string(payload) {
		t.Errorf("Payload mismatch")
	}

	// Test WriteMuxFrame (server -> client data frame)
	out := new(bytes.Buffer)
	if err := WriteMuxFrame(out, 1, MuxKeep, MuxOptData, []byte("hello")); err != nil {
		t.Fatalf("WriteMuxFrame: %v", err)
	}
	f2, err := ReadMuxFrame(out)
	if err != nil {
		t.Fatalf("ReadMuxFrame2: %v", err)
	}
	if f2.SessionID != 1 || f2.Status != MuxKeep || string(f2.Payload) != "hello" {
		t.Errorf("Write/Read roundtrip failed: %+v", f2)
	}
}
