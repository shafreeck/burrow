package socks5

import (
	"bytes"
	"testing"
)

func TestHandshakeAndRequest(t *testing.T) {
	// Simulate client + server over a buffer.
	// Client greeting: VER=5, NMETHODS=1, METHODS=[0x00]
	clientHello := []byte{0x05, 0x01, 0x00}
	// Client request: VER=5, CMD=1, RSV=0, ATYP=3, domain "example.com", port 80
	req := []byte{0x05, 0x01, 0x00, 0x03, 11}
	req = append(req, "example.com"...)
	req = append(req, 0x00, 0x50)

	// Server side: use a bytes.Buffer as the "connection"
	var buf bytes.Buffer
	buf.Write(clientHello)

	if err := Handshake(&buf); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	// Handshake consumed 3 bytes, wrote 2 bytes response.
	// Now feed the request.
	buf.Write(req[0:0]) // no-op
	r := bytes.NewReader(req)
	parsed, err := ParseRequest(r)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Addr != "example.com:80" {
		t.Errorf("addr=%q, want example.com:80", parsed.Addr)
	}

	// Check the handshake response bytes are at the start.
	// (buf now contains: response from Handshake)
	out := buf.Bytes()
	if len(out) < 2 || out[0] != 0x05 || out[1] != 0x00 {
		t.Errorf("handshake response = %x, want 0500", out)
	}
}

func TestWriteReply(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteReply(&buf, RepSuccess); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if len(b) != 10 || b[0] != 0x05 || b[1] != 0x00 {
		t.Errorf("reply = %x", b)
	}
}
