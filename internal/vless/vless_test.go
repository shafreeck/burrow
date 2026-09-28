package vless

import (
	"bytes"
	"testing"
)

func TestParseTCPIPv4(t *testing.T) {
	// ver=0, uuid=16 bytes, addonLen=0, cmd=TCP, port=443, atype=IPv4, addr=1.2.3.4
	buf := []byte{0x00}
	buf = append(buf, bytes.Repeat([]byte{0xAB}, 16)...)
	buf = append(buf, 0x00)       // addon len
	buf = append(buf, CmdTCP)     // cmd
	buf = append(buf, 0x01, 0xBB) // port 443
	buf = append(buf, ATypeIPv4)
	buf = append(buf, 1, 2, 3, 4)

	req, err := Parse(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if req.Command != CmdTCP {
		t.Errorf("command = %x, want %x", req.Command, CmdTCP)
	}
	if req.Addr != "1.2.3.4:443" {
		t.Errorf("addr = %q, want 1.2.3.4:443", req.Addr)
	}
}

func TestParseTCPDomain(t *testing.T) {
	buf := []byte{0x00}
	buf = append(buf, bytes.Repeat([]byte{0xCD}, 16)...)
	buf = append(buf, 0x00)
	buf = append(buf, CmdTCP)
	buf = append(buf, 0x00, 0x50) // port 80
	buf = append(buf, ATypeDomain)
	buf = append(buf, byte(len("example.com")))
	buf = append(buf, "example.com"...)

	req, err := Parse(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if req.Addr != "example.com:80" {
		t.Errorf("addr = %q, want example.com:80", req.Addr)
	}
}

func TestParseBadVersion(t *testing.T) {
	buf := []byte{0x01}
	buf = append(buf, bytes.Repeat([]byte{0}, 17)...)
	if _, err := Parse(bytes.NewReader(buf)); err != ErrBadVersion {
		t.Errorf("err = %v, want ErrBadVersion", err)
	}
}

func TestParseUDPRejected(t *testing.T) {
	buf := []byte{0x00}
	buf = append(buf, bytes.Repeat([]byte{0}, 16)...)
	buf = append(buf, 0x00)
	buf = append(buf, CmdUDP)
	buf = append(buf, 0x00, 0x35, ATypeIPv4, 8, 8, 8, 8)
	if _, err := Parse(bytes.NewReader(buf)); err != ErrBadCommand {
		t.Errorf("err = %v, want ErrBadCommand", err)
	}
}

func TestWriteResponse(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResponse(&buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), []byte{0x00, 0x00}) {
		t.Errorf("response = %x, want 0000", buf.Bytes())
	}
}
