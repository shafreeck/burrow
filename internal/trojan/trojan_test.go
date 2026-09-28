package trojan

import (
	"bytes"
	"strings"
	"testing"
)

func TestPasswordHash(t *testing.T) {
	// Known test vector: SHA224("password") hex.
	h := PasswordHash("password")
	if len(h) != 56 {
		t.Fatalf("hash len = %d, want 56", len(h))
	}
	// Deterministic.
	if PasswordHash("password") != h {
		t.Fatal("not deterministic")
	}
	if PasswordHash("other") == h {
		t.Fatal("collision")
	}
}

func TestVerifyPassword(t *testing.T) {
	pw := "test-secret"
	hash := PasswordHash(pw)

	// Valid.
	r := strings.NewReader(hash + "\r\n")
	if err := VerifyPassword(r, pw); err != nil {
		t.Fatal("valid password rejected:", err)
	}

	// Invalid.
	r = strings.NewReader(hash + "\r\n")
	if err := VerifyPassword(r, "wrong"); err == nil {
		t.Fatal("invalid password accepted")
	}

	// Bad line ending.
	r = strings.NewReader(hash + "\n\n")
	if err := VerifyPassword(r, pw); err == nil {
		t.Fatal("bad CRLF accepted")
	}
}

func TestParseRequest(t *testing.T) {
	// CMD=TCP, ATYP=Domain, "example.com", port 80, CRLF.
	var buf bytes.Buffer
	buf.Write([]byte{CmdTCP, ATypeDomain, 11})
	buf.WriteString("example.com")
	buf.Write([]byte{0, 80})
	buf.Write([]byte{'\r', '\n'})

	req, err := ParseRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if req.Addr != "example.com:80" {
		t.Fatalf("addr = %q", req.Addr)
	}
}

func TestParseRequestIPv4(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{CmdTCP, ATypeIPv4, 93, 184, 216, 34})
	buf.Write([]byte{1, 187}) // 443
	buf.Write([]byte{'\r', '\n'})

	req, err := ParseRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if req.Addr != "93.184.216.34:443" {
		t.Fatalf("addr = %q", req.Addr)
	}
}

func TestParseRequestRejectsUDP(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{CmdUDP, ATypeIPv4, 1, 2, 3, 4})
	buf.Write([]byte{0, 53})
	buf.Write([]byte{'\r', '\n'})

	if _, err := ParseRequest(&buf); err == nil {
		t.Fatal("UDP should be rejected")
	}
}
