package ws

import (
	"bufio"
	"bytes"
	"net"
	"sync"
	"testing"
)

// pipeConn creates an in-memory net.Conn pair.
func pipeConn() (net.Conn, net.Conn) {
	a, b := net.Pipe()
	return a, b
}

func TestFrameLengthOverflow(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := newConn(b, rwFor(b), true)
	go a.Write([]byte{0x82, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	if _, _, err := c.ReadFrame(); err == nil {
		t.Fatal("overflowing frame length accepted")
	}
}

func TestConcurrentClose(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := newConn(a, rwFor(a), true)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.Close() }()
	}
	wg.Wait()
}

func rwFor(c net.Conn) *bufio.ReadWriter {
	return bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
}

func TestTextRoundtrip(t *testing.T) {
	ca, cb := pipeConn()
	defer ca.Close()
	defer cb.Close()

	// serverSide=true on both ends is fine for framing test (no mask)
	sa := newConn(ca, rwFor(ca), true)
	sb := newConn(cb, rwFor(cb), true)

	msg := []byte("hello websocket")
	go func() { _ = sa.WriteText(msg) }()

	op, payload, err := sb.ReadFrame()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if op != OpText {
		t.Fatalf("opcode=%d, want %d", op, OpText)
	}
	if !bytes.Equal(payload, msg) {
		t.Fatalf("payload mismatch")
	}
}

func TestBinaryRoundtrip(t *testing.T) {
	ca, cb := pipeConn()
	defer ca.Close()
	defer cb.Close()

	sa := newConn(ca, rwFor(ca), true)
	sb := newConn(cb, rwFor(cb), true)

	// large payload to exercise 16-bit length
	msg := bytes.Repeat([]byte("x"), 70000)
	go func() { _ = sa.WriteBinary(msg) }()

	op, payload, err := sb.ReadFrame()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if op != OpBinary {
		t.Fatalf("opcode=%d", op)
	}
	if !bytes.Equal(payload, msg) {
		t.Fatalf("payload mismatch: %d bytes", len(payload))
	}
}

func TestPingAutoPong(t *testing.T) {
	ca, cb := pipeConn()
	defer ca.Close()
	defer cb.Close()

	sa := newConn(ca, rwFor(ca), true)
	sb := newConn(cb, rwFor(cb), true)

	// Write ping+text from a goroutine; sb.ReadFrame should skip the
	// ping (auto-pong in background) and return the text.
	// Note: we don't verify the pong bytes here — net.Pipe is
	// synchronous and ping/pong simultaneous r/w would deadlock in test.
	go func() {
		_ = sa.writeFrame(OpPing, []byte("pingdata"))
		_ = sa.WriteText([]byte("after ping"))
	}()

	// Read the pong in background so sb's auto-pong doesn't block.
	go func() {
		_, _, _ = sa.ReadFrame()
	}()

	op, payload, err := sb.ReadFrame()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if op != OpText || string(payload) != "after ping" {
		t.Fatalf("got op=%d payload=%q", op, payload)
	}
}

func TestFrameTooLarge(t *testing.T) {
	ca, cb := pipeConn()
	defer ca.Close()
	defer cb.Close()

	sb := newConn(cb, rwFor(cb), true)

	// Craft a frame header claiming a payload larger than MaxFrameSize.
	// Use 127 (64-bit length) to encode MaxFrameSize+1.
	go func() {
		w := bufio.NewWriter(ca)
		// FIN + binary opcode, no mask, 127 = 8-byte length follows
		w.Write([]byte{0x82, 0x7F})
		var lenBytes [8]byte
		n := uint64(MaxFrameSize + 1)
		for i := 7; i >= 0; i-- {
			lenBytes[i] = byte(n)
			n >>= 8
		}
		w.Write(lenBytes[:])
		w.Flush()
	}()

	_, _, err := sb.ReadFrame()
	if err == nil {
		t.Fatal("expected frame-too-large error, got nil")
	}
}

func TestClientMasksWithRandomKey(t *testing.T) {
	ca, cb := pipeConn()
	defer ca.Close()
	defer cb.Close()

	// client side (masks), server side (doesn't mask)
	client := newConn(ca, rwFor(ca), false)
	server := newConn(cb, rwFor(cb), true)

	msg := []byte("mask me")
	orig := append([]byte(nil), msg...) // copy for later comparison

	go func() { _ = client.WriteText(msg) }()

	op, payload, err := server.ReadFrame()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if op != OpText {
		t.Fatalf("opcode=%d", op)
	}
	if !bytes.Equal(payload, orig) {
		t.Fatalf("payload mismatch after unmask")
	}
	// Caller's slice must not be modified in place.
	if !bytes.Equal(msg, orig) {
		t.Fatalf("client payload was modified in place")
	}
}
