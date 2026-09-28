// Package ws provides minimal WebSocket framing over a hijacked HTTP
// connection (server side) and over a raw TCP/TLS socket (client side).
// Only what the tunnel needs: text/binary frames, ping/pong, close.
// No external dependencies.
package ws

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Opcodes.
const (
	OpText   = 0x1
	OpBinary = 0x2
	OpClose  = 0x8
	OpPing   = 0x9
	OpPong   = 0xA
)

// MaxFrameSize caps a single WebSocket frame payload at 8 MiB.
// Larger frames are rejected to avoid OOM from a malicious peer.
const MaxFrameSize = 8 << 20

// Conn is a WebSocket connection with a write mutex.
type Conn struct {
	netConn net.Conn
	rw      *bufio.ReadWriter
	// serverSide=false means we must mask client->server frames.
	serverSide bool
	wmu        chan struct{} // binary semaphore as mutex
	closed     chan struct{}
	closeOnce  sync.Once
}

// ServerHandshake hijacks w and performs the server side of the WS handshake.
func ServerHandshake(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, fmt.Errorf("missing Sec-WebSocket-Key")
	}
	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("hijack not supported")
	}
	nc, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n\r\n", accept)
	if err := rw.Flush(); err != nil {
		nc.Close()
		return nil, err
	}
	return newConn(nc, rw, true), nil
}

// ClientHandshake performs the client side over an already-connected
// (optionally TLS) net.Conn talking HTTP to host.
func ClientHandshake(nc net.Conn, host, path string) (*Conn, error) {
	rw := bufio.NewReadWriter(bufio.NewReader(nc), bufio.NewWriter(nc))
	// Random key per connection (RFC 6455).
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("rand key: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	fmt.Fprintf(rw, "GET %s HTTP/1.1\r\nHost: %s\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, host, key)
	if err := rw.Flush(); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(rw.Reader, nil)
	if err != nil {
		return nil, fmt.Errorf("handshake response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 101 {
		return nil, fmt.Errorf("handshake status: %s", resp.Status)
	}
	// Validate the 101 response per RFC 6455.
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		return nil, fmt.Errorf("handshake: bad Upgrade header %q", resp.Header.Get("Upgrade"))
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Connection")), "upgrade") {
		return nil, fmt.Errorf("handshake: bad Connection header %q", resp.Header.Get("Connection"))
	}
	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	wantAccept := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if resp.Header.Get("Sec-WebSocket-Accept") != wantAccept {
		return nil, fmt.Errorf("handshake: bad Sec-WebSocket-Accept")
	}
	return newConn(nc, rw, false), nil
}

func newConn(nc net.Conn, rw *bufio.ReadWriter, serverSide bool) *Conn {
	c := &Conn{
		netConn:    nc,
		rw:         rw,
		serverSide: serverSide,
		wmu:        make(chan struct{}, 1),
		closed:     make(chan struct{}),
	}
	c.wmu <- struct{}{}
	return c
}

func (c *Conn) lock()   { <-c.wmu }
func (c *Conn) unlock() { c.wmu <- struct{}{} }

// ReadFrame reads one frame. Returns opcode and payload.
// Handles ping (auto pong) and close transparently by returning them;
// caller decides. Fragmentation is not supported (tunnel never fragments).
func (c *Conn) ReadFrame() (opcode int, payload []byte, err error) {
	for {
		op, p, err := c.readOne()
		if err != nil {
			return 0, nil, err
		}
		switch op {
		case OpPing:
			_ = c.WritePong(p)
			continue
		case OpPong:
			continue // ignore
		default:
			return op, p, nil
		}
	}
}

func (c *Conn) readOne() (int, []byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c.rw, hdr); err != nil {
		return 0, nil, err
	}
	fin := hdr[0]&0x80 != 0
	op := int(hdr[0] & 0x0F)
	masked := hdr[1]&0x80 != 0
	n := int(hdr[1] & 0x7F)
	switch n {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(c.rw, ext); err != nil {
			return 0, nil, err
		}
		n = int(ext[0])<<8 | int(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(c.rw, ext); err != nil {
			return 0, nil, err
		}
		length := binary.BigEndian.Uint64(ext)
		if length > MaxFrameSize {
			return 0, nil, fmt.Errorf("frame too large: %d > %d", length, MaxFrameSize)
		}
		n = int(length)
	}
	var mask []byte
	if masked {
		mask = make([]byte, 4)
		if _, err := io.ReadFull(c.rw, mask); err != nil {
			return 0, nil, err
		}
	}
	if n > MaxFrameSize {
		return 0, nil, fmt.Errorf("frame too large: %d > %d", n, MaxFrameSize)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(c.rw, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	if !fin {
		return 0, nil, fmt.Errorf("fragmented frame not supported")
	}
	return op, payload, nil
}

func (c *Conn) writeFrame(op int, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("frame too large: %d > %d", len(payload), MaxFrameSize)
	}
	c.lock()
	defer c.unlock()
	select {
	case <-c.closed:
		return fmt.Errorf("ws closed")
	default:
	}
	c.netConn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	defer c.netConn.SetWriteDeadline(time.Time{})
	hdr := []byte{byte(0x80 | op)}
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n < 65536:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 127, 0, 0, 0, 0,
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	// Mask only when we are the client. Use a random mask per frame
	// (RFC 6455) and don't modify the caller's payload in place.
	if !c.serverSide {
		hdr[1] |= 0x80
		var mask [4]byte
		if _, err := rand.Read(mask[:]); err != nil {
			return fmt.Errorf("rand mask: %w", err)
		}
		hdr = append(hdr, mask[:]...)
		masked := make([]byte, len(payload))
		for i := range payload {
			masked[i] = payload[i] ^ mask[i%4]
		}
		payload = masked
	}
	if _, err := c.rw.Write(hdr); err != nil {
		return err
	}
	if _, err := c.rw.Write(payload); err != nil {
		return err
	}
	return c.rw.Flush()
}

// WriteText sends a text frame.
func (c *Conn) WriteText(p []byte) error { return c.writeFrame(OpText, p) }

// WriteBinary sends a binary frame.
func (c *Conn) WriteBinary(p []byte) error { return c.writeFrame(OpBinary, p) }

// WritePong answers a ping.
func (c *Conn) WritePong(p []byte) error { return c.writeFrame(OpPong, p) }

// WriteClose sends a close frame and closes the underlying conn.
func (c *Conn) WriteClose() error {
	_ = c.writeFrame(OpClose, nil)
	return c.Close()
}

// Close closes the connection.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		err = c.netConn.Close()
	})
	return err
}
