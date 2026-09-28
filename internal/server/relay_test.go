package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shafreeck/burrow/internal/agent"
	"github.com/shafreeck/burrow/internal/trojan"
	"github.com/shafreeck/burrow/internal/vless"
)

func connectedServer(t *testing.T) *Server {
	t.Helper()
	s := New(Config{Token: "agent-secret", VLESSUUID: strings.Repeat("ab", 16), Logf: func(string, ...interface{}) {}})
	httpServer := httptest.NewServer(s.Handler())
	ctx, cancel := context.WithCancel(context.Background())
	a := agent.New(agent.Config{ServerURL: "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/ws", Token: "agent-secret", Logf: func(string, ...interface{}) {}})
	done := make(chan struct{})
	go func() { a.RunContext(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; httpServer.Close() })
	if s.waitAgent(3*time.Second) == nil {
		t.Fatal("agent did not connect")
	}
	return s
}

func inbound(t *testing.T, handler func(net.Conn)) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err == nil {
			handler(c)
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() {
		c.Close()
		ln.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("inbound handler did not exit")
		}
	})
	return c
}

func target(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(5 * time.Second)); handler(c) }()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func portBytes(addr string) []byte {
	_, p, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	return []byte{byte(n >> 8), byte(n)}
}
func vlessHeader(cmd byte, addr string) []byte {
	b := append([]byte{0}, bytes.Repeat([]byte{0xab}, 16)...)
	b = append(b, 0, cmd)
	if cmd != vless.CmdMux {
		b = append(b, portBytes(addr)...)
		b = append(b, vless.ATypeIPv4, 127, 0, 0, 1)
	}
	return b
}

func TestServerFirstDataAndEOF(t *testing.T) {
	for _, protocol := range []string{"vless", "trojan", "http", "socks5"} {
		t.Run(protocol, func(t *testing.T) {
			s := connectedServer(t)
			greeting := strings.Repeat("immediate upstream response\n", 2000)
			addr := target(t, func(c net.Conn) { io.WriteString(c, greeting) })
			var c net.Conn
			var reader io.Reader
			switch protocol {
			case "vless":
				c = inbound(t, s.handleVLESS)
				c.Write(vlessHeader(vless.CmdTCP, addr))
				var response [2]byte
				if _, err := io.ReadFull(c, response[:]); err != nil {
					t.Fatal(err)
				}
				reader = c
			case "trojan":
				c = inbound(t, func(c net.Conn) { s.handleTrojan(c, "password") })
				header := []byte(trojan.PasswordHash("password") + "\r\n")
				header = append(header, trojan.CmdTCP, trojan.ATypeIPv4, 127, 0, 0, 1)
				header = append(header, portBytes(addr)...)
				header = append(header, '\r', '\n')
				c.Write(header)
				reader = c
			case "socks5":
				c = inbound(t, s.handleSOCKS5)
				c.Write([]byte{5, 1, 0})
				reply := make([]byte, 2)
				if _, err := io.ReadFull(c, reply); err != nil {
					t.Fatal(err)
				}
				req := []byte{5, 1, 0, 1, 127, 0, 0, 1}
				req = append(req, portBytes(addr)...)
				c.Write(req)
				reply = make([]byte, 10)
				if _, err := io.ReadFull(c, reply); err != nil {
					t.Fatal(err)
				}
				reader = c
			case "http":
				p := httptest.NewServer(http.HandlerFunc(s.handleProxy))
				defer p.Close()
				var err error
				c, err = net.Dial("tcp", p.Listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
				br := bufio.NewReader(c)
				resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != 200 {
					t.Fatal(resp.Status)
				}
				reader = br
			}
			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != greeting {
				t.Fatalf("lost bytes: received %d, expected %d", len(got), len(greeting))
			}
		})
	}
}

func muxNew(sid uint16, addr string, data []byte) []byte {
	meta := []byte{byte(sid >> 8), byte(sid), vless.MuxNew, vless.MuxOptData, vless.MuxNetTCP}
	meta = append(meta, portBytes(addr)...)
	meta = append(meta, vless.ATypeIPv4, 127, 0, 0, 1)
	b := []byte{0, byte(len(meta))}
	b = append(b, meta...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func TestMuxFirstPayloadAndSessionReuse(t *testing.T) {
	s := connectedServer(t)
	addr := target(t, func(c net.Conn) {
		buf := make([]byte, 5)
		if _, err := io.ReadFull(c, buf); err == nil {
			c.Write(append([]byte("echo:"), buf...))
		}
	})
	c := inbound(t, s.handleVLESS)
	c.Write(vlessHeader(vless.CmdMux, ""))
	var response [2]byte
	if _, err := io.ReadFull(c, response[:]); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := c.Write(muxNew(1, addr, []byte("hello"))); err != nil {
			t.Fatal(err)
		}
		var received []byte
		for {
			f, err := vless.ReadMuxFrame(c)
			if err != nil {
				t.Fatal(err)
			}
			if f.SessionID != 1 {
				t.Fatal(f.SessionID)
			}
			received = append(received, f.Payload...)
			if f.Status == vless.MuxEnd {
				break
			}
		}
		if string(received) != "echo:hello" {
			t.Fatalf("MUX payload: %q", received)
		}
	}
}

func TestAgentCannotCompleteOrCloseOtherAgentsStreams(t *testing.T) {
	s := New(Config{})
	a, b := &agentConn{id: "a"}, &agentConn{id: "b"}
	ch := make(chan map[string]interface{}, 1)
	s.pending["request"] = &pendingRequest{agent: a, reply: ch}
	s.onText(b, []byte(`{"type":"connect_result","id":"request","ok":true}`))
	if len(ch) != 0 || s.pending["request"] == nil {
		t.Fatal("another agent completed pending request")
	}
	st := &stream{id: "stream", agent: a, done: make(chan struct{}), toNet: make(chan []byte, 1)}
	s.streams[st.id] = st
	s.onText(b, []byte(`{"type":"close","id":"stream"}`))
	select {
	case <-st.done:
		t.Fatal("another agent closed stream")
	default:
	}
}
