package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/shafreeck/burrow/internal/ws"
)

func TestCONNECTProxyAuthenticationAndBufferedData(t *testing.T) {
	verified := make(chan bool, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verified <- r.Method == "CONNECT" && r.Host == "target.test:443" && r.Header.Get("Proxy-Authorization") == "Basic dXNlcjpwYXNz"
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\ngreeting")
		io.Copy(io.Discard, c)
	}))
	defer proxy.Close()
	u, _ := url.Parse(proxy.URL)
	u.User = url.UserPassword("user", "pass")
	a := New(Config{})
	c, err := a.viaProxy(context.Background(), u.String(), "target.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 8)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "greeting" || !<-verified {
		t.Fatal("CONNECT authentication or tunneled bytes lost")
	}
}

func TestCONNECTCancellation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		http.ReadRequest(bufio.NewReader(c))
		close(accepted)
		io.Copy(io.Discard, c)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, err := New(Config{}).viaProxy(ctx, "http://"+ln.Addr().String(), "example.com:443")
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	<-accepted
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled CONNECT succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("CONNECT ignored cancellation")
	}
}

func TestRejectedHelloStopsSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := ws.ServerHandshake(w, r)
		if err != nil {
			return
		}
		defer c.Close()
		c.ReadFrame()
		c.WriteText([]byte(`{"type":"hello_ack","ok":false}`))
	}))
	defer srv.Close()
	a := New(Config{ServerURL: "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws", Logf: func(string, ...interface{}) {}})
	if err := a.runOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "hello rejected") {
		t.Fatalf("error=%v", err)
	}
}

func TestCloseWhileConnectIsPending(t *testing.T) {
	connecting := make(chan struct{})
	release := make(chan struct{})
	closed := make(chan error, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		close(connecting)
		<-release
		io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		c.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		_, err = c.Read(b[:])
		closed <- err
	}))
	defer proxy.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := ws.ServerHandshake(w, r)
		if err != nil {
			return
		}
		defer c.Close()
		c.ReadFrame()
		c.WriteText([]byte(`{"type":"hello_ack","ok":true}`))
		msg, _ := json.Marshal(map[string]interface{}{"type": "connect", "id": "pending", "host": "example.com", "port": 443})
		c.WriteText(msg)
		<-connecting
		// Session closure must cancel both the pending CONNECT handshake and
		// any socket returned concurrently with it.
		c.Close()
		close(release)
	}))
	defer srv.Close()
	a := New(Config{ServerURL: "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws", UpstreamProxy: proxy.URL, Logf: func(string, ...interface{}) {}})
	if err := a.runOnce(ctx); err == nil {
		t.Fatal("expected session closure")
	}
	select {
	case err := <-closed:
		if err == nil {
			t.Fatal("late stream remained open")
		}
		if n, ok := err.(net.Error); ok && n.Timeout() {
			t.Fatal("late stream was not closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending connection leaked")
	}
}
