package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shafreeck/burrow/internal/proto"
	"github.com/shafreeck/burrow/internal/ws"
)

func TestHealthyAndLegacyHeartbeats(t *testing.T) {
	for _, application := range []bool{true, false} {
		name := "application"
		if !application {
			name = "legacy websocket"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			var pings atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, err := ws.ServerHandshake(w, r)
				if err != nil {
					return
				}
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				c.ReadFrame()
				ack, _ := json.Marshal(proto.HelloAck{Type: proto.TypeHelloAck, OK: true, Heartbeat: application})
				c.WriteText(ack)
				for {
					_, raw, err := c.ReadFrame() // Automatically answers legacy WebSocket pings.
					if err != nil {
						return
					}
					var msg proto.Heartbeat
					if json.Unmarshal(raw, &msg) == nil && msg.Type == proto.TypePing {
						pings.Add(1)
						msg.Type = proto.TypePong
						pong, _ := json.Marshal(msg)
						c.WriteText(pong)
					}
				}
			}))
			a := New(Config{ServerURL: "ws" + strings.TrimPrefix(srv.URL, "http"), Logf: t.Logf})
			a.heartbeatInterval = 20 * time.Millisecond
			a.heartbeatTimeout = 150 * time.Millisecond
			done := make(chan error, 1)
			go func() { done <- a.runOnce(ctx) }()
			defer func() { cancel(); srv.Close() }()
			select {
			case err := <-done:
				t.Fatalf("healthy session closed: %v", err)
			case <-time.After(500 * time.Millisecond):
			}
			if application && pings.Load() < 3 {
				t.Fatal("application heartbeat did not run")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("heartbeat prevented cancellation")
			}
		})
	}
}

func TestUnmatchedPongDoesNotHideBrokenRoundTrip(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := ws.ServerHandshake(w, r)
		if err != nil {
			return
		}
		defer c.Close()
		stop := context.AfterFunc(ctx, func() { c.Close() })
		defer stop()
		c.ReadFrame()
		c.WriteText([]byte(`{"type":"hello_ack","ok":true,"heartbeat":true}`))
		for {
			if _, _, err := c.ReadFrame(); err != nil {
				return
			}
			c.WritePong([]byte("1")) // Transport remains responsive.
			c.WriteText([]byte(`{"type":"pong","id":"old-session"}`))
		}
	}))
	defer srv.Close()
	a := New(Config{ServerURL: "ws" + strings.TrimPrefix(srv.URL, "http"), Logf: t.Logf})
	a.heartbeatInterval = 20 * time.Millisecond
	a.heartbeatTimeout = 100 * time.Millisecond
	done := make(chan error, 1)
	go func() { done <- a.runOnce(ctx) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "heartbeat timeout") {
			t.Fatalf("error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("unmatched pong kept a broken application session alive")
	}
}
