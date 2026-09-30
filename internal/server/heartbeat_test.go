package server

import (
	"encoding/json"
	"log"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shafreeck/burrow/internal/proto"
	"github.com/shafreeck/burrow/internal/ws"
)

func heartbeatClient(t *testing.T, s *Server, enabled bool) *ws.Conn {
	t.Helper()
	h := httptest.NewServer(s.Handler())
	t.Cleanup(h.Close)
	nc, err := net.Dial("tcp", h.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	nc.SetDeadline(time.Now().Add(3 * time.Second))
	c, err := ws.ClientHandshake(nc, h.Listener.Addr().String(), "/ws")
	if err != nil {
		nc.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	hello, _ := json.Marshal(proto.Hello{Type: proto.TypeHello, Version: "1", Heartbeat: enabled})
	if err := c.WriteText(hello); err != nil {
		t.Fatal(err)
	}
	_, p, err := c.ReadFrame()
	var ack proto.HelloAck
	if err != nil || json.Unmarshal(p, &ack) != nil || !ack.OK || ack.Heartbeat != enabled {
		t.Fatalf("ack=%s error=%v", p, err)
	}
	select {
	case <-s.Ready():
	case <-time.After(time.Second):
		t.Fatal("agent not registered")
	}
	return c
}

func TestHeartbeatRemovesStaleAgentWithBlockedStream(t *testing.T) {
	s := New(Config{Logf: log.Printf})
	s.heartbeatTimeout = 200 * time.Millisecond
	c := heartbeatClient(t, s, true)
	ac := s.pickAgent()
	st := &stream{id: "blocked", agent: ac, toNet: make(chan []byte), done: make(chan struct{})}
	s.streamsMu.Lock()
	s.streams[st.id] = st
	s.streamsMu.Unlock()
	reply := make(chan map[string]interface{}, 1)
	s.pendingMu.Lock()
	s.pending["pending"] = &pendingRequest{agent: ac, reply: reply}
	s.pendingMu.Unlock()
	if err := c.WriteText([]byte(`{"type":"data","id":"blocked","payload":"eA=="}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-st.done:
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not unblock the stalled stream")
	}
	select {
	case res := <-reply:
		if res["error"] != "agent disconnected" {
			t.Fatal(res)
		}
	case <-time.After(time.Second):
		t.Fatal("pending request survived stale agent")
	}
	if s.pickAgent() != nil {
		t.Fatal("stale agent remains selectable")
	}
	if _, _, err := c.ReadFrame(); err == nil {
		t.Fatal("stale socket remains open")
	}
}

func TestServerHeartbeatRefreshAndLegacyClient(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		name := "heartbeat"
		if !enabled {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			s := New(Config{Logf: log.Printf})
			s.heartbeatTimeout = 200 * time.Millisecond
			c := heartbeatClient(t, s, enabled)
			for i := 0; i < 8; i++ {
				time.Sleep(50 * time.Millisecond)
				if enabled {
					c.WriteText([]byte(`{"type":"ping","id":"check"}`))
					_, p, err := c.ReadFrame()
					var pong proto.Heartbeat
					if err != nil || json.Unmarshal(p, &pong) != nil || pong.Type != proto.TypePong || pong.ID != "check" {
						t.Fatalf("pong=%s err=%v", p, err)
					}
				}
				if s.pickAgent() == nil {
					t.Fatal("healthy/legacy agent was evicted")
				}
			}
		})
	}
}
