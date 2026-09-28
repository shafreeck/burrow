package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/shafreeck/burrow/internal/proto"
	"github.com/shafreeck/burrow/internal/ws"
)

type heartbeat struct {
	mu      sync.Mutex
	waiting string
	acked   chan struct{}
	failure error
	done    chan struct{}
}

func (h *heartbeat) pong(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.waiting != "" && id == h.waiting {
		h.waiting = ""
		close(h.acked)
	}
}

func (h *heartbeat) err() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.failure
}

func (a *Agent) startHeartbeat(ctx context.Context, c *ws.Conn, application bool, closeSession func()) *heartbeat {
	h := &heartbeat{done: make(chan struct{})}
	fail := func(err error) {
		h.mu.Lock()
		if h.failure == nil {
			h.failure = err
		}
		h.mu.Unlock()
		// Closing both sides also interrupts a blocked writer or upstream relay.
		c.Close()
		closeSession()
	}
	go func() {
		defer close(h.done)
		for seq := uint64(1); ; seq++ {
			timer := time.NewTimer(a.heartbeatInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			id := strconv.FormatUint(seq, 10)
			acked := make(chan struct{})
			h.mu.Lock()
			h.waiting, h.acked = id, acked
			h.mu.Unlock()
			// Independent of WriteText: its mutex or the socket may be blocked.
			expired := make(chan struct{})
			deadline := time.AfterFunc(a.heartbeatTimeout, func() {
				defer close(expired)
				select {
				case <-ctx.Done():
					return
				case <-acked:
					return
				default:
					fail(fmt.Errorf("heartbeat timeout after %s", a.heartbeatTimeout))
				}
			})
			var err error
			if application {
				ping, _ := json.Marshal(proto.Heartbeat{Type: proto.TypePing, ID: id})
				err = c.WriteText(ping)
			} else {
				err = c.WritePing([]byte(id))
			}
			if err == nil {
				select {
				case <-ctx.Done():
				case <-acked:
				case <-expired:
				}
			}
			if !deadline.Stop() {
				<-expired
			}
			if err != nil {
				fail(fmt.Errorf("heartbeat write: %w", err))
				return
			}
			if ctx.Err() != nil || h.err() != nil {
				return
			}
		}
	}()
	return h
}
