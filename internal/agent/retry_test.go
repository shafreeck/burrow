package agent

import (
	"context"
	"errors"
	"fmt"
	"github.com/shafreeck/burrow/internal/ws"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRetryBoundsAndClasses(t *testing.T) {
	for i := 0; i < 100; i++ {
		d := retryDelay(time.Second)
		if d < 800*time.Millisecond || d > 1200*time.Millisecond {
			t.Fatal(d)
		}
		if retryDelay(30*time.Second) > 30*time.Second {
			t.Fatal("cap")
		}
	}
	if errorClass(context.Canceled) != "canceled" || errorClass(&ws.CloseError{Code: 1000}) != "remote_close" {
		t.Fatal("classification")
	}
}

func TestRemoteCloseDiagnostics(t *testing.T) {
	events := make(chan string, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := ws.ServerHandshake(w, r)
		if e != nil {
			return
		}
		defer c.Close()
		c.ReadFrame()
		c.WriteText([]byte(`{"type":"hello_ack","ok":true,"build":"peer-revision","session":"server-session","heartbeat":true}`))
		c.WriteClose()
	}))
	defer srv.Close()
	a := New(Config{ServerURL: "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws", Logf: func(f string, args ...interface{}) { events <- fmt.Sprintf(f, args...) }})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := a.runOnce(ctx)
	var ce *ws.CloseError
	if !errors.As(err, &ce) || ce.Code != 1005 {
		t.Fatalf("close=%v", err)
	}
	close(events)
	found := false
	for event := range events {
		if strings.Contains(event, `"event":"session_ended"`) {
			found = true
			for _, field := range []string{`"close_code":1005`, `"peer_version":"peer-revision"`, `"stage":"established"`, `"session":`} {
				if !strings.Contains(event, field) {
					t.Fatal(event)
				}
			}
		}
	}
	if !found {
		t.Fatal("missing session event")
	}
}
