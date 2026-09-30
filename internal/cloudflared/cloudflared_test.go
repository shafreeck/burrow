package cloudflared

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQuickChildExitObserved(t *testing.T) {
	script := filepath.Join(t.TempDir(), "fake-cloudflared")
	if e := os.WriteFile(script, []byte("#!/bin/sh\necho https://test-name.trycloudflare.com >&2\nsleep 0.1\nexit 7\n"), 0700); e != nil {
		t.Fatal(e)
	}
	events := make(chan string, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tunnel, e := StartContext(ctx, script, "http://127.0.0.1:1", func(s string) { events <- s })
	if e != nil {
		t.Fatal(e)
	}
	defer tunnel.Stop()
	for {
		select {
		case event := <-events:
			if strings.Contains(event, "process exited") && strings.Contains(event, "exit status 7") {
				return
			}
		case <-ctx.Done():
			t.Fatal("exit not observed")
		}
	}
}
