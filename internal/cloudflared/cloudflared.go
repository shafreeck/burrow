// Package cloudflared manages a cloudflared quick-tunnel child process.
package cloudflared

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"sync"
)

// Tunnel wraps a running `cloudflared tunnel --url` process.
type Tunnel struct {
	cmd    *exec.Cmd
	urlCh  chan string
	errCh  chan error
	mu     sync.Mutex
	url    string
	closed bool
}

var urlRe = regexp.MustCompile(`https://[a-z0-9-]+\.trycloudflare\.com`)

// Start launches `cloudflared tunnel --url <target>` and waits until the
// public URL appears in its log output. Stdout and stderr are consumed
// concurrently: the URL is printed to stderr, and stdout may never close.
func Start(cloudflaredBin, target string, logFn func(string)) (*Tunnel, error) {
	t := &Tunnel{
		urlCh: make(chan string, 1),
		errCh: make(chan error, 1),
	}
	t.cmd = exec.Command(cloudflaredBin, "tunnel", "--url", target)
	stderr, err := t.cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}
	stdout, err := t.cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	if err := t.cmd.Start(); err != nil {
		return nil, fmt.Errorf("start cloudflared: %w", err)
	}
	go t.watch(stdout, logFn)
	go t.watch(stderr, logFn)
	go func() {
		t.errCh <- t.cmd.Wait()
	}()
	select {
	case url := <-t.urlCh:
		t.mu.Lock()
		t.url = url
		t.mu.Unlock()
		return t, nil
	case err := <-t.errCh:
		return nil, fmt.Errorf("cloudflared exited: %w", err)
	}
}

func (t *Tunnel) watch(r io.Reader, logFn func(string)) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if logFn != nil {
			logFn("[cloudflared] " + line)
		}
		if m := urlRe.FindString(line); m != "" {
			select {
			case t.urlCh <- m:
			default:
			}
		}
	}
}

// URL returns the public tunnel URL.
func (t *Tunnel) URL() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.url
}

// Stop kills the tunnel process.
func (t *Tunnel) Stop() error {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	if t.cmd.Process != nil {
		return t.cmd.Process.Kill()
	}
	return nil
}
