package main

import (
	"context"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestTransportCombinations(t *testing.T) {
	for _, tc := range []struct {
		name            string
		tunnel          bool
		domain          string
		acme            bool
		cert, key, mode string
		invalid         bool
	}{
		{name: "local", mode: "none"},
		{name: "quick", tunnel: true, mode: "quick"},
		{name: "fixed", tunnel: true, domain: "burrow.example.com", mode: "external"},
		{name: "acme", domain: "example.com", acme: true, mode: "none"},
		{name: "files", cert: "cert.pem", key: "key.pem", mode: "none"},
		{name: "implicit acme rejected", domain: "example.com", invalid: true},
		{name: "missing domain", acme: true, invalid: true},
		{name: "missing key", cert: "cert.pem", invalid: true},
		{name: "acme files conflict", domain: "example.com", acme: true, cert: "cert.pem", key: "key.pem", invalid: true},
		{name: "tunnel acme conflict", tunnel: true, domain: "example.com", acme: true, invalid: true},
		{name: "literal backslash", tunnel: true, domain: `burrow\.example.com`, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode, err := validateTransport(tc.tunnel, false, tc.domain, tc.acme, tc.cert, tc.key)
			if (err != nil) != tc.invalid {
				t.Fatalf("mode=%q error=%v", mode, err)
			}
			if !tc.invalid && mode != tc.mode {
				t.Fatalf("mode=%q want %q", mode, tc.mode)
			}
		})
	}
}

func TestServerProcess(t *testing.T) {
	if os.Getenv("BURROW_TEST_SERVER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"burrow-server"}, os.Args[i+1:]...)
			break
		}
	}
	flag.CommandLine = flag.NewFlagSet("burrow-server", flag.ExitOnError)
	main()
	os.Exit(0)
}

func TestFixedTunnelStartsHTTPWithoutACMEOrQuickTunnel(t *testing.T) {
	for _, tc := range []struct {
		name      string
		protocols []string
	}{
		{name: "control plane only"},
		{name: "vless only", protocols: []string{"vless"}},
		{name: "multiple including repeated protocol", protocols: []string{"vless", "http", "socks5", "trojan", "http"}},
	} {
		t.Run(tc.name, func(t *testing.T) { checkFixedTunnelListeners(t, tc.protocols) })
	}
}

func checkFixedTunnelListeners(t *testing.T, protocols []string) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "server.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	args := []string{"-test.run=^TestServerProcess$", "--", "--listen", "127.0.0.1:0", "--tunnel", "--domain", "burrow.example.com", "--cloudflared", "/does-not-exist", "--vless-uuid", strings.Repeat("ab", 16), "--trojan-password", "test-password"}
	for _, protocol := range protocols {
		args = append(args, "--bind", protocol+"://127.0.0.1:0")
	}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "BURROW_TEST_SERVER=1", "HTTPS_PROXY=http://127.0.0.1:1")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { cmd.Process.Kill(); <-done })
	re := regexp.MustCompile(`control plane: (http://127\.0\.0\.1:\d+)`)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(logPath)
		if match := re.FindStringSubmatch(string(raw)); len(match) == 2 {
			client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}}
			defer client.CloseIdleConnections()
			resp, err := client.Get(match[1])
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || !strings.Contains(string(body), "burrow server") {
				t.Fatalf("origin response %d %s", resp.StatusCode, body)
			}
			if strings.Contains(string(raw), "acme:") || strings.Contains(string(raw), "Starting Cloudflare quick") {
				t.Fatalf("unexpected certificate/tunnel creation: %s", raw)
			}
			listeners := regexp.MustCompile(`proxy inbound: (http|socks5|vless|trojan)://(127\.0\.0\.1:\d+)`).FindAllStringSubmatch(string(raw), -1)
			if len(listeners) != len(protocols) {
				t.Fatalf("got %d listeners, want %d: %s", len(listeners), len(protocols), raw)
			}
			addresses := make(map[string]bool)
			for i, listener := range listeners {
				if listener[1] != protocols[i] || addresses[listener[2]] {
					t.Fatalf("listener missing, reordered, or repeated: %s", raw)
				}
				addresses[listener[2]] = true
				conn, err := net.DialTimeout("tcp", listener[2], time.Second)
				if err != nil {
					t.Fatal(err)
				}
				conn.SetDeadline(time.Now().Add(time.Second))
				if listener[1] == "socks5" {
					conn.Write([]byte{5, 1, 0})
					var reply [2]byte
					if _, err := io.ReadFull(conn, reply[:]); err != nil || reply != [2]byte{5, 0} {
						conn.Close()
						t.Fatalf("SOCKS5 handshake: %x, %v", reply, err)
					}
				}
				conn.Close()
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	raw, _ := os.ReadFile(logPath)
	t.Fatalf("server did not start: %s", raw)
}

func TestSystemProxyRequiresExplicitHTTPProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestServerProcess$", "--", "--listen", "127.0.0.1:0", "--system-proxy")
	cmd.Env = append(os.Environ(), "BURROW_TEST_SERVER=1")
	out, err := cmd.CombinedOutput()
	if err == nil || ctx.Err() != nil || !strings.Contains(string(out), "--system-proxy requires --bind http://host:port") {
		t.Fatalf("expected missing HTTP proxy error, got %v: %s", err, out)
	}
	if strings.Contains(string(out), "control plane:") {
		t.Fatalf("validation must fail before opening listeners: %s", out)
	}
}
