// Package agent implements the VM side of the tunnel: connects to the
// server over WebSocket (optionally via an upstream HTTP CONNECT proxy),
// serves fetch and stream-connect requests using an upstream proxy
// for egress.
package agent

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/shafreeck/muser/internal/proto"
	"github.com/shafreeck/muser/internal/ws"
)

// Config for the agent.
type Config struct {
	ServerURL string // wss://host/ws  (or ws://)
	Token     string
	// Upstream HTTP CONNECT proxy for egress, e.g. "http://198.19.0.1:3128".
	// Empty means direct egress.
	UpstreamProxy string
	// InsecureTLS skips TLS cert verification (self-signed testing only).
	InsecureTLS bool
	Logf        func(string, ...interface{})
}

// Agent is the tunnel agent.
type Agent struct {
	cfg  Config
	logf func(string, ...interface{})

	mu      sync.Mutex
	streams map[string]net.Conn
}

func New(cfg Config) *Agent {
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	return &Agent{
		cfg:     cfg,
		logf:    cfg.Logf,
		streams: make(map[string]net.Conn),
	}
}

func (a *Agent) log(format string, args ...interface{}) {
	a.logf("[agent] "+format, args...)
}

// dialServer connects to the tunnel server. Uses the upstream proxy only
// for non-local targets; localhost always dials direct.
func (a *Agent) dialServer() (net.Conn, error) {
	u, err := url.Parse(a.cfg.ServerURL)
	if err != nil {
		return nil, err
	}
	host := u.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		if u.Scheme == "wss" || u.Scheme == "https" {
			host = net.JoinHostPort(host, "443")
		} else {
			host = net.JoinHostPort(host, "80")
		}
	}

	var conn net.Conn
	hostname := u.Hostname()
	useProxy := a.cfg.UpstreamProxy != "" && !isLocal(hostname)
	if useProxy {
		conn, err = a.viaProxy(a.cfg.UpstreamProxy, host)
		if err != nil {
			return nil, fmt.Errorf("proxy dial: %w", err)
		}
	} else {
		conn, err = net.DialTimeout("tcp", host, 15*time.Second)
		if err != nil {
			return nil, err
		}
	}

	if u.Scheme == "wss" || u.Scheme == "https" {
		tlsCfg := &tls.Config{ServerName: u.Hostname()}
		if a.cfg.InsecureTLS {
			tlsCfg.InsecureSkipVerify = true
		}
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls: %w", err)
		}
		conn = tlsConn
	}
	return conn, nil
}

// viaProxy opens a TCP connection to target through an HTTP CONNECT proxy.
func (a *Agent) viaProxy(proxyURL, target string) (net.Conn, error) {
	pu, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	phost := pu.Host
	if _, _, err := net.SplitHostPort(phost); err != nil {
		phost = net.JoinHostPort(phost, "80")
	}
	conn, err := net.DialTimeout("tcp", phost, 15*time.Second)
	if err != nil {
		return nil, err
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy response: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("proxy status: %s", resp.Status)
	}
	// If buffered data remains, wrap.
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// isLocal reports whether hostname is a loopback address.
func isLocal(hostname string) bool {
	if hostname == "localhost" {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}

// Run connects and serves forever with reconnect backoff.
// Backoff resets after a session that lasted long enough to be healthy.
func (a *Agent) Run() {
	backoff := time.Second
	for {
		start := time.Now()
		err := a.runOnce()
		// Clean up any streams left from the dead session.
		a.mu.Lock()
		for id, c := range a.streams {
			c.Close()
			delete(a.streams, id)
		}
		a.mu.Unlock()
		if err != nil {
			a.log("connection error: %v", err)
		}
		if time.Since(start) > 30*time.Second {
			backoff = time.Second // healthy session, reset
		}
		a.log("reconnecting in %v...", backoff)
		time.Sleep(backoff)
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (a *Agent) runOnce() error {
	u, _ := url.Parse(a.cfg.ServerURL)
	a.log("connecting to %s...", a.cfg.ServerURL)
	nc, err := a.dialServer()
	if err != nil {
		return err
	}
	path := u.RequestURI()
	wsc, err := ws.ClientHandshake(nc, u.Host, path)
	if err != nil {
		nc.Close()
		return fmt.Errorf("ws handshake: %w", err)
	}
	defer wsc.Close()
	a.log("websocket connected")

	// hello
	hello, _ := json.Marshal(map[string]string{
		"type": proto.TypeHello, "token": a.cfg.Token, "version": "1",
	})
	_ = wsc.WriteText(hello)

	for {
		op, payload, err := wsc.ReadFrame()
		if err != nil {
			return err
		}
		switch op {
		case ws.OpClose:
			return fmt.Errorf("closed by server")
		case ws.OpText:
			a.onText(wsc, payload)
		case ws.OpBinary:
			a.onBinary(wsc, payload)
		}
	}
}

func (a *Agent) onText(wsc *ws.Conn, payload []byte) {
	var msg map[string]interface{}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return
	}
	t, _ := msg["type"].(string)
	switch t {
	case proto.TypeHelloAck:
		if ok, _ := msg["ok"].(bool); !ok {
			a.log("hello rejected (bad token?)")
		}
	case proto.TypeFetch:
		go a.replyFetch(wsc, msg)
	case proto.TypeConnect:
		go a.doConnect(wsc, msg)
	case proto.TypeClose:
		if id, ok := msg["id"].(string); ok {
			a.mu.Lock()
			c := a.streams[id]
			delete(a.streams, id)
			a.mu.Unlock()
			if c != nil {
				c.Close()
			}
		}
	case proto.TypeData:
		// Stream data via text frame (base64) for Cloudflare Tunnel compat.
		if id, ok := msg["id"].(string); ok {
			if b64, ok := msg["payload"].(string); ok {
				if data, err := base64.StdEncoding.DecodeString(b64); err == nil {
					a.mu.Lock()
					c := a.streams[id]
					a.mu.Unlock()
					if c != nil {
						c.SetWriteDeadline(time.Now().Add(10 * time.Second))
						_, _ = c.Write(data)
					}
				}
			}
		}
	}
}

func (a *Agent) onBinary(wsc *ws.Conn, frame []byte) {
	id, payload, ok := proto.DecodeDataFrame(frame)
	if !ok {
		return
	}
	a.mu.Lock()
	c := a.streams[id]
	a.mu.Unlock()
	if c == nil {
		return
	}
	// Write to upstream. Best effort.
	c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, _ = c.Write(payload)
}

// replyFetch performs an HTTP request via upstream proxy and replies.
func (a *Agent) replyFetch(wsc *ws.Conn, msg map[string]interface{}) {
	id, _ := msg["id"].(string)
	method, _ := msg["method"].(string)
	urlStr, _ := msg["url"].(string)
	if method == "" {
		method = "GET"
	}
	res := map[string]interface{}{"type": proto.TypeFetchResult, "id": id}

	var bodyReader io.Reader
	if b64, ok := msg["body"].(string); ok && b64 != "" {
		if raw, err := base64.StdEncoding.DecodeString(b64); err == nil {
			bodyReader = strings.NewReader(string(raw))
		}
	}
	req, err := http.NewRequest(method, urlStr, bodyReader)
	if err != nil {
		res["error"] = err.Error()
		b, _ := json.Marshal(res)
		wsc.WriteText(b)
		return
	}
	if hs, ok := msg["headers"].(map[string]interface{}); ok {
		for k, v := range hs {
			if vs, ok := v.(string); ok {
				req.Header.Set(k, vs)
			}
		}
	}
	client := &http.Client{Timeout: 25 * time.Second}
	if a.cfg.UpstreamProxy != "" {
		if pu, err := url.Parse(a.cfg.UpstreamProxy); err == nil {
			client.Transport = &http.Transport{Proxy: http.ProxyURL(pu)}
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		res["error"] = err.Error()
		b, _ := json.Marshal(res)
		wsc.WriteText(b)
		return
	}
	defer resp.Body.Close()
	bb, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	res["status"] = resp.StatusCode
	hdr := map[string]string{}
	for k, vs := range resp.Header {
		if len(vs) > 0 {
			hdr[k] = vs[0]
		}
	}
	res["headers"] = hdr
	res["body"] = base64.StdEncoding.EncodeToString(bb)
	b, _ := json.Marshal(res)
	_ = wsc.WriteText(b)
	a.log("fetch %s -> %d (%d bytes)", urlStr, resp.StatusCode, len(bb))
}

// doConnect opens a TCP stream via upstream CONNECT proxy.
func (a *Agent) doConnect(wsc *ws.Conn, msg map[string]interface{}) {
	id, _ := msg["id"].(string)
	host, _ := msg["host"].(string)
	port := 443
	if p, ok := msg["port"].(float64); ok {
		port = int(p)
	}
	res := map[string]interface{}{"type": proto.TypeConnectResult, "id": id}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	var conn net.Conn
	var err error
	if a.cfg.UpstreamProxy != "" {
		conn, err = a.viaProxy(a.cfg.UpstreamProxy, target)
	} else {
		conn, err = net.DialTimeout("tcp", target, 15*time.Second)
	}
	if err != nil {
		res["ok"] = false
		res["error"] = err.Error()
		b, _ := json.Marshal(res)
		wsc.WriteText(b)
		return
	}
	a.mu.Lock()
	a.streams[id] = conn
	a.mu.Unlock()
	res["ok"] = true
	b, _ := json.Marshal(res)
	wsc.WriteText(b)
	a.log("stream %s -> %s open", id, target)

	// upstream -> server
	go func() {
		defer func() {
			a.mu.Lock()
			delete(a.streams, id)
			a.mu.Unlock()
			conn.Close()
			bye, _ := json.Marshal(map[string]string{"type": proto.TypeClose, "id": id})
			wsc.WriteText(bye)
		}()
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				// Send as text frame (base64) for Cloudflare Tunnel compatibility.
				dm := proto.Data{
					Type:    proto.TypeData,
					ID:      id,
					Payload: base64.StdEncoding.EncodeToString(buf[:n]),
				}
				jd, _ := json.Marshal(dm)
				if os.Getenv("AGENT_DEBUG") != "" {
					log.Printf("[agent-debug] stream %s: read %d bytes from upstream, sending data msg %d bytes", id, n, len(jd))
				}
				if werr := wsc.WriteText(jd); werr != nil {
					if os.Getenv("AGENT_DEBUG") != "" {
						log.Printf("[agent-debug] stream %s: WriteText failed: %v", id, werr)
					}
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
}
