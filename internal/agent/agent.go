// Package agent implements the VM side of the tunnel: connects to the
// server over WebSocket (optionally via an upstream HTTP CONNECT proxy),
// serves fetch and stream-connect requests using an upstream proxy
// for egress.
package agent

import (
	"bufio"
	"context"
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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shafreeck/burrow/internal/proto"
	"github.com/shafreeck/burrow/internal/ws"
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
}

// Each WebSocket session owns its streams, including dials still in progress.
// A late dial from an old session must never survive a reconnect.
type session struct {
	*Agent
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	streams map[string]*agentStream
	closed  bool
}

type agentStream struct {
	conn net.Conn
}

func New(cfg Config) *Agent {
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	return &Agent{
		cfg:  cfg,
		logf: cfg.Logf,
	}
}

func (cfg Config) Validate() error {
	u, err := url.Parse(cfg.ServerURL)
	if err != nil || u == nil || u.Hostname() == "" || (u.Scheme != "ws" && u.Scheme != "wss") {
		return fmt.Errorf("server must be a ws:// or wss:// URL with a hostname")
	}
	if cfg.UpstreamProxy != "" {
		pu, err := url.Parse(cfg.UpstreamProxy)
		if err != nil || pu == nil || pu.Hostname() == "" || (pu.Scheme != "http" && pu.Scheme != "https") {
			return fmt.Errorf("upstream must be an http:// or https:// CONNECT proxy URL")
		}
	}
	return nil
}

func (s *session) close() {
	s.cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for id, st := range s.streams {
		if st.conn != nil {
			st.conn.Close()
		}
		delete(s.streams, id)
	}
}

func (a *Agent) log(format string, args ...interface{}) {
	a.logf("[agent] "+format, args...)
}

// dialServer connects to the tunnel server. Uses the upstream proxy only
// for non-local targets; localhost always dials direct.
func (a *Agent) dialServer(ctx context.Context) (net.Conn, error) {
	u, err := url.Parse(a.cfg.ServerURL)
	if err != nil {
		return nil, err
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "wss" {
			port = "443"
		}
	}
	host := net.JoinHostPort(u.Hostname(), port)

	var conn net.Conn
	hostname := u.Hostname()
	useProxy := a.cfg.UpstreamProxy != "" && !isLocal(hostname)
	if useProxy {
		conn, err = a.viaProxy(ctx, a.cfg.UpstreamProxy, host)
		if err != nil {
			return nil, fmt.Errorf("proxy dial: %w", err)
		}
	} else {
		conn, err = (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", host)
		if err != nil {
			return nil, err
		}
	}
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	if u.Scheme == "wss" || u.Scheme == "https" {
		tlsCfg := &tls.Config{ServerName: u.Hostname()}
		if a.cfg.InsecureTLS {
			tlsCfg.InsecureSkipVerify = true
		}
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls: %w", err)
		}
		conn = tlsConn
	}
	return conn, nil
}

// viaProxy opens a TCP connection to target through an HTTP CONNECT proxy.
func (a *Agent) viaProxy(ctx context.Context, proxyURL, target string) (net.Conn, error) {
	pu, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	if pu.Hostname() == "" || (pu.Scheme != "http" && pu.Scheme != "https") {
		return nil, fmt.Errorf("unsupported CONNECT proxy URL")
	}
	port := pu.Port()
	if port == "" {
		port = "80"
		if pu.Scheme == "https" {
			port = "443"
		}
	}
	phost := net.JoinHostPort(pu.Hostname(), port)
	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", phost)
	if err != nil {
		return nil, err
	}
	rawConn := conn
	stop := context.AfterFunc(ctx, func() { rawConn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	if pu.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: pu.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("proxy TLS: %w", err)
		}
		conn = tlsConn
	}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
	if pu.User != nil {
		password, _ := pu.User.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(pu.User.Username()+":"+password)))
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy response: %w", err)
	}
	if resp.StatusCode != 200 {
		conn.Close()
		resp.Body.Close()
		return nil, fmt.Errorf("proxy status: %s", resp.Status)
	}
	conn.SetDeadline(time.Time{})
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
	a.RunContext(context.Background())
}

// RunContext reconnects until ctx is canceled.
func (a *Agent) RunContext(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := a.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			a.log("connection error: %v", err)
		}
		if time.Since(start) > 30*time.Second {
			backoff = time.Second // healthy session, reset
		}
		a.log("reconnecting in %v...", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func (a *Agent) runOnce(ctx context.Context) error {
	if err := a.cfg.Validate(); err != nil {
		return err
	}
	u, _ := url.Parse(a.cfg.ServerURL)
	a.log("connecting to %s...", a.cfg.ServerURL)
	nc, err := a.dialServer(ctx)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { nc.Close() })
	defer stop()
	path := u.RequestURI()
	wsc, err := ws.ClientHandshake(nc, u.Host, path)
	if err != nil {
		nc.Close()
		return fmt.Errorf("ws handshake: %w", err)
	}
	defer wsc.Close()

	// hello
	hello, _ := json.Marshal(map[string]string{
		"type": proto.TypeHello, "token": a.cfg.Token, "version": "1",
	})
	if err := wsc.WriteText(hello); err != nil {
		return err
	}
	op, payload, err := wsc.ReadFrame()
	if err != nil {
		return fmt.Errorf("hello: %w", err)
	}
	var ack struct {
		Type string `json:"type"`
		OK   bool   `json:"ok"`
	}
	if op != ws.OpText || json.Unmarshal(payload, &ack) != nil || ack.Type != proto.TypeHelloAck || !ack.OK {
		return fmt.Errorf("hello rejected or invalid acknowledgement")
	}
	nc.SetDeadline(time.Time{})
	a.log("websocket connected and authenticated")
	sessionCtx, cancel := context.WithCancel(ctx)
	s := &session{Agent: a, ctx: sessionCtx, cancel: cancel, streams: make(map[string]*agentStream)}
	defer s.close()

	for {
		op, payload, err := wsc.ReadFrame()
		if err != nil {
			return err
		}
		switch op {
		case ws.OpClose:
			return fmt.Errorf("closed by server")
		case ws.OpText:
			s.onText(wsc, payload)
		case ws.OpBinary:
			s.onBinary(wsc, payload)
		}
	}
}

func (a *session) onText(wsc *ws.Conn, payload []byte) {
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
		id, _ := msg["id"].(string)
		if id == "" {
			return
		}
		a.mu.Lock()
		if a.closed || a.streams[id] != nil {
			a.mu.Unlock()
			return
		}
		st := &agentStream{}
		a.streams[id] = st
		a.mu.Unlock()
		go a.doConnect(wsc, msg, st)
	case proto.TypeClose:
		if id, ok := msg["id"].(string); ok {
			a.mu.Lock()
			c := a.streams[id]
			delete(a.streams, id)
			a.mu.Unlock()
			if c != nil && c.conn != nil {
				c.conn.Close()
			}
		}
	case proto.TypeData:
		// Stream data via text frame (base64) for Cloudflare Tunnel compat.
		if id, ok := msg["id"].(string); ok {
			if b64, ok := msg["payload"].(string); ok {
				if data, err := base64.StdEncoding.DecodeString(b64); err == nil {
					a.mu.Lock()
					st := a.streams[id]
					var c net.Conn
					if st != nil {
						c = st.conn
					}
					a.mu.Unlock()
					if c != nil {
						c.SetWriteDeadline(time.Now().Add(10 * time.Second))
						if _, err := c.Write(data); err != nil {
							c.Close()
						}
					}
				}
			}
		}
	}
}

func (a *session) onBinary(wsc *ws.Conn, frame []byte) {
	id, payload, ok := proto.DecodeDataFrame(frame)
	if !ok {
		return
	}
	a.mu.Lock()
	st := a.streams[id]
	var c net.Conn
	if st != nil {
		c = st.conn
	}
	a.mu.Unlock()
	if c == nil {
		return
	}
	// Write to upstream. Best effort.
	c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(payload); err != nil {
		c.Close()
	}
}

// replyFetch performs an HTTP request via upstream proxy and replies.
func (a *session) replyFetch(wsc *ws.Conn, msg map[string]interface{}) {
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
	req, err := http.NewRequestWithContext(a.ctx, method, urlStr, bodyReader)
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
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Timeout: 25 * time.Second, Transport: transport}
	defer client.CloseIdleConnections()
	if a.cfg.UpstreamProxy != "" {
		if pu, err := url.Parse(a.cfg.UpstreamProxy); err == nil {
			transport.Proxy = http.ProxyURL(pu)
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
	// Base64 plus JSON must fit within the 8 MiB WebSocket frame limit.
	const maxFetchBody = 4 << 20
	bb, readErr := io.ReadAll(io.LimitReader(resp.Body, maxFetchBody+1))
	if readErr != nil || len(bb) > maxFetchBody {
		res["error"] = "fetch body is unreadable or exceeds 4 MiB"
		b, _ := json.Marshal(res)
		wsc.WriteText(b)
		return
	}
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
func (a *session) doConnect(wsc *ws.Conn, msg map[string]interface{}, st *agentStream) {
	id, _ := msg["id"].(string)
	host, _ := msg["host"].(string)
	port := 443
	if p, ok := msg["port"].(float64); ok {
		port = int(p)
	}
	res := map[string]interface{}{"type": proto.TypeConnectResult, "id": id}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	defer func() {
		a.mu.Lock()
		if a.streams[id] == st {
			delete(a.streams, id)
		}
		a.mu.Unlock()
	}()

	var conn net.Conn
	var err error
	if host == "" || port < 1 || port > 65535 {
		err = fmt.Errorf("invalid target host or port")
	} else if a.cfg.UpstreamProxy != "" {
		conn, err = a.viaProxy(a.ctx, a.cfg.UpstreamProxy, target)
	} else {
		conn, err = (&net.Dialer{Timeout: 15 * time.Second}).DialContext(a.ctx, "tcp", target)
	}
	if err != nil {
		res["ok"] = false
		res["error"] = err.Error()
		b, _ := json.Marshal(res)
		wsc.WriteText(b)
		return
	}
	a.mu.Lock()
	if a.closed || a.streams[id] != st {
		a.mu.Unlock()
		conn.Close()
		return
	}
	st.conn = conn
	a.mu.Unlock()
	res["ok"] = true
	b, _ := json.Marshal(res)
	if err := wsc.WriteText(b); err != nil {
		conn.Close()
		return
	}
	a.log("stream %s -> %s open", id, target)

	// upstream -> server
	func() {
		defer func() {
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
