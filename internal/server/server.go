// Package server implements the public side of the tunnel:
//   - /ws: WebSocket endpoint for agents
//   - /fetch: single-shot HTTP fetch through the tunnel (test/debug)
//   - HTTP proxy on a separate listener: CONNECT + plain HTTP forwarding
package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/shafreeck/burrow/internal/diagnostic"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shafreeck/burrow/internal/proto"
	"github.com/shafreeck/burrow/internal/ws"
)

// Config for the server.
type Config struct {
	Listen    string // e.g. "127.0.0.1:9000"
	ProxyAddr string // e.g. "127.0.0.1:8080", "" to disable proxy
	VLESSAddr string // e.g. "127.0.0.1:8443", "" to disable VLESS inbound
	SOCKSAddr string // e.g. "127.0.0.1:1080", "" to disable SOCKS5 inbound
	Token     string // shared secret, "" to disable auth
	VLESSUUID string // VLESS UUID (32 hex, no dashes), "" to disable UUID check
	Domain    string // public domain for TLS/ACME, "" to disable
	TLSCert   string // path to TLS cert PEM, "" to disable TLS
	TLSKey    string // path to TLS key PEM, "" to disable TLS
	Debug     bool   // expose /debug and /fetch (default false)
	Logf      func(string, ...interface{})
}

// Server is the tunnel server.
type Server struct {
	cfg  Config
	logf func(string, ...interface{})

	mu     sync.Mutex
	agents map[string]*agentConn

	pendingMu sync.Mutex
	pending   map[string]*pendingRequest

	streamsMu        sync.Mutex
	streams          map[string]*stream
	agentReady       chan struct{}
	readyOnce        sync.Once
	heartbeatTimeout time.Duration
	directDial       func(string, int) (net.Conn, error)
}

type agentConn struct {
	id        string
	ws        *ws.Conn
	heartbeat *time.Timer
	connected time.Time
	lastPing  atomic.Int64
	build     string
}

type stream struct {
	id    string
	agent *agentConn
	// toNet carries data agent -> browser. Sends block (backpressure),
	// aborting when done is closed. Never closed; done signals end.
	toNet     chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

func (st *stream) sendToNet(payload []byte) bool {
	select {
	case st.toNet <- payload:
		return true
	case <-st.done:
		return false
	}
}

func (st *stream) close() {
	st.closeOnce.Do(func() { close(st.done) })
}

// New creates a Server.
func New(cfg Config) *Server {
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	return &Server{
		cfg:              cfg,
		logf:             cfg.Logf,
		agents:           make(map[string]*agentConn),
		pending:          make(map[string]*pendingRequest),
		streams:          make(map[string]*stream),
		agentReady:       make(chan struct{}),
		heartbeatTimeout: 45 * time.Second,
		directDial:       dialDirect,
	}
}

// Ready closes after the first authenticated agent connects.
func (s *Server) Ready() <-chan struct{} { return s.agentReady }

func (s *Server) log(format string, args ...interface{}) {
	s.logf("[server] "+format, args...)
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// pickAgent returns any connected agent, or nil.
func (s *Server) pickAgent() *agentConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.agents {
		return a
	}
	return nil
}

// waitAgent waits up to timeout for an agent.
func (s *Server) waitAgent(timeout time.Duration) *agentConn {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if a := s.pickAgent(); a != nil {
			return a
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

// --- WebSocket endpoint ---

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	id := newID()
	rejected := func(stage, reason string) {
		diagnostic.Event(s.logf, "agent_rejected", map[string]interface{}{"session": id, "stage": stage, "reason": reason})
	}
	c, err := ws.ServerHandshake(w, r)
	if err != nil {
		rejected("websocket_handshake", diagnostic.Safe(err.Error(), s.cfg.Token))
		s.log("ws handshake failed: %s", diagnostic.Safe(err.Error(), s.cfg.Token))
		http.Error(w, err.Error(), 400)
		return
	}

	// Wait for hello before registering. Token is validated here;
	// unauthenticated clients never enter the agents map.
	hello, ok := s.readHello(c)
	if !ok {
		rejected("authentication", "invalid_or_timed_out_hello")
		c.Close()
		return
	}
	if s.cfg.Token != "" {
		tok, _ := hello["token"].(string)
		if tok != s.cfg.Token {
			ack, _ := json.Marshal(map[string]interface{}{
				"type": proto.TypeHelloAck, "ok": false,
			})
			c.WriteText(ack)
			c.Close()
			rejected("authentication", "bad_token")
			s.log("agent rejected: bad token")
			return
		}
	}
	heartbeatEnabled, _ := hello["heartbeat"].(bool)
	ack, _ := json.Marshal(proto.HelloAck{
		Type: proto.TypeHelloAck, OK: true, Heartbeat: heartbeatEnabled, Build: diagnostic.Version(), Session: id,
	})
	if err := c.WriteText(ack); err != nil {
		c.Close()
		return
	}

	peerBuild, _ := hello["build"].(string)
	peerSession, _ := hello["session"].(string)
	ac := &agentConn{id: id, ws: c, connected: time.Now(), build: diagnostic.Safe(peerBuild, s.cfg.Token)}
	s.mu.Lock()
	s.agents[id] = ac
	n := len(s.agents)
	s.mu.Unlock()
	diagnostic.Event(s.logf, "agent_authenticated", map[string]interface{}{"session": id, "peer_session": diagnostic.Safe(peerSession, s.cfg.Token), "peer_version": ac.build, "heartbeat": heartbeatEnabled, "agents": n})
	s.log("agent connected id=%s total=%d", id, n)
	s.readyOnce.Do(func() { close(s.agentReady) })

	var closeOnce sync.Once
	cleanup := func(reason string, code int, detail string) {
		closeOnce.Do(func() {
			s.mu.Lock()
			delete(s.agents, id)
			n := len(s.agents)
			s.mu.Unlock()
			c.Close()
			// fail streams on this agent
			s.streamsMu.Lock()
			var dead []*stream
			for sid, st := range s.streams {
				if st.agent == ac {
					delete(s.streams, sid)
					dead = append(dead, st)
				}
			}
			s.streamsMu.Unlock()
			for _, st := range dead {
				st.close()
			}
			// fail pending requests on this agent
			s.pendingMu.Lock()
			for pid, req := range s.pending {
				if req.agent != ac {
					continue
				}
				delete(s.pending, pid)
				select {
				case req.reply <- map[string]interface{}{"error": "agent disconnected"}:
				default:
				}
			}
			s.pendingMu.Unlock()
			diagnostic.Event(s.logf, "agent_disconnected", map[string]interface{}{"session": id, "peer_version": ac.build, "stage": "established", "duration_ms": time.Since(ac.connected).Milliseconds(), "reason": reason, "close_code": code, "detail": diagnostic.Safe(detail, s.cfg.Token), "last_ping_unix_ms": ac.lastPing.Load(), "agents": n})
			s.log("agent disconnected id=%s total=%d", id, n)
		})
	}
	defer cleanup("handler_exit", 0, "")
	if heartbeatEnabled {
		ac.heartbeat = time.AfterFunc(s.heartbeatTimeout, func() {
			s.log("agent heartbeat timeout id=%s", id)
			// Run cleanup here, even if dispatch is blocked by a slow stream.
			cleanup("heartbeat_timeout", 0, "")
		})
		defer ac.heartbeat.Stop()
	}

	for {
		op, payload, err := c.ReadFrame()
		if err != nil {
			cleanup("transport_read", 0, err.Error())
			return
		}
		switch op {
		case ws.OpClose:
			code, reason := ws.CloseInfo(payload)
			cleanup("remote_close", code, reason)
			return
		case ws.OpText:
			s.onText(ac, payload)
		case ws.OpBinary:
			s.onBinary(ac, payload)
		}
	}
}

// readHello reads the first frame and expects a hello message.
// Returns false on timeout, wrong type, or parse error.
func (s *Server) readHello(c *ws.Conn) (map[string]interface{}, bool) {
	type result struct {
		op      int
		payload []byte
		err     error
	}
	ch := make(chan result, 1)
	go func() {
		op, p, err := c.ReadFrame()
		ch <- result{op, p, err}
	}()
	var res result
	select {
	case res = <-ch:
	case <-time.After(10 * time.Second):
		s.log("hello timeout")
		return nil, false
	}
	if res.err != nil || res.op != ws.OpText {
		return nil, false
	}
	var hello map[string]interface{}
	if err := json.Unmarshal(res.payload, &hello); err != nil {
		return nil, false
	}
	if t, _ := hello["type"].(string); t != proto.TypeHello {
		return nil, false
	}
	return hello, true
}

func (s *Server) onText(ac *agentConn, payload []byte) {
	var msg map[string]interface{}
	if err := json.Unmarshal(payload, &msg); err != nil {
		return
	}
	t, _ := msg["type"].(string)
	switch t {
	case proto.TypePing:
		id, _ := msg["id"].(string)
		if id == "" {
			return
		}
		ac.lastPing.Store(time.Now().UTC().UnixMilli())
		if ac.heartbeat != nil {
			ac.heartbeat.Reset(s.heartbeatTimeout)
		}
		pong, _ := json.Marshal(proto.Heartbeat{Type: proto.TypePong, ID: id})
		if err := ac.ws.WriteText(pong); err != nil {
			ac.ws.Close()
		}
	case proto.TypeFetchResult, proto.TypeConnectResult:
		if id, ok := msg["id"].(string); ok {
			s.pendingMu.Lock()
			req := s.pending[id]
			if req == nil || req.agent != ac {
				s.pendingMu.Unlock()
				return
			}
			delete(s.pending, id)
			s.pendingMu.Unlock()
			if req != nil {
				select {
				case req.reply <- msg:
				default:
				}
			}
		}
	case proto.TypeClose:
		if id, ok := msg["id"].(string); ok {
			s.streamsMu.Lock()
			st := s.streams[id]
			if st != nil && st.agent == ac {
				delete(s.streams, id)
				st.close()
			}
			s.streamsMu.Unlock()
		}
	case proto.TypeData:
		// Stream data via text frame (base64) for Cloudflare Tunnel compat.
		if id, ok := msg["id"].(string); ok {
			if b64, ok := msg["payload"].(string); ok {
				if data, err := base64.StdEncoding.DecodeString(b64); err == nil {
					s.streamsMu.Lock()
					st, ok := s.streams[id]
					s.streamsMu.Unlock()
					if ok && st.agent == ac {
						st.sendToNet(data)
					}
				}
			}
		}
	}
}

func (s *Server) onBinary(ac *agentConn, frame []byte) {
	id, payload, ok := proto.DecodeDataFrame(frame)
	if !ok {
		return
	}
	s.streamsMu.Lock()
	st, ok := s.streams[id]
	s.streamsMu.Unlock()
	if !ok || st.agent != ac {
		return
	}
	// Blocking send: TCP backpressure propagates to the agent.
	// Aborts if the stream was closed.
	st.sendToNet(payload)
}

func (s *Server) closeStream(id string) {
	s.streamsMu.Lock()
	st, ok := s.streams[id]
	if ok {
		delete(s.streams, id)
	}
	s.streamsMu.Unlock()
	if ok {
		st.close()
	}
}

// --- /fetch ---

func (s *Server) handleFetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		http.Error(w, "Missing ?url=", 400)
		return
	}
	ac := s.waitAgent(5 * time.Second)
	if ac == nil {
		http.Error(w, "No agent connected", 502)
		return
	}
	id := newID()
	ch := make(chan map[string]interface{}, 1)
	s.pendingMu.Lock()
	s.pending[id] = &pendingRequest{agent: ac, reply: ch}
	s.pendingMu.Unlock()

	req := map[string]interface{}{
		"type":   proto.TypeFetch,
		"id":     id,
		"method": "GET",
		"url":    target,
	}
	b, _ := json.Marshal(req)
	if err := ac.ws.WriteText(b); err != nil {
		s.pendingMu.Lock()
		delete(s.pending, id)
		s.pendingMu.Unlock()
		http.Error(w, "send failed", 502)
		return
	}
	select {
	case res := <-ch:
		if e, _ := res["error"].(string); e != "" {
			http.Error(w, e, 502)
			return
		}
		b64, _ := res["body"].(string)
		body, _ := base64.StdEncoding.DecodeString(b64)
		status := 502
		if f, ok := res["status"].(float64); ok {
			status = int(f)
		}
		w.WriteHeader(status)
		w.Write(body)
	case <-time.After(30 * time.Second):
		s.pendingMu.Lock()
		delete(s.pending, id)
		s.pendingMu.Unlock()
		http.Error(w, "Agent timeout", 504)
	}
}

// --- HTTP proxy ---

// ServeProxy runs a blocking HTTP proxy on addr (CONNECT + plain HTTP).
func (s *Server) ServeProxy(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.ServeProxyListener(ln)
}

func (s *Server) ServeProxyListener(ln net.Listener) error {
	s.log("proxy listening on %s", ln.Addr())
	return (&http.Server{Handler: http.HandlerFunc(s.handleProxy), ReadHeaderTimeout: 10 * time.Second}).Serve(ln)
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	// Plain HTTP: forward as fetch.
	s.handlePlainHTTP(w, r)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
		port = "443"
	}

	// Cloudflare edge bypass (TUN loop fix)
	if isCloudflareEdge(host, atoi(port)) {
		p, _ := strconv.Atoi(port)
		s.log("http-proxy: cloudflare edge %s:%d, dialing direct", host, p)
		target, derr := s.directDial(host, p)
		if derr != nil {
			http.Error(w, "Direct dial failed", 502)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			target.Close()
			http.Error(w, "Hijack not supported", 500)
			return
		}
		client, _, herr := hj.Hijack()
		if herr != nil {
			target.Close()
			http.Error(w, "Hijack failed", 500)
			return
		}
		client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		s.relayDirect(client, target)
		return
	}

	ac := s.waitAgent(10 * time.Second)
	if ac == nil {
		http.Error(w, "No agent connected", 502)
		return
	}
	st, err := s.openAgentStream(ac, host, atoi(port))
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	streamID := st.id
	defer s.endAgentStream(st)

	// Hijack browser connection.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", 500)
		return
	}
	bconn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	brw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	brw.Flush()

	defer bconn.Close()

	// browser -> agent. On exit (browser closed or error), tear down the stream.
	go func() {
		defer s.closeStream(streamID)
		buf := make([]byte, 32*1024)
		for {
			n, err := brw.Read(buf)
			if n > 0 {
				// Send as text frame (base64) for Cloudflare Tunnel compatibility.
				dm := proto.Data{
					Type:    proto.TypeData,
					ID:      streamID,
					Payload: base64.StdEncoding.EncodeToString(buf[:n]),
				}
				jd, _ := json.Marshal(dm)
				if werr := ac.ws.WriteText(jd); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// agent -> browser
	for {
		data, ok := st.receive()
		if !ok {
			return
		}
		if _, err := bconn.Write(data); err != nil {
			return
		}
	}
}

func (s *Server) handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	ac := s.waitAgent(5 * time.Second)
	if ac == nil {
		http.Error(w, "No agent connected", 502)
		return
	}
	// Read body
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
		if err != nil {
			http.Error(w, "Request body exceeds 4 MiB or could not be read", http.StatusRequestEntityTooLarge)
			return
		}
	}
	headers := map[string]string{}
	for k, vs := range r.Header {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}
	id := newID()
	ch := make(chan map[string]interface{}, 1)
	s.pendingMu.Lock()
	s.pending[id] = &pendingRequest{agent: ac, reply: ch}
	s.pendingMu.Unlock()

	// Reconstruct absolute URL
	url := r.URL.String()
	if r.URL.Host == "" {
		url = "http://" + r.Host + r.URL.RequestURI()
	}
	req := map[string]interface{}{
		"type":    proto.TypeFetch,
		"id":      id,
		"method":  r.Method,
		"url":     url,
		"headers": headers,
		"body":    body,
	}
	b, _ := json.Marshal(req)
	if err := ac.ws.WriteText(b); err != nil {
		s.pendingMu.Lock()
		delete(s.pending, id)
		s.pendingMu.Unlock()
		http.Error(w, "send failed", 502)
		return
	}
	select {
	case res := <-ch:
		if e, _ := res["error"].(string); e != "" {
			http.Error(w, e, 502)
			return
		}
		if hs, ok := res["headers"].(map[string]interface{}); ok {
			for k, v := range hs {
				if vs, ok := v.(string); ok {
					w.Header().Set(k, vs)
				}
			}
		}
		status := 502
		if f, ok := res["status"].(float64); ok {
			status = int(f)
		}
		w.WriteHeader(status)
		if bstr, ok := res["body"].(string); ok {
			if raw, err := base64.StdEncoding.DecodeString(bstr); err == nil {
				w.Write(raw)
			} else {
				w.Write([]byte(bstr))
			}
		}
	case <-time.After(30 * time.Second):
		s.pendingMu.Lock()
		delete(s.pending, id)
		s.pendingMu.Unlock()
		http.Error(w, "Agent timeout", 504)
	}
}

// --- main HTTP mux ---

// Handler returns the HTTP handler for the tunnel control plane.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWS)
	mux.HandleFunc("/healthz", s.health)
	if s.cfg.Debug {
		mux.HandleFunc("/diagnostics", s.diagnostics)
	}
	// ACME HTTP-01 challenge (for --domain auto-cert).
	mux.HandleFunc("/.well-known/acme-challenge/", handleACMEChallenge)
	if s.cfg.Debug {
		mux.HandleFunc("/fetch", s.handleFetch)
		mux.HandleFunc("/debug", func(w http.ResponseWriter, r *http.Request) {
			s.mu.Lock()
			n := len(s.agents)
			s.mu.Unlock()
			fmt.Fprintf(w, "agents: %d", n)
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("burrow server control plane. Agent WebSocket: /ws. Origin health: /healthz (does not verify Tunnel or egress)."))
	})
	return mux
}

// Serve runs the control-plane HTTP server (blocking).
func (s *Server) Serve() error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	return s.ServeListener(ln)
}

// ServeListener serves the control plane on an already-bound listener.
// This lets callers start the origin before bringing up a tunnel.
func (s *Server) ServeListener(ln net.Listener) error {
	s.log("control plane listening on %s", ln.Addr())
	httpServer := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		s.log("TLS enabled (cert=%s)", s.cfg.TLSCert)
		return httpServer.ServeTLS(ln, s.cfg.TLSCert, s.cfg.TLSKey)
	}
	return httpServer.Serve(ln)
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}
