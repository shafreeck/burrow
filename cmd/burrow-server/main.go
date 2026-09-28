// Command burrow-server: public side of the VM tunnel.
// Listens for agent WebSocket connections, exposes /fetch for testing,
// and runs a local HTTP proxy (CONNECT + plain HTTP) through the tunnel.
//
// Optionally auto-starts a Cloudflare quick tunnel:
//
//	burrow-server --tunnel --bind http://127.0.0.1:18080
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/shafreeck/burrow/internal/ca"
	"github.com/shafreeck/burrow/internal/cloudflared"
	"github.com/shafreeck/burrow/internal/server"
	"github.com/shafreeck/burrow/internal/systemproxy"
)

// stateFile returns the path for persisted server state (UUID, etc).
func stateFile() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		dir = "."
	} else {
		dir = filepath.Join(dir, "burrow")
	}
	os.MkdirAll(dir, 0700)
	return filepath.Join(dir, "server.json")
}

// loadOrGenerateUUID loads the VLESS UUID from state file, or generates
// and persists a new one. The UUID is stable across restarts.
func loadOrGenerateUUID(logf func(string, ...interface{})) string {
	path := stateFile()
	if data, err := os.ReadFile(path); err == nil {
		var st struct {
			VLESSUUID string `json:"vless_uuid"`
		}
		if json.Unmarshal(data, &st) == nil && len(st.VLESSUUID) == 32 {
			logf("vless: using persisted UUID from %s", path)
			return st.VLESSUUID
		}
	}
	// Generate new.
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		logf("vless: rand failed: %v", err)
		os.Exit(1)
	}
	// Set version 4 and variant bits (RFC 4122).
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	hexUUID := fmt.Sprintf("%x", uuid[:])

	st := struct {
		VLESSUUID string `json:"vless_uuid"`
	}{VLESSUUID: hexUUID}
	data, _ := json.MarshalIndent(st, "", "  ")
	os.WriteFile(path, data, 0600)
	logf("vless: generated new UUID, saved to %s", path)
	return hexUUID
}

// formatUUID converts 32-char hex to standard xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.
func formatUUID(hexUUID string) string {
	if len(hexUUID) != 32 {
		return hexUUID
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hexUUID[0:8], hexUUID[8:12], hexUUID[12:16], hexUUID[16:20], hexUUID[20:32])
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() (runErr error) {
	genUUID := flag.Bool("gen-uuid", false, "generate a random UUID and exit")
	listen := flag.String("listen", "127.0.0.1:9000", "control-plane listen address")
	var bindings inboundBindings
	flag.Var(&bindings, "bind", "proxy inbound URL: http://, socks5://, vless://, or trojan://host:port (repeatable; none by default)")
	systemProxy := flag.Bool("system-proxy", false, "temporarily point this machine's desktop HTTP/HTTPS proxies at the first http:// --bind; restore on exit")
	proxyService := flag.String("proxy-service", "", "macOS network service for --system-proxy (empty = all enabled services)")
	restoreProxy := flag.Bool("restore-system-proxy", false, "restore saved desktop proxy settings after an unclean exit and exit")
	trojanPassword := flag.String("trojan-password", "", "Trojan password (empty = auto-generate)")
	tunnel := flag.Bool("tunnel", false, "use Cloudflare Tunnel: random Quick Tunnel, or an existing fixed tunnel with --domain")
	noTunnel := flag.Bool("no-tunnel", false, "deprecated: use --tunnel=false")
	cfBin := flag.String("cloudflared", "cloudflared", "cloudflared binary")
	cfVerbose := flag.Bool("verbose", false, "show full cloudflared logs (default: only errors)")
	token := flag.String("token", "", "shared secret for agents (empty disables auth)")
	vlessUUID := flag.String("vless-uuid", "", "VLESS UUID (empty = auto-generate and persist)")
	domain := flag.String("domain", "", "public hostname: fixed Cloudflare tunnel with --tunnel, direct certificate with --acme")
	tlsCert := flag.String("tls-cert", "", "TLS certificate PEM file (empty disables TLS)")
	tlsKey := flag.String("tls-key", "", "TLS private key PEM file (empty disables TLS)")
	acmeEnabled := flag.Bool("acme", false, "obtain a Let's Encrypt certificate for --domain (direct TLS only)")
	acmeListen := flag.String("acme-listen", ":80", "HTTP-01 listen address while obtaining a certificate; public port 80 must reach it")
	acmeEmail := flag.String("acme-email", "", "email for Let's Encrypt account (with --domain)")
	acmeStaging := flag.Bool("acme-staging", false, "use Let's Encrypt staging (testing)")
	debug := flag.Bool("debug", false, "expose /debug and /fetch endpoints (or TUNNEL_DEBUG=1)")
	installCA := flag.Bool("install-ca", false, "install embedded Hatch sandbox egress CA to system trust store and exit")
	flag.Parse()
	if *restoreProxy {
		return systemproxy.RestoreSaved()
	}
	if *installCA {
		if err := ca.Install(); err != nil {
			return fmt.Errorf("install-ca: %w", err)
		}
		return nil
	}
	if *genUUID {
		var uuid [16]byte
		rand.Read(uuid[:])
		// Format as standard UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
		fmt.Printf("%08x-%04x-%04x-%04x-%012x\n",
			uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
		// Also print as 32-char hex for --token
		fmt.Printf("%032x\n", uuid)
		return nil
	}
	if os.Getenv("TUNNEL_DEBUG") == "1" {
		*debug = true
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	logf := func(f string, a ...interface{}) { log.Printf(f, a...) }

	mode, err := validateTransport(*tunnel, *noTunnel, *domain, *acmeEnabled, *tlsCert, *tlsKey)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	systemProxyIndex := -1
	if *systemProxy {
		systemProxyIndex, err = bindings.systemProxyBinding()
		if err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Direct TLS needs a reachable HTTP-01 listener before contacting ACME.
	// Cloudflare tunnels terminate public TLS at the edge and use local HTTP.
	if *acmeEnabled {
		certDir := "./certs"
		certPath, keyPath, err := server.ObtainCertViaACME(*domain, *acmeEmail, certDir, *acmeListen, *acmeStaging, logf)
		if err != nil {
			fmt.Fprintln(os.Stderr, "acme failed:", err)
			fmt.Fprintf(os.Stderr, "hint: public http://%s:80/.well-known/acme-challenge/ must reach --acme-listen %s\n", *domain, *acmeListen)
			return fmt.Errorf("ACME certificate acquisition failed")
		}
		*tlsCert = certPath
		*tlsKey = keyPath
	}
	var inboundTLS *tls.Config
	if *tlsCert != "" {
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			return fmt.Errorf("TLS certificate: %w", err)
		}
		inboundTLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}

	// VLESS UUID: explicit flag > persisted state > auto-generate.
	// This way the user never has to run --gen-uuid manually.
	uuid := *vlessUUID
	if bindings.has("vless") {
		if uuid == "" {
			// Backward compat: --token as UUID (32 hex).
			if len(*token) == 32 {
				uuid = *token
			}
		}
		if uuid == "" {
			uuid = loadOrGenerateUUID(logf)
		}
		uuid = strings.ToLower(strings.ReplaceAll(uuid, "-", ""))
		decoded, err := hex.DecodeString(uuid)
		if err != nil || len(decoded) != 16 {
			return fmt.Errorf("--vless-uuid must contain 16 bytes as 32 hex digits or a standard UUID")
		}
		fmt.Printf("\n  VLESS UUID: %s\n", formatUUID(uuid))
	}
	pw := *trojanPassword
	if bindings.has("trojan") && pw == "" {
		rb := make([]byte, 16)
		if _, err := rand.Read(rb); err != nil {
			return fmt.Errorf("generate Trojan password: %w", err)
		}
		pw = fmt.Sprintf("%x", rb)
		logf("trojan: auto-generated password: %s", pw)
	}

	srv := server.New(server.Config{
		Listen:    *listen,
		Token:     *token,
		VLESSUUID: uuid,
		Domain:    *domain,
		TLSCert:   *tlsCert,
		TLSKey:    *tlsKey,
		Debug:     *debug,
		Logf:      logf,
	})

	// Bind and start the origin before starting or advertising a tunnel.
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("control plane: %w", err)
	}
	defer ln.Close()
	// Bind every requested address before starting a tunnel. Any conflict
	// closes the listeners already opened by this run.
	var listeners []net.Listener
	var actualProxyAddr string
	for i, b := range bindings {
		listener, err := net.Listen("tcp", b.Address)
		if err != nil {
			return fmt.Errorf("--bind %s: %w", b, err)
		}
		defer listener.Close()
		if inboundTLS != nil && (b.Protocol == "vless" || b.Protocol == "trojan") {
			listener = tls.NewListener(listener, inboundTLS)
		}
		listeners = append(listeners, listener)
		if i == systemProxyIndex {
			actualProxyAddr = listener.Addr().String()
		}
	}
	serveErr := make(chan error, len(bindings)+1)
	go func() { serveErr <- srv.ServeListener(ln) }()
	for i, b := range bindings {
		listener := listeners[i]
		go func(b inboundBinding, listener net.Listener) {
			var err error
			switch b.Protocol {
			case "http":
				err = srv.ServeProxyListener(listener)
			case "socks5":
				err = srv.ServeSOCKS5Listener(listener)
			case "vless":
				err = srv.ServeVLESSListener(listener)
			case "trojan":
				err = srv.ServeTrojanListener(listener, pw)
			}
			serveErr <- fmt.Errorf("%s: %w", b, err)
		}(b, listener)
		logf("proxy inbound: %s://%s", b.Protocol, listener.Addr())
		if b.Protocol == "vless" {
			security := "none"
			if inboundTLS != nil {
				security = "tls"
				if *domain != "" {
					security += "&sni=" + url.QueryEscape(*domain)
				}
			}
			fmt.Printf("  VLESS URL:  vless://%s@%s?encryption=none&security=%s&type=tcp#burrow\n\n",
				formatUUID(uuid), listener.Addr(), security)
		}
	}

	if mode == "quick" {
		fmt.Println("Starting Cloudflare quick tunnel...")
		// Filter cloudflared logs: only show errors unless --verbose.
		// The URL is extracted and displayed prominently below.
		logFn := func(s string) {
			if *cfVerbose {
				logf("%s", s)
			} else if isImportant(s) {
				logf("%s", s)
			}
		}
		t, err := cloudflared.StartContext(ctx, *cfBin, "http://"+ln.Addr().String(), logFn)
		if err != nil {
			return fmt.Errorf("cloudflared failed: %w", err)
		}
		defer t.Stop()
		printTunnelBox(t.URL(), wsURL(t.URL()))
	} else if mode == "external" {
		logf("using externally managed tunnel: %s -> http://%s (TLS handled by Cloudflare)", *domain, *listen)
		logf("cloudflared must already be running with this hostname route")
		publicURL := "https://" + *domain
		printTunnelBox(publicURL, wsURL(publicURL))
	}

	scheme := "http"
	if *tlsCert != "" {
		scheme = "https"
	}
	logf("control plane: %s://%s", scheme, ln.Addr())
	if *systemProxy {
		logf("system proxy: waiting for an authenticated agent before changing desktop settings")
		select {
		case <-srv.Ready():
		case err := <-serveErr:
			return err
		case <-ctx.Done():
			return nil
		}
		restore, err := systemproxy.Enable(actualProxyAddr, *proxyService)
		if err != nil {
			return fmt.Errorf("system proxy: %w", err)
		}
		defer func() {
			if err := restore(); err != nil {
				logf("system proxy: %v", err)
				runErr = errors.Join(runErr, err)
			} else {
				logf("system proxy: original settings restored")
			}
		}()
		logf("system proxy: this machine's desktop HTTP/HTTPS proxies configured; original settings saved")
	}

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		return nil
	}
}

func wsURL(public string) string {
	// https://xxx.trycloudflare.com -> wss://xxx.trycloudflare.com
	if len(public) > 8 && public[:8] == "https://" {
		return "wss://" + public[8:]
	}
	return public
}

// isImportant reports whether a cloudflared log line is worth showing
// in non-verbose mode (errors, warnings, critical failures).
func isImportant(s string) bool {
	// cloudflared logs look like: "2026-09-28T14:42:10Z ERR ..." or "WRN"
	for _, kw := range []string{" ERR ", " WRN ", "ERR|", "critical", "failed", "Failed", "FAILED"} {
		if contains(s, kw) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// printTunnelBox displays the tunnel URL prominently, separated from logs.
func printTunnelBox(public, ws string) {
	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("  Agent connection")
	fmt.Println()
	fmt.Printf("  Public URL:  %s\n", public)
	fmt.Println()
	fmt.Printf("  Agent command:\n")
	fmt.Printf("    burrow-agent --server %s/ws \\\n", ws)
	fmt.Printf("        --upstream http://<proxy> [--token <token>]\n")
	fmt.Println("============================================================")
	fmt.Println()
}
