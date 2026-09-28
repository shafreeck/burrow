// Command muser-server: public side of the VM tunnel.
// Listens for agent WebSocket connections, exposes /fetch for testing,
// and runs a local HTTP proxy (CONNECT + plain HTTP) through the tunnel.
//
// Optionally auto-starts a Cloudflare quick tunnel:
//
//	muser-server --tunnel --proxy 127.0.0.1:8080
package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/shafreeck/muser/internal/ca"
	"github.com/shafreeck/muser/internal/cloudflared"
	"github.com/shafreeck/muser/internal/server"
)

// stateFile returns the path for persisted server state (UUID, etc).
func stateFile() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		dir = "."
	} else {
		dir = filepath.Join(dir, "muser")
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
	genUUID := flag.Bool("gen-uuid", false, "generate a random UUID and exit")
	listen := flag.String("listen", "127.0.0.1:9000", "control-plane listen address")
	proxyAddr := flag.String("proxy", "127.0.0.1:8080", "local HTTP proxy address (empty to disable)")
	vlessAddr := flag.String("vless", "127.0.0.1:8443", "VLESS TCP inbound address (empty to disable)")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "SOCKS5 TCP inbound address (empty to disable)")
	trojanAddr := flag.String("trojan", "", "Trojan inbound address (empty to disable)")
	trojanPassword := flag.String("trojan-password", "", "Trojan password (empty = auto-generate)")
	tunnel := flag.Bool("tunnel", false, "auto-start cloudflared quick tunnel to --listen")
	noTunnel := flag.Bool("no-tunnel", false, "deprecated: use --tunnel=false")
	cfBin := flag.String("cloudflared", "cloudflared", "cloudflared binary")
	cfVerbose := flag.Bool("verbose", false, "show full cloudflared logs (default: only errors)")
	token := flag.String("token", "", "shared secret for agents (empty disables auth)")
	vlessUUID := flag.String("vless-uuid", "", "VLESS UUID (empty = auto-generate and persist)")
	domain := flag.String("domain", "", "public domain for TLS/ACME (e.g. tunnel.example.com); empty disables")
	tlsCert := flag.String("tls-cert", "", "TLS certificate PEM file (empty disables TLS)")
	tlsKey := flag.String("tls-key", "", "TLS private key PEM file (empty disables TLS)")
	acmeEmail := flag.String("acme-email", "", "email for Let's Encrypt account (with --domain)")
	acmeStaging := flag.Bool("acme-staging", false, "use Let's Encrypt staging (testing)")
	debug := flag.Bool("debug", false, "expose /debug and /fetch endpoints (or TUNNEL_DEBUG=1)")
	installCA := flag.Bool("install-ca", false, "install embedded Hatch sandbox egress CA to system trust store and exit")
	flag.Parse()
	_ = noTunnel
	if *installCA {
		if err := ca.Install(); err != nil {
			log.Fatalf("install-ca: %v", err)
		}
		return
	}
	if *genUUID {
		var uuid [16]byte
		rand.Read(uuid[:])
		// Format as standard UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
		fmt.Printf("%08x-%04x-%04x-%04x-%012x\n",
			uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
		// Also print as 32-char hex for --token
		fmt.Printf("%032x\n", uuid)
		return
	}
	if os.Getenv("TUNNEL_DEBUG") == "1" {
		*debug = true
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	logf := func(f string, a ...interface{}) { log.Printf(f, a...) }

	// ACME auto-cert: if --domain is set but no --tls-cert, try Let's Encrypt.
	// Note: port 80 must reach this server for HTTP-01 validation.
	// The challenge is served on the control-plane port; use a reverse
	// proxy or NAT to forward port 80 if --listen is not :80.
	if *domain != "" && *tlsCert == "" {
		certDir := "./certs"
		certPath, keyPath, err := server.ObtainCertViaACME(*domain, *acmeEmail, certDir, *acmeStaging, logf)
		if err != nil {
			fmt.Fprintln(os.Stderr, "acme failed:", err)
			fmt.Fprintln(os.Stderr, "hint: ensure port 80 reaches this server for HTTP-01")
			os.Exit(1)
		}
		*tlsCert = certPath
		*tlsKey = keyPath
	}

	// VLESS UUID: explicit flag > persisted state > auto-generate.
	// This way the user never has to run --gen-uuid manually.
	uuid := *vlessUUID
	if *vlessAddr != "" {
		if uuid == "" {
			// Backward compat: --token as UUID (32 hex).
			if len(*token) == 32 {
				uuid = *token
			}
		}
		if uuid == "" {
			uuid = loadOrGenerateUUID(logf)
		}
		// Print UUID and import URL for client config.
		vlessURL := fmt.Sprintf("vless://%s@%s?encryption=none&security=none&type=tcp#muser",
			formatUUID(uuid), *vlessAddr)
		fmt.Printf("\n  VLESS UUID: %s\n", formatUUID(uuid))
		fmt.Printf("  VLESS URL:  %s\n\n", vlessURL)
	}

	srv := server.New(server.Config{
		Listen:    *listen,
		ProxyAddr: *proxyAddr,
		VLESSAddr: *vlessAddr,
		SOCKSAddr: *socksAddr,
		Token:     *token,
		VLESSUUID: uuid,
		Domain:    *domain,
		TLSCert:   *tlsCert,
		TLSKey:    *tlsKey,
		Debug:     *debug,
		Logf:      logf,
	})

	if *tunnel {
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
		t, err := cloudflared.Start(*cfBin, "http://"+*listen, logFn)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cloudflared failed:", err)
			os.Exit(1)
		}
		defer t.Stop()
		printTunnelBox(t.URL(), wsURL(t.URL()))
	}

	if *proxyAddr != "" {
		go func() {
			logf("proxy error: %v", srv.ServeProxy(*proxyAddr))
		}()
		logf("local proxy: http://%s (set as browser proxy)", *proxyAddr)
	}

	if *vlessAddr != "" {
		go func() {
			logf("vless error: %v", srv.ServeVLESS(*vlessAddr))
		}()
		logf("vless inbound: %s", *vlessAddr)
	}

	if *socksAddr != "" {
		go func() {
			logf("socks5 error: %v", srv.ServeSOCKS5(*socksAddr))
		}()
		logf("socks5 inbound: %s", *socksAddr)
	}

	if *trojanAddr != "" {
		pw := *trojanPassword
		if pw == "" {
			// Auto-generate a password if not provided.
			rb := make([]byte, 16)
			rand.Read(rb)
			pw = fmt.Sprintf("%x", rb)
			logf("trojan: auto-generated password: %s", pw)
		}
		go func() {
			logf("trojan error: %v", srv.ServeTrojan(*trojanAddr, pw))
		}()
		logf("trojan inbound: %s", *trojanAddr)
	}

	logf("control plane: http://%s", *listen)
	if err := srv.Serve(); err != nil {
		logf("server error: %v", err)
		os.Exit(1)
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
	fmt.Println("  Tunnel is ready!")
	fmt.Println()
	fmt.Printf("  Public URL:  %s\n", public)
	fmt.Println()
	fmt.Printf("  Agent command:\n")
	fmt.Printf("    muser-agent --server %s/ws \\\n", ws)
	fmt.Printf("        --upstream http://<proxy> [--token <token>]\n")
	fmt.Println("============================================================")
	fmt.Println()
}
