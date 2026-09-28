// Command burrow-agent: VM side of the tunnel.
// Connects to the server over WebSocket and serves fetch/connect
// requests using an upstream HTTP CONNECT proxy for egress.
//
// Example (sandbox):
//
//	burrow-agent --server wss://xxx.trycloudflare.com/ws \
//	    --upstream http://198.19.0.1:3128
package main

import (
	"flag"
	"log"
	"os"

	"github.com/shafreeck/burrow/internal/agent"
)

func main() {
	serverURL := flag.String("server", "", "tunnel server WebSocket URL (wss://host/ws)")
	token := flag.String("token", "", "shared secret (must match server)")
	upstream := flag.String("upstream", "", "upstream HTTP CONNECT proxy for egress (e.g. http://198.19.0.1:3128)")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification (testing only)")
	flag.Parse()

	if *serverURL == "" {
		*serverURL = os.Getenv("TUNNEL_SERVER")
	}
	if *serverURL == "" {
		log.Fatal("--server is required (or TUNNEL_SERVER env)")
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	cfg := agent.Config{
		ServerURL:     *serverURL,
		Token:         *token,
		UpstreamProxy: *upstream,
		InsecureTLS:   *insecure,
		Logf:          func(f string, a ...interface{}) { log.Printf(f, a...) },
	}
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}
	ag := agent.New(cfg)
	ag.Run()
}
