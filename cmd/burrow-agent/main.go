// Command burrow-agent: VM side of the tunnel.
// Connects to the server over WebSocket and serves fetch/connect
// requests using an upstream HTTP CONNECT proxy for egress.
//
// Example (sandbox):
//
//	burrow-agent --server wss://xxx.trycloudflare.com/ws \
//	    --upstream "$BURROW_UPSTREAM"
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/shafreeck/burrow/internal/agent"
	"github.com/shafreeck/burrow/internal/diagnostic"
)

func main() {
	version := flag.Bool("version", false, "print build revision and exit")
	serverURL := flag.String("server", "", "tunnel server WebSocket URL (wss://host/ws)")
	token := flag.String("token", "", "shared secret (must match server; alternatively BURROW_TOKEN)")
	upstream := flag.String("upstream", "", "remote environment HTTP CONNECT proxy for server and target egress; empty = direct; alternatively BURROW_UPSTREAM")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification (testing only)")
	flag.Parse()
	if *version {
		fmt.Println(diagnostic.Version())
		return
	}

	if *serverURL == "" {
		*serverURL = os.Getenv("TUNNEL_SERVER")
	}
	if *serverURL == "" {
		log.Fatal("--server is required (or TUNNEL_SERVER env)")
	}

	if *token == "" {
		*token = os.Getenv("BURROW_TOKEN")
	}
	if *upstream == "" {
		*upstream = os.Getenv("BURROW_UPSTREAM")
	}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.LUTC)
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ag.RunContext(ctx)
}
