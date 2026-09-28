package server

import (
	"context"
	"net"
	"strings"
	"time"
)

// Cloudflare edge domains that cloudflared connects to for tunnel control.
// When the server runs with --tunnel and the host has TUN mode enabled,
// cloudflared's own traffic gets intercepted by TUN and looped back into
// our proxy. We detect these targets and dial them directly (bypassing
// both the agent tunnel and the TUN interface).
var cloudflareEdgeSuffixes = []string{
	".argotunnel.com",
	".v2.argotunnel.com",
	".trycloudflare.com", // in case someone proxies the tunnel URL itself
}

// isCloudflareEdge reports whether host is a Cloudflare tunnel edge domain.
func isCloudflareEdge(host string) bool {
	// Strip port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, suffix := range cloudflareEdgeSuffixes {
		if strings.HasSuffix(host, suffix) || host == strings.TrimPrefix(suffix, ".") {
			return true
		}
	}
	return false
}

// dialDirect dials host:port directly, bypassing the agent tunnel.
// It binds to the physical (non-TUN) interface to avoid routing loops
// when a TUN VPN is active on this host.
func dialDirect(host string, port int) (net.Conn, error) {
	addr := net.JoinHostPort(host, itoa(port))

	dialer := &net.Dialer{
		Timeout: 15 * time.Second,
		Control: bindToPhysicalInterface,
	}

	// Use context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	return dialer.DialContext(ctx, "tcp", addr)
}

// itoa is a simple int-to-string (avoid strconv import cycle concerns).
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [16]byte
	pos := len(b)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
