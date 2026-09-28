package server

import (
	"context"
	"net"
	"net/netip"
	"strconv"
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
	".cftunnel.com",
	".trycloudflare.com", // in case someone proxies the tunnel URL itself
}

// Published tunnel destinations, not the general Cloudflare CDN ranges.
// cloudflared often dials resolved IPs, so hostname-only rules miss TUN loops.
// https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/tunnel-with-firewall/
var cloudflareTunnelIPs = func() map[netip.Addr]bool {
	ips := make(map[netip.Addr]bool)
	for _, ip := range []string{
		"198.41.192.167", "198.41.192.67", "198.41.192.57", "198.41.192.107", "198.41.192.27",
		"198.41.192.7", "198.41.192.227", "198.41.192.47", "198.41.192.37", "198.41.192.77",
		"198.41.200.13", "198.41.200.193", "198.41.200.33", "198.41.200.233", "198.41.200.53",
		"198.41.200.63", "198.41.200.113", "198.41.200.73", "198.41.200.43", "198.41.200.23",
	} {
		ips[netip.MustParseAddr(ip)] = true
	}
	for _, prefix := range []string{"198.41.218.", "198.41.219."} {
		for i := 1; i <= 10; i++ {
			ips[netip.MustParseAddr(prefix+strconv.Itoa(i))] = true
		}
	}
	for _, prefix := range []string{"2606:4700:a0::", "2606:4700:a8::", "2606:4700:a1::", "2606:4700:a9::"} {
		for _, suffix := range []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"} {
			ips[netip.MustParseAddr(prefix+suffix)] = true
		}
	}
	return ips
}()

// isCloudflareEdge recognizes tunnel hostnames and known tunnel IPs on 7844.
func isCloudflareEdge(host string, port int) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return port == 7844 && cloudflareTunnelIPs[ip.Unmap()]
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
	return dialDirectNetwork("tcp", addr)
}

func dialDirectNetwork(network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: 15 * time.Second,
		Control: bindToPhysicalInterface,
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			dialer.Control = nil
		}
	}

	// Use context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	return dialer.DialContext(ctx, network, addr)
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
