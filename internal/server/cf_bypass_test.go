package server

import "testing"

func TestCloudflareTunnelTargets(t *testing.T) {
	for _, tc := range []struct {
		host string
		port int
		want bool
	}{
		{"region1.v2.argotunnel.com", 7844, true},
		{"QUIC.CFTUNNEL.COM.", 7844, true},
		{"some-tunnel.trycloudflare.com", 443, true},
		{"198.41.192.167", 7844, true},
		{"198.41.200.13", 7844, true},
		{"198.41.218.10", 7844, true},
		{"2606:4700:a8::10", 7844, true},
		{"::ffff:198.41.200.13", 7844, true},
		{"198.41.192.167", 443, false},
		{"198.41.192.168", 7844, false},
		{"2606:4700:a8::a", 7844, false},
		{"1.1.1.1", 7844, false},
		{"argotunnel.com.example.org", 7844, false},
		{"notargotunnel.com", 7844, false},
		{"www.google.com", 443, false},
	} {
		if got := isCloudflareEdge(tc.host, tc.port); got != tc.want {
			t.Errorf("%s:%d: %v, want %v", tc.host, tc.port, got, tc.want)
		}
	}
}
