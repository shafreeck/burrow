package main

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type inboundBinding struct {
	Protocol string
	Address  string
}

func (b inboundBinding) String() string { return b.Protocol + "://" + b.Address }

// inboundBindings implements flag.Value so each --bind adds one listener.
type inboundBindings []inboundBinding

func (bs *inboundBindings) String() string {
	var values []string
	for _, b := range *bs {
		values = append(values, b.String())
	}
	return strings.Join(values, ", ")
}

func (bs *inboundBindings) Set(value string) error {
	u, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("use protocol://host:port: %w", err)
	}
	switch u.Scheme {
	case "http", "socks5", "vless", "trojan":
	default:
		return fmt.Errorf("supported --bind protocols: http, socks5, vless, trojan")
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || strings.ContainsAny(value, "?#") {
		return fmt.Errorf("--bind accepts only protocol://host:port; use --vless-uuid or --trojan-password for credentials")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || host == "" {
		return fmt.Errorf("--bind requires an explicit host and port; use brackets for IPv6")
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return fmt.Errorf("--bind port must be an integer from 0 to 65535")
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("--bind port must be an integer from 0 to 65535")
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else {
		host = strings.ToLower(host)
	}
	b := inboundBinding{Protocol: u.Scheme, Address: net.JoinHostPort(host, strconv.Itoa(n))}
	for _, existing := range *bs {
		// Port zero requests a new ephemeral port on each bind.
		if n != 0 && existing.Address == b.Address {
			return fmt.Errorf("--bind address %s is already used by %s", b.Address, existing.Protocol)
		}
	}
	*bs = append(*bs, b)
	return nil
}

func (bs inboundBindings) has(protocol string) bool {
	for _, b := range bs {
		if b.Protocol == protocol {
			return true
		}
	}
	return false
}

// The first HTTP binding is the explicit destination for desktop proxy setup.
func (bs inboundBindings) systemProxyBinding() (int, error) {
	for i, b := range bs {
		if b.Protocol != "http" {
			continue
		}
		return i, nil
	}
	return -1, fmt.Errorf("--system-proxy requires --bind http://host:port")
}
