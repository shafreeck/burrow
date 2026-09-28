//go:build windows

package server

import "syscall"

// Windows uses the configured OS route. TUN clients must exclude cloudflared
// themselves; this is separate from the WinINet system proxy setting.
func bindToPhysicalInterface(network, address string, c syscall.RawConn) error { return nil }
