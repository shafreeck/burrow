//go:build darwin

package server

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// bindToPhysicalInterface binds the socket to the physical (non-TUN, non-loopback)
// interface, bypassing any TUN VPN. This does not require sudo - it's a
// per-socket option controlled by the application.
func bindToPhysicalInterface(network, address string, c syscall.RawConn) error {
	iface, err := physicalInterface()
	if err != nil {
		// If we can't find a physical interface, don't bind (fall back to default routing)
		return nil
	}

	var bindErr error
	err = c.Control(func(fd uintptr) {
		// IP_BOUND_IF binds the socket to a specific interface index on macOS
		bindErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, iface.Index)
	})
	if err != nil {
		return err
	}
	return bindErr
}

// physicalInterface returns the first non-loopback, non-TUN, up interface with an IPv4 address.
func physicalInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		// Skip down, loopback, and TUN interfaces
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := iface.Name
		// Skip TUN/TAP interfaces (utun*, tun*, tap*)
		if len(name) >= 4 && (name[:4] == "utun" || name[:3] == "tun" || name[:3] == "tap") {
			continue
		}
		// Must have an IPv4 address
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				return &iface, nil
			}
		}
	}
	return nil, net.ErrClosed // no suitable interface found
}
