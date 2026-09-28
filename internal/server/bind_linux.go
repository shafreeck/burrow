//go:build linux

package server

import (
	"net"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// bindToPhysicalInterface binds the socket to the physical (non-TUN, non-loopback)
// interface device, bypassing any TUN VPN. Uses SO_BINDTODEVICE which does not
// require sudo for the socket option itself (but the process needs CAP_NET_RAW
// which is typically available).
func bindToPhysicalInterface(network, address string, c syscall.RawConn) error {
	iface, err := physicalInterface()
	if err != nil {
		// If we can't find a physical interface, don't bind (fall back to default routing)
		return nil
	}

	var bindErr error
	err = c.Control(func(fd uintptr) {
		// SO_BINDTODEVICE binds the socket to a specific interface by name on Linux
		bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface.Name)
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
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := iface.Name
		if strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "tap") || strings.HasPrefix(name, "utun") {
			continue
		}
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
	return nil, net.ErrClosed
}
