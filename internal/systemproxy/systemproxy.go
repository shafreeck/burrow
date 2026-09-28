// Package systemproxy temporarily changes desktop HTTP/HTTPS proxy settings.
// A durable snapshot allows recovery after an unclean process exit.
package systemproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type change struct{ Key, Before, After string }
type snapshot struct {
	Platform, Backend string
	Changes           []change
}
type backend interface {
	name() string
	plan(host, port, service string) ([]change, error)
	read(key string) (string, error)
	write(key, value string) error
	refresh() error
}
type command func(string, ...string) (string, error)

func runCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s failed: %w", filepath.Base(name), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func StatePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "burrow", "system-proxy.json"), nil
}

// Enable changes settings only after the caller has bound its HTTP proxy.
// restore should be deferred before returning to the event loop.
func Enable(addr, service string) (restore func() error, err error) {
	host, port, err := proxyTarget(addr)
	if err != nil {
		return nil, err
	}
	b, err := newBackend("")
	if err != nil {
		return nil, err
	}
	changes, err := b.plan(host, port, service)
	if err != nil {
		return nil, err
	}
	path, err := StatePath()
	if err != nil {
		return nil, err
	}
	return apply(b, changes, path)
}

// Listeners may bind public/private IPs or all interfaces. Desktop clients
// need a connectable address, so wildcard listeners use local loopback.
func proxyTarget(addr string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", "", err
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("system proxy requires a bound HTTP listener with a valid port")
	}
	if host == "localhost" {
		return host, port, nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", "", fmt.Errorf("system proxy requires a concrete listener IP address (or localhost): %w", err)
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() {
		if ip.Is4() {
			host = "127.0.0.1"
		} else {
			host = "::1"
		}
	}
	return host, port, nil
}

func apply(b backend, changes []change, path string) (func() error, error) {
	if len(changes) == 0 {
		return nil, fmt.Errorf("no supported network services found")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("save system proxy settings: %w; if a previous run exited unexpectedly, use --restore-system-proxy", err)
	}
	snap := snapshot{Platform: runtime.GOOS, Backend: b.name(), Changes: changes}
	err = json.NewEncoder(f).Encode(snap)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		os.Remove(path)
		return nil, err
	}
	restore := func() error { return restoreChanges(b, changes, path, false) }
	for _, c := range changes {
		if c.Before == c.After {
			continue
		}
		if err := b.write(c.Key, c.After); err != nil {
			return nil, errors.Join(err, restoreChanges(b, changes, path, true))
		}
	}
	if err := b.refresh(); err != nil {
		return nil, errors.Join(err, restoreChanges(b, changes, path, true))
	}
	// Read back: a command returning success does not prove settings changed.
	for _, c := range changes {
		got, err := b.read(c.Key)
		if err != nil || got != c.After {
			return nil, errors.Join(fmt.Errorf("system proxy verification failed for %s: %v", c.Key, err), restoreChanges(b, changes, path, true))
		}
	}
	return restore, nil
}

func restoreChanges(b backend, changes []change, path string, force bool) error {
	var errs []error
	for i := len(changes) - 1; i >= 0; i-- {
		c := changes[i]
		current, err := b.read(c.Key)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if current == c.Before {
			continue
		}
		if !force && current != c.After {
			errs = append(errs, fmt.Errorf("%s changed outside burrow; leaving it unchanged", c.Key))
			continue
		}
		if err := b.write(c.Key, c.Before); err != nil {
			errs = append(errs, err)
			continue
		}
		current, err = b.read(c.Key)
		if err != nil || current != c.Before {
			errs = append(errs, fmt.Errorf("could not verify restoration of %s: %v", c.Key, err))
		}
	}
	if err := b.refresh(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("system proxy restore incomplete; snapshot kept at %s: %w", path, errors.Join(errs...))
	}
	return os.Remove(path)
}

func RestoreSaved() error {
	path, err := StatePath()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Platform != runtime.GOOS {
		return fmt.Errorf("proxy snapshot belongs to %s", snap.Platform)
	}
	b, err := newBackend(snap.Backend)
	if err != nil {
		return err
	}
	return restoreChanges(b, snap.Changes, path, false)
}
