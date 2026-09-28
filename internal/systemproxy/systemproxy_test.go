package systemproxy

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestProxyTargetFromListener(t *testing.T) {
	for _, tc := range []struct{ listen, target string }{
		{"127.0.0.1:18080", "127.0.0.1:18080"},
		{"localhost:18080", "localhost:18080"},
		{"0.0.0.0:18080", "127.0.0.1:18080"},
		{"[::]:18080", "[::1]:18080"},
		{"192.168.1.10:18080", "192.168.1.10:18080"},
		{"203.0.113.10:18080", "203.0.113.10:18080"},
		{"[2001:db8::1]:18080", "[2001:db8::1]:18080"},
	} {
		host, port, err := proxyTarget(tc.listen)
		if err != nil || net.JoinHostPort(host, port) != tc.target {
			t.Fatalf("%s: got %s:%s, %v; want %s", tc.listen, host, port, err, tc.target)
		}
	}
	for _, addr := range []string{":18080", "127.0.0.1:0", "127.0.0.1:65536", "http://127.0.0.1:18080"} {
		if _, _, err := proxyTarget(addr); err == nil {
			t.Fatalf("invalid address accepted: %s", addr)
		}
	}
}

type fakeBackend struct {
	values map[string]string
	fail   string
	failed bool
}

func (b *fakeBackend) name() string                                  { return "fake" }
func (b *fakeBackend) plan(string, string, string) ([]change, error) { return nil, nil }
func (b *fakeBackend) read(k string) (string, error)                 { return b.values[k], nil }
func (b *fakeBackend) write(k, v string) error {
	b.values[k] = v
	if k == b.fail && !b.failed {
		b.failed = true
		return errors.New("partial write failed")
	}
	return nil
}
func (b *fakeBackend) refresh() error { return nil }

func TestSnapshotRestoreAndRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "partial failure"}[fail], func(t *testing.T) {
			b := &fakeBackend{values: map[string]string{"http": "old-http", "https": "old-https"}}
			if fail {
				b.fail = "https"
			}
			path := filepath.Join(t.TempDir(), "proxy.json")
			restore, err := apply(b, []change{{"http", "old-http", "burrow"}, {"https", "old-https", "burrow"}}, path)
			if fail {
				if err == nil {
					t.Fatal("write failure hidden")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
					t.Fatal("snapshot permissions")
				}
				if _, err := apply(b, []change{{"http", "burrow", "another"}}, path); err == nil {
					t.Fatal("overlapping owner accepted")
				}
				if err := restore(); err != nil {
					t.Fatal(err)
				}
			}
			if b.values["http"] != "old-http" || b.values["https"] != "old-https" {
				t.Fatalf("settings not restored: %v", b.values)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("snapshot retained after successful restoration")
			}
		})
	}
}

func TestRestorePreservesOutsideChanges(t *testing.T) {
	b := &fakeBackend{values: map[string]string{"http": "old", "https": "old"}}
	path := filepath.Join(t.TempDir(), "proxy.json")
	restore, err := apply(b, []change{{"http", "old", "burrow"}, {"https", "old", "burrow"}}, path)
	if err != nil {
		t.Fatal(err)
	}
	b.values["http"] = "user-changed"
	if err := restore(); err == nil {
		t.Fatal("outside change not reported")
	}
	if b.values["http"] != "user-changed" || b.values["https"] != "old" {
		t.Fatal(b.values)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("recovery snapshot lost")
	}
}
