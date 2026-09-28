package systemproxy

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestGNOMEAndKDESettingsRestore(t *testing.T) {
	for _, desktop := range []string{"gnome", "kde5", "kde6"} {
		t.Run(desktop, func(t *testing.T) {
			values := map[string]string{}
			run := func(name string, args ...string) (string, error) {
				if name == "dbus-send" {
					return "", nil
				}
				if name == "gsettings" {
					key := args[1] + "/" + args[2]
					switch args[0] {
					case "writable":
						return "true", nil
					case "get":
						if v, ok := values[key]; ok {
							return v, nil
						}
						return "'auto'", nil
					case "set":
						values[key] = args[3]
						return "", nil
					}
				}
				key := args[5]
				if strings.HasPrefix(name, "kreadconfig") {
					if v, ok := values[key]; ok {
						return v, nil
					}
					return missingKDE, nil
				}
				if args[6] == "--delete" {
					delete(values, key)
				} else {
					values[key] = args[6]
				}
				return "", nil
			}
			var b backend = gnomeBackend{run}
			if desktop != "gnome" {
				b = kdeBackend{run, desktop[3:]}
			}
			changes, err := b.plan("127.0.0.1", "8080", "")
			if err != nil {
				t.Fatal(err)
			}
			original := map[string]string{}
			for _, c := range changes {
				original[c.Key] = c.Before
			}
			restore, err := apply(b, changes, filepath.Join(t.TempDir(), "proxy.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := restore(); err != nil {
				t.Fatal(err)
			}
			for key, want := range original {
				got, err := b.read(key)
				if err != nil || got != want {
					t.Fatalf("%s restored to %q, want %q: %v", key, got, want, err)
				}
			}
		})
	}
}

func TestMacOSSettingsRestore(t *testing.T) {
	proxies := map[string]macProxy{"web": {false, "old-http", 9001, false}, "secureweb": {true, "old-https", 9002, false}}
	auto := map[string]bool{"pac": true, "discovery": true}
	original := map[string]macProxy{}
	for k, v := range proxies {
		original[k] = v
	}
	state := func(v bool, on, off string) string {
		if v {
			return on
		}
		return off
	}
	run := func(name string, args ...string) (string, error) {
		if name != "/usr/sbin/networksetup" {
			t.Fatal(name)
		}
		switch args[0] {
		case "-listallnetworkservices":
			return "An asterisk (*) denotes disabled services.\nWi-Fi\n*Disabled", nil
		case "-getautoproxyurl":
			return "URL: https://old.example/proxy.pac\nEnabled: " + state(auto["pac"], "Yes", "No"), nil
		case "-getproxyautodiscovery":
			return "Auto Proxy Discovery: " + state(auto["discovery"], "On", "Off"), nil
		case "-setautoproxystate":
			auto["pac"] = args[2] == "on"
			return "", nil
		case "-setproxyautodiscovery":
			auto["discovery"] = args[2] == "on"
			return "", nil
		}
		for _, kind := range []string{"web", "secureweb"} {
			p := proxies[kind]
			switch args[0] {
			case "-get" + kind + "proxy":
				return fmt.Sprintf("Enabled: %s\nServer: %s\nPort: %d\nAuthenticated Proxy Enabled: 0", state(p.Enabled, "Yes", "No"), p.Server, p.Port), nil
			case "-set" + kind + "proxy":
				p.Server = args[2]
				fmt.Sscan(args[3], &p.Port)
				p.Enabled = true
				proxies[kind] = p
				return "", nil
			case "-set" + kind + "proxystate":
				p.Enabled = args[2] == "on"
				proxies[kind] = p
				return "", nil
			}
		}
		return "", fmt.Errorf("unexpected command %v", args)
	}
	b := macBackend{run}
	changes, err := b.plan("127.0.0.1", "8080", "")
	if err != nil {
		t.Fatal(err)
	}
	restore, err := apply(b, changes, filepath.Join(t.TempDir(), "proxy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(proxies, original) || !auto["pac"] || !auto["discovery"] {
		t.Fatalf("original settings not restored: %v %v", proxies, auto)
	}
}
