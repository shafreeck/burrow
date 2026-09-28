package systemproxy

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type macBackend struct{ run command }
type macSetting struct{ Service, Kind string }
type macProxy struct {
	Enabled       bool
	Server        string
	Port          int
	Authenticated bool
}

func (b macBackend) name() string   { return "macos" }
func (b macBackend) refresh() error { return nil }
func macKey(service, kind string) string {
	v, _ := json.Marshal(macSetting{service, kind})
	return string(v)
}
func (b macBackend) read(key string) (string, error) {
	var k macSetting
	if err := json.Unmarshal([]byte(key), &k); err != nil {
		return "", err
	}
	cmd := "-get" + k.Kind + "proxy"
	if k.Kind == "pac" {
		cmd = "-getautoproxyurl"
	}
	if k.Kind == "discovery" {
		cmd = "-getproxyautodiscovery"
	}
	out, err := b.run("/usr/sbin/networksetup", cmd, k.Service)
	if err != nil {
		return "", err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		kv := strings.SplitN(line, ": ", 2)
		if len(kv) == 2 {
			fields[kv[0]] = kv[1]
		}
	}
	if k.Kind == "discovery" {
		if fields["Auto Proxy Discovery"] == "On" {
			return "true", nil
		}
		if fields["Auto Proxy Discovery"] == "Off" {
			return "false", nil
		}
		return "", fmt.Errorf("unrecognized discovery settings")
	}
	if fields["Enabled"] != "Yes" && fields["Enabled"] != "No" {
		return "", fmt.Errorf("unrecognized proxy settings for %s", k.Service)
	}
	enabled := fields["Enabled"] == "Yes"
	if k.Kind == "pac" {
		return strconv.FormatBool(enabled), nil
	}
	port, err := strconv.Atoi(fields["Port"])
	if err != nil {
		return "", err
	}
	p := macProxy{enabled, fields["Server"], port, fields["Authenticated Proxy Enabled"] == "1"}
	raw, _ := json.Marshal(p)
	return string(raw), nil
}
func (b macBackend) write(key, value string) error {
	var k macSetting
	if err := json.Unmarshal([]byte(key), &k); err != nil {
		return err
	}
	state := func(v bool) string {
		if v {
			return "on"
		}
		return "off"
	}
	if k.Kind == "pac" || k.Kind == "discovery" {
		cmd := "-setautoproxystate"
		if k.Kind == "discovery" {
			cmd = "-setproxyautodiscovery"
		}
		_, err := b.run("/usr/sbin/networksetup", cmd, k.Service, state(value == "true"))
		return err
	}
	var p macProxy
	if err := json.Unmarshal([]byte(value), &p); err != nil {
		return err
	}
	if p.Authenticated {
		return fmt.Errorf("cannot restore authenticated macOS proxy without keychain credentials")
	}
	if _, err := b.run("/usr/sbin/networksetup", "-set"+k.Kind+"proxy", k.Service, p.Server, strconv.Itoa(p.Port), "off"); err != nil {
		return err
	}
	_, err := b.run("/usr/sbin/networksetup", "-set"+k.Kind+"proxystate", k.Service, state(p.Enabled))
	return err
}
func (b macBackend) plan(host, port, service string) ([]change, error) {
	services := []string{service}
	if service == "" {
		out, err := b.run("/usr/sbin/networksetup", "-listallnetworkservices")
		if err != nil {
			return nil, err
		}
		services = nil
		for _, line := range strings.Split(out, "\n") {
			if line != "" && !strings.HasPrefix(line, "*") && !strings.HasPrefix(line, "An asterisk") {
				services = append(services, line)
			}
		}
	}
	var changes []change
	for _, svc := range services {
		for _, kind := range []string{"pac", "discovery", "web", "secureweb"} {
			key := macKey(svc, kind)
			before, err := b.read(key)
			if err != nil {
				return nil, err
			}
			after := "false"
			if kind == "web" || kind == "secureweb" {
				var p macProxy
				if err := json.Unmarshal([]byte(before), &p); err != nil {
					return nil, err
				}
				if p.Authenticated {
					return nil, fmt.Errorf("%s has an authenticated proxy; automatic replacement cannot preserve its credentials", svc)
				}
				n, _ := strconv.Atoi(port)
				raw, _ := json.Marshal(macProxy{true, host, n, false})
				after = string(raw)
			}
			changes = append(changes, change{key, before, after})
		}
	}
	return changes, nil
}

type gnomeBackend struct{ run command }

func (b gnomeBackend) name() string   { return "gnome" }
func (b gnomeBackend) refresh() error { return nil }
func (b gnomeBackend) read(key string) (string, error) {
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid GNOME setting")
	}
	return b.run("gsettings", "get", parts[0], parts[1])
}
func (b gnomeBackend) write(key, value string) error {
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid GNOME setting")
	}
	_, err := b.run("gsettings", "set", parts[0], parts[1], value)
	return err
}
func (b gnomeBackend) plan(host, port, service string) ([]change, error) {
	if service != "" {
		return nil, fmt.Errorf("--proxy-service applies only to macOS")
	}
	changes := []change{{Key: "org.gnome.system.proxy.http/host", After: "'" + host + "'"}, {Key: "org.gnome.system.proxy.http/port", After: port}, {Key: "org.gnome.system.proxy.https/host", After: "'" + host + "'"}, {Key: "org.gnome.system.proxy.https/port", After: port}, {Key: "org.gnome.system.proxy.http/use-authentication", After: "false"}, {Key: "org.gnome.system.proxy/use-same-proxy", After: "false"}, {Key: "org.gnome.system.proxy/mode", After: "'manual'"}}
	for i := range changes {
		parts := strings.SplitN(changes[i].Key, "/", 2)
		writable, err := b.run("gsettings", "writable", parts[0], parts[1])
		if err != nil {
			return nil, err
		}
		if writable != "true" {
			return nil, fmt.Errorf("GNOME proxy settings are locked")
		}
		changes[i].Before, err = b.read(changes[i].Key)
		if err != nil {
			return nil, err
		}
	}
	return changes, nil
}

type kdeBackend struct {
	run     command
	version string
}

func (b kdeBackend) name() string { return "kde" + b.version }
func (b kdeBackend) refresh() error {
	_, err := b.run("dbus-send", "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:")
	return err
}

const missingKDE = "__burrow_absent_7d98ee__"

func (b kdeBackend) read(key string) (string, error) {
	return b.run("kreadconfig"+b.version, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", key, "--default", missingKDE)
}
func (b kdeBackend) write(key, value string) error {
	args := []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", key}
	if value == missingKDE {
		args = append(args, "--delete")
	} else {
		args = append(args, value)
	}
	_, err := b.run("kwriteconfig"+b.version, args...)
	return err
}
func (b kdeBackend) plan(host, port, service string) ([]change, error) {
	if service != "" {
		return nil, fmt.Errorf("--proxy-service applies only to macOS")
	}
	proxy := "http://" + net.JoinHostPort(host, port)
	changes := []change{{Key: "httpProxy", After: proxy}, {Key: "httpsProxy", After: proxy}, {Key: "ReversedException", After: "false"}, {Key: "ProxyType", After: "1"}}
	for i := range changes {
		var err error
		changes[i].Before, err = b.read(changes[i].Key)
		if err != nil {
			return nil, err
		}
	}
	return changes, nil
}
