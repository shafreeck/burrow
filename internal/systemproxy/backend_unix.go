//go:build !windows

package systemproxy

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func newBackend(saved string) (backend, error) {
	if runtime.GOOS == "darwin" {
		if saved != "" && saved != "macos" {
			return nil, fmt.Errorf("unsupported snapshot backend %s", saved)
		}
		return macBackend{runCommand}, nil
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("system proxy is unsupported on %s", runtime.GOOS)
	}
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" || (os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "") {
		return nil, fmt.Errorf("--system-proxy requires a GNOME or KDE desktop session; headless Linux has no unified system proxy")
	}
	desktop := strings.ToLower(os.Getenv("XDG_CURRENT_DESKTOP"))
	if strings.HasPrefix(saved, "kde") || (saved == "" && strings.Contains(desktop, "kde")) {
		for _, version := range []string{"6", "5"} {
			if saved != "" && saved != "kde"+version {
				continue
			}
			if _, err := exec.LookPath("kreadconfig" + version); err != nil {
				continue
			}
			if _, err := exec.LookPath("kwriteconfig" + version); err != nil {
				continue
			}
			if _, err := exec.LookPath("dbus-send"); err != nil {
				return nil, err
			}
			return kdeBackend{runCommand, version}, nil
		}
		return nil, fmt.Errorf("KDE proxy settings require kreadconfig and kwriteconfig (version 5 or 6)")
	}
	if saved == "gnome" || (saved == "" && (strings.Contains(desktop, "gnome") || strings.Contains(desktop, "unity") || strings.Contains(desktop, "cinnamon") || strings.Contains(desktop, "budgie"))) {
		if _, err := exec.LookPath("gsettings"); err != nil {
			return nil, err
		}
		return gnomeBackend{runCommand}, nil
	}
	return nil, fmt.Errorf("unsupported Linux desktop %q; supported: GNOME and KDE", desktop)
}
