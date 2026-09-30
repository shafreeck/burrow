// Package diagnostic provides credential-safe connection events and build identity.
package diagnostic

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"runtime/debug"
	"strings"
	"time"
)

// Revision can be supplied with -ldflags '-X .../internal/diagnostic.Revision=SHA'.
var Revision string

func Version() string {
	if Revision != "" {
		return Revision
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		rev := "development"
		dirty := false
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				rev = s.Value
			}
			if s.Key == "vcs.modified" {
				dirty = s.Value == "true"
			}
		}
		if dirty {
			rev += "+dirty"
		}
		return rev
	}
	return "development"
}
func ID() string { var b [8]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }

// Endpoint intentionally excludes userinfo, paths, queries and fragments.
func Endpoint(raw string) string {
	u, e := url.Parse(raw)
	if e != nil {
		return "invalid"
	}
	return u.Scheme + "://" + u.Host
}

var urls = regexp.MustCompile(`(?:https?|wss?)://[^\s"<>]+`)
var authorization = regexp.MustCompile(`(?i)(?:Bearer|Basic)\s+[^\s,;]+`)
var secrets = regexp.MustCompile(`(?i)(token|password|authorization|secret)([=: ]+)[^\s,;]+`)

func Safe(raw string, values ...string) string {
	for _, v := range values {
		if v != "" {
			raw = strings.ReplaceAll(raw, v, "[redacted]")
		}
	}
	raw = urls.ReplaceAllStringFunc(raw, Endpoint)
	raw = authorization.ReplaceAllString(raw, "[redacted authorization]")
	raw = secrets.ReplaceAllString(raw, "$1$2[redacted]")
	if len(raw) > 512 {
		raw = raw[:512]
	}
	return raw
}
func Event(logf func(string, ...interface{}), event string, fields map[string]interface{}) {
	fields["event"] = event
	fields["time"] = time.Now().UTC().Format(time.RFC3339Nano)
	fields["version"] = Version()
	b, _ := json.Marshal(fields)
	logf("%s", b)
}
