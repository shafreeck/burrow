package diagnostic

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestSafe(t *testing.T) {
	value := Safe(`close token=abc https://user:pass@example.com/ws?token=secret credential`, "credential")
	for _, secret := range []string{"abc", "user", "pass", "secret", "credential"} {
		if strings.Contains(value, secret) {
			t.Fatalf("leaked %s: %s", secret, value)
		}
	}
}
func TestEvent(t *testing.T) {
	var out string
	Event(func(f string, a ...interface{}) { out = fmt.Sprintf(f, a...) }, "closed", map[string]interface{}{"session": "abc"})
	var m map[string]interface{}
	if json.Unmarshal([]byte(out), &m) != nil || m["event"] != "closed" || !strings.HasSuffix(m["time"].(string), "Z") {
		t.Fatal(out)
	}
}
