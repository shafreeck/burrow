package main

import (
	"os/exec"
	"testing"
)

func TestShellQuote(t *testing.T) {
	raw := "wss://example.com/a'b?x=$(touch never)&y=1"
	out, err := exec.Command("sh", "-c", "printf '%s' "+shellQuote(raw)).Output()
	if err != nil || string(out) != raw {
		t.Fatalf("%q %v", out, err)
	}
}
