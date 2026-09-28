package main

import "testing"

func TestBindURLs(t *testing.T) {
	for _, tc := range []struct {
		url, address string
		invalid      bool
	}{
		{url: "vless://127.0.0.1:8443", address: "127.0.0.1:8443"},
		{url: "http://localhost:18080/", address: "localhost:18080"},
		{url: "socks5://[::1]:1080", address: "[::1]:1080"},
		{url: "trojan://0.0.0.0:443", address: "0.0.0.0:443"},
		{url: "http://127.0.0.1:0", address: "127.0.0.1:0"},
		{url: "vless://127.0.0.1:08443", address: "127.0.0.1:8443"},
		{url: "127.0.0.1:8443", invalid: true},
		{url: "https://localhost:443", invalid: true},
		{url: "socks://localhost:1080", invalid: true},
		{url: "vless://localhost", invalid: true},
		{url: "vless://:8443", invalid: true},
		{url: "vless://::1:8443", invalid: true},
		{url: "http://localhost:", invalid: true},
		{url: "http://localhost:65536", invalid: true},
		{url: "http://localhost:-1", invalid: true},
		{url: "http://localhost:http", invalid: true},
		{url: "http://localhost:8080/path", invalid: true},
		{url: "http://localhost:8080?proxy=1", invalid: true},
		{url: "http://localhost:8080#tag", invalid: true},
		{url: "trojan://password@localhost:443", invalid: true},
	} {
		t.Run(tc.url, func(t *testing.T) {
			var bs inboundBindings
			err := bs.Set(tc.url)
			if (err != nil) != tc.invalid {
				t.Fatalf("error=%v", err)
			}
			if !tc.invalid && (len(bs) != 1 || bs[0].Address != tc.address) {
				t.Fatalf("bindings=%v", bs)
			}
		})
	}
}

func TestBindDuplicatesAndSystemProxySelection(t *testing.T) {
	var bs inboundBindings
	for _, value := range []string{"vless://127.0.0.1:8443", "http://127.0.0.1:18080", "http://127.0.0.1:18081"} {
		if err := bs.Set(value); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"vless://127.0.0.1:08443", "http://127.0.0.1:8443"} {
		if err := bs.Set(value); err == nil {
			t.Fatalf("duplicate address accepted: %s", value)
		}
	}
	if index, err := bs.systemProxyBinding(); err != nil || index != 1 {
		t.Fatalf("first HTTP binding: index=%d err=%v", index, err)
	}
	if _, err := bs[:1].systemProxyBinding(); err == nil {
		t.Fatal("system proxy without HTTP binding accepted")
	}
	bs[1].Address = "0.0.0.0:18080"
	if index, err := bs.systemProxyBinding(); err != nil || index != 1 {
		t.Fatalf("wildcard first HTTP binding: index=%d err=%v", index, err)
	}
}
