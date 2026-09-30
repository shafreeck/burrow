package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthLayers(t *testing.T) {
	s := New(Config{})
	for _, tc := range []struct {
		path     string
		status   int
		contains string
	}{{"/healthz", 200, `"egress":"unverified"`}, {"/diagnostics", 404, "404"}, {"/missing", 404, "404"}} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", tc.path, nil))
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.contains) {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body.String())
		}
	}
	s.cfg.Debug = true
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/diagnostics", nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), "token") {
		t.Fatal(w.Body.String())
	}
}
