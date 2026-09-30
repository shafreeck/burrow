package server

import (
	"encoding/json"
	"net/http"

	"github.com/shafreeck/burrow/internal/diagnostic"
)

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	s.mu.Lock()
	n := len(s.agents)
	s.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]interface{}{"origin": "ok", "agent_connected": n > 0, "tunnel": "unknown", "egress": "unverified"})
}

// Detailed diagnostics share --debug's explicit opt-in; no credentials or target traffic.
func (s *Server) diagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	peers := make([]map[string]interface{}, 0, len(s.agents))
	for _, a := range s.agents {
		peers = append(peers, map[string]interface{}{"session": a.id, "version": a.build, "connected_utc": a.connected.UTC(), "last_ping_unix_ms": a.lastPing.Load()})
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]interface{}{"version": diagnostic.Version(), "origin": "ok", "agents": peers, "tunnel": "externally_verified_only", "egress": "unverified"})
}
