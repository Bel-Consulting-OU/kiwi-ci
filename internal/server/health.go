package server

import (
	"context"
	"net/http"
	"time"
)

// liveness reports that the process is up. It never checks dependencies:
// a live control plane that cannot reach its store must still report
// liveness so an orchestrator does not kill it while it retries.
func (s *Server) liveness(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// readiness reports whether the control plane can serve traffic. In dev mode
// the in-memory maps are always ready. In DB mode the store must answer a
// probe (leader or standby with a live pool); otherwise 503.
func (s *Server) readiness(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if _, err := s.DB.SchemaVersion(ctx); err != nil {
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}
