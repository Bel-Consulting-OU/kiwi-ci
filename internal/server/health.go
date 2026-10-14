package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/version"
)

// statePersistenceDegradedBody is the fixed /readiness body for a control
// plane whose snapshot write failed. /readiness is unauthenticated, so the
// raw persist error must NOT be echoed here: it would leak filesystem paths
// and store internals. The diagnostic stays in the structured logs emitted
// by persistCheckedErrLocked for the failing mutation.
const statePersistenceDegradedBody = "state persistence degraded"

// run-key identity index readiness bodies. Also fixed and internal-detail
// free: the probe is unauthenticated, so it must not leak SQL object names
// or duplicate row counts beyond the operator log line.
const (
	runKeyIndexMissingBody = "database is missing the run key identity index"
	runKeyIndexUnknownBody = "database run key identity index not verifiable"
)

// versionInfo reports build identity and the compatibility contract as one
// unauthenticated document. It never touches the store: the compatibility
// surface is generated from version.ContractVersions at compile time, so a
// control plane whose database is down still answers this probe. The body is
// the version.Full() map plus the RenderCompatibilityJSON object under
// "compatibility", so an operator or a peer can discover what this binary
// produces and consumes without reading the repository docs.
func (s *Server) versionInfo(w http.ResponseWriter, _ *http.Request) {
	full := version.Full()
	var compat map[string]any
	if err := json.Unmarshal(version.RenderCompatibilityJSON(), &compat); err != nil {
		// RenderCompatibilityJSON is a compile-time document: a parse
		// failure is a build defect, not an operational condition. Fail
		// closed with 500 rather than emit a partial identity.
		http.Error(w, "version document unavailable", http.StatusInternalServerError)
		return
	}
	body := make(map[string]any, len(full)+1)
	for k, v := range full {
		body[k] = v
	}
	body["compatibility"] = compat
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		return
	}
}

// liveness reports that the process is up. It never checks dependencies:
// a live control plane that cannot reach its store must still report
// liveness so an orchestrator does not kill it while it retries.
func (s *Server) liveness(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// readiness reports whether the control plane can serve traffic. In dev mode
// the in-memory maps are always ready. In DB mode the store must answer a
// probe (leader or standby with a live pool); otherwise 503. A draining
// control plane is deliberately not ready: new leases are refused, so a load
// balancer must route traffic away while in-flight jobs finish. A control
// plane whose filesystem snapshot write failed, or whose security-state file
// in ANY directory was published without certified crash durability, is
// likewise not ready: an acknowledged mutation may not be durable, and the
// signal is exposed as X-Kiwi-State: degraded until a later persist succeeds.
// The uncertain directories themselves are named in the structured log
// (noteFilePersistResult), never in this unauthenticated body.
// readinessLease reports whether THIS replica can serve runner lease
// mutations (POST /api/v1/runners/{id}/next). Standbys answer 503 so a load
// balancer can pin lease traffic to the scheduler leader while still using
// /readiness for every other route. The body is a fixed string: the probe is
// unauthenticated.
func (s *Server) readinessLease(w http.ResponseWriter, r *http.Request) {
	if s.isDraining() {
		w.Header().Set("X-Kiwi-Draining", "true")
		http.Error(w, "control plane draining", http.StatusServiceUnavailable)
		return
	}
	if s.persistenceDegraded() {
		w.Header().Set("X-Kiwi-State", "degraded")
		http.Error(w, statePersistenceDegradedBody, http.StatusServiceUnavailable)
		return
	}
	if s.DB == nil {
		// Dev in-memory store: the single process is always the scheduler.
		w.WriteHeader(http.StatusOK)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if s.Sched == nil || !s.Sched.IsLeader(ctx) {
		http.Error(w, "scheduler standby", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) readiness(w http.ResponseWriter, r *http.Request) {
	if s.isDraining() {
		w.Header().Set("X-Kiwi-Draining", "true")
		http.Error(w, "control plane draining", http.StatusServiceUnavailable)
		return
	}
	if s.persistenceDegraded() {
		w.Header().Set("X-Kiwi-State", "degraded")
		// Fixed body: the underlying persist error and the uncertain
		// directories are in the logs, not on an unauthenticated probe (X1A).
		http.Error(w, statePersistenceDegradedBody, http.StatusServiceUnavailable)
		return
	}
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
	if err := s.checkSchemaCompatibility(ctx); err != nil {
		w.Header().Set("X-Kiwi-State", "schema-incompatible")
		// A floor READ failure is intentionally indistinguishable from an
		// incompatible floor here: both mean "compatibility unproven" and
		// readiness must not report 200.
		http.Error(w, "database schema requires a newer binary", http.StatusServiceUnavailable)
		return
	}
	// Migration 0048 creates jobs_run_key_idx CONDITIONALLY: a database that
	// held duplicate (run_id, key) rows at 0048 time never got the index, and
	// migration 0053 re-runs the creation so an operator repair (cancel or
	// remove the duplicates, re-migrate) installs it. Until then readiness
	// reports not-ready and kiwi_run_key_index_present stays 0, so the index
	// cannot silently stay missing. A probe error also fails readiness:
	// presence is unproven, never assumed.
	if rk, ok := s.DB.(storage.RunKeyIndexStore); ok {
		present, err := rk.RunKeyIndexPresent(ctx)
		if err != nil {
			w.Header().Set("X-Kiwi-State", "run-key-index-unproven")
			http.Error(w, runKeyIndexUnknownBody, http.StatusServiceUnavailable)
			return
		}
		if !present {
			s.metricSet("kiwi_run_key_index_present", 0, nil)
			w.Header().Set("X-Kiwi-State", "run-key-index-missing")
			http.Error(w, runKeyIndexMissingBody, http.StatusServiceUnavailable)
			return
		}
		s.metricSet("kiwi_run_key_index_present", 1, nil)
	}
	w.WriteHeader(http.StatusOK)
}
