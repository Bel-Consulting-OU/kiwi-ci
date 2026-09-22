package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const drainFlagFile = "drain.flag"

// drainRequest is the POST /api/v1/drain body.
type drainRequest struct {
	Reason string `json:"reason,omitempty"`
}

// drainStatus is the GET /api/v1/drain (and POST /api/v1/drain success)
// response. ActiveJobsKnown distinguishes an authoritative in-flight count
// (true) from the fail-closed reporting value (false); a caller must never
// read ActiveJobs as "drained" while ActiveJobsKnown is false.
type drainStatus struct {
	Draining   bool   `json:"draining"`
	Reason     string `json:"reason,omitempty"`
	ActiveJobs int    `json:"active_jobs"`
	// ActiveJobsKnown is false when the store could not produce the
	// in-flight count. ActiveJobs is then the fail-closed reporting value
	// (never zero) and must not be read as "drained".
	ActiveJobsKnown bool `json:"active_jobs_known"`
}

// isDraining reports the drain state under the drain mutex.
func (s *Server) isDraining() bool {
	s.drainMu.Lock()
	defer s.drainMu.Unlock()
	return s.draining
}

// drainReasonOf returns the recorded drain reason.
func (s *Server) drainReasonOf() string {
	s.drainMu.Lock()
	defer s.drainMu.Unlock()
	return s.drainReason
}

// BeginDrain marks the control plane draining: new leases are refused
// (503 + X-Kiwi-Draining), readiness reports 503, while heartbeats and
// completions keep working so in-flight jobs can finish. The state is
// persisted in dataDir/drain.flag so a restarted process stays draining.
// The app agent calls this from its --drain-on-sigterm handler and then
// polls ActiveJobs() until the in-flight count reaches zero (or the 30s
// budget expires) before exiting.
//
// It is the no-error signal-path entry point required by the drainableServer
// seam in internal/app: a persistence failure is logged prominently by
// beginDrain and the in-memory state stays set (fail closed to draining),
// but the process must NOT describe itself as durably drained — a restart
// could resume taking leases. The HTTP handler uses beginDrain directly to
// answer 503 on that failure.
func (s *Server) BeginDrain(reason string) {
	_ = s.beginDrain(reason)
}

// beginDrain sets the in-memory drain state, persists drain.flag and reports
// the persistence outcome. The in-memory state is set FIRST and cleared by
// nothing here: a drain request must fail closed to draining (refusing new
// leases) even when the flag cannot be written, because resuming service
// after an operator/signal drain would be worse. On error a prominent log
// states that the node is draining in memory only.
//
// The two failure phases leave different on-disk states and both keep the
// drain set: a pre-rename failure means drain.flag was definitely not
// published (a restart resumes leases — hence the fail-closed in-memory
// state and the 503), while a post-rename directory-fsync failure
// (fsutil.Renamed) means the flag IS visible with uncertified durability.
// persistDrainFlagLocked folds the outcome into the shared degraded marker,
// so a published-but-uncertain drain keeps /readiness 503 degraded until a
// retry persists successfully and reconciles.
func (s *Server) beginDrain(reason string) error {
	s.drainMu.Lock()
	s.draining = true
	s.drainReason = reason
	s.drainMu.Unlock()
	err := s.persistDrainFlagLocked()
	meta := map[string]string{"reason": reason}
	if err != nil {
		meta["durable"] = "false"
		s.logError("drain: drain.flag was NOT persisted; the node is draining in memory only and a restart may resume taking leases", "reason", reason, "error", err.Error())
	}
	s.auditLocked("server.drain", "admin", "", "", "control plane draining", meta)
	return err
}

// persistDrainFlagLocked writes the drain state into dataDir/drain.flag and
// reports whether the flag became durable. A no-op (nil) when no data dir is
// configured: there is no file to become durable and a restarted process
// starts clean. Callers must not acknowledge a durable drain when this
// returns an error.
//
// The fsutil.AtomicWriteError phase decides what a restart would see: a
// pre-rename failure leaves the previous flag (here: absent) intact, while a
// post-rename failure leaves the NEW flag visible but uncertified. Every
// outcome is folded into the shared degraded marker (noteFilePersistResult):
// a published-but-uncertain failure arms it and a later successful persist —
// the retry's reconciliation — heals it.
func (s *Server) persistDrainFlagLocked() error {
	if s.dataDir == "" {
		return nil
	}
	s.drainMu.Lock()
	b, err := jsonMarshal(map[string]string{"reason": s.drainReason})
	s.drainMu.Unlock()
	if err != nil {
		return err
	}
	err = fsutil.AtomicWriteFile(joinDataDir(s.dataDir, drainFlagFile), b, 0o600)
	s.noteFilePersistResult(err)
	return err
}

// loadDrainFlag restores a persisted drain state at startup.
func (s *Server) loadDrainFlag(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	b, err := readFileIfExists(dataDir, drainFlagFile)
	if err != nil {
		return err
	}
	if b == nil {
		return nil
	}
	var f struct {
		Reason string `json:"reason,omitempty"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	s.drainMu.Lock()
	s.draining = true
	s.drainReason = f.Reason
	s.drainMu.Unlock()
	return nil
}

// unknownActiveJobs is the fail-closed value reported when the store cannot
// prove the in-flight count. The drain seam in internal/app polls
// ActiveJobs() and only stops at exactly zero, so an UNKNOWN count must
// never render as zero: it keeps the drain waiting (bounded by the explicit
// shutdown timeout) instead of falsely declaring the node drained.
const unknownActiveJobs = 1

// activeJobCount returns the in-flight job count and whether it is known.
// Memory mode is authoritative over the in-memory maps. DB mode asks the
// store for one aggregate running count: an error means UNKNOWN, never zero.
// The previous implementation listed runs (capped at 10000) and silently
// continued past per-run errors, so a transient failure or the ceiling could
// report zero and let a shutdown proceed while jobs were still running.
func (s *Server) activeJobCount() (int, bool) {
	if s.DB != nil {
		ctx, cancel := contextTimeout(5 * time.Second)
		defer cancel()
		n, err := s.DB.CountRunningJobs(ctx)
		if err != nil {
			s.logError("drain: running-job count unavailable; treating drain as not proven", "error", err.Error())
			return 0, false
		}
		return n, true
	}
	return s.activeJobsMemory(), true
}

// ActiveJobs reports the in-flight job count for the drain seam and the
// drain status endpoint. An unknown store count is reported as
// unknownActiveJobs so a drain can never observe zero from a failure.
func (s *Server) ActiveJobs() int {
	n, known := s.activeJobCount()
	if !known {
		return unknownActiveJobs
	}
	return n
}

func (s *Server) activeJobsMemory() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, j := range s.jobs {
		if j.Status == model.StatusRunning {
			n++
		}
	}
	return n
}

// drainServer implements POST /api/v1/drain (admin tier).
func (s *Server) drainServer(w http.ResponseWriter, r *http.Request) {
	var in drainRequest
	if !decode(w, r, &in) {
		return
	}
	reason := in.Reason
	if reason == "" {
		reason = "administrative drain"
	}
	if err := s.beginDrain(reason); err != nil {
		// Fail closed for both phases: the node is draining in memory (no
		// new leases). On a pre-rename failure drain.flag was not published
		// at all, so a restart would resume taking leases; on a post-rename
		// failure the flag is visible but its crash durability is
		// uncertified. Either way the drain is not acknowledged as durable:
		// answer the readiness degraded pattern (the shared marker is armed
		// for the published-uncertain phase by persistDrainFlagLocked). A
		// retry persists and acks.
		w.Header().Set("X-Kiwi-State", "degraded")
		http.Error(w, statePersistenceDegradedBody, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, s.drainStatusSnapshot())
}

// drainStatus implements GET /api/v1/drain (admin tier). The response's
// ActiveJobsKnown reports whether ActiveJobs is the store's authoritative
// in-flight count: false means the count was unavailable and a drain must
// keep waiting (ActiveJobs is then the fail-closed unknownActiveJobs value).
func (s *Server) drainStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.drainStatusSnapshot())
}

// drainStatusSnapshot builds the drain-status body, folding an unavailable
// store count into ActiveJobsKnown=false with ActiveJobs set to the
// fail-closed unknownActiveJobs value so the JSON itself can never read as
// drained.
func (s *Server) drainStatusSnapshot() drainStatus {
	n, known := s.activeJobCount()
	if !known {
		n = unknownActiveJobs
	}
	return drainStatus{
		Draining:        s.isDraining(),
		Reason:          s.drainReasonOf(),
		ActiveJobs:      n,
		ActiveJobsKnown: known,
	}
}

// contextTimeout builds a bounded background context for drain bookkeeping.
func contextTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
