package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const drainFlagFile = "drain.flag"

// drainRequest is the POST /api/v1/drain body.
type drainRequest struct {
	Reason string `json:"reason,omitempty"`
}

// drainStatus is the GET /api/v1/drain response.
type drainStatus struct {
	Draining   bool   `json:"draining"`
	Reason     string `json:"reason,omitempty"`
	ActiveJobs int    `json:"active_jobs"`
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
func (s *Server) BeginDrain(reason string) {
	s.drainMu.Lock()
	s.draining = true
	s.drainReason = reason
	s.drainMu.Unlock()
	s.persistDrainFlagLocked()
	s.auditLocked("server.drain", "admin", "", "", "control plane draining", map[string]string{"reason": reason})
}

// persistDrainFlagLocked writes the drain state into dataDir/drain.flag.
func (s *Server) persistDrainFlagLocked() {
	if s.dataDir == "" {
		return
	}
	s.drainMu.Lock()
	b, err := jsonMarshal(map[string]string{"reason": s.drainReason})
	s.drainMu.Unlock()
	if err != nil {
		return
	}
	_ = writeFileAtomic(joinDataDir(s.dataDir, drainFlagFile), b, 0o600)
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

// ActiveJobs counts jobs currently holding a running lease (the in-flight
// work a drain must wait for). Memory mode reads the in-memory maps; DB
// mode counts running jobs across non-terminal runs through the store.
func (s *Server) ActiveJobs() int {
	if s.DB != nil {
		ctx, cancel := contextTimeout(5 * time.Second)
		defer cancel()
		runs, err := s.DB.ListRuns(ctx, 10000)
		if err != nil {
			return s.activeJobsMemory()
		}
		total := 0
		for _, run := range runs {
			if run.Status.Terminal() {
				continue
			}
			jobs, err := s.DB.ListJobsByRun(ctx, run.ID)
			if err != nil {
				continue
			}
			for _, j := range jobs {
				if j.Status == model.StatusRunning {
					total++
				}
			}
		}
		return total
	}
	return s.activeJobsMemory()
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
	s.BeginDrain(reason)
	writeJSON(w, http.StatusOK, s.drainStatusSnapshot())
}

// drainStatus implements GET /api/v1/drain (admin tier).
func (s *Server) drainStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.drainStatusSnapshot())
}

func (s *Server) drainStatusSnapshot() drainStatus {
	return drainStatus{
		Draining:   s.isDraining(),
		Reason:     s.drainReasonOf(),
		ActiveJobs: s.ActiveJobs(),
	}
}

// contextTimeout builds a bounded background context for drain bookkeeping.
func contextTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
