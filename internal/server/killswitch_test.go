package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// seedDBRunningJob plants a running job leased by runnerID into the fake
// store with a retry budget.
func seedDBRunningJob(t *testing.T, s *Server, f *dbFakeStore, jobID, runID, runnerID string, attempts int, maxRetries int) {
	t.Helper()
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	f.mu.Lock()
	f.runs[runID] = model.Run{ID: runID, Repo: "https://github.com/o/r.git", RepoFullName: "o/r", Status: model.StatusRunning}
	f.jobs[jobID] = model.Job{ID: jobID, RunID: runID, Key: "build", RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Status: model.StatusRunning, Attempts: attempts, MaxInfraRetries: maxRetries,
		LeaseRunnerID: runnerID, LeaseTokenHash: []byte{1, 2, 3}, LeaseGeneration: 2, LeaseExpiresAt: &exp}
	f.runners[runnerID] = model.Runner{ID: runnerID, Name: runnerID, Capacity: 1, ActiveJobs: []string{jobID}, Busy: true}
	f.mu.Unlock()
}

func TestDBRunnerDisableRequeuesRunningJobs(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	seedDBRunningJob(t, s, f, "job-1", "run-1", "runner-1", 1, 2)

	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-1/disable", "admin-tok", "{}")
	if w.Code != http.StatusOK {
		t.Fatalf("disable = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	j := f.jobs["job-1"]
	audit := append([]model.AuditEvent(nil), f.audit...)
	f.mu.Unlock()
	// Retry budget still available: requeued with attempts++ and the lease
	// cleared.
	if j.Status != model.StatusQueued {
		t.Fatalf("job status = %q, want queued (retry budget available)", j.Status)
	}
	if j.Attempts != 2 {
		t.Fatalf("attempts = %d, want 2", j.Attempts)
	}
	if j.LeaseRunnerID != "" || j.LeaseTokenHash != nil || j.LeaseExpiresAt != nil {
		t.Fatalf("lease not invalidated: %+v", j)
	}
	// The disable audit line plus a per-job kill-switch audit line exist.
	sawDisable, sawJob := false, false
	for _, e := range audit {
		switch e.Action {
		case "runner.disable":
			sawDisable = true
		case "job.runner_disabled_requeued":
			sawJob = true
		}
	}
	if !sawDisable || !sawJob {
		t.Fatalf("audit missing: disable=%v job=%v (%+v)", sawDisable, sawJob, audit)
	}
	// The runner row stays disabled.
	f.mu.Lock()
	ri := f.runners["runner-1"]
	f.mu.Unlock()
	if !ri.Disabled {
		t.Fatal("runner not marked disabled")
	}
}

func TestDBRunnerDisableCancelsWhenBudgetExhausted(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	seedDBRunningJob(t, s, f, "job-1", "run-1", "runner-1", 3, 2)
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-1/disable", "admin-tok", "{}"); w.Code != http.StatusOK {
		t.Fatalf("disable = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	j := f.jobs["job-1"]
	f.mu.Unlock()
	if j.Status != model.StatusCancelled {
		t.Fatalf("job status = %q, want cancelled (retry budget exhausted)", j.Status)
	}
	if j.Attempts != 4 {
		t.Fatalf("attempts = %d, want 4", j.Attempts)
	}
	if j.LeaseRunnerID != "" || j.LeaseTokenHash != nil || j.LeaseExpiresAt != nil {
		t.Fatalf("lease not invalidated: %+v", j)
	}
	if j.FinishedAt == nil {
		t.Fatal("cancelled job missing finished_at")
	}
}

func TestRunnerDisableRequiresRunnerManageRole(t *testing.T) {
	s := storeServer(t, "admin-tok", map[string]auth.Principal{
		"read-tok":   {Subject: "reader", Roles: []auth.Role{auth.RoleRead}},
		"manage-tok": {Subject: "ops", Roles: []auth.Role{auth.RoleRunnerManage}},
	})
	// A read-only principal may not disable a runner.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r1/disable", "read-tok", "{}"); w.Code != http.StatusForbidden {
		t.Fatalf("read principal disable: want 403 got %d", w.Code)
	}
	// A runner-manage principal may.
	s.mu.Lock()
	s.runners["r1"] = model.Runner{ID: "r1", Name: "r1", Capacity: 1}
	s.mu.Unlock()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r1/disable", "manage-tok", "{}"); w.Code != http.StatusOK {
		t.Fatalf("manage principal disable: want 200 got %d: %s", w.Code, w.Body.String())
	}
}

func TestMemoryRunnerDisableStillCancels(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	exp := time.Now().UTC().Add(time.Hour)
	s.runs["run-1"] = model.Run{ID: "run-1", Repo: "https://github.com/o/r.git", RepoFullName: "o/r", Status: model.StatusRunning}
	s.jobs["job-1"] = model.Job{ID: "job-1", RunID: "run-1", Key: "build", Status: model.StatusRunning, LeaseRunnerID: "runner-1", LeaseTokenHash: []byte{1}, LeaseGeneration: 1, LeaseExpiresAt: &exp}
	s.runners["runner-1"] = model.Runner{ID: "runner-1", Name: "runner-1", Capacity: 1, ActiveJobs: []string{"job-1"}}
	s.mu.Unlock()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner-1/disable", "admin-tok", "{}"); w.Code != http.StatusOK {
		t.Fatalf("disable = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	j := s.jobs["job-1"]
	s.mu.Unlock()
	if j.Status != model.StatusCancelled || j.LeaseRunnerID != "" || j.LeaseTokenHash != nil {
		t.Fatalf("memory-mode disable did not cancel job: %+v", j)
	}
}
