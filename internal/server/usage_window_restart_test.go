package server

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// TestUsageWindowRebuiltFromFSJobsAfterRestart is B6: the trailing-24h usage
// window (daily cost/energy budget) is rebuilt from the durable completed
// jobs on an fs restart, so exhausting a daily budget survives a restart and
// keeps refusing leases; a job finished more than 24h ago is not counted.
func TestUsageWindowRebuiltFromFSJobsAfterRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	// Any positive cost exhausts the budget, so the assertion is about the
	// window surviving restart, not about a specific amount.
	s.DailyCostLimit = 1e-9
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: smokePipeline,
	}); err != nil {
		t.Fatal(err)
	}
	runnerID, task := registerUsageRunner(t, s)
	time.Sleep(20 * time.Millisecond) // non-zero billable duration
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d, want 204: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	completed := s.jobs[task.Job.ID]
	s.mu.Unlock()
	if !completed.UsageRecorded || completed.Cost <= 0 || completed.FinishedAt == nil {
		t.Fatalf("completion did not record durable usage: %+v", completed)
	}
	if _, exceeded := s.dailyBudgetExceeded(context.Background()); !exceeded {
		t.Fatal("in-process budget not exhausted after the completion")
	}

	// Restart on the same state dir: BEFORE B6 the reconstructed window was
	// empty and the budget reset to zero.
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.DailyCostLimit = 1e-9
	s2.mu.Lock()
	rebuiltJob := s2.jobs[task.Job.ID]
	s2.mu.Unlock()
	s2.usageMu.Lock()
	window := append([]usageEntry(nil), s2.usage...)
	s2.usageMu.Unlock()
	if !rebuiltJob.UsageRecorded || rebuiltJob.Cost <= 0 {
		t.Fatalf("restored job lost its durable usage: %+v", rebuiltJob)
	}
	if len(window) != 1 {
		t.Fatalf("rebuilt usage window = %d entries, want exactly 1: %+v", len(window), window)
	}
	if window[0].Cost != rebuiltJob.Cost || window[0].EnergyWh != rebuiltJob.EnergyWh {
		t.Fatalf("rebuilt usage %+v does not match the durable job cost=%v energy=%v", window[0], rebuiltJob.Cost, rebuiltJob.EnergyWh)
	}
	if !window[0].FinishedAt.Equal(*rebuiltJob.FinishedAt) {
		t.Fatalf("rebuilt usage finished_at = %v, want %v", window[0].FinishedAt, *rebuiltJob.FinishedAt)
	}
	reason, exceeded := s2.dailyBudgetExceeded(context.Background())
	if !exceeded || reason != queueReasonDailyCostExceeded {
		t.Fatalf("restarted budget = %q/%v, want %s/true (fs restart must not reset the daily budget)", reason, exceeded, queueReasonDailyCostExceeded)
	}

	// The quota enforcement path (lease gate) rejects while exhausted.
	nextRunner := registerRollbackRunner(t, s2, 1)
	w := doJSON(t, s2, http.MethodPost, "/api/v1/runners/"+nextRunner+"/next", "token", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("lease while budget exhausted = %d, want 204: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Kiwi-Quota"); got != queueReasonDailyCostExceeded {
		t.Fatalf("lease refusal header = %q, want %s", got, queueReasonDailyCostExceeded)
	}

	// Age the completed job past the trailing window in the durable snapshot
	// and restart again: it must not contribute.
	past := time.Now().UTC().Add(-25 * time.Hour)
	s2.mu.Lock()
	aged := s2.jobs[task.Job.ID]
	aged.FinishedAt = &past
	s2.jobs[task.Job.ID] = aged
	if err := s2.persistLocked(); err != nil {
		s2.mu.Unlock()
		t.Fatal(err)
	}
	s2.mu.Unlock()

	s3, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s3.DailyCostLimit = 1e-9
	s3.usageMu.Lock()
	agedWindow := len(s3.usage)
	s3.usageMu.Unlock()
	if agedWindow != 0 {
		t.Fatalf("usage older than 24h was counted: %d window entries", agedWindow)
	}
	if reason, exceeded := s3.dailyBudgetExceeded(context.Background()); exceeded {
		t.Fatalf("aged-out usage still exhausted the budget: %s", reason)
	}
	nextRunner3 := registerRollbackRunner(t, s3, 1)
	w = doJSON(t, s3, http.MethodPost, "/api/v1/runners/"+nextRunner3+"/next", "token", "")
	if got := w.Header().Get("X-Kiwi-Quota"); got != "" {
		t.Fatalf("lease after the usage aged out = %d/%q, want no quota refusal", w.Code, got)
	}
}
