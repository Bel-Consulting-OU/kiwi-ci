package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// wave1RunningJob seeds one running, leased job into the mem store.
func wave1RunningJob(m *memStore, jobID, runID, runnerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobs[jobID] = model.Job{
		ID:              jobID,
		RunID:           runID,
		Key:             "build",
		Status:          model.StatusRunning,
		LeaseRunnerID:   runnerID,
		LeaseGeneration: 1,
	}
}

// TestMemCompleteJobReceiptConflict mirrors the SQL receipt equality fix: an
// identical replay is idempotent, a different result for the same lease fails
// closed with ErrCompletionConflict, and the stored receipt/job are unchanged.
func TestMemCompleteJobReceiptConflict(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	const (
		jobID    = "job-1"
		runID    = "run-1"
		runnerID = "runner-1"
	)
	wave1RunningJob(m, jobID, runID, runnerID)
	receipt := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "hash-success"}
	if err := m.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", map[string]string{"o": "1"}, receipt); err != nil {
		t.Fatalf("completion: %v", err)
	}
	// Exact replay (same result hash) is an idempotent success.
	if err := m.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", map[string]string{"o": "1"}, receipt); err != nil {
		t.Fatalf("identical replay = %v, want nil", err)
	}
	// A conflicting result for the same identity fails closed.
	conflict := receipt
	conflict.ResultHash = "hash-failure"
	err := m.CompleteJob(ctx, jobID, 1, runnerID, model.StatusFailure, "boom", nil, conflict)
	if !errors.Is(err, ErrCompletionConflict) {
		t.Fatalf("conflicting completion = %v, want ErrCompletionConflict", err)
	}
	m.mu.Lock()
	j := m.jobs[jobID]
	stored := m.receipts[m.receiptKey(jobID, 1, runnerID)]
	m.mu.Unlock()
	if j.Status != model.StatusSuccess || j.Error != "" || j.Outputs["o"] != "1" {
		t.Fatalf("conflict mutated the job: %+v", j)
	}
	if stored.ResultHash != "hash-success" {
		t.Fatalf("conflict overwrote the receipt: %+v", stored)
	}
}

// TestFaultyStoreCompletionConflictPassThrough proves the wrapper returns the
// inner ErrCompletionConflict untouched while still honoring injected faults.
func TestFaultyStoreCompletionConflictPassThrough(t *testing.T) {
	inner := newMemStore()
	wave1RunningJob(inner, "job-1", "run-1", "runner-1")
	f := &FaultyStore{Inner: inner}
	ctx := context.Background()
	receipt := model.CompletionReceipt{JobID: "job-1", Generation: 1, RunnerID: "runner-1", ResultHash: "a"}
	if err := f.CompleteJob(ctx, "job-1", 1, "runner-1", model.StatusSuccess, "", nil, receipt); err != nil {
		t.Fatalf("completion: %v", err)
	}
	conflict := receipt
	conflict.ResultHash = "b"
	if err := f.CompleteJob(ctx, "job-1", 1, "runner-1", model.StatusFailure, "boom", nil, conflict); !errors.Is(err, ErrCompletionConflict) {
		t.Fatalf("wrapper result = %v, want ErrCompletionConflict", err)
	}
	// A fault injected on the NEXT mutating call replaces the inner result.
	injected := errors.New("injected completion failure")
	f.FailAfter = f.Mutations() + 1
	f.Err = injected
	if err := f.CompleteJob(ctx, "job-1", 1, "runner-1", model.StatusFailure, "boom", nil, conflict); !errors.Is(err, injected) {
		t.Fatalf("injected fault = %v, want %v", err, injected)
	}
}
