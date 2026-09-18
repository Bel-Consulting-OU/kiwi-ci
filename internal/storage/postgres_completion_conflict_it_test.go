package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestPostgresIntegrationCompleteJobReceiptHashConflict proves the S-A fix
// against real PostgreSQL: a replay is idempotent only when the stored
// result_hash equals the incoming hash; a concurrent completion with a
// different result fails closed with ErrCompletionConflict and leaves the
// original job/receipt untouched.
func TestPostgresIntegrationCompleteJobReceiptHashConflict(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	runnerID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	pgITSeedRunner(t, st, runnerID, 2, 0, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("lease: %v", err)
	}

	receipt := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "hash-success"}
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", map[string]string{"o": "1"}, receipt); err != nil {
		t.Fatalf("completion: %v", err)
	}
	// The exact replay is still an idempotent success.
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", map[string]string{"o": "1"}, receipt); err != nil {
		t.Fatalf("identical replay = %v, want nil", err)
	}

	// A different result for the same lease fails closed.
	conflict := receipt
	conflict.ResultHash = "hash-failure"
	err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusFailure, "boom", nil, conflict)
	if !errors.Is(err, ErrCompletionConflict) {
		t.Fatalf("conflicting completion = %v, want ErrCompletionConflict", err)
	}
	gotReceipt, ok, err := st.HasCompletionReceipt(ctx, jobID, 1, runnerID)
	if err != nil || !ok || gotReceipt.ResultHash != "hash-success" {
		t.Fatalf("receipt after conflict = %+v ok=%v err=%v", gotReceipt, ok, err)
	}
	job, err := st.GetJob(ctx, jobID)
	if err != nil || job.Status != model.StatusSuccess || job.Error != "" || job.Outputs["o"] != "1" {
		t.Fatalf("job after conflict = %+v err=%v", job, err)
	}
	// The conflicting loser must not have inserted its own outbox effects.
	var effects int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE kind=$1`, OutboxKindCompletionReconcile).Scan(&effects); err != nil {
		t.Fatalf("count effects: %v", err)
	}
	if effects != 1 {
		t.Fatalf("completion reconcile intents = %d, want 1", effects)
	}
}

// TestPostgresIntegrationCompleteJobInsertConflictHash pins the
// ON CONFLICT DO NOTHING branch: with a receipt already present while the job
// still looks running, the insert conflict must validate the stored hash
// instead of treating existence as a replay.
func TestPostgresIntegrationCompleteJobInsertConflictHash(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	runnerID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	pgITSeedRunner(t, st, runnerID, 2, 0, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("lease: %v", err)
	}
	// A receipt planted outside CompleteJob (same shape as a peer's durable
	// completion acknowledged via InsertCompletionReceipt).
	if err := st.InsertCompletionReceipt(ctx, model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "planted"}); err != nil {
		t.Fatalf("plant receipt: %v", err)
	}

	// Same hash: the insert conflict is an idempotent success (the partial
	// transaction is discarded, and the planted receipt is authoritative).
	same := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "planted"}
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, same); err != nil {
		t.Fatalf("same-hash insert conflict = %v, want nil", err)
	}
	got, ok, err := st.HasCompletionReceipt(ctx, jobID, 1, runnerID)
	if err != nil || !ok || got.ResultHash != "planted" {
		t.Fatalf("receipt after same-hash conflict = %+v ok=%v err=%v", got, ok, err)
	}

	// Different hash: fail closed and roll the whole completion back.
	different := same
	different.ResultHash = "other"
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusFailure, "boom", nil, different); !errors.Is(err, ErrCompletionConflict) {
		t.Fatalf("different-hash insert conflict = %v, want ErrCompletionConflict", err)
	}
	job, err := st.GetJob(ctx, jobID)
	if err != nil || job.Status != model.StatusRunning {
		t.Fatalf("job after conflicting insert = %+v err=%v, want still running", job, err)
	}
	got, ok, err = st.HasCompletionReceipt(ctx, jobID, 1, runnerID)
	if err != nil || !ok || got.ResultHash != "planted" {
		t.Fatalf("receipt after different-hash conflict = %+v ok=%v err=%v", got, ok, err)
	}
}
