package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITCompletionLease seeds a run/job/runner and acquires lease generation 1.
func pgITCompletionLease(t *testing.T, st *PostgresStore) (jobID, runnerID string) {
	t.Helper()
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID = pgITNewID(t)
	runnerID = pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	pgITSeedRunner(t, st, runnerID, 2, 0, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("lease: %v", err)
	}
	return jobID, runnerID
}

// TestPostgresIntegrationCompletionReceiptV2RuntimeEvidence proves against
// real PostgreSQL that the v2 receipt binds the observed runtime evidence: a
// replay with changed runtime, outputs, status or error conflicts, the
// identical replay is accepted, and the first receipt is written exactly
// once.
func TestPostgresIntegrationCompletionReceiptV2RuntimeEvidence(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	jobID, runnerID := pgITCompletionLease(t, st)

	outputs := map[string]string{"digest": "abc"}
	runtimeA := &model.ObservedRuntime{OS: "linux", Arch: "amd64", MainImage: "alpine:3.20"}
	receipt := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: CompletionResultDigestV2(model.StatusSuccess, "", outputs, runtimeA), ResultHashVersion: CompletionResultHashVersionV2}
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", outputs, receipt, runtimeA); err != nil {
		t.Fatalf("first completion: %v", err)
	}
	// Identical replay with the same runtime evidence is idempotent.
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", outputs, receipt, runtimeA); err != nil {
		t.Fatalf("identical replay = %v, want nil", err)
	}
	// Changed runtime evidence for the same identity conflicts.
	runtimeB := &model.ObservedRuntime{OS: "linux", Arch: "arm64"}
	changedRuntime := receipt
	changedRuntime.ResultHash = CompletionResultDigestV2(model.StatusSuccess, "", outputs, runtimeB)
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", outputs, changedRuntime, runtimeB); !errors.Is(err, ErrCompletionConflict) {
		t.Fatalf("changed-runtime replay = %v, want ErrCompletionConflict", err)
	}
	// Changed outputs/status/error conflict under the v2 digest.
	changedOutputs := receipt
	changedOutputs.ResultHash = CompletionResultDigestV2(model.StatusSuccess, "", map[string]string{"digest": "def"}, runtimeA)
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", map[string]string{"digest": "def"}, changedOutputs, runtimeA); !errors.Is(err, ErrCompletionConflict) {
		t.Fatalf("changed-outputs replay = %v, want ErrCompletionConflict", err)
	}
	changedStatus := receipt
	changedStatus.ResultHash = CompletionResultDigestV2(model.StatusFailure, "", outputs, runtimeA)
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusFailure, "", outputs, changedStatus, runtimeA); !errors.Is(err, ErrCompletionConflict) {
		t.Fatalf("changed-status replay = %v, want ErrCompletionConflict", err)
	}
	changedError := receipt
	changedError.ResultHash = CompletionResultDigestV2(model.StatusFailure, "boom", outputs, runtimeA)
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusFailure, "boom", outputs, changedError, runtimeA); !errors.Is(err, ErrCompletionConflict) {
		t.Fatalf("changed-error replay = %v, want ErrCompletionConflict", err)
	}
	// The stored receipt is the first v2 identity, written exactly once.
	got, ok, err := st.HasCompletionReceipt(ctx, jobID, 1, runnerID)
	if err != nil || !ok {
		t.Fatalf("receipt = %+v ok=%v err=%v", got, ok, err)
	}
	if got.ResultHash != receipt.ResultHash || got.ResultHashVersion != CompletionResultHashVersionV2 {
		t.Fatalf("stored receipt = %+v, want the first v2 identity", got)
	}
	var rows int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM completion_receipts WHERE job_id=$1 AND generation=1 AND runner_id=$2`, jobID, runnerID).Scan(&rows); err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	if rows != 1 {
		t.Fatalf("receipt rows = %d, want exactly 1", rows)
	}
	// The job keeps the first completion's runtime evidence.
	job, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if job.Status != model.StatusSuccess || job.ObservedRuntime == nil || job.ObservedRuntime.Arch != runtimeA.Arch {
		t.Fatalf("job after conflicts = %+v", job)
	}
}

// TestPostgresIntegrationCompletionLegacyV1ReceiptRuntimeGate proves the
// legacy compatibility rule against real PostgreSQL: a v1-identical retry
// without runtime evidence replays, a v2-evidence-bearing retry on a legacy
// receipt with no stored evidence conflicts, and an equal stored capture
// replays.
func TestPostgresIntegrationCompletionLegacyV1ReceiptRuntimeGate(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	jobID, runnerID := pgITCompletionLease(t, st)

	outputs := map[string]string{"o": "1"}
	legacy := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: CompletionResultDigestV1(model.StatusSuccess, "", outputs), ResultHashVersion: CompletionResultHashVersionLegacy}
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", outputs, legacy, nil); err != nil {
		t.Fatalf("legacy completion: %v", err)
	}
	// v1-labelled retry replays.
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", outputs, legacy, nil); err != nil {
		t.Fatalf("legacy-identical replay = %v, want nil", err)
	}
	// A v2 retry without runtime evidence still resolves the legacy identity.
	v2NoRuntime := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: CompletionResultDigestV2(model.StatusSuccess, "", outputs, nil)}
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", outputs, v2NoRuntime, nil); err != nil {
		t.Fatalf("v2 replay without evidence = %v, want nil", err)
	}
	// A v2-evidence-bearing retry conflicts: the legacy receipt never bound
	// the runtime and the stored job has none.
	runtimeA := &model.ObservedRuntime{OS: "linux", Arch: "amd64"}
	v2WithRuntime := v2NoRuntime
	v2WithRuntime.ResultHash = CompletionResultDigestV2(model.StatusSuccess, "", outputs, runtimeA)
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", outputs, v2WithRuntime, runtimeA); !errors.Is(err, ErrCompletionConflict) {
		t.Fatalf("evidence-bearing retry against legacy receipt = %v, want ErrCompletionConflict", err)
	}
	got, ok, err := st.HasCompletionReceipt(ctx, jobID, 1, runnerID)
	if err != nil || !ok || got.ResultHashVersion != CompletionResultHashVersionLegacy || got.ResultHash != legacy.ResultHash {
		t.Fatalf("legacy receipt rewritten: %+v ok=%v err=%v", got, ok, err)
	}

	// A legacy completion that persisted runtime evidence accepts a v2 retry
	// with the SAME evidence and rejects a different capture.
	job2, runner2 := pgITCompletionLease(t, st)
	legacy2 := model.CompletionReceipt{JobID: job2, Generation: 1, RunnerID: runner2, ResultHash: CompletionResultDigestV1(model.StatusSuccess, "", outputs), ResultHashVersion: CompletionResultHashVersionLegacy}
	if err := st.CompleteJob(ctx, job2, 1, runner2, model.StatusSuccess, "", outputs, legacy2, runtimeA); err != nil {
		t.Fatalf("legacy completion with evidence: %v", err)
	}
	// The job row carries the captured runtime evidence (the DB claim does
	// not rewrite the payload, so this also pins the column-vs-payload
	// generation handling in the legacy comparison).
	jobAfterLegacy, err := st.GetJob(ctx, job2)
	if err != nil {
		t.Fatalf("GetJob after legacy: %v", err)
	}
	if jobAfterLegacy.Status != model.StatusSuccess || jobAfterLegacy.LeaseGeneration != 1 || jobAfterLegacy.ObservedRuntime == nil {
		t.Fatalf("job after legacy completion = %+v, want terminal generation 1 with observed runtime", jobAfterLegacy)
	}
	v2Equal := legacy2
	v2Equal.ResultHashVersion = 0
	v2Equal.ResultHash = CompletionResultDigestV2(model.StatusSuccess, "", outputs, runtimeA)
	if err := st.CompleteJob(ctx, job2, 1, runner2, model.StatusSuccess, "", outputs, v2Equal, runtimeA); err != nil {
		t.Fatalf("v2 retry with equal stored evidence = %v, want nil", err)
	}
	runtimeB := &model.ObservedRuntime{OS: "linux", Arch: "arm64"}
	v2Different := v2Equal
	v2Different.ResultHash = CompletionResultDigestV2(model.StatusSuccess, "", outputs, runtimeB)
	if err := st.CompleteJob(ctx, job2, 1, runner2, model.StatusSuccess, "", outputs, v2Different, runtimeB); !errors.Is(err, ErrCompletionConflict) {
		t.Fatalf("v2 retry with different stored evidence = %v, want ErrCompletionConflict", err)
	}
}

// TestPostgresIntegrationCompletionReceiptVersionDefault pins the migration
// semantics for rows written through InsertCompletionReceipt without an
// explicit version: they keep the legacy v1 label.
func TestPostgresIntegrationCompletionReceiptVersionDefault(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	jobID, runnerID := pgITCompletionLease(t, st)
	if err := st.InsertCompletionReceipt(ctx, model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "planted"}); err != nil {
		t.Fatalf("plant receipt: %v", err)
	}
	got, ok, err := st.HasCompletionReceipt(ctx, jobID, 1, runnerID)
	if err != nil || !ok || got.ResultHashVersion != CompletionResultHashVersionLegacy {
		t.Fatalf("planted receipt = %+v ok=%v err=%v, want legacy version 1", got, ok, err)
	}
}
