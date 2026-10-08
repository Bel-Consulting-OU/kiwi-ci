package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestPostgresIntegrationExecutionAttestationCommitOnce proves the durable
// insert-once contract: the first commit creates the row + the
// execution.attested event in one transaction, a replay returns the stored
// row and appends nothing, and the envelope reference is enumerated for CAS
// GC.
func TestPostgresIntegrationExecutionAttestationCommitOnce(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	pgITSeedRunner(t, st, runnerID, 1, 0, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 1}); err != nil {
		t.Fatalf("lease: %v", err)
	}
	receipt := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "h1"}
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, receipt, nil); err != nil {
		t.Fatalf("complete: %v", err)
	}

	rec := model.ExecutionAttestationRecord{
		JobID: jobID, Generation: 1, RunID: runID, Status: string(model.StatusSuccess),
		StatementSHA256: strings.Repeat("a", 64), EnvelopeRef: "cas:" + strings.Repeat("b", 64),
	}
	stored, created, err := st.CommitExecutionAttestation(ctx, rec, ExecutionAttestationEvent(rec))
	if err != nil || !created {
		t.Fatalf("commit = %v/%v, want created", created, err)
	}
	if stored.CreatedAt.IsZero() || stored.StatementSHA256 != rec.StatementSHA256 {
		t.Fatalf("stored = %+v", stored)
	}
	replay := rec
	replay.StatementSHA256 = strings.Repeat("c", 64)
	again, created, err := st.CommitExecutionAttestation(ctx, replay, ExecutionAttestationEvent(replay))
	if err != nil || created {
		t.Fatalf("replay = %v/%v, want stored", created, err)
	}
	if again.StatementSHA256 != rec.StatementSHA256 {
		t.Fatalf("replay rewrote the row: %+v", again)
	}
	got, found, err := st.GetExecutionAttestation(ctx, jobID, 1)
	if err != nil || !found || got.EnvelopeRef != rec.EnvelopeRef {
		t.Fatalf("get = %+v/%v/%v", got, found, err)
	}
	if _, found, err := st.GetExecutionAttestation(ctx, jobID, 2); err != nil || found {
		t.Fatalf("missing generation = %v/%v, want absent", found, err)
	}
	var rows int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM execution_attestations WHERE job_id=$1`, jobID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("execution_attestations rows = %d, want 1", rows)
	}
	refs, err := st.ListAllExecutionAttestationEnvelopeRefs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	foundRef := false
	for _, ref := range refs {
		if ref == rec.EnvelopeRef {
			foundRef = true
		}
	}
	if !foundRef {
		t.Fatalf("attestation ref %q missing from %v", rec.EnvelopeRef, refs)
	}
	// The event exists exactly once.
	events, _, err := st.ListExecutionEvents(ctx, 0, MaxExecutionEventLimit, runID)
	if err != nil {
		t.Fatal(err)
	}
	attested := 0
	for _, e := range events {
		if e.Type == model.EventExecutionAttested {
			attested++
			if e.Attempt != 1 || e.JobID != jobID || e.Payload["attempt"] != jobID+":1" {
				t.Fatalf("attested event = %+v", e)
			}
		}
	}
	if attested != 1 {
		t.Fatalf("execution.attested events = %d, want 1", attested)
	}
}

// TestPostgresIntegrationRequiredProvenanceGate proves the SQL completion
// gate: with Provenance=required, an artifact row without provenance cannot
// satisfy completion even though the artifact exists, while an artifact with
// durable provenance can.
func TestPostgresIntegrationRequiredProvenanceGate(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	complete := func(t *testing.T, runID, jobID, runnerID string, withProvenance bool) error {
		t.Helper()
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 1}); err != nil {
			t.Fatalf("lease: %v", err)
		}
		if err := st.InsertJobContracts(ctx, jobID, map[string]ArtifactContract{
			"bin": {Name: "bin", Required: true, Provenance: ArtifactProvenanceRequired},
		}); err != nil {
			t.Fatalf("contracts: %v", err)
		}
		art := model.ArtifactRecord{
			ID: pgITNewID(t), RunID: runID, JobID: jobID, Name: "bin",
			SHA256: strings.Repeat("1", 64), Size: 1, LeaseGeneration: 1, CreatedAt: time.Now().UTC(),
		}
		if withProvenance {
			art.ProvenanceSHA256 = strings.Repeat("2", 64)
		}
		if _, _, err := st.InsertArtifactOnceForLease(ctx, jobID, runnerID, 1, art); err != nil {
			t.Fatalf("artifact insert: %v", err)
		}
		receipt := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "h1"}
		return st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, receipt, nil)
	}

	t.Run("artifact without provenance blocks completion", func(t *testing.T) {
		err := complete(t, pgITNewID(t), pgITNewID(t), pgITNewID(t), false)
		if !errors.Is(err, ErrRequiredArtifactMissing) {
			t.Fatalf("completion = %v, want ErrRequiredArtifactMissing", err)
		}
	})
	t.Run("artifact with provenance completes", func(t *testing.T) {
		if err := complete(t, pgITNewID(t), pgITNewID(t), pgITNewID(t), true); err != nil {
			t.Fatalf("completion = %v", err)
		}
	})
}

// TestPostgresIntegrationLogEntryLeaseGeneration proves migration 0051: the
// lease generation round-trips through AppendLog/AppendLogBatch/ReadLogs and
// legacy rows (inserted without the column) read back as 0.
func TestPostgresIntegrationLogEntryLeaseGeneration(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)

	e := model.LogEntry{RunID: runID, JobID: pgITNewID(t), Step: "run", Line: "single", LeaseGeneration: 7, CreatedAt: time.Now().UTC()}
	if err := st.AppendLog(ctx, e); err != nil {
		t.Fatalf("append: %v", err)
	}
	entries, err := st.ReadLogs(ctx, runID, -1, 100)
	if err != nil || len(entries) != 1 {
		t.Fatalf("read = %+v err=%v", entries, err)
	}
	if entries[0].LeaseGeneration != 7 {
		t.Fatalf("single log generation = %d, want 7", entries[0].LeaseGeneration)
	}

	batchRun := pgITNewID(t)
	batch := []model.LogEntry{
		{RunID: batchRun, Line: "batch-1", LeaseGeneration: 5, CreatedAt: time.Now().UTC()},
		{RunID: batchRun, Line: "batch-2", LeaseGeneration: 5, CreatedAt: time.Now().UTC()},
	}
	ident := LogBatchIdentity{JobID: pgITNewID(t), Generation: 5, BatchID: "b-" + batchRun}
	if ok, err := st.AppendLogBatch(ctx, batch, ident); err != nil || !ok {
		t.Fatalf("append batch = %v/%v", ok, err)
	}
	entries, err = st.ReadLogs(ctx, batchRun, -1, 100)
	if err != nil || len(entries) != 2 {
		t.Fatalf("batch read = %+v err=%v", entries, err)
	}
	for i, got := range entries {
		if got.LeaseGeneration != 5 {
			t.Fatalf("batch log %d generation = %d, want 5", i, got.LeaseGeneration)
		}
	}

	// Legacy row: written without the column so the DEFAULT 0 applies.
	legacyRun := pgITNewID(t)
	if _, err := st.pool.Exec(ctx, `INSERT INTO log_entries (run_id, line, created_at) VALUES ($1, $2, $3)`, legacyRun, "legacy", time.Now().UTC()); err != nil {
		t.Fatalf("legacy insert: %v", err)
	}
	entries, err = st.ReadLogs(ctx, legacyRun, -1, 100)
	if err != nil || len(entries) != 1 {
		t.Fatalf("legacy read = %+v err=%v", entries, err)
	}
	if entries[0].LeaseGeneration != 0 {
		t.Fatalf("legacy log generation = %d, want 0", entries[0].LeaseGeneration)
	}
}
