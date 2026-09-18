package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestPostgresIntegrationAppendLogBatchPayloadIdentity proves the S-B fix
// against real PostgreSQL: the receipt digest makes an identical replay a
// no-op even when the replay carries a fresh CreatedAt and re-allocated Seq
// values (the lost-204 retry), while a reused (job, generation, batch_id)
// with different lines is a conflict whose transaction rolls back and leaves
// the original rows intact.
func TestPostgresIntegrationAppendLogBatchPayloadIdentity(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	identity := LogBatchIdentity{JobID: jobID, Generation: 1, BatchID: "batch-" + pgITRandomHex(t, 8)}
	now := time.Now().UTC()
	entries := []model.LogEntry{
		{Seq: 1, RunID: runID, JobID: jobID, JobKey: "build", Step: "run", Line: "one", CreatedAt: now},
		{Seq: 2, RunID: runID, JobID: jobID, JobKey: "build", Step: "run", Line: "two", CreatedAt: now},
		{Seq: 3, RunID: runID, JobID: jobID, JobKey: "build", Step: "run", Line: "three", CreatedAt: now},
	}

	inserted, err := st.AppendLogBatch(ctx, entries, identity)
	if err != nil || !inserted {
		t.Fatalf("first append = inserted=%v err=%v, want true, nil", inserted, err)
	}
	digest := LogBatchPayloadDigest(identity, entries)
	var stored string
	if err := st.pool.QueryRow(ctx, `SELECT payload_sha256 FROM log_batches WHERE job_id=$1 AND generation=$2 AND batch_id=$3`,
		identity.JobID, identity.Generation, identity.BatchID).Scan(&stored); err != nil {
		t.Fatalf("read payload_sha256: %v", err)
	}
	if stored != digest {
		t.Fatalf("stored digest = %q, want %q", stored, digest)
	}

	// A redelivery with a FRESH CreatedAt and re-allocated Seq values --
	// exactly what the server builds after a lost 204 -- is the same logical
	// payload and must be an idempotent no-op: one copy of the lines. This is
	// the retry-idempotency property the digest's field scope exists for.
	replay := redeliverBatchEntries(entries, 100, 2*time.Minute)
	if got := LogBatchPayloadDigest(identity, replay); got != digest {
		t.Fatalf("redelivery digest = %q, want the stored %q (CreatedAt/Seq must not participate)", got, digest)
	}
	inserted, err = st.AppendLogBatch(ctx, replay, identity)
	if err != nil || inserted {
		t.Fatalf("identical replay = inserted=%v err=%v, want false, nil", inserted, err)
	}
	got, err := st.ReadLogs(ctx, runID, 0, 100)
	if err != nil || len(got) != 3 {
		t.Fatalf("logs after replay = %d, %v; want 3", len(got), err)
	}

	// A reused identity with different lines fails closed and inserts nothing.
	conflict := append([]model.LogEntry(nil), entries...)
	conflict[1].Line = "changed"
	if _, err := st.AppendLogBatch(ctx, conflict, identity); !errors.Is(err, ErrLogBatchConflict) {
		t.Fatalf("conflicting payload = %v, want ErrLogBatchConflict", err)
	}
	got, err = st.ReadLogs(ctx, runID, 0, 100)
	if err != nil || len(got) != 3 {
		t.Fatalf("logs after conflict = %d, %v; want the original 3", len(got), err)
	}
	if got[1].Line != "two" {
		t.Fatalf("conflict mutated the stored lines: %+v", got)
	}
	var batches int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM log_batches WHERE job_id=$1`, jobID).Scan(&batches); err != nil || batches != 1 {
		t.Fatalf("log_batches rows = %d, %v; want 1", batches, err)
	}
}
