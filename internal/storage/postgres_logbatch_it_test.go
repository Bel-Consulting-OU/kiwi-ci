package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITLeasedLogJob seeds one queued run/job and acquires generation 1 under a
// fresh runner, returning the coordinates the log-fence tests need. The lease
// is live at the database clock, so append calls through the fenced paths
// commit until the test deliberately supersedes or expires it.
func pgITLeasedLogJob(t *testing.T, st *PostgresStore) (runID, jobID, runnerID string) {
	t.Helper()
	ctx := context.Background()
	runID, jobID, runnerID = pgITNewID(t), pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	pgITSeedRunner(t, st, runnerID, 2, 0, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("lease job %s: %v", jobID, err)
	}
	return runID, jobID, runnerID
}

// TestPostgresIntegrationAppendLogBatchPayloadIdentity proves the S-B fix
// against real PostgreSQL: the receipt digest makes an identical replay a
// no-op even when the replay carries a fresh CreatedAt and re-allocated Seq
// values (the lost-204 retry), while a reused (job, generation, batch_id)
// with different lines is a conflict whose transaction rolls back and leaves
// the original rows intact.
func TestPostgresIntegrationAppendLogBatchPayloadIdentity(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID, runnerID := pgITLeasedLogJob(t, st)
	identity := LogBatchIdentity{JobID: jobID, Generation: 1, BatchID: "batch-" + pgITRandomHex(t, 8)}
	now := time.Now().UTC()
	entries := []model.LogEntry{
		{Seq: 1, RunID: runID, JobID: jobID, JobKey: "build-" + jobID, Step: "run", Line: "one", CreatedAt: now, LeaseGeneration: 1},
		{Seq: 2, RunID: runID, JobID: jobID, JobKey: "build-" + jobID, Step: "run", Line: "two", CreatedAt: now, LeaseGeneration: 1},
		{Seq: 3, RunID: runID, JobID: jobID, JobKey: "build-" + jobID, Step: "run", Line: "three", CreatedAt: now, LeaseGeneration: 1},
	}

	inserted, err := st.AppendLogBatch(ctx, runnerID, entries, identity)
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
	inserted, err = st.AppendLogBatch(ctx, runnerID, replay, identity)
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
	if _, err := st.AppendLogBatch(ctx, runnerID, conflict, identity); !errors.Is(err, ErrLogBatchConflict) {
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

// TestPostgresIntegrationAppendLogBatchLeaseFence proves the batch commit is
// fenced by the LIVE lease generation inside its own transaction (I3 GAP-1):
// once the lease is superseded or expired, both a fresh batch and a replay of
// an already-receipted batch are refused with ErrLeaseLost and nothing is
// inserted — the stale generation never gets the idempotent 204.
func TestPostgresIntegrationAppendLogBatchLeaseFence(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID, runnerID := pgITLeasedLogJob(t, st)
	identity := LogBatchIdentity{JobID: jobID, Generation: 1, BatchID: "batch-" + pgITRandomHex(t, 8)}
	now := time.Now().UTC()
	entries := []model.LogEntry{
		{RunID: runID, JobID: jobID, JobKey: "build-" + jobID, Step: "run", Line: "one", CreatedAt: now, LeaseGeneration: 1},
		{RunID: runID, JobID: jobID, JobKey: "build-" + jobID, Step: "run", Line: "two", CreatedAt: now, LeaseGeneration: 1},
	}
	if inserted, err := st.AppendLogBatch(ctx, runnerID, entries, identity); err != nil || !inserted {
		t.Fatalf("live batch = inserted=%v err=%v", inserted, err)
	}
	countLines := func() int {
		t.Helper()
		var n int
		if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM log_entries WHERE run_id=$1`, runID).Scan(&n); err != nil {
			t.Fatalf("count lines: %v", err)
		}
		return n
	}
	before := countLines()

	// A concurrent supersede (generation bump) and an expiry: the predicate
	// must fail closed for both, because it is evaluated against the LOCKED
	// row in the append transaction.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET lease_generation = lease_generation + 1 WHERE id=$1`, jobID); err != nil {
		t.Fatalf("bump generation: %v", err)
	}
	if _, err := st.AppendLogBatch(ctx, runnerID, entries, identity); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("superseded replay = %v, want ErrLeaseLost", err)
	}
	fresh := LogBatchIdentity{JobID: jobID, Generation: 1, BatchID: "batch-" + pgITRandomHex(t, 8)}
	freshEntries := append([]model.LogEntry(nil), entries...)
	freshEntries[0].Line = "fresh"
	if _, err := st.AppendLogBatch(ctx, runnerID, freshEntries, fresh); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("superseded fresh batch = %v, want ErrLeaseLost", err)
	}
	if got := countLines(); got != before {
		t.Fatalf("stale batch persisted lines: %d -> %d", before, got)
	}

	// Expiry alone is enough: restore the generation and age the lease.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET lease_generation = $2, lease_expires_at = clock_timestamp() - interval '1 second' WHERE id=$1`, jobID, 1); err != nil {
		t.Fatalf("expire lease: %v", err)
	}
	if _, err := st.AppendLogBatch(ctx, runnerID, entries, identity); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expired replay = %v, want ErrLeaseLost", err)
	}
	if got := countLines(); got != before {
		t.Fatalf("expired batch persisted lines: %d -> %d", before, got)
	}
	// The receipt row of the live generation is untouched (the replay was
	// refused, not treated as a duplicate/conflict).
	var batches int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM log_batches WHERE job_id=$1`, jobID).Scan(&batches); err != nil || batches != 1 {
		t.Fatalf("log_batches rows after refusals = %d, %v; want 1", batches, err)
	}
}

// TestPostgresIntegrationAppendLogForLeaseFence proves the single-line commit
// is fenced like the batch: the live lease appends with a commit-ordered seq,
// a superseded/expired generation is ErrLeaseLost, and the line carries the
// predicate generation and locked-job identity.
func TestPostgresIntegrationAppendLogForLeaseFence(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID, runnerID := pgITLeasedLogJob(t, st)
	e := model.LogEntry{RunID: runID, JobID: jobID, JobKey: "build-" + jobID, Step: "run", Line: "one", CreatedAt: time.Now().UTC()}
	if err := st.AppendLogForLease(ctx, jobID, runnerID, 1, e); err != nil {
		t.Fatalf("live line: %v", err)
	}
	got, err := st.ReadLogs(ctx, runID, 0, 10)
	if err != nil || len(got) != 1 || got[0].LeaseGeneration != 1 || got[0].JobID != jobID || got[0].JobKey != "build-"+jobID {
		t.Fatalf("stored line = %+v, %v", got, err)
	}

	// A superseded generation commits nothing.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET lease_generation = 2 WHERE id=$1`, jobID); err != nil {
		t.Fatalf("bump generation: %v", err)
	}
	if err := st.AppendLogForLease(ctx, jobID, runnerID, 1, model.LogEntry{RunID: runID, Line: "stale", CreatedAt: time.Now().UTC()}); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale line = %v, want ErrLeaseLost", err)
	}
	// A line cross-bound to another run is refused while the lease is live.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET lease_generation = 1 WHERE id=$1`, jobID); err != nil {
		t.Fatalf("restore generation: %v", err)
	}
	foreignRun := pgITNewID(t)
	if err := st.AppendLogForLease(ctx, jobID, runnerID, 1, model.LogEntry{RunID: foreignRun, Line: "foreign", CreatedAt: time.Now().UTC()}); !errors.Is(err, ErrLeaseIdentityMismatch) {
		t.Fatalf("foreign run line = %v, want ErrLeaseIdentityMismatch", err)
	}
	if got, err := st.ReadLogs(ctx, runID, 0, 10); err != nil || len(got) != 1 {
		t.Fatalf("refused lines persisted = %d, %v", len(got), err)
	}
}
