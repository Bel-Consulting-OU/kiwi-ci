package storage

// Real-PostgreSQL integration tests for completion receipt retention. They
// follow the package convention: gated on KIWI_TEST_POSTGRES_URL through
// pgITStore/pgITDSN (skipped when unset and in -short mode) and every test
// owns a throwaway schema that is dropped on cleanup.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// pgITCompletionReceiptRows counts the physical receipt rows for one key, so
// tests can distinguish "invisible because past the TTL" from "reclaimed".
func pgITCompletionReceiptRows(t *testing.T, st *PostgresStore, jobID, runnerID string) int {
	t.Helper()
	var n int
	if err := st.pool.QueryRow(context.Background(), `SELECT count(*) FROM completion_receipts WHERE job_id=$1 AND runner_id=$2`, jobID, runnerID).Scan(&n); err != nil {
		t.Fatalf("count completion_receipts: %v", err)
	}
	return n
}

// TestPostgresIntegrationCompletionReceiptTTLPrune proves DB-mode receipts
// follow the shared fs retention contract: a receipt past CompletionReceiptTTL
// stops deduping immediately (the replay is rejected like fs mode, never
// reconciled) and is physically reclaimed by the next receipt write, while a
// fresh receipt and an unrelated within-TTL receipt survive and still dedupe.
func TestPostgresIntegrationCompletionReceiptTTLPrune(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	pgITSeedRunner(t, st, runnerID, 1, 0, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 1}); err != nil {
		t.Fatalf("lease: %v", err)
	}
	receipt := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "hash-ttl"}
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, receipt); err != nil {
		t.Fatalf("CompleteJob: %v", err)
	}

	// A fresh receipt dedupes: the exact replay is acknowledged.
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, receipt); err != nil {
		t.Fatalf("fresh replay: %v", err)
	}

	// A within-TTL receipt for an unrelated key is the row the prune must
	// leave alone.
	keptJob, keptRunner := pgITNewID(t), pgITNewID(t)
	if _, err := st.pool.Exec(ctx, `INSERT INTO completion_receipts (job_id, generation, runner_id, result_hash, created_at) VALUES ($1, 7, $2, 'kept', now() - make_interval(secs => $3))`,
		keptJob, keptRunner, (6 * 24 * time.Hour).Seconds()); err != nil {
		t.Fatalf("seed within-TTL receipt: %v", err)
	}

	// Age the completed job's receipt past CompletionReceiptTTL directly in
	// the table (the store deliberately has no backdating API).
	if _, err := st.pool.Exec(ctx, `UPDATE completion_receipts SET created_at = now() - make_interval(secs => $1) WHERE job_id=$2 AND generation=1 AND runner_id=$3`,
		(CompletionReceiptTTL + time.Hour).Seconds(), jobID, runnerID); err != nil {
		t.Fatalf("age receipt: %v", err)
	}

	// The aged receipt is invisible to replay detection even before the
	// physical prune: the replay is rejected exactly like fs mode instead of
	// being acknowledged and reconciled. (The store reports the cleared
	// lease_runner_id as a generation mismatch or a lease conflict; the
	// server maps both to 409, which is the replay contract under test.)
	err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, receipt)
	if err == nil {
		t.Fatal("aged replay must be rejected")
	}
	if !errors.Is(err, ErrGenerationMismatch) && !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("aged replay = %v, want a stale-lease rejection", err)
	}
	if rec, has, err := st.HasCompletionReceipt(ctx, jobID, 1, runnerID); err != nil || has {
		t.Fatalf("aged receipt = %+v has=%v err=%v, want missing", rec, has, err)
	}
	if n := pgITCompletionReceiptRows(t, st, jobID, runnerID); n != 1 {
		t.Fatalf("aged receipt rows = %d, want 1 before the write-path prune", n)
	}

	// Any receipt insert prunes: the expired row is reclaimed, the fresh
	// insert and the unrelated within-TTL receipt stay.
	freshJob, freshRunner := pgITNewID(t), pgITNewID(t)
	fresh := model.CompletionReceipt{JobID: freshJob, Generation: 1, RunnerID: freshRunner, ResultHash: "fresh"}
	if err := st.InsertCompletionReceipt(ctx, fresh); err != nil {
		t.Fatalf("InsertCompletionReceipt: %v", err)
	}
	if n := pgITCompletionReceiptRows(t, st, jobID, runnerID); n != 0 {
		t.Fatalf("aged receipt rows after prune = %d, want 0", n)
	}
	if rec, has, err := st.HasCompletionReceipt(ctx, freshJob, 1, freshRunner); err != nil || !has || rec.ResultHash != "fresh" {
		t.Fatalf("fresh receipt = %+v has=%v err=%v, want retained", rec, has, err)
	}
	if rec, has, err := st.HasCompletionReceipt(ctx, keptJob, 7, keptRunner); err != nil || !has || rec.ResultHash != "kept" {
		t.Fatalf("within-TTL receipt = %+v has=%v err=%v, want retained", rec, has, err)
	}
	// The fresh receipt still dedupes on a replayed insert.
	if err := st.InsertCompletionReceipt(ctx, fresh); err != nil {
		t.Fatalf("fresh replay insert: %v", err)
	}
	if n := pgITCompletionReceiptRows(t, st, freshJob, freshRunner); n != 1 {
		t.Fatalf("fresh receipt rows after replay = %d, want 1", n)
	}
}

// TestPostgresIntegrationCompletionReceiptCapPrune proves the MaxCompletionReceipts
// cap shared with fs mode is enforced on the write path once the table holds
// more than the cap: the oldest rows are reclaimed, the newest receipt
// survives and dedupes, and the table lands exactly at the cap.
func TestPostgresIntegrationCompletionReceiptCapPrune(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	// Bulk-seed MaxCompletionReceipts+7 within-TTL rows with distinct
	// created_at values (newest = smallest i), then make the planner estimate
	// current for the reltuples-gated cap sweep.
	const extra = 7
	if _, err := st.pool.Exec(ctx, `INSERT INTO completion_receipts (job_id, generation, runner_id, result_hash, created_at)
		SELECT 'cap-' || lpad(i::text, 27, '0'), 1, 'cap-runner', 'h', now() - make_interval(secs => i)
		FROM generate_series(1, $1::bigint) AS i`, MaxCompletionReceipts+extra); err != nil {
		t.Fatalf("bulk seed receipts: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `ANALYZE completion_receipts`); err != nil {
		t.Fatalf("analyze receipts: %v", err)
	}

	freshJob, freshRunner := pgITNewID(t), pgITNewID(t)
	fresh := model.CompletionReceipt{JobID: freshJob, Generation: 1, RunnerID: freshRunner, ResultHash: "fresh"}
	if err := st.InsertCompletionReceipt(ctx, fresh); err != nil {
		t.Fatalf("InsertCompletionReceipt: %v", err)
	}

	var n int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM completion_receipts`).Scan(&n); err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	if n != MaxCompletionReceipts {
		t.Fatalf("receipt rows after cap prune = %d, want %d", n, MaxCompletionReceipts)
	}
	// The newest receipt (the one just inserted) survives and dedupes.
	if rec, has, err := st.HasCompletionReceipt(ctx, freshJob, 1, freshRunner); err != nil || !has || rec.ResultHash != "fresh" {
		t.Fatalf("newest receipt = %+v has=%v err=%v, want kept", rec, has, err)
	}
	// The oldest bulk row is gone; the newest bulk row remains.
	var gone int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM completion_receipts WHERE job_id = 'cap-' || lpad(($1::bigint)::text, 27, '0')`, MaxCompletionReceipts+extra).Scan(&gone); err != nil || gone != 0 {
		t.Fatalf("oldest capped row = %d err=%v, want 0", gone, err)
	}
	var kept int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM completion_receipts WHERE job_id = 'cap-' || lpad('1', 27, '0')`).Scan(&kept); err != nil || kept != 1 {
		t.Fatalf("newest bulk row = %d err=%v, want 1", kept, err)
	}
	// A replayed insert remains idempotent.
	if err := st.InsertCompletionReceipt(ctx, fresh); err != nil {
		t.Fatalf("fresh replay insert: %v", err)
	}
}

// TestPostgresIntegrationCompletionReceiptRetentionMigration proves the
// retention index migration applies over a table that already carries rows:
// the schema is rolled back to the pre-0016 state (index dropped, version
// unrecorded), a receipt is seeded, and the real Migrate re-applies 0016
// without touching the row.
func TestPostgresIntegrationCompletionReceiptRetentionMigration(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	all, err := migrations.All()
	if err != nil {
		t.Fatalf("migrations.All: %v", err)
	}
	retentionVersion := 0
	for _, m := range all {
		if m.Name == "0016_completion_receipt_retention.sql" {
			retentionVersion = m.Version
		}
	}
	if retentionVersion == 0 {
		t.Fatal("completion receipt retention migration is not embedded")
	}
	if _, err := st.pool.Exec(ctx, `DROP INDEX completion_receipts_created_at_idx`); err != nil {
		t.Fatalf("drop retention index: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = $1`, retentionVersion); err != nil {
		t.Fatalf("unrecord migration %d: %v", retentionVersion, err)
	}
	jobID, runnerID := pgITNewID(t), pgITNewID(t)
	if _, err := st.pool.Exec(ctx, `INSERT INTO completion_receipts (job_id, generation, runner_id, result_hash) VALUES ($1, 1, $2, 'pre-existing')`, jobID, runnerID); err != nil {
		t.Fatalf("seed pre-existing receipt: %v", err)
	}

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate over pre-existing rows: %v", err)
	}
	var haveIndex bool
	if err := st.pool.QueryRow(ctx, `SELECT to_regclass('completion_receipts_created_at_idx') IS NOT NULL`).Scan(&haveIndex); err != nil || !haveIndex {
		t.Fatalf("retention index after migrate = %v err=%v, want true", haveIndex, err)
	}
	want := all[len(all)-1].Version
	if v, err := st.SchemaVersion(ctx); err != nil || v != want {
		t.Fatalf("SchemaVersion after migrate = %d err=%v, want %d", v, err, want)
	}
	rec, has, err := st.HasCompletionReceipt(ctx, jobID, 1, runnerID)
	if err != nil || !has || rec.ResultHash != "pre-existing" {
		t.Fatalf("pre-existing receipt after migrate = %+v has=%v err=%v, want retained", rec, has, err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}
