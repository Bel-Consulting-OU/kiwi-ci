package storage

// Real-PostgreSQL integration coverage for the resource reservation ledger's
// failure paths: the claim's check-and-reserve is part of the lease
// transaction, so a failing reservation read/write must roll the whole claim
// back (job stays queued, runner slot free, no ledger row), the observation
// API must report store errors, and the promotion reconciliation must fail
// closed when the ledger cannot be swept.

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITSeedReservableJob enqueues one run/job and a runner with room for it,
// returning the IDs a claim needs.
func pgITSeedReservableJob(t *testing.T, st *PostgresStore) (jobID, runnerID string) {
	t.Helper()
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	runnerID = pgITNewID(t)
	pgITSeedRunner(t, st, runnerID, 2, 0, 0)
	return jobID, runnerID
}

// TestPostgresIntegrationReservationClaimFailureRollsBack proves a failure
// inside the reservation write aborts the entire lease claim: no job claim,
// no runner slot, no ledger row, and the failure is reported.
func TestPostgresIntegrationReservationClaimFailureRollsBack(t *testing.T) {
	ctx := context.Background()

	t.Run("insert-fails", func(t *testing.T) {
		st := pgITStore(t)
		jobID, runnerID := pgITSeedReservableJob(t, st)
		pgITBoomOp(t, st, "job_resource_reservations", "INSERT")
		claim := LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 2, MemoryRequest: 1 << 20}
		if _, err := st.AcquireLeaseAtomic(ctx, claim); err == nil {
			t.Fatal("claim with a failing reservation insert succeeded")
		}
		assertClaimRolledBack(t, st, jobID, runnerID, 0)
	})

	t.Run("delete-fails", func(t *testing.T) {
		st := pgITStore(t)
		jobID, runnerID := pgITSeedReservableJob(t, st)
		// A stale row for THIS job (a release a crashed replica never
		// completed) makes the claim's replace DELETE match a row, so the
		// injected delete failure actually fires.
		if _, err := st.pool.Exec(ctx, `INSERT INTO job_resource_reservations (job_id, runner_id, generation, cpu, memory, disk, pids) VALUES ($1, $2, 0, 1, 0, 0, 0)`, jobID, runnerID); err != nil {
			t.Fatalf("seed stale row: %v", err)
		}
		pgITBoomOp(t, st, "job_resource_reservations", "DELETE")
		claim := LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 2, MemoryRequest: 1 << 20}
		if _, err := st.AcquireLeaseAtomic(ctx, claim); err == nil {
			t.Fatal("claim with a failing stale-row delete succeeded")
		}
		// The transaction rolled back: the pre-existing STALE row (generation
		// 0) survives, no generation-1 claim row was written.
		assertClaimRolledBack(t, st, jobID, runnerID, 1)
	})

	t.Run("sum-read-fails", func(t *testing.T) {
		st := pgITStore(t)
		jobID, runnerID := pgITSeedReservableJob(t, st)
		// The SUM reads the runner_id column: retyping it makes the
		// admission read fail inside the claim transaction.
		pgITBreakColumnToArray(t, st, "job_resource_reservations", "runner_id")
		claim := LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 2, MemoryRequest: 1 << 20}
		if _, err := st.AcquireLeaseAtomic(ctx, claim); err == nil {
			t.Fatal("claim with a failing reservation read succeeded")
		}
		assertClaimRolledBack(t, st, jobID, runnerID, 0)
	})
}

// assertClaimRolledBack pins the rollback invariants shared by every failure:
// the job is queued with no lease, the runner slot is free, and the job's
// reservation rows are exactly the pre-existing stale ones (none written by
// the failed claim).
func assertClaimRolledBack(t *testing.T, st *PostgresStore, jobID, runnerID string, wantRows int) {
	t.Helper()
	ctx := context.Background()
	if j, err := st.GetJob(ctx, jobID); err != nil || j.Status != model.StatusQueued || j.LeaseRunnerID != "" {
		t.Fatalf("job after failed claim = %+v err=%v, want queued with no lease", j, err)
	}
	if ri, err := st.GetRunner(ctx, runnerID); err != nil || len(ri.ActiveJobs) != 0 || ri.Busy {
		t.Fatalf("runner after failed claim = %+v err=%v, want a free slot", ri, err)
	}
	var rows, claimedRows int
	if err := st.pool.QueryRow(ctx, `SELECT COUNT(*), COALESCE(SUM(CASE WHEN generation <> 0 THEN 1 ELSE 0 END), 0) FROM job_resource_reservations WHERE job_id=$1`, jobID).Scan(&rows, &claimedRows); err != nil {
		t.Fatalf("count reservations: %v", err)
	}
	if rows != wantRows || claimedRows != 0 {
		t.Fatalf("reservation rows after failed claim = %d (claimed %d), want %d stale and no claim row", rows, claimedRows, wantRows)
	}
}

// TestPostgresIntegrationReservationObservationErrors proves the observation
// API distinguishes "no reservations" from "the ledger cannot be read": a
// broken relation surfaces an error instead of a zero/empty answer.
func TestPostgresIntegrationReservationObservationErrors(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	jobID, runnerID := pgITSeedReservableJob(t, st)
	claim := LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 2, CPURequest: 1, MemoryRequest: 1 << 20, PIDsRequest: 16}
	if _, err := st.AcquireLeaseAtomic(ctx, claim); err != nil {
		t.Fatal(err)
	}
	// The healthy read sees the row first (proves the fixture is real).
	if sum, err := st.RunnerReservedResources(ctx, runnerID); err != nil || sum.CPU != 1 || sum.Memory != 1<<20 {
		t.Fatalf("healthy sum = (%+v, %v)", sum, err)
	}
	// Break the ledger type: both the SUM and the listing must fail.
	pgITBreakColumnToArray(t, st, "job_resource_reservations", "runner_id")
	if _, err := st.RunnerReservedResources(ctx, runnerID); err == nil {
		t.Fatal("RunnerReservedResources over a broken ledger succeeded")
	}
	if _, err := st.ListResourceReservations(ctx, runnerID); err == nil {
		t.Fatal("ListResourceReservations over a broken ledger succeeded")
	}
}

// TestPostgresIntegrationReservationListScanError proves a row that cannot be
// scanned (a mistyped job_id) is reported instead of producing a partial
// listing.
func TestPostgresIntegrationReservationListScanError(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	jobID, runnerID := pgITSeedReservableJob(t, st)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 2}); err != nil {
		t.Fatal(err)
	}
	pgITBreakColumnToArray(t, st, "job_resource_reservations", "job_id")
	if rows, err := st.ListResourceReservations(ctx, runnerID); err == nil || rows != nil {
		t.Fatalf("listing over a mistyped job_id = (%v, %v), want an error", rows, err)
	}
}

// TestPostgresIntegrationResourceReconcileSweepFailures proves the promotion
// reconciliation fails closed when it cannot sweep the ledger: an injected
// delete failure leaves the transaction uncommitted (the caller sees the
// error, no partial ledger mutation is observable by another connection).
func TestPostgresIntegrationResourceReconcileSweepFailures(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	jobID, runnerID := pgITSeedReservableJob(t, st)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 2}); err != nil {
		t.Fatal(err)
	}
	// A stale row the sweep must delete (its job is not running), so the
	// injected per-row delete failure fires.
	if _, err := st.pool.Exec(ctx, `INSERT INTO job_resource_reservations (job_id, runner_id, generation, cpu, memory, disk, pids) VALUES ($1, $2, 1, 0, 0, 0, 0)`, pgITNewID(t), runnerID); err != nil {
		t.Fatalf("seed stale row: %v", err)
	}
	pgITBoomOp(t, st, "job_resource_reservations", "DELETE")
	if _, err := st.ReconcileResourceReservations(ctx); err == nil {
		t.Fatal("reconcile with a failing stale sweep succeeded")
	}
	// The failure rolled back: the live job's reservation row is untouched
	// and no sweep was committed.
	rows, err := st.ListResourceReservations(ctx, runnerID)
	if err != nil {
		t.Fatalf("list after failed reconcile: %v", err)
	}
	live := 0
	for _, row := range rows {
		if row.JobID == jobID && row.Generation == 1 {
			live++
		}
	}
	if live != 1 {
		t.Fatalf("live reservation after failed reconcile = %d, want 1 (rows=%+v)", live, rows)
	}
}

// TestPostgresIntegrationResourceReconcileInsertFailureIsAtomic proves a
// failure in the reconcile's upsert phase aborts the pass: the ledger still
// reflects the pre-pass state (the sweep's deletes rolled back with it).
func TestPostgresIntegrationResourceReconcileInsertFailureIsAtomic(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	jobID, runnerID := pgITSeedReservableJob(t, st)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 2, MemoryRequest: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	// A stale row (a completed job) that phase 1 would delete.
	staleJob := pgITNewID(t)
	if _, err := st.pool.Exec(ctx, `INSERT INTO job_resource_reservations (job_id, runner_id, generation, cpu, memory, disk, pids) VALUES ($1, $2, 1, 0, 0, 0, 0)`, staleJob, runnerID); err != nil {
		t.Fatalf("seed stale row: %v", err)
	}
	// The upsert (INSERT ... ON CONFLICT) fires the INSERT trigger.
	pgITBoomOp(t, st, "job_resource_reservations", "INSERT")
	if _, err := st.ReconcileResourceReservations(ctx); err == nil {
		t.Fatal("reconcile with a failing upsert succeeded")
	}
	var rows int
	if err := st.pool.QueryRow(ctx, `SELECT COUNT(*) FROM job_resource_reservations WHERE job_id=$1`, staleJob).Scan(&rows); err != nil {
		t.Fatalf("count stale row: %v", err)
	}
	if rows != 1 {
		t.Fatalf("failed reconcile committed its stale sweep: %d rows", rows)
	}
}
