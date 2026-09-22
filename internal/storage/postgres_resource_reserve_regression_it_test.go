package storage

// Regression (E4-B): the claim's resource SUM must EXCLUDE the candidate
// job's own reservation row. A stale row for the SAME job (a release a
// crashed replica never completed) used to be summed together with the job's
// new request, so a re-lease could spuriously fail with ErrResourceCapacity
// even though the runner had room. The stale row is REPLACED by the re-lease
// (job_id primary key), so excluding it cannot under-count a live sibling.

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITResourceClaimAt is pgITResourceClaim with an explicit lease generation.
func pgITResourceClaimAt(jobID, runnerID string, request model.ResourceCapacity, generation int64) LeaseClaim {
	return LeaseClaim{
		JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: generation,
		ExpiresAt:  time.Now().UTC().Add(time.Hour),
		Runtime:    "container",
		CPURequest: request.CPU, MemoryRequest: request.Memory, DiskRequest: request.Disk, PIDsRequest: request.PIDs,
	}
}

func TestIntegrationResourceAdmissionStaleOwnRowDoubleCountPostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID, profileID := pgITNewID(t), "res-own-"+pgITRandomHex(t, 6)
	threeGiB := model.ResourceCapacity{Memory: 3 << 30}
	fiveGiB := model.ResourceCapacity{Memory: 5 << 30}
	pgITResourceProfileRunner(t, st, runnerID, profileID, 8, model.ResourceCapacity{Memory: 8 << 30})
	runID, live, stale := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	pgITResourceEnqueue(t, st, runID, live, pgITRepo, threeGiB)
	if err := st.InsertJob(ctx, pgITResourceJob(runID, stale, pgITRepo, fiveGiB)); err != nil {
		t.Fatalf("insert second job: %v", err)
	}
	// A live sibling holds 3 GiB.
	if _, err := st.AcquireLeaseAtomic(ctx, pgITResourceClaim(live, runnerID, threeGiB)); err != nil {
		t.Fatalf("live sibling lease: %v", err)
	}
	// The candidate leases once (generation 1), then a crashed replica
	// requeues it WITHOUT releasing its reservation row: the job is queued
	// again (with the next generation) while its own stale row survives.
	if _, err := st.AcquireLeaseAtomic(ctx, pgITResourceClaimAt(stale, runnerID, fiveGiB, 1)); err != nil {
		t.Fatalf("first candidate lease: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET status='queued', lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL WHERE id=$1`, stale); err != nil {
		t.Fatalf("requeue without release: %v", err)
	}
	var rows int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM job_resource_reservations`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("precondition: ledger rows = %d, want the live sibling + the stale own row", rows)
	}

	// Re-lease with generation 2: the SUM must be the sibling's 3 GiB (the
	// candidate's own stale row excluded), so 3+5 = 8 fits exactly. Counting
	// the stale row would make it 3+5+5 = 13 > 8 and fail spuriously.
	if _, err := st.AcquireLeaseAtomic(ctx, pgITResourceClaimAt(stale, runnerID, fiveGiB, 2)); err != nil {
		t.Fatalf("re-lease with a stale own row: %v (the candidate counted its own stale reservation)", err)
	}
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{Memory: 8 << 30}, 2)
	var generation int64
	if err := st.pool.QueryRow(ctx, `SELECT generation FROM job_resource_reservations WHERE job_id=$1`, stale).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	if generation != 2 {
		t.Fatalf("candidate reservation generation = %d, want the re-lease's 2 (stale row replaced)", generation)
	}
}
