package storage

// Real-PostgreSQL integration test for the self-healing reservation ledger
// (K6-B). Gated on KIWI_TEST_POSTGRES_URL like every *_it_test.go here.
//
// Defect: during a rolling upgrade the OLD binary can serve a job's
// /complete or /cancel, so the release DELETE the NEW binary owns never runs
// for that job and its reservation row is left behind. The SUM used to count
// every row for the runner with no join against jobs, so the orphan row kept
// shrinking the runner's remaining capacity until claims failed with
// ErrResourceCapacity — permanent capacity loss until an operator
// intervened. Capacity must now return from the ledger read itself, with no
// operator action, and the orphan row must be swept by the next reconcile.

import (
	"context"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestIntegrationResourceCapacityHealsAfterOldReplicaCompletionPostgres
// simulates an old-replica completion: the job row is finished and its lease
// cleared, but the reservation row it holds is NOT deleted (the old binary
// does not know the ledger). The capacity the row was charging must return to
// the runner immediately, and the next reconcile must remove the row itself.
func TestIntegrationResourceCapacityHealsAfterOldReplicaCompletionPostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID, profileID := pgITNewID(t), "res-selfheal-"+pgITRandomHex(t, 6)
	fourGiB := model.ResourceCapacity{Memory: 4 << 30}
	pgITResourceProfileRunner(t, st, runnerID, profileID, 8, model.ResourceCapacity{Memory: 8 << 30})
	runID := pgITNewID(t)
	job1, job2, job3 := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	pgITResourceEnqueue(t, st, runID, job1, pgITRepo, fourGiB)
	if err := st.InsertJob(ctx, pgITResourceJob(runID, job2, pgITRepo, fourGiB)); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertJob(ctx, pgITResourceJob(runID, job3, pgITRepo, fourGiB)); err != nil {
		t.Fatal(err)
	}

	// The new binary leases both 4 GiB jobs: the runner's 8 GiB is fully
	// reserved.
	for _, id := range []string{job1, job2} {
		if _, err := st.AcquireLeaseAtomic(ctx, pgITResourceClaim(id, runnerID, fourGiB)); err != nil {
			t.Fatalf("lease %s: %v", id, err)
		}
	}
	pgITAssertReservations(t, st, runnerID, model.AddResourceCapacity(fourGiB, fourGiB), 2)

	// The OLD replica completes job1: the job row is finished, the lease is
	// cleared and the runner slot released — but the reservation row stays,
	// exactly as an old binary that never knew the ledger leaves it.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET status='success', finished_at=now(), lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL WHERE id=$1`, job1); err != nil {
		t.Fatalf("old-replica completion: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE runners SET active_jobs = COALESCE(active_jobs, '[]'::jsonb) - $2 WHERE id=$1`, runnerID, job1); err != nil {
		t.Fatalf("old-replica slot release: %v", err)
	}

	// The leak is physically present...
	list, err := st.ListResourceReservations(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("ledger rows = %d, want the 2 rows the old replica left behind", len(list))
	}
	// ...but it charges nothing: the capacity the orphan row held is back.
	reserved, err := st.RunnerReservedResources(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved != fourGiB {
		t.Fatalf("reserved after the old-replica completion = %+v, want the live job's 4 GiB only", reserved)
	}
	// The batched fleet fold agrees with the per-runner SUM on the leaked row.
	sums, err := st.RunnerReservationSums(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := sums[runnerID]; got != reserved {
		t.Fatalf("batched sum = %+v, per-runner sum = %+v: the fleet view must agree under a leak", got, reserved)
	}

	// Capacity returns WITHOUT operator action: the third 4 GiB job leases.
	if _, err := st.AcquireLeaseAtomic(ctx, pgITResourceClaim(job3, runnerID, fourGiB)); err != nil {
		t.Fatalf("claim after the leaked row (capacity did not heal): %v", err)
	}
	pgITAssertReservations(t, st, runnerID, model.AddResourceCapacity(fourGiB, fourGiB), 3)

	// The reconcile sweep removes the orphan row itself; the live rows stay.
	res, err := st.ReconcileResourceReservations(ctx)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Running != 2 || res.Upserted != 2 || res.Deleted != 1 {
		t.Fatalf("reconcile result = %+v, want running=2 upserted=2 deleted=1 (the orphan row)", res)
	}
	list, err = st.ListResourceReservations(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("ledger rows after reconcile = %d, want the 2 live rows (%+v)", len(list), list)
	}
	for _, r := range list {
		if r.JobID == job1 {
			t.Fatalf("the orphan row for %s survived the reconcile sweep", job1)
		}
	}
	reserved, err = st.RunnerReservedResources(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Memory != 8<<30 {
		t.Fatalf("reserved after the sweep = %+v, want 8 GiB", reserved)
	}

	// A completion served by THIS binary still releases its row exactly once
	// (the release path is unchanged by the self-healing read).
	if err := st.CompleteJob(ctx, job3, 1, runnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: job3, Generation: 1, RunnerID: runnerID}); err != nil {
		t.Fatalf("complete job3: %v", err)
	}
	pgITAssertReservations(t, st, runnerID, fourGiB, 1)
}
