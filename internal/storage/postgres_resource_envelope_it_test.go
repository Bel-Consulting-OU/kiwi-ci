package storage

// Real-PostgreSQL integration tests for the aggregate service-envelope
// reservation (E-envelope). Gated on KIWI_TEST_POSTGRES_URL like every
// *_it_test.go here.
//
// The defect these pin: the scheduler reserves only the job's own
// ResourceRequest(), so on hosts where the executor cannot establish a
// job-scoped parent cgroup (non-Linux, cgroup v1, no delegation, systemd
// driver) the declared services are bounded only by per-container caps and
// the runner's capacity is oversubscribed across replicas. The claim must
// reserve the job's own request PLUS the aggregate service envelope
// (model.Job.ServiceEnvelopeRequest) in the ONE per-job ledger row, the
// release paths must stay unchanged, and the promotion reconciliation must
// reconstruct the same aggregate from the persisted payload so a rolling
// upgrade cannot under-reserve.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITEnvelopeClaim builds the atomic claim for one job carrying both its own
// request and its aggregate service envelope.
func pgITEnvelopeClaim(jobID, runnerID string, own, envelope model.ResourceCapacity) LeaseClaim {
	return LeaseClaim{
		JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1,
		ExpiresAt:  time.Now().UTC().Add(time.Hour),
		Runtime:    "container",
		CPURequest: own.CPU, MemoryRequest: own.Memory, DiskRequest: own.Disk, PIDsRequest: own.PIDs,
		ServiceEnvelopeRequest: envelope,
	}
}

// pgITEnvelopeJob builds a queued job with its own request and the aggregate
// service envelope persisted in the payload.
func pgITEnvelopeJob(runID, jobID, repo string, own, envelope model.ResourceCapacity) model.Job {
	j := pgITResourceJob(runID, jobID, repo, own)
	j.ServiceEnvelopeRequest = envelope
	return j
}

// pgITEnqueueEnvelopeJob enqueues one run whose single job carries the given
// own request and service envelope.
func pgITEnqueueEnvelopeJob(t *testing.T, st *PostgresStore, runID, jobID string, own, envelope model.ResourceCapacity) {
	t.Helper()
	req := InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{jobID: pgITEnvelopeJob(runID, jobID, pgITRepo, own, envelope)},
	}
	if err := st.InsertCompiledRun(context.Background(), req); err != nil {
		t.Fatalf("enqueue %s/%s: %v", runID, jobID, err)
	}
}

// TestIntegrationResourceAdmissionServiceEnvelopePostgres: the claim
// transaction reserves job + services in one row — a job whose OWN request
// fits but whose aggregate does not is rejected with ErrResourceCapacity and
// writes nothing — a job without services reserves exactly its own request,
// the release deletes the single row, and the promotion reconciliation agrees
// with the claim's arithmetic.
func TestIntegrationResourceAdmissionServiceEnvelopePostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID, profileID := pgITNewID(t), "env-adm-"+pgITRandomHex(t, 6)
	pgITResourceProfileRunner(t, st, runnerID, profileID, 8, model.ResourceCapacity{Memory: 8 << 30})

	runID := pgITNewID(t)
	svcJob, overJob, plainJob := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	fiveGiB := model.ResourceCapacity{Memory: 5 << 30}
	twoGiB := model.ResourceCapacity{Memory: 2 << 30}
	threeGiB := model.ResourceCapacity{Memory: 3 << 30}
	fourGiB := model.ResourceCapacity{Memory: 4 << 30}
	pgITEnqueueEnvelopeJob(t, st, runID, svcJob, fiveGiB, twoGiB)
	if err := st.InsertJob(ctx, pgITEnvelopeJob(runID, overJob, pgITRepo, fiveGiB, fourGiB)); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertJob(ctx, pgITEnvelopeJob(runID, plainJob, pgITRepo, threeGiB, model.ResourceCapacity{})); err != nil {
		t.Fatal(err)
	}

	// 5+4 = 9 > 8: rejected before anything is written, even though the own
	// request (5) fits.
	if _, err := st.AcquireLeaseAtomic(ctx, pgITEnvelopeClaim(overJob, runnerID, fiveGiB, fourGiB)); !errors.Is(err, ErrResourceCapacity) {
		t.Fatalf("claim with 5GiB+4GiB envelope = %v, want ErrResourceCapacity", err)
	}
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{}, 0)

	// 5+2 = 7 <= 8: admitted, and the ONE row carries the aggregate.
	if _, err := st.AcquireLeaseAtomic(ctx, pgITEnvelopeClaim(svcJob, runnerID, fiveGiB, twoGiB)); err != nil {
		t.Fatalf("claim with 5GiB+2GiB envelope: %v", err)
	}
	sevenGiB := model.ResourceCapacity{Memory: 7 << 30}
	pgITAssertReservations(t, st, runnerID, sevenGiB, 1)

	// The reconciliation derives the same total from the payload.
	res, err := st.ReconcileResourceReservations(ctx)
	if err != nil {
		t.Fatalf("reconcile after claim: %v", err)
	}
	if res.Running != 1 || res.Upserted != 1 || res.Deleted != 0 {
		t.Fatalf("reconcile result = %+v, want running=1 upserted=1 deleted=0", res)
	}
	pgITAssertReservations(t, st, runnerID, sevenGiB, 1)

	// The plain job's own 3 GiB does not fit the remaining 1 GiB.
	if _, err := st.AcquireLeaseAtomic(ctx, pgITEnvelopeClaim(plainJob, runnerID, threeGiB, model.ResourceCapacity{})); !errors.Is(err, ErrResourceCapacity) {
		t.Fatalf("plain claim while services hold capacity = %v, want ErrResourceCapacity", err)
	}

	// Completion deletes the single row; the plain job then reserves exactly
	// its own request (no services -> zero envelope -> unchanged behavior).
	receipt := model.CompletionReceipt{JobID: svcJob, Generation: 1, RunnerID: runnerID}
	if err := st.CompleteJob(ctx, svcJob, 1, runnerID, model.StatusSuccess, "", nil, receipt); err != nil {
		t.Fatalf("complete service job: %v", err)
	}
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{}, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, pgITEnvelopeClaim(plainJob, runnerID, threeGiB, model.ResourceCapacity{})); err != nil {
		t.Fatalf("plain claim after release: %v", err)
	}
	pgITAssertReservations(t, st, runnerID, threeGiB, 1)
}

// TestIntegrationResourceReconcileServiceEnvelopePostgres: a promoted leader
// reconstructs the SAME aggregate for pre-existing running jobs — the payload
// envelope is added to the own request, a LEGACY payload without the field
// contributes zero (exactly what the pre-field ledger charged), and a corrupt
// envelope value contributes zero instead of wedging the pass. The rebuilt
// ledger blocks work the runner cannot hold.
func TestIntegrationResourceReconcileServiceEnvelopePostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID, profileID := pgITNewID(t), "env-rec-"+pgITRandomHex(t, 6)
	pgITResourceProfileRunner(t, st, runnerID, profileID, 8, model.ResourceCapacity{Memory: 16 << 30})

	runID := pgITNewID(t)
	svcJob, legacyJob, corruptJob, waiter7, waiter6 := pgITNewID(t), pgITNewID(t), pgITNewID(t), pgITNewID(t), pgITNewID(t)
	threeGiB := model.ResourceCapacity{Memory: 3 << 30}
	twoGiB := model.ResourceCapacity{Memory: 2 << 30}
	sevenGiB := model.ResourceCapacity{Memory: 7 << 30}
	sixGiB := model.ResourceCapacity{Memory: 6 << 30}
	// svc: own 3 + envelope 2 = 5; legacy: own 3, field absent; corrupt: own
	// 2, envelope not an object.
	pgITEnqueueEnvelopeJob(t, st, runID, svcJob, threeGiB, twoGiB)
	if err := st.InsertJob(ctx, pgITEnvelopeJob(runID, legacyJob, pgITRepo, threeGiB, model.ResourceCapacity{})); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertJob(ctx, pgITEnvelopeJob(runID, corruptJob, pgITRepo, twoGiB, model.ResourceCapacity{})); err != nil {
		t.Fatal(err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload = payload - 'service_envelope_request' WHERE id=$1`, legacyJob); err != nil {
		t.Fatalf("strip legacy envelope: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload = jsonb_set(payload, '{service_envelope_request}', '"corrupt"'::jsonb) WHERE id=$1`, corruptJob); err != nil {
		t.Fatalf("corrupt envelope: %v", err)
	}

	// An old-version leader created all three leases after the migration: the
	// ledger is empty (the rolling-upgrade precondition).
	pgITSimulateOldLeaderRunningJob(t, st, runnerID, svcJob, 1)
	pgITSimulateOldLeaderRunningJob(t, st, runnerID, legacyJob, 1)
	pgITSimulateOldLeaderRunningJob(t, st, runnerID, corruptJob, 1)
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{}, 0)

	res, err := st.ReconcileResourceReservations(ctx)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Running != 3 || res.Upserted != 3 || res.Deleted != 0 {
		t.Fatalf("reconcile result = %+v, want running=3 upserted=3 deleted=0", res)
	}
	// 5 (job+services) + 3 (legacy, own only) + 2 (corrupt envelope, own
	// only) = 10 GiB.
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{Memory: 10 << 30}, 3)

	// A 7 GiB queued job no longer fits (10+7 > 16); a 6 GiB one does. With
	// the pre-envelope ledger the service job would have charged 3 GiB and the
	// 7 GiB job would have been admitted (7+3+3+2 = 15 <= 16).
	if err := st.InsertJob(ctx, pgITEnvelopeJob(runID, waiter7, pgITRepo, sevenGiB, model.ResourceCapacity{})); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertJob(ctx, pgITEnvelopeJob(runID, waiter6, pgITRepo, sixGiB, model.ResourceCapacity{})); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, pgITEnvelopeClaim(waiter7, runnerID, sevenGiB, model.ResourceCapacity{})); !errors.Is(err, ErrResourceCapacity) {
		t.Fatalf("7GiB waiter after aggregate reconcile = %v, want ErrResourceCapacity", err)
	}
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{Memory: 10 << 30}, 3)
	if _, err := st.AcquireLeaseAtomic(ctx, pgITEnvelopeClaim(waiter6, runnerID, sixGiB, model.ResourceCapacity{})); err != nil {
		t.Fatalf("6GiB waiter after aggregate reconcile: %v", err)
	}
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{Memory: 16 << 30}, 4)
}
