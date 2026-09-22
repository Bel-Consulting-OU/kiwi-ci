package storage

// Real-PostgreSQL integration tests for the leader-promotion resource
// reconciliation (E4-B). Gated on KIWI_TEST_POSTGRES_URL like every
// *_it_test.go here.
//
// The defect these pin: migration 0030 leaves an EMPTY reservation ledger, so
// a rolling upgrade can over-admit — an old-version leader keeps creating
// running jobs after the migration, and when a new-version replica becomes
// leader the reservation SUM is too small. The promotion hook must rebuild
// the ledger from the authoritative persisted lease state BEFORE any lease is
// issued, drop rows that no longer describe a live lease, and be idempotent,
// repair-callable and safe under concurrent promotion.

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITSimulateOldLeaderRunningJob marks a queued job as running under a lease
// WITHOUT writing a reservation row — exactly what an old-version leader (or a
// pre-0030 database) leaves behind — and appends it to the runner's active
// set like that leader's claim would have.
func pgITSimulateOldLeaderRunningJob(t *testing.T, st *PostgresStore, runnerID, jobID string, generation int64) {
	t.Helper()
	ctx := context.Background()
	ct, err := st.pool.Exec(ctx, `UPDATE jobs SET status='running', attempts = attempts + 1, started_at = COALESCE(started_at, now()), lease_runner_id=$2, lease_token_hash='x'::bytea, lease_generation=$3, lease_expires_at=now() + interval '1 hour' WHERE id=$1`,
		jobID, runnerID, generation)
	if err != nil {
		t.Fatalf("simulate old leader job %s: %v", jobID, err)
	}
	if ct.RowsAffected() != 1 {
		t.Fatalf("simulate old leader job %s: no row updated", jobID)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE runners SET active_jobs = COALESCE(active_jobs, '[]'::jsonb) || to_jsonb($2::text) WHERE id=$1`, runnerID, jobID); err != nil {
		t.Fatalf("simulate old leader runner active jobs: %v", err)
	}
}

// pgITReservationGeneration reads one job's ledger generation (0, false when
// absent).
func pgITReservationGeneration(t *testing.T, st *PostgresStore, jobID string) (int64, bool) {
	t.Helper()
	var generation int64
	err := st.pool.QueryRow(context.Background(), `SELECT generation FROM job_resource_reservations WHERE job_id=$1`, jobID).Scan(&generation)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false
	}
	if err != nil {
		t.Fatalf("read reservation generation for %s: %v", jobID, err)
	}
	return generation, true
}

// TestIntegrationResourceReconcilePromotionPostgres (E4-B): a promoted
// leader rebuilds the ledger from pre-existing running jobs (real running
// rows written directly, as an old-version leader would), drops stale rows
// (job not running, stale generation), and the rebuilt ledger then BLOCKS a
// claim that would oversubscribe the runner. Repeated passes are idempotent
// and the repair call converges on the same ledger.
func TestIntegrationResourceReconcilePromotionPostgres(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID, profileID := pgITNewID(t), "res-rec-"+pgITRandomHex(t, 6)
	pgITResourceProfileRunner(t, st, runnerID, profileID, 8, model.ResourceCapacity{Memory: 8 << 30})
	runID := pgITNewID(t)
	old1, old2, queued := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	pgITResourceEnqueue(t, st, runID, old1, pgITRepo, model.ResourceCapacity{Memory: 5 << 30})
	if err := st.InsertJob(ctx, pgITResourceJob(runID, old2, pgITRepo, model.ResourceCapacity{Memory: 3 << 30})); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertJob(ctx, pgITResourceJob(runID, queued, pgITRepo, model.ResourceCapacity{Memory: 4 << 30})); err != nil {
		t.Fatal(err)
	}

	// An OLD-version leader created two running leases after the migration:
	// the ledger is empty (the defect's precondition).
	pgITSimulateOldLeaderRunningJob(t, st, runnerID, old1, 1)
	pgITSimulateOldLeaderRunningJob(t, st, runnerID, old2, 3)
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{}, 0)

	// Two stale rows: a leftover for a job that is not running, and a
	// wrong-generation row for a running job.
	if _, err := st.pool.Exec(ctx, `INSERT INTO job_resource_reservations (job_id, runner_id, generation, cpu, memory, disk, pids) VALUES ($1, $2, 0, 0, 1048576, 0, 0)`, queued, runnerID); err != nil {
		t.Fatalf("plant queued-job row: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `INSERT INTO job_resource_reservations (job_id, runner_id, generation, cpu, memory, disk, pids) VALUES ($1, $2, 2, 0, 1048576, 0, 0)`, old2, runnerID); err != nil {
		t.Fatalf("plant stale-generation row: %v", err)
	}

	res, err := st.ReconcileResourceReservations(ctx)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Running != 2 || res.Upserted != 2 || res.Deleted != 2 {
		t.Fatalf("reconcile result = %+v, want running=2 upserted=2 deleted=2", res)
	}
	// The authoritative request is derived from the persisted job payload,
	// and the stale rows are gone: 5 GiB + 3 GiB charged, no more, no less.
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{Memory: 8 << 30}, 2)
	if generation, ok := pgITReservationGeneration(t, st, queued); ok {
		t.Fatalf("queued job still holds a reservation (generation %d)", generation)
	}
	if generation, ok := pgITReservationGeneration(t, st, old2); !ok || generation != 3 {
		t.Fatalf("old job %s generation = %d (present=%v), want the live lease's 3", old2, generation, ok)
	}

	// The ledger now blocks the 4 GiB waiter: the runner's remaining
	// capacity is zero. This is the over-admission the empty ledger allowed.
	if _, err := st.AcquireLeaseAtomic(ctx, pgITResourceClaim(queued, runnerID, model.ResourceCapacity{Memory: 4 << 30})); !errors.Is(err, ErrResourceCapacity) {
		t.Fatalf("claim after reconciliation = %v, want ErrResourceCapacity", err)
	}
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{Memory: 8 << 30}, 2)

	// Idempotent repeat: nothing to delete, the same rows rewritten.
	res2, err := st.ReconcileResourceReservations(ctx)
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if res2.Running != 2 || res2.Upserted != 2 || res2.Deleted != 0 {
		t.Fatalf("second reconcile result = %+v, want running=2 upserted=2 deleted=0", res2)
	}
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{Memory: 8 << 30}, 2)

	// Completion releases one lease; the repair path reconciles the rest.
	if err := st.CompleteJob(ctx, old1, 1, runnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: old1, Generation: 1, RunnerID: runnerID}); err != nil {
		t.Fatalf("complete old job: %v", err)
	}
	if _, err := st.ReconcileResourceReservations(ctx); err != nil {
		t.Fatalf("repair reconcile: %v", err)
	}
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{Memory: 3 << 30}, 1)
	if _, err := st.AcquireLeaseAtomic(ctx, pgITResourceClaim(queued, runnerID, model.ResourceCapacity{Memory: 4 << 30})); err != nil {
		t.Fatalf("waiter lease after repair: %v", err)
	}
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{Memory: 7 << 30}, 2)
}

// TestIntegrationResourceReconcileStaleLeaderPostgres (E4-B): the
// reconciliation is leader-fenced. A store that retains no (or a stale)
// leadership epoch mutates nothing.
func TestIntegrationResourceReconcileStaleLeaderPostgres(t *testing.T) {
	env := pgITSetup(t)
	st := env.open(t)
	env.migrate(t, st)
	pgITArmFence(t, st)
	ctx := context.Background()
	runnerID, profileID := pgITNewID(t), "res-stale-"+pgITRandomHex(t, 6)
	pgITResourceProfileRunner(t, st, runnerID, profileID, 8, model.ResourceCapacity{Memory: 8 << 30})
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITResourceEnqueue(t, st, runID, jobID, pgITRepo, model.ResourceCapacity{Memory: 5 << 30})
	pgITSimulateOldLeaderRunningJob(t, st, runnerID, jobID, 1)

	standby := env.open(t)
	if _, err := standby.ReconcileResourceReservations(ctx); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("standby reconcile error = %v, want ErrStaleLeader", err)
	}
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{}, 0)

	// A wrong retained epoch fails the same way (split-brain window).
	if _, err := st.pool.Exec(ctx, `UPDATE leader_fence SET epoch = epoch + 1`); err != nil { // simulate a newer leader's publication
		t.Fatal(err)
	}
	if _, err := st.ReconcileResourceReservations(ctx); !errors.Is(err, ErrStaleLeader) {
		t.Fatalf("stale-epoch reconcile error = %v, want ErrStaleLeader", err)
	}
	pgITAssertReservations(t, st, runnerID, model.ResourceCapacity{}, 0)
}

// TestIntegrationResourceReconcileConcurrentPromotionPostgres (E4-B): two
// replicas reconciling concurrently (both fence-armed, as after a contested
// promotion) while claims run cannot lose or duplicate reservations: every
// ledger row matches a running job and the runner's SUM equals the running
// jobs' requests, with exactly the resource capacity admitting work.
func TestIntegrationResourceReconcileConcurrentPromotionPostgres(t *testing.T) {
	env := pgITSetup(t)
	stA := env.open(t)
	env.migrate(t, stA)
	pgITArmFence(t, stA)
	stB := env.open(t)
	pgITArmFence(t, stB)

	ctx := context.Background()
	runnerID, profileID := pgITNewID(t), "res-race-rec-"+pgITRandomHex(t, 6)
	twoGiB := model.ResourceCapacity{Memory: 2 << 30}
	pgITResourceProfileRunner(t, stA, runnerID, profileID, 8, model.ResourceCapacity{Memory: 8 << 30})
	runID := pgITNewID(t)
	// Two running leases from the previous (old-version) leader: 4 GiB
	// charged, no ledger rows.
	pre1, pre2 := pgITNewID(t), pgITNewID(t)
	pgITResourceEnqueue(t, stA, runID, pre1, pgITRepo, twoGiB)
	if err := stA.InsertJob(ctx, pgITResourceJob(runID, pre2, pgITRepo, twoGiB)); err != nil {
		t.Fatal(err)
	}
	pgITSimulateOldLeaderRunningJob(t, stA, runnerID, pre1, 1)
	pgITSimulateOldLeaderRunningJob(t, stA, runnerID, pre2, 1)
	// Four queued 2 GiB jobs: exactly two can fit the remaining 4 GiB.
	jobIDs := make([]string, 4)
	for i := range jobIDs {
		jobIDs[i] = pgITNewID(t)
		if err := stA.InsertJob(ctx, pgITResourceJob(runID, jobIDs[i], pgITRepo, twoGiB)); err != nil {
			t.Fatal(err)
		}
	}

	var wg sync.WaitGroup
	errorsCh := make(chan error, 16)
	for _, st := range []*PostgresStore{stA, stB} {
		wg.Add(1)
		go func(st *PostgresStore) {
			defer wg.Done()
			for i := 0; i < 3; i++ {
				if _, err := st.ReconcileResourceReservations(ctx); err != nil {
					errorsCh <- err
					return
				}
			}
		}(st)
		for _, jobID := range jobIDs {
			wg.Add(1)
			go func(st *PostgresStore, jobID string) {
				defer wg.Done()
				_, err := st.AcquireLeaseAtomic(ctx, pgITResourceClaim(jobID, runnerID, twoGiB))
				if err != nil && !errors.Is(err, ErrResourceCapacity) && !errors.Is(err, ErrLeaseConflict) && !errors.Is(err, ErrNoCapacity) {
					errorsCh <- err
				}
			}(st, jobID)
		}
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Fatalf("concurrent promotion error: %v", err)
	}

	// Every row must match a running job's live lease; no stale row may
	// survive a reconcile, and the SUM must equal the running requests.
	var mismatches int
	if err := stA.pool.QueryRow(ctx, `SELECT count(*) FROM job_resource_reservations r
		WHERE NOT EXISTS (
			SELECT 1 FROM jobs j WHERE j.id = r.job_id AND j.status = 'running'
			  AND COALESCE(j.lease_runner_id, '') <> '' AND j.lease_generation = r.generation
		)`).Scan(&mismatches); err != nil {
		t.Fatal(err)
	}
	if mismatches != 0 {
		t.Fatalf("%d ledger rows do not match a live running lease", mismatches)
	}
	var runningRequests int64
	if err := stA.pool.QueryRow(ctx, `SELECT COALESCE(SUM(COALESCE((payload->>'memory_request')::bigint, 0)), 0) FROM jobs WHERE status='running' AND COALESCE(lease_runner_id, '') <> ''`).Scan(&runningRequests); err != nil {
		t.Fatal(err)
	}
	reserved, err := stA.RunnerReservedResources(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Memory != runningRequests {
		t.Fatalf("reserved memory = %d, want the running jobs' sum %d", reserved.Memory, runningRequests)
	}
	if runningRequests != 8<<30 {
		t.Fatalf("running requests = %d, want exactly 8 GiB (capacity: 4 GiB pre-existing + 4 GiB newly leased)", runningRequests)
	}
}
