package storage

// Resource admission and the durable per-lease resource reservation ledger.
//
// The lease claim is the ONLY place a reservation is acquired: the same
// transaction that flips a queued job to running (AcquireLeaseAtomic, and
// the in-memory mirror in faultstore.go) sums the runner's live reservations,
// checks the candidate's TOTAL request — its own CPU/memory/disk/PIDs plus
// the aggregate service envelope (LeaseClaim.RequestedResources) — against
// the runner's remaining resource capacity, and inserts the ledger row. The
// single row therefore covers the main container and every declared service;
// there is no separate service row and the release paths are unchanged. Every
// path that ends or invalidates a lease deletes the row in its own
// transaction, so no transition can strand a reservation:
//
//   - completion             (CompleteJob)
//   - run cancellation       (CancelRunJobs)
//   - supersession           (cancelSupersededTx)
//   - expired-lease recovery (RecoverExpiredLease, incl. corrupt payloads)
//   - runner revoke/disable  (RevokeRunnerLeases / DisableRunnerAndRevokeCert)
//   - legacy release helper  (ReleaseRunnerJob)
//   - queue-timeout expiry   (ExpireQueuedJob; queued jobs hold no row, the
//     delete is the documented idempotent no-op)
//
// A release is DELETE ... WHERE job_id=$1, so it is idempotent by
// construction: a replayed release removes nothing and a re-lease REPLACES
// the job's own row instead of double-counting it. job_id is the primary
// key, which makes "at most one live reservation per job" a database
// invariant rather than a discipline.
//
// Self-healing reads (K6-B): during a rolling upgrade an OLD binary can
// complete or cancel a job while the NEW binary owns the release paths, so
// that job's row is left behind with no live lease. The live SUM and the
// batched fold therefore count only rows that STILL describe a live lease —
// the job is running, still leased, and at the SAME generation the row
// recorded (liveReservationExistsSQL, the exact predicate the leader's stale
// sweep deletes by). A leaked row stops shrinking the runner's remaining
// capacity the moment this binary serves claims, with no operator action, and
// the orphan row itself is removed by the next
// ReconcileResourceReservations pass (promotion or the repair command).
//
// Capacity model: a runner's resource capacity is the linked profile's
// max_cpu/max_memory/max_disk/max_pids (migration 0030); a runner without a
// linked profile uses its registration snapshot (ResourceCapacity), which
// registrations that predate the feature leave zero. A ZERO dimension is
// UNCONSTRAINED and is skipped by the admission check, so every existing
// deployment (no capacities configured) keeps exactly its pre-0030
// behavior. Memory mode is single-process by construction: the in-memory
// store applies the same check-and-reserve under its own mutex, which is a
// capacity guarantee inside one process, not across replicas.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// ErrResourceCapacity means the atomic lease's resource reservation
// predicate rejected the candidate: the runner's remaining resource capacity
// (per dimension with a configured capacity) cannot fit the job's requested
// resources. The whole lease transaction rolled back — no job claim, no
// runner slot, no reservation — and the scheduler tries the next candidate.
var ErrResourceCapacity = errors.New("storage: runner resource capacity exceeded")

// ResourceReservation is one durable per-lease reservation row: the
// resources of a RUNNING job charged against its runner until the lease
// ends. Generation records the lease generation that acquired it, so an
// operator can correlate a row with the job's lease.
type ResourceReservation struct {
	JobID      string
	RunnerID   string
	Generation int64
	CPU        float64
	Memory     int64
	Disk       int64
	PIDs       int
	CreatedAt  time.Time
}

// Capacity returns the reservation's quantities as a ResourceCapacity.
func (r ResourceReservation) Capacity() model.ResourceCapacity {
	return model.ResourceCapacity{CPU: r.CPU, Memory: r.Memory, Disk: r.Disk, PIDs: r.PIDs}
}

// ResourceAdmission is the ONE resource-capacity predicate every lease path
// shares (the SQL claim transaction, the in-memory claim, the scheduler's
// candidate pre-filter and the queue-reason explainer). Capacity carries the
// runner's configured capacities (zero = unconstrained dimension), Reserved
// the live sum of its running jobs' reservations and Requested the
// candidate's requests.
type ResourceAdmission struct {
	Capacity  model.ResourceCapacity
	Reserved  model.ResourceCapacity
	Requested model.ResourceCapacity
}

// Allows reports whether the requested resources fit the runner's REMAINING
// capacity. Unconstrained (zero) capacity dimensions impose no limit, so a
// runner with no configured capacities admits every job (documented
// unconstrained-count behavior: only the job-count capacity applies).
func (a ResourceAdmission) Allows() bool {
	return !a.ExceedsRemaining()
}

// EverSatisfiable reports whether the runner's CONFIGURED capacity can fit
// the request at all, ignoring what is currently reserved. A false result
// means no amount of waiting frees the runner for this job: the queue
// explainer surfaces the existing "no compatible runner" semantics instead
// of an infinite RUNNER_CAPACITY wait.
func (a ResourceAdmission) EverSatisfiable() bool {
	return !overCapacity(a.Capacity, a.Requested)
}

// ExceedsRemaining reports whether any constrained dimension's reserved +
// requested quantity exceeds the capacity.
func (a ResourceAdmission) ExceedsRemaining() bool {
	if a.Capacity.CPU > 0 && a.Reserved.CPU+a.Requested.CPU > a.Capacity.CPU {
		return true
	}
	if a.Capacity.Memory > 0 && a.Reserved.Memory+a.Requested.Memory > a.Capacity.Memory {
		return true
	}
	if a.Capacity.Disk > 0 && a.Reserved.Disk+a.Requested.Disk > a.Capacity.Disk {
		return true
	}
	if a.Capacity.PIDs > 0 && a.Reserved.PIDs+a.Requested.PIDs > a.Capacity.PIDs {
		return true
	}
	return false
}

// overCapacity reports whether the request alone exceeds a configured
// capacity in any dimension (the permanent-incompatibility test).
func overCapacity(capacity, requested model.ResourceCapacity) bool {
	if capacity.CPU > 0 && requested.CPU > capacity.CPU {
		return true
	}
	if capacity.Memory > 0 && requested.Memory > capacity.Memory {
		return true
	}
	if capacity.Disk > 0 && requested.Disk > capacity.Disk {
		return true
	}
	if capacity.PIDs > 0 && requested.PIDs > capacity.PIDs {
		return true
	}
	return false
}

// reserveResourcesTx implements the claim's check-and-reserve inside the
// caller's lease transaction: it reads the live SUM of the runner's
// reservations, evaluates the shared ResourceAdmission predicate against
// capacity, and inserts the ledger row. capacity is the runner's effective
// resource capacity the claim resolved (live profile first, registration
// snapshot second); the runner row is locked by the caller, so the SUM
// cannot move under a concurrent claim for the same runner.
//
// The reserved quantities are the claim's TOTAL request — the candidate job's
// own request PLUS its aggregate service envelope (LeaseClaim.
// RequestedResources, the same model.Job.ReservedResources the scheduler
// pre-filter and the fs/dev path charge) — so the single row per job covers
// the main container and every declared service; there is no separate service
// row and the release paths are unchanged.
//
// The SUM EXCLUDES the candidate job's own row: a surviving stale row for
// THIS job (a release a crashed replica never completed, or a pre-reconcile
// row with an older generation) must never make the job count its own
// request twice and spuriously fail the claim. The DELETE below replaces that
// row, so the exclusion cannot under-count a live sibling.
func reserveResourcesTx(ctx context.Context, tx pgx.Tx, claim LeaseClaim, capacity model.ResourceCapacity) error {
	reserved, err := runnerReservedResourcesExcludingTx(ctx, tx, claim.RunnerID, claim.JobID)
	if err != nil {
		return err
	}
	requested := claim.RequestedResources()
	admission := ResourceAdmission{Capacity: capacity, Reserved: reserved, Requested: requested}
	if !admission.Allows() {
		return fmt.Errorf("%w: runner %s requested cpu=%v memory=%d disk=%d pids=%d, reserved cpu=%v memory=%d disk=%d pids=%d, capacity cpu=%v memory=%d disk=%d pids=%d",
			ErrResourceCapacity, claim.RunnerID,
			requested.CPU, requested.Memory, requested.Disk, requested.PIDs,
			reserved.CPU, reserved.Memory, reserved.Disk, reserved.PIDs,
			capacity.CPU, capacity.Memory, capacity.Disk, capacity.PIDs)
	}
	// Replace any stale row for this job (a re-lease after a release a
	// crashed replica could not complete): the job_id primary key keeps at
	// most one live reservation per job, so a re-lease can never
	// double-charge the runner.
	if _, err := tx.Exec(ctx, `DELETE FROM job_resource_reservations WHERE job_id=$1`, claim.JobID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO job_resource_reservations (job_id, runner_id, generation, cpu, memory, disk, pids) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		claim.JobID, claim.RunnerID, claim.Generation, requested.CPU, requested.Memory, requested.Disk, requested.PIDs); err != nil {
		return err
	}
	return nil
}

// releaseResourcesTx deletes one job's reservation row inside the caller's
// transaction. It is idempotent (a missing row is a no-op) and needs no
// payload: the primary key is the whole identity, so even a corrupt job
// payload can release its capacity exactly once.
func releaseResourcesTx(ctx context.Context, tx pgx.Tx, jobID string) error {
	_, err := tx.Exec(ctx, `DELETE FROM job_resource_reservations WHERE job_id=$1`, jobID)
	return err
}

// rowQuerier is the narrow read surface shared by pgx.Tx and *pgxpool.Pool
// for the reservation reads, so the same SUM/listing helpers serve both the
// claim transaction and the exported observation API.
type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// liveReservationExistsSQL is the ONE "this row still describes a live lease"
// predicate (alias r), shared by the capacity SUM, the batched fleet fold and
// the leader's stale sweep so all three can never disagree about which rows
// count. A row is live only when its job is still running, still leased, and
// still at the generation the row recorded: an old-replica completion or a
// crashed release leaves a row that fails this test, and such a row must
// neither shrink the runner's remaining capacity nor survive a reconcile.
const liveReservationExistsSQL = `EXISTS (
			SELECT 1 FROM jobs j
			WHERE j.id = r.job_id
			  AND j.status = 'running'
			  AND COALESCE(j.lease_runner_id, '') <> ''
			  AND j.lease_generation = r.generation
		)`

// runnerReservedResourcesTx sums the runner's LIVE reservations inside the
// caller's transaction (or over the pool for the observation API). No live
// row means zero on every dimension; a stale row a pre-upgrade replica left
// behind contributes nothing.
func runnerReservedResourcesTx(ctx context.Context, q rowQuerier, runnerID string) (model.ResourceCapacity, error) {
	return runnerReservedResourcesExcludingTx(ctx, q, runnerID, "")
}

// runnerReservedResourcesExcludingTx is runnerReservedResourcesTx with one
// job's row excluded from the SUM (empty excludeJobID sums every live row).
// The lease claim excludes the candidate's own row so a stale row for the
// SAME job can never double-count against it.
func runnerReservedResourcesExcludingTx(ctx context.Context, q rowQuerier, runnerID, excludeJobID string) (model.ResourceCapacity, error) {
	var out model.ResourceCapacity
	err := q.QueryRow(ctx, `SELECT COALESCE(SUM(r.cpu), 0), COALESCE(SUM(r.memory), 0), COALESCE(SUM(r.disk), 0), COALESCE(SUM(r.pids), 0) FROM job_resource_reservations r WHERE r.runner_id=$1 AND ($2 = '' OR r.job_id <> $2) AND `+liveReservationExistsSQL, runnerID, excludeJobID).
		Scan(&out.CPU, &out.Memory, &out.Disk, &out.PIDs)
	if err != nil {
		return model.ResourceCapacity{}, err
	}
	return out, nil
}

// ResourceReservationStore exposes the durable reservation ledger for
// observability and tests: the per-runner sums prove that every release path
// leaves no leak, and the listing proves exactly-once release. PostgresStore
// and the in-memory store implement it.
type ResourceReservationStore interface {
	// RunnerReservedResources sums the resources currently reserved by the
	// runner's running jobs (zero when nothing is reserved). Only rows whose
	// job is still running, still leased and at the recorded generation
	// count: a row an old replica left behind after a completion it served
	// contributes zero immediately (see liveReservationExistsSQL), so a
	// rolling upgrade can never shrink a runner's capacity permanently.
	RunnerReservedResources(ctx context.Context, runnerID string) (model.ResourceCapacity, error)
	// ListResourceReservations returns the runner's ledger rows ordered by
	// job ID (empty when none). The listing is RAW: it reports every stored
	// row, including a stale row a pre-upgrade replica left behind (which the
	// SUM already ignores and the next reconcile deletes), so operators can
	// see exactly what a repair pass will sweep.
	ListResourceReservations(ctx context.Context, runnerID string) ([]ResourceReservation, error)
}

// RunnerReservedResources implements ResourceReservationStore.
func (s *PostgresStore) RunnerReservedResources(ctx context.Context, runnerID string) (model.ResourceCapacity, error) {
	return runnerReservedResourcesTx(ctx, s.pool, runnerID)
}

// ListResourceReservations implements ResourceReservationStore.
func (s *PostgresStore) ListResourceReservations(ctx context.Context, runnerID string) ([]ResourceReservation, error) {
	if err := ValidateRunnerID(runnerID); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT job_id, runner_id, generation, cpu, memory, disk, pids, created_at FROM job_resource_reservations WHERE runner_id=$1 ORDER BY job_id ASC`, runnerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ResourceReservation{}
	for rows.Next() {
		var r ResourceReservation
		if err := rows.Scan(&r.JobID, &r.RunnerID, &r.Generation, &r.CPU, &r.Memory, &r.Disk, &r.PIDs, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

var _ ResourceReservationStore = (*PostgresStore)(nil)
