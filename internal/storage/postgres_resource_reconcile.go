package storage

// Leader-promotion reconciliation of the durable resource reservation
// ledger (migration 0030) and the shared repair entry point around it.
//
// The ledger is populated exclusively by the atomic lease claim, so a
// database that predates the feature (or was mid-upgrade while an
// OLD-version leader kept claiming jobs) can hold RUNNING leased jobs with
// ZERO reservation rows. A new-version replica that becomes leader would then
// sum an empty ledger and admit work the runner cannot hold — the
// rolling-upgrade over-admission window. ReconcileResourceReservations closes
// it: it derives the ledger from the authoritative persisted lease state
// (status=running + lease_runner_id + lease_generation + the payload's
// request fields), repairs stale rows, and must complete BEFORE the promoting
// leader issues any lease (Server.ensureResourceReconciled).
//
// The operation is idempotent and safe to re-run concurrently: the whole
// reconcile runs in ONE transaction, serialized by a transaction-scoped
// advisory lock, and leader-fenced by the store's retained epoch, so a stale
// leader mutates nothing (ErrStaleLeader) and two promoting replicas cannot
// interleave their DELETE/UPSERT phases. Reservation rows written
// concurrently by a claim are protected by the (job_id) primary key and the
// generation guard below: reconcile never downgrades a freshly claimed
// generation.
//
// The reconstructed quantities are the job's TOTAL reservation: its own
// request PLUS the aggregate service envelope persisted in the payload
// (service_envelope_request.cpu/memory/pids), the same total the claim's
// reserveResourcesTx writes, so a rolling upgrade cannot under-reserve a
// running job with services. A legacy payload without the field contributes
// zero, which reproduces the pre-field reservation exactly (the documented
// backward-compatible behavior); the pre-field ledger never charged an
// envelope, so nothing regresses for those rows.

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// ResourceReconcileResult reports what one reconciliation pass observed and
// changed. Repeated passes on unchanged data report the same Running count
// and zero Deleted rows (idempotence), while Upserted counts the ledger rows
// (re)written for live leases.
type ResourceReconcileResult struct {
	// Running is the number of running jobs holding a live lease that the
	// pass scanned (the authoritative source rows).
	Running int
	// Upserted is the number of ledger rows written for those jobs.
	Upserted int
	// Deleted is the number of ledger rows removed because they no longer
	// describe a live running lease (job not running, no lease runner, or a
	// stale generation).
	Deleted int
}

// ResourceReconcileStore is the leader-only reconciliation contract behind
// the promotion hook and the operator repair path. PostgresStore enforces it
// inside one leader-fenced transaction; the in-memory store rebuilds its
// reservation map under its own mutex (single-process semantics).
//
// A store that does not implement the contract cannot have diverged from its
// own claim path (the ledger is derived from it), so callers treat the
// absence as "nothing to reconcile".
type ResourceReconcileStore interface {
	// ReconcileResourceReservations rebuilds the runner resource reservation
	// ledger from the running jobs' live leases: it upserts one reservation
	// per running leased job (job, runner, generation, requested resources)
	// and deletes every row that does not correspond to such a job.
	ReconcileResourceReservations(ctx context.Context) (ResourceReconcileResult, error)
}

// ReconcileResourceReservations implements ResourceReconcileStore for the
// SQL ledger. See the file comment for the ordering contract (BEFORE lease
// issuance on promotion) and the concurrency argument.
func (s *PostgresStore) ReconcileResourceReservations(ctx context.Context) (ResourceReconcileResult, error) {
	tx, err := s.beginFencedTx(ctx)
	if err != nil {
		return ResourceReconcileResult{}, err
	}
	defer tx.Rollback(ctx)

	// One reconcile at a time across replicas: a promoting leader and a
	// repair pass (or two racing promotions) serialize here instead of
	// interleaving their DELETE/UPSERT phases.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockKey("kiwi-resource-reconcile", "global")); err != nil {
		return ResourceReconcileResult{}, err
	}

	res := ResourceReconcileResult{}
	// Phase 1: drop rows that do not describe a live lease. This covers
	// both "job no longer running" and "stale generation" rows; the upsert
	// below re-creates the row for a running job whose generation matches.
	deleted, err := deleteStaleReservationsTx(ctx, tx)
	if err != nil {
		return ResourceReconcileResult{}, err
	}
	res.Deleted += deleted

	// Phase 2: the authoritative request of every running leased job is
	// derived from the persisted job row (status + lease identity) and its
	// payload, never from a caller-supplied value. The generation guard
	// keeps a concurrent re-lease's fresh row authoritative. The payload
	// reads are type-guarded: a corrupt request value contributes zero
	// instead of failing the whole pass (a corrupt payload cannot be leased
	// again — it is terminally recovered by the expiry sweep — so zero is
	// the only knowable answer, and the pass must not wedge lease issuance).
	rows, err := tx.Query(ctx, `INSERT INTO job_resource_reservations (job_id, runner_id, generation, cpu, memory, disk, pids)
		SELECT j.id, j.lease_runner_id, j.lease_generation, `+resourceRequestSQL+`
		FROM jobs j
		WHERE j.status = 'running' AND COALESCE(j.lease_runner_id, '') <> ''
		ON CONFLICT (job_id) DO UPDATE
			SET runner_id = EXCLUDED.runner_id,
			    generation = EXCLUDED.generation,
			    cpu = EXCLUDED.cpu,
			    memory = EXCLUDED.memory,
			    disk = EXCLUDED.disk,
			    pids = EXCLUDED.pids
			WHERE job_resource_reservations.generation <= EXCLUDED.generation
		RETURNING job_id`)
	if err != nil {
		return ResourceReconcileResult{}, err
	}
	for rows.Next() {
		var jobID string
		if err := rows.Scan(&jobID); err != nil {
			rows.Close()
			return ResourceReconcileResult{}, err
		}
		res.Upserted++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return ResourceReconcileResult{}, err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE status = 'running' AND COALESCE(lease_runner_id, '') <> ''`).Scan(&res.Running); err != nil {
		return ResourceReconcileResult{}, err
	}

	// Phase 3: repeat the stale sweep. A completion/recovery that committed
	// between phases 1 and 2 is invisible to phase 1 and could have its row
	// re-created by phase 2 from the stale snapshot; this second sweep sees
	// the committed state and removes it. The symmetric interleavings are
	// covered by the concurrent transaction's own release DELETE.
	deleted, err = deleteStaleReservationsTx(ctx, tx)
	if err != nil {
		return ResourceReconcileResult{}, err
	}
	res.Deleted += deleted

	if err := tx.Commit(ctx); err != nil {
		return ResourceReconcileResult{}, err
	}
	return res, nil
}

// resourceRequestSQL renders the four request values of a running job row
// (alias j) from its payload, defaulting an absent or unparseable value to
// zero. The job's OWN request and its aggregate service envelope
// (service_envelope_request) are summed here, matching
// LeaseClaim.RequestedResources / model.Job.ReservedResources exactly, so the
// promoted leader's ledger equals what the claim would have written. The
// legacy case — a payload persisted before the envelope field — contributes
// zero envelope, which is precisely what the pre-field reservation charged.
// The regex guards keep a corrupt payload (including a non-object
// service_envelope_request) from aborting the pass with a cast error: a
// corrupt value contributes zero, the only knowable answer, and the job is
// terminally recovered by the expiry sweep rather than leased again.
const resourceRequestSQL = `
	       COALESCE(CASE WHEN (j.payload->>'cpu_request') ~ '^[0-9.eE+-]+$' THEN (j.payload->>'cpu_request')::double precision END, 0)
	       + COALESCE(CASE WHEN (j.payload->'service_envelope_request'->>'cpu') ~ '^[0-9.eE+-]+$' THEN (j.payload->'service_envelope_request'->>'cpu')::double precision END, 0),
	       COALESCE(CASE WHEN (j.payload->>'memory_request') ~ '^[0-9]+$' THEN (j.payload->>'memory_request')::bigint END, 0)
	       + COALESCE(CASE WHEN (j.payload->'service_envelope_request'->>'memory') ~ '^[0-9]+$' THEN (j.payload->'service_envelope_request'->>'memory')::bigint END, 0),
	       COALESCE(CASE WHEN (j.payload->>'disk_request') ~ '^[0-9]+$' THEN (j.payload->>'disk_request')::bigint END, 0)
	       + COALESCE(CASE WHEN (j.payload->'service_envelope_request'->>'disk') ~ '^[0-9]+$' THEN (j.payload->'service_envelope_request'->>'disk')::bigint END, 0),
	       COALESCE(CASE WHEN (j.payload->>'pids_request') ~ '^[0-9]+$' THEN (j.payload->>'pids_request')::int END, 0)
	       + COALESCE(CASE WHEN (j.payload->'service_envelope_request'->>'pids') ~ '^[0-9]+$' THEN (j.payload->'service_envelope_request'->>'pids')::int END, 0)`

// deleteStaleReservationsTx removes every reservation row that does not match
// a running job's live lease identity (job id, runner, generation) and
// returns the number of rows deleted.
func deleteStaleReservationsTx(ctx context.Context, tx pgx.Tx) (int, error) {
	ct, err := tx.Exec(ctx, `DELETE FROM job_resource_reservations AS r
		WHERE NOT EXISTS (
			SELECT 1 FROM jobs j
			WHERE j.id = r.job_id
			  AND j.status = 'running'
			  AND COALESCE(j.lease_runner_id, '') <> ''
			  AND j.lease_generation = r.generation
		)`)
	if err != nil {
		return 0, err
	}
	return int(ct.RowsAffected()), nil
}

var _ ResourceReconcileStore = (*PostgresStore)(nil)
