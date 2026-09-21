package storage

// Transactional lease recovery and revocation for PostgresStore.
//
// Each method below is ONE database transaction covering the complete
// transition: the job row and payload, the lease fields, the runner's
// active_jobs/counters, the quota reservation counters, dependent jobs, the
// run aggregation and the audit event. The previous scheduler-side sequence
// (UpdateJob, then ReleaseRunnerJob, then a best-effort quota adjustment) is
// deliberately gone: a crash between those steps could leave a job that no
// longer matches the running+leased predicate while its runner slot and
// quota reservation stayed stranded forever.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

var _ RecoveryStore = (*PostgresStore)(nil)

// insertRecoveryAuditTx writes one recovery audit event inside the caller's
// transaction, so the evidence commits with the transition it describes.
func insertRecoveryAuditTx(ctx context.Context, tx pgx.Tx, action, actor string, j model.Job, msg string, meta map[string]string, now time.Time) error {
	auditID, err := newID()
	if err != nil {
		return err
	}
	metaJSON, err := jsonMarshal(meta)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events (id, action, actor, run_id, job_id, message, metadata, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		auditID, action, actor, j.RunID, j.ID, msg, metaJSON, now)
	return err
}

// RevokeRunnerLeases invalidates every running lease held by runnerID in ONE
// transaction (see RecoveryStore.RevokeRunnerLeases). Lock order is jobs
// first, then the runner row — the same job -> runner order AcquireLeaseAtomic,
// CompleteJob and RecoverExpiredLease use, so revocation can never deadlock
// against a concurrent claim or completion.
//
// This is deliberately NOT epoch-fenced: it is the runner-disable kill switch
// driven by an admin API call that must work on any replica (and the
// two-replica regression races it through both stores), it is transactional
// and idempotent, and it revokes only leases the named runner holds — there is
// no leader-owned state for a stale leader to corrupt.
func (s *PostgresStore) RevokeRunnerLeases(ctx context.Context, runnerID, reason string) ([]string, error) {
	if err := ValidateRunnerID(runnerID); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	revoked, _, err := s.revokeRunnerLeasesTx(ctx, tx, runnerID, reason, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return revoked, nil
}

// revokeRunnerLeasesTx applies the complete runner-scoped lease revocation
// (phases 1-3 of the kill switch) inside the caller's transaction and returns
// the revoked job IDs plus the affected run IDs. RevokeRunnerLeases and the
// atomic runner disable share it, so both transitions move the job rows, the
// quota counters, the runner active set/counters, the dependents and the run
// aggregations identically. Lock order is jobs first, then the runner row —
// the order AcquireLeaseAtomic, CompleteJob and RecoverExpiredLease use.
func (s *PostgresStore) revokeRunnerLeasesTx(ctx context.Context, tx pgx.Tx, runnerID, reason string, now time.Time) ([]string, map[string]struct{}, error) {
	// Phase 1: lock every running lease of the runner. The cursor is closed
	// before any UPDATE (pgx forbids Exec on an open cursor connection).
	rows, err := tx.Query(ctx, `SELECT `+jobCols+` FROM jobs WHERE status='running' AND lease_runner_id=$1 ORDER BY id FOR UPDATE`, runnerID)
	if err != nil {
		return nil, nil, err
	}
	leased := []model.Job{}
	for rows.Next() {
		js := jobScanner{}
		if err := rows.Scan(jobTargets(&js)...); err != nil {
			rows.Close()
			return nil, nil, err
		}
		j, err := js.job()
		if err != nil {
			rows.Close()
			return nil, nil, err
		}
		leased = append(leased, j)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if len(leased) == 0 {
		// Nothing to revoke: idempotent replay of a concurrent replica.
		return []string{}, map[string]struct{}{}, nil
	}

	revoked := make([]string, 0, len(leased))
	runIDs := map[string]struct{}{}
	for _, j := range leased {
		// Same decision RecoverExpired makes from the lease-time increment:
		// a lease consumes exactly one attempt, the recovery path only reads
		// the retry budget.
		requeue := j.Attempts <= j.MaxInfraRetries
		if requeue {
			j.Status = model.StatusQueued
			j.Error = reason + "; retrying"
		} else {
			j.Status = model.StatusCancelled
			j.Error = reason
			j.FinishedAt = &now
		}
		j.LeaseRunnerID = ""
		j.LeaseTokenHash = nil
		j.LeaseExpiresAt = nil
		jp, err := jsonMarshal(j)
		if err != nil {
			return nil, nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE jobs SET status=$2, error=$3, finished_at=$4, lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL, payload=$5 WHERE id=$1`,
			j.ID, string(j.Status), nullText(j.Error), j.FinishedAt, jp); err != nil {
			return nil, nil, err
		}
		// The invalidated lease releases its running reservation; a requeued
		// job re-reserves a queued slot in the same statement pair.
		if requeue {
			if err := s.adjustQuotaTx(ctx, tx, RepoIDForJob(j), -1, 1); err != nil {
				return nil, nil, err
			}
		} else {
			if err := s.adjustQuotaTx(ctx, tx, RepoIDForJob(j), -1, 0); err != nil {
				return nil, nil, err
			}
		}
		action := "job.runner_disabled_cancelled"
		if requeue {
			action = "job.runner_disabled_requeued"
		}
		if err := insertRecoveryAuditTx(ctx, tx, action, "admin", j, reason, map[string]string{"job": j.Key, "runner": runnerID}, now); err != nil {
			return nil, nil, err
		}
		revoked = append(revoked, j.ID)
		if j.RunID != "" {
			runIDs[j.RunID] = struct{}{}
		}
	}

	// Phase 2: the runner row. Every revoked job is spliced out of
	// active_jobs (idempotent when a stale entry is already absent), the
	// failure counter moves once per invalidated lease (the same accounting
	// ReleaseRunnerJob applied per job), and last_seen moves. A missing
	// runner row is tolerated: the quota release above is repository-scoped.
	for _, id := range revoked {
		if err := s.releaseRunnerSlotTx(ctx, tx, runnerID, id); err != nil {
			return nil, nil, err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE runners SET failed = failed + $2, last_seen = $3 WHERE id = $1`, runnerID, len(revoked), now); err != nil {
		return nil, nil, err
	}

	// Phase 3: dependent jobs and run aggregation commit with the
	// transitions they observe, never as a later best-effort pass.
	for _, id := range revoked {
		if err := s.recomputeDependentsTx(ctx, tx, id, now); err != nil {
			return nil, nil, err
		}
	}
	for runID := range runIDs {
		if err := s.recomputeRunTx(ctx, tx, runID); err != nil {
			return nil, nil, err
		}
	}
	return revoked, runIDs, nil
}

// repoIDForRecoveryTx resolves the quota-scoped canonical repository identity
// for a recovery transition whose job payload cannot be decoded. The run row
// (jobs.run_id is a NOT NULL foreign key) is the authoritative repository
// metadata: its payload holds the same PolicyRepoID/RepoID/Repo+RepoFullName
// the job payload was copied from, and canonicalPolicyRepoIDSQLExpr applies
// the exact policy-first derivation the quota keys use. An empty result (no
// run row, or a run whose payload is itself unresolvable) means there is no
// scoped counter key to move: the caller tolerates it exactly like a missing
// quota_reservations row.
func (s *PostgresStore) repoIDForRecoveryTx(ctx context.Context, tx pgx.Tx, runID string) (string, error) {
	if runID == "" {
		return "", nil
	}
	var id string
	err := tx.QueryRow(ctx, `SELECT `+canonicalPolicyRepoIDSQLExpr("repo")+` FROM runs WHERE id=$1`, runID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(id), nil
}

// RecoverExpiredLease requeues or terminally fails ONE expired running lease
// in a single transaction (see RecoveryStore.RecoverExpiredLease). The job
// row is locked first and the runner row second, matching the claim and
// completion lock order. The transaction is leader-FENCED: the store's
// retained leadership epoch must still match the durable leader_fence row
// (asserted inside this transaction), so a replica whose cached leadership
// outlived its advisory lock is rejected with ErrStaleLeader and recovers
// nothing.
//
// A payload that cannot be decoded is NOT an abort: the row is still a
// running lease holding a runner slot and a quota reservation, so the same
// fenced transaction fails it terminally with CorruptLeaseRecoveryReason,
// clears the lease columns, releases the runner active slot, the runner
// failure counter, the running quota reservation (scoped by the run's
// canonical identity) and recomputes dependents/run; the corrupt payload is
// left untouched as evidence, while the relational columns carry the terminal
// state. Retry fields (MaxInfraRetries) live in the payload and cannot be
// trusted, so the forced transition is terminal failure — never a re-queue.
func (s *PostgresStore) RecoverExpiredLease(ctx context.Context, jobID string, expectedGeneration int64, now time.Time) error {
	if err := ValidateJobID(jobID); err != nil {
		return err
	}
	tx, err := s.beginFencedTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var (
		payload        []byte
		status         string
		runID          string
		key            string
		leaseRunnerID  string
		generation     int64
		attempts       int
		leaseExpiresAt *time.Time
	)
	// The lease columns are authoritative: lease claims update the columns
	// without rewriting the payload, so attempts/expiry must be read from
	// the row, never from the (stale) jsonb copy.
	err = tx.QueryRow(ctx, `SELECT payload, status, run_id, key, COALESCE(lease_runner_id, ''), lease_generation, attempts, lease_expires_at FROM jobs WHERE id=$1 FOR UPDATE`, jobID).
		Scan(&payload, &status, &runID, &key, &leaseRunnerID, &generation, &attempts, &leaseExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	// Idempotent no-op: the job is no longer a running lease with the
	// generation this caller observed (a concurrent recovery, completion or
	// re-lease already moved it).
	if model.Status(status) != model.StatusRunning || generation != expectedGeneration {
		return tx.Commit(ctx)
	}
	var j model.Job
	if err := json.Unmarshal(payload, &j); err != nil {
		return s.recoverCorruptLeaseTx(ctx, tx, jobID, runID, key, leaseRunnerID, now)
	}
	j.ID = jobID
	j.RunID = runID
	j.Key = key
	j.Attempts = attempts
	j.LeaseRunnerID = leaseRunnerID
	j.LeaseExpiresAt = leaseExpiresAt
	if leaseExpiresAt != nil && leaseExpiresAt.After(now) {
		return tx.Commit(ctx)
	}
	requeue := j.Attempts <= j.MaxInfraRetries
	if requeue {
		j.Status = model.StatusQueued
		j.Error = "runner lease expired; retrying"
	} else {
		j.Status = model.StatusFailure
		j.Error = "runner lease expired and infrastructure retry budget exhausted"
		j.FinishedAt = &now
	}
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	jp, err := jsonMarshal(j)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET status=$2, error=$3, finished_at=$4, lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL, payload=$5 WHERE id=$1`,
		jobID, string(j.Status), nullText(j.Error), j.FinishedAt, jp); err != nil {
		return err
	}
	if requeue {
		if err := s.adjustQuotaTx(ctx, tx, RepoIDForJob(j), -1, 1); err != nil {
			return err
		}
	} else {
		if err := s.adjustQuotaTx(ctx, tx, RepoIDForJob(j), -1, 0); err != nil {
			return err
		}
	}
	if leaseRunnerID != "" {
		if err := s.releaseRunnerSlotTx(ctx, tx, leaseRunnerID, jobID); err != nil {
			return err
		}
		// The lost-runner recovery accounts one runner failure per expired
		// lease, exactly like the previous ReleaseRunnerJob(StatusFailure).
		if _, err := tx.Exec(ctx, `UPDATE runners SET failed = failed + 1, last_seen = $2 WHERE id = $1`, leaseRunnerID, now); err != nil {
			return err
		}
	}
	action := "job.lease_expired"
	msg := "job requeued after lost runner"
	if !requeue {
		action = "job.lost_runner"
		msg = j.Error
	}
	if err := insertRecoveryAuditTx(ctx, tx, action, "scheduler", j, msg, map[string]string{"job": key}, now); err != nil {
		return err
	}
	if err := s.recomputeDependentsTx(ctx, tx, jobID, now); err != nil {
		return err
	}
	if err := s.recomputeRunTx(ctx, tx, runID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// recoverCorruptLeaseTx applies the forced terminal recovery of an expired
// running lease whose payload cannot be decoded, inside the caller's fenced
// transaction. It releases every piece of SHARED capacity from the
// relational columns: the runner active slot and failure counter
// (lease_runner_id), the running quota reservation (scoped by the run's
// canonical identity, see repoIDForRecoveryTx), the lease columns, and the
// dependent/run aggregation. The payload is deliberately left untouched: it
// is the corruption evidence, and the jobs columns are the authoritative
// state every reader merges over it. The audit row records the forced
// transition and why it is terminal.
func (s *PostgresStore) recoverCorruptLeaseTx(ctx context.Context, tx pgx.Tx, jobID, runID, key, leaseRunnerID string, now time.Time) error {
	repoID, err := s.repoIDForRecoveryTx(ctx, tx, runID)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET status=$2, error=$3, finished_at=$4, lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL WHERE id=$1`,
		jobID, string(model.StatusFailure), CorruptLeaseRecoveryReason, now); err != nil {
		return err
	}
	// Retry policy (MaxInfraRetries) lives in the payload and cannot be
	// trusted, so the forced transition is terminal failure and the running
	// reservation is RELEASED, never converted into a queued reservation.
	if err := s.adjustQuotaTx(ctx, tx, repoID, -1, 0); err != nil {
		return err
	}
	if leaseRunnerID != "" {
		if err := s.releaseRunnerSlotTx(ctx, tx, leaseRunnerID, jobID); err != nil {
			return err
		}
		// The same accounting as a lost-runner recovery: one invalidated
		// lease, one runner failure.
		if _, err := tx.Exec(ctx, `UPDATE runners SET failed = failed + 1, last_seen = $2 WHERE id = $1`, leaseRunnerID, now); err != nil {
			return err
		}
	}
	auditJob := model.Job{ID: jobID, RunID: runID, Key: key}
	if err := insertRecoveryAuditTx(ctx, tx, "job.corrupt_payload_recovered", "scheduler", auditJob, CorruptLeaseRecoveryReason,
		map[string]string{"job": key, "reason": "corrupt_payload", "transition": "terminal_failure"}, now); err != nil {
		return err
	}
	if err := s.recomputeDependentsTx(ctx, tx, jobID, now); err != nil {
		return err
	}
	if err := s.recomputeRunTx(ctx, tx, runID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ExpireQueuedJob terminal-cancels ONE queue-timed-out job in a single
// transaction (see RecoveryStore.ExpireQueuedJob). The queued quota
// reservation is released inside the same transaction, so a crash can never
// leave a cancelled job still holding queue depth. Like every leader-only
// recovery mutation it is epoch-FENCED inside the transaction: a stale leader
// is rejected with ErrStaleLeader and expires nothing.
//
// deadline is the queue_deadline COLUMN the discovery observed; a ZERO
// deadline means the candidate carried no persisted column (a legacy row
// whose only deadline source is the payload). The effective deadline is
// re-derived under the row lock: the column first, then — only while the
// payload decodes — the payload/compiled fallback with QueueDeadlineFor
// semantics. A payload that cannot be decoded no longer aborts the expiry
// when the column proves the deadline: the malformed job is terminally
// cancelled with CorruptQueueExpiryReason, the queued reservation is
// released, and the corrupt payload stays untouched as evidence.
func (s *PostgresStore) ExpireQueuedJob(ctx context.Context, jobID string, deadline time.Time) error {
	if err := ValidateJobID(jobID); err != nil {
		return err
	}
	tx, err := s.beginFencedTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	var observed *time.Time
	if !deadline.IsZero() {
		observed = &deadline
	}

	var (
		payload        []byte
		status         string
		runID          string
		key            string
		columnDeadline *time.Time
	)
	err = tx.QueryRow(ctx, `SELECT payload, status, run_id, key, queue_deadline FROM jobs WHERE id=$1 FOR UPDATE`, jobID).
		Scan(&payload, &status, &runID, &key, &columnDeadline)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if model.Status(status) != model.StatusQueued && model.Status(status) != model.StatusWaitingApproval {
		// A concurrent lease, cancel or recovery already moved the job.
		return tx.Commit(ctx)
	}
	var j model.Job
	decodeErr := json.Unmarshal(payload, &j)
	j.ID = jobID
	j.RunID = runID
	j.Key = key
	// The persisted column is authoritative; a NULL column falls back to the
	// payload-derived deadline exactly like QueueDeadlineFor, but only while
	// the payload can be trusted. An undecodable payload can therefore never
	// invent a deadline — it only keeps the row expirable when the column
	// itself proves one elapsed.
	eff := columnDeadline
	if eff == nil {
		if decodeErr != nil {
			return tx.Commit(ctx)
		}
		eff = QueueDeadlineFor(j)
	}
	if eff == nil || eff.After(now) || (observed != nil && (eff.After(*observed) || observed.After(now))) {
		// No provable deadline, the deadline was cleared or moved past what
		// the caller observed, or it has not actually passed yet: nothing to
		// expire.
		return tx.Commit(ctx)
	}
	corrupt := decodeErr != nil
	reason := "queue timeout"
	action := "job.queue_timeout"
	msg := "job cancelled after queue deadline"
	if corrupt {
		reason = CorruptQueueExpiryReason
		action = "job.corrupt_payload_expired"
		msg = CorruptQueueExpiryReason
	}
	j.Status = model.StatusCancelled
	j.Error = reason
	j.FinishedAt = &now
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	if corrupt {
		// Columns only: the payload is the corruption evidence and is never
		// rewritten (readers merge the columns over it).
		if _, err := tx.Exec(ctx, `UPDATE jobs SET status='cancelled', error=$2, finished_at=$3, lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL WHERE id=$1`,
			jobID, reason, now); err != nil {
			return err
		}
	} else {
		jp, err := jsonMarshal(j)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE jobs SET status='cancelled', error=$2, finished_at=$3, lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL, payload=$4 WHERE id=$1`,
			jobID, reason, now, jp); err != nil {
			return err
		}
	}
	// A timed-out job never runs: return its reserved queued slot. The quota
	// scope comes from the job payload normally, and from the run's canonical
	// identity when the job payload is corrupt.
	repoID := RepoIDForJob(j)
	if corrupt {
		if repoID, err = s.repoIDForRecoveryTx(ctx, tx, runID); err != nil {
			return err
		}
	}
	if err := s.adjustQuotaTx(ctx, tx, repoID, 0, -1); err != nil {
		return err
	}
	if err := insertRecoveryAuditTx(ctx, tx, action, "scheduler", j, msg, map[string]string{"job": key}, now); err != nil {
		return err
	}
	if err := s.recomputeDependentsTx(ctx, tx, jobID, now); err != nil {
		return err
	}
	if err := s.recomputeRunTx(ctx, tx, runID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ---------------------------------------------------------------------------
// bounded candidate discovery (RecoveryScanStore)
// ---------------------------------------------------------------------------

// recoveryCandidateCols is the exact relational column list the queue-timeout
// candidate query scans into RecoveryCandidate. lease_generation is taken
// from the column (payload copies are stale by design: lease claims update
// columns without rewriting the payload) and queue_deadline is the
// migration-0021 column. The expired-running query selects a NULL deadline
// instead: lease recovery has no queue deadline to observe.
const recoveryCandidateCols = "id, lease_generation, queue_deadline"

// listRecoveryCandidates runs ONE bounded, id-ordered candidate page. No
// payload is read, let alone decoded: an individually undecodable payload can
// neither shrink the page (which used to make a corrupt row disappear from
// every sweep) nor shadow the candidates after it. The applier re-reads and
// re-checks every candidate inside its own transaction.
func (s *PostgresStore) listRecoveryCandidates(ctx context.Context, query string, now time.Time, afterID string, limit int) ([]RecoveryCandidate, error) {
	rows, err := s.pool.Query(ctx, query, now, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RecoveryCandidate{}
	for rows.Next() {
		var c RecoveryCandidate
		if err := rows.Scan(&c.ID, &c.LeaseGeneration, &c.QueueDeadline); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ListExpiredRunningJobs returns one bounded page of running jobs whose lease
// expired at or before now (see RecoveryDiscoveryStore for the cursor
// contract). A running job with a NULL lease_expires_at is included: it is an
// orphaned lease with no recorded expiry, exactly what the sweep must recover.
// The candidate's QueueDeadline is NULL by construction: a lease recovery has
// no queue deadline to observe.
func (s *PostgresStore) ListExpiredRunningJobs(ctx context.Context, now time.Time, afterID string, limit int) ([]RecoveryCandidate, error) {
	if limit <= 0 {
		return nil, nil
	}
	return s.listRecoveryCandidates(ctx,
		`SELECT id, lease_generation, NULL::timestamptz FROM jobs
		 WHERE status='running' AND (lease_expires_at IS NULL OR lease_expires_at <= $1) AND id > $2
		 ORDER BY id ASC LIMIT $3`, now, afterID, limit)
}

// ListQueueTimedOutJobs returns one bounded page of queued or
// approval-waiting jobs whose queue deadline elapsed (see RecoveryScanStore
// for the cursor contract). The queue_deadline column (migration 0021) is the
// indexed discovery source; rows whose column is NULL but whose payload still
// carries a deadline (legacy compiled-payload queue_timeout, or a payload
// written outside the canonical job path) are returned by the fallback
// predicate as a SUPERSET. The candidate carries the COLUMN deadline (nil for
// the fallback rows); the applier re-derives the effective deadline with
// QueueDeadlineFor semantics under its own row lock before applying.
func (s *PostgresStore) ListQueueTimedOutJobs(ctx context.Context, now time.Time, afterID string, limit int) ([]RecoveryCandidate, error) {
	if limit <= 0 {
		return nil, nil
	}
	return s.listRecoveryCandidates(ctx,
		`SELECT `+recoveryCandidateCols+` FROM jobs
		 WHERE status IN ('queued', 'waiting_approval')
		   AND id > $2
		   AND (
		         (queue_deadline IS NOT NULL AND queue_deadline <= $1)
		      OR (queue_deadline IS NULL AND (
		              payload ? 'queue_deadline'
		           OR payload #>> '{compiled_job_payload,effective_job,job,queue_timeout}' IS NOT NULL))
		   )
		 ORDER BY id ASC LIMIT $3`, now, afterID, limit)
}
