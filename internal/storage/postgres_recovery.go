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
func (s *PostgresStore) RevokeRunnerLeases(ctx context.Context, runnerID, reason string) ([]string, error) {
	if err := ValidateRunnerID(runnerID); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()

	// Phase 1: lock every running lease of the runner. The cursor is closed
	// before any UPDATE (pgx forbids Exec on an open cursor connection).
	rows, err := tx.Query(ctx, `SELECT `+jobCols+` FROM jobs WHERE status='running' AND lease_runner_id=$1 ORDER BY id FOR UPDATE`, runnerID)
	if err != nil {
		return nil, err
	}
	leased := []model.Job{}
	for rows.Next() {
		js := jobScanner{}
		if err := rows.Scan(jobTargets(&js)...); err != nil {
			rows.Close()
			return nil, err
		}
		j, err := js.job()
		if err != nil {
			rows.Close()
			return nil, err
		}
		leased = append(leased, j)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(leased) == 0 {
		// Nothing to revoke: idempotent replay of a concurrent replica.
		return []string{}, tx.Commit(ctx)
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
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE jobs SET status=$2, error=$3, finished_at=$4, lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL, payload=$5 WHERE id=$1`,
			j.ID, string(j.Status), nullText(j.Error), j.FinishedAt, jp); err != nil {
			return nil, err
		}
		// The invalidated lease releases its running reservation; a requeued
		// job re-reserves a queued slot in the same statement pair.
		if requeue {
			if err := s.adjustQuotaTx(ctx, tx, RepoIDForJob(j), -1, 1); err != nil {
				return nil, err
			}
		} else {
			if err := s.adjustQuotaTx(ctx, tx, RepoIDForJob(j), -1, 0); err != nil {
				return nil, err
			}
		}
		action := "job.runner_disabled_cancelled"
		if requeue {
			action = "job.runner_disabled_requeued"
		}
		if err := insertRecoveryAuditTx(ctx, tx, action, "admin", j, reason, map[string]string{"job": j.Key, "runner": runnerID}, now); err != nil {
			return nil, err
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
			return nil, err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE runners SET failed = failed + $2, last_seen = $3 WHERE id = $1`, runnerID, len(revoked), now); err != nil {
		return nil, err
	}

	// Phase 3: dependent jobs and run aggregation commit with the
	// transitions they observe, never as a later best-effort pass.
	for _, id := range revoked {
		if err := s.recomputeDependentsTx(ctx, tx, id, now); err != nil {
			return nil, err
		}
	}
	for runID := range runIDs {
		if err := s.recomputeRunTx(ctx, tx, runID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return revoked, nil
}

// RecoverExpiredLease requeues or terminally fails ONE expired running lease
// in a single transaction (see RecoveryStore.RecoverExpiredLease). The job
// row is locked first and the runner row second, matching the claim and
// completion lock order.
func (s *PostgresStore) RecoverExpiredLease(ctx context.Context, jobID string, expectedGeneration int64, now time.Time) error {
	if err := ValidateJobID(jobID); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
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
		return err
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

// ExpireQueuedJob terminal-cancels ONE queue-timed-out job in a single
// transaction (see RecoveryStore.ExpireQueuedJob). The queued quota
// reservation is released inside the same transaction, so a crash can never
// leave a cancelled job still holding queue depth.
func (s *PostgresStore) ExpireQueuedJob(ctx context.Context, jobID string, deadline time.Time) error {
	if err := ValidateJobID(jobID); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()

	var (
		payload []byte
		status  string
		runID   string
		key     string
	)
	err = tx.QueryRow(ctx, `SELECT payload, status, run_id, key FROM jobs WHERE id=$1 FOR UPDATE`, jobID).
		Scan(&payload, &status, &runID, &key)
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
	if err := json.Unmarshal(payload, &j); err != nil {
		return err
	}
	j.ID = jobID
	j.RunID = runID
	j.Key = key
	eff := QueueDeadlineFor(j)
	if eff == nil || eff.After(deadline) || deadline.After(now) {
		// The deadline was cleared, moved past what the caller observed, or
		// has not actually passed yet: nothing to expire.
		return tx.Commit(ctx)
	}
	j.Status = model.StatusCancelled
	j.Error = "queue timeout"
	j.FinishedAt = &now
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	jp, err := jsonMarshal(j)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET status='cancelled', error=$2, finished_at=$3, lease_runner_id=NULL, lease_token_hash=NULL, lease_expires_at=NULL, payload=$4 WHERE id=$1`,
		jobID, "queue timeout", now, jp); err != nil {
		return err
	}
	// A timed-out job never runs: return its reserved queued slot.
	if err := s.adjustQuotaTx(ctx, tx, RepoIDForJob(j), 0, -1); err != nil {
		return err
	}
	if err := insertRecoveryAuditTx(ctx, tx, "job.queue_timeout", "scheduler", j, "job cancelled after queue deadline", map[string]string{"job": key}, now); err != nil {
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
