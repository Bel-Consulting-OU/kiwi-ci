package storage

// Atomic runner disable for PostgresStore.
//
// The previous admin path composed UpsertRunner(disabled) + RevokeRunnerLeases
// + a certificate revocation + audit as independent operations and answered
// success even when the durable certificate revocation was never recorded, so
// a disabled runner's still-valid certificate could be replayed on another
// replica.
// DisableRunnerAndRevokeCert commits all four effects in ONE transaction and
// the handler fails closed when it cannot commit.

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

var _ RunnerDisableStore = (*PostgresStore)(nil)

// insertRunnerAuditTx writes one runner-scoped audit event inside the
// caller's transaction, so the evidence commits with the transition it
// describes (the DB audit table is never a separate best-effort append on
// this path).
func insertRunnerAuditTx(ctx context.Context, tx pgx.Tx, action, actor, msg string, meta map[string]string, now time.Time) error {
	auditID, err := newID()
	if err != nil {
		return err
	}
	metaJSON, err := jsonMarshal(meta)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_events (id, action, actor, run_id, job_id, message, metadata, created_at) VALUES ($1, $2, $3, '', '', $4, $5, $6)`,
		auditID, action, actor, msg, metaJSON, now)
	return err
}

// DisableRunnerAndRevokeCert applies the complete runner-disable kill switch
// in ONE transaction (see RunnerDisableStore): every running lease is
// requeued or terminal-cancelled exactly like RevokeRunnerLeases, the runner
// row is marked disabled with its payload's revoked_at stamped, the
// certificate serial is durably revoked (conflict-tolerant, permanent), and
// the runner.disable / runner.cert_revoked audit rows are written. A missing
// runner row reports ErrNotFound and rolls everything back, so the handler
// can never acknowledge a disable that is not durably complete. Lock order
// stays jobs first, then the runner row, matching the other lease
// transitions.
func (s *PostgresStore) DisableRunnerAndRevokeCert(ctx context.Context, runnerID, certSerial, actor string) (int, error) {
	if err := ValidateRunnerID(runnerID); err != nil {
		return 0, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()

	revoked, _, err := s.revokeRunnerLeasesTx(ctx, tx, runnerID, "runner disabled", now)
	if err != nil {
		return 0, err
	}

	// The runner row is locked (the lease phase took the same runner lock
	// whenever it revoked at least one lease; with no leases this SELECT
	// takes it first and no job lock is held, so the jobs -> runner order
	// cannot cycle).
	var payload []byte
	err = tx.QueryRow(ctx, `SELECT payload FROM runners WHERE id=$1 FOR UPDATE`, runnerID).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	var ri model.Runner
	if err := json.Unmarshal(payload, &ri); err != nil {
		return 0, err
	}
	ri.ID = runnerID
	ri.Disabled = true
	if certSerial != "" && ri.RevokedAt == nil {
		ri.RevokedAt = &now
	}
	rp, err := jsonMarshal(ri)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE runners SET disabled=TRUE, payload=$2 WHERE id=$1`, runnerID, rp); err != nil {
		return 0, err
	}
	if certSerial != "" {
		if _, err := tx.Exec(ctx, `INSERT INTO cert_revocations (serial, revoked_at, reason, runner_id) VALUES ($1, $2, 'runner disabled', $3) ON CONFLICT (serial) DO NOTHING`,
			certSerial, now, runnerID); err != nil {
			return 0, err
		}
	}
	if err := insertRunnerAuditTx(ctx, tx, "runner.disable", actor, "runner disabled", map[string]string{"runner": runnerID}, now); err != nil {
		return 0, err
	}
	if certSerial != "" {
		if err := insertRunnerAuditTx(ctx, tx, "runner.cert_revoked", actor, "runner certificate serial revoked", map[string]string{"runner": runnerID, "serial": certSerial}, now); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(revoked), nil
}
