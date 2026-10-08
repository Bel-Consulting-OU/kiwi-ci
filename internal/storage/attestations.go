package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// ExecutionAttestationStore is the durable final-execution-attestation
// contract. One attempt (job_id, generation) has exactly ONE attestation
// row: CommitExecutionAttestation is insert-once (ON CONFLICT DO NOTHING)
// and, when the caller supplies the execution.attested semantic event, the
// event is appended in the SAME transaction that creates the row, so a
// created attestation can never exist without its event and a replay can
// never append a second one. The returned record is the canonical stored row
// (the existing one on replay) and created reports whether this call made
// the commit.
type ExecutionAttestationStore interface {
	CommitExecutionAttestation(ctx context.Context, rec model.ExecutionAttestationRecord, event model.ExecutionEvent) (model.ExecutionAttestationRecord, bool, error)
	GetExecutionAttestation(ctx context.Context, jobID string, generation int64) (model.ExecutionAttestationRecord, bool, error)
}

var (
	_ ExecutionAttestationStore = (*PostgresStore)(nil)
	_ ExecutionAttestationStore = (*memStore)(nil)
)

// CommitExecutionAttestation is the PostgreSQL authoritative insert: the row
// is inserted once per (job_id, generation) and the event is appended inside
// the same transaction only when this call created the row, so exactly one
// row and one event exist per attempt even under concurrent replicas. A
// replay returns the STORED row (created=false) and appends nothing.
func (s *PostgresStore) CommitExecutionAttestation(ctx context.Context, rec model.ExecutionAttestationRecord, event model.ExecutionEvent) (model.ExecutionAttestationRecord, bool, error) {
	if rec.JobID == "" {
		return model.ExecutionAttestationRecord{}, false, errors.New("storage: execution attestation requires a job id")
	}
	tx, err := s.beginSchemaCompatibleTx(ctx)
	if err != nil {
		return model.ExecutionAttestationRecord{}, false, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var createdAt *time.Time
	if !rec.CreatedAt.IsZero() {
		t := rec.CreatedAt.UTC()
		createdAt = &t
	}
	tag, err := tx.Exec(ctx, `INSERT INTO execution_attestations (job_id, generation, run_id, status, statement_sha256, envelope_ref, created_at) VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, clock_timestamp())) ON CONFLICT (job_id, generation) DO NOTHING`,
		rec.JobID, rec.Generation, rec.RunID, rec.Status, rec.StatementSHA256, rec.EnvelopeRef, createdAt)
	if err != nil {
		return model.ExecutionAttestationRecord{}, false, err
	}
	if tag.RowsAffected() == 1 {
		// execution.attested shares the row's transaction: a failed append
		// rolls the attestation back, so a created row always has its event.
		if err := appendExecutionEventTx(ctx, tx, event); err != nil {
			return model.ExecutionAttestationRecord{}, false, err
		}
		// Return the canonical STORED row (created_at from the database
		// clock) so callers observe exactly what a later read returns.
		stored, err := readExecutionAttestationTx(ctx, tx, rec.JobID, rec.Generation)
		if err != nil {
			return model.ExecutionAttestationRecord{}, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return model.ExecutionAttestationRecord{}, false, err
		}
		return stored, true, nil
	}
	stored, err := readExecutionAttestationTx(ctx, tx, rec.JobID, rec.Generation)
	if err != nil {
		return model.ExecutionAttestationRecord{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return model.ExecutionAttestationRecord{}, false, err
	}
	return stored, false, nil
}

// GetExecutionAttestation reads one durable row. The bool reports whether
// the record exists.
func (s *PostgresStore) GetExecutionAttestation(ctx context.Context, jobID string, generation int64) (model.ExecutionAttestationRecord, bool, error) {
	rec, err := readExecutionAttestationQueryRow(ctx, s.pool.QueryRow(ctx, `SELECT job_id, generation, COALESCE(run_id, ''), COALESCE(status, ''), COALESCE(statement_sha256, ''), COALESCE(envelope_ref, ''), created_at FROM execution_attestations WHERE job_id=$1 AND generation=$2`, jobID, generation))
	if errors.Is(err, pgx.ErrNoRows) {
		return model.ExecutionAttestationRecord{}, false, nil
	}
	if err != nil {
		return model.ExecutionAttestationRecord{}, false, err
	}
	return rec, true, nil
}

// ListAllExecutionAttestationEnvelopeRefs reads every non-empty envelope
// reference. The read is full-table by design: a bounded read could omit a
// live reference and the collector would delete the envelope it names.
func (s *PostgresStore) ListAllExecutionAttestationEnvelopeRefs(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT envelope_ref FROM execution_attestations WHERE envelope_ref <> '' ORDER BY created_at ASC, job_id ASC, generation ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, rows.Err()
}

func readExecutionAttestationTx(ctx context.Context, tx pgx.Tx, jobID string, generation int64) (model.ExecutionAttestationRecord, error) {
	return readExecutionAttestationQueryRow(ctx, tx.QueryRow(ctx, `SELECT job_id, generation, COALESCE(run_id, ''), COALESCE(status, ''), COALESCE(statement_sha256, ''), COALESCE(envelope_ref, ''), created_at FROM execution_attestations WHERE job_id=$1 AND generation=$2`, jobID, generation))
}

func readExecutionAttestationQueryRow(ctx context.Context, row pgx.Row) (model.ExecutionAttestationRecord, error) {
	var rec model.ExecutionAttestationRecord
	if err := row.Scan(&rec.JobID, &rec.Generation, &rec.RunID, &rec.Status, &rec.StatementSHA256, &rec.EnvelopeRef, &rec.CreatedAt); err != nil {
		return model.ExecutionAttestationRecord{}, err
	}
	return rec, nil
}

// CommitExecutionAttestation is the in-memory mirror: the same insert-once
// semantics under the store lock, with the semantic event appended via the
// shared in-memory appender in the same critical section.
func (m *memStore) CommitExecutionAttestation(ctx context.Context, rec model.ExecutionAttestationRecord, event model.ExecutionEvent) (model.ExecutionAttestationRecord, bool, error) {
	if rec.JobID == "" {
		return model.ExecutionAttestationRecord{}, false, errors.New("storage: execution attestation requires a job id")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := rec.Key()
	if existing, ok := m.attestations[key]; ok {
		return existing, false, nil
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	m.attestations[key] = rec
	if event.Type != "" {
		// Memory mode cannot fail the append (the DB mode's fail-closed
		// contract is exercised by PostgreSQL, where the append is a real
		// transaction step); the event commits with the row under m.mu.
		m.appendExecutionEventLocked(event)
	}
	return rec, true, nil
}

// GetExecutionAttestation is the in-memory mirror.
func (m *memStore) GetExecutionAttestation(ctx context.Context, jobID string, generation int64) (model.ExecutionAttestationRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.attestations[model.AttemptID(jobID, generation)]
	return rec, ok, nil
}

// FaultyStore delegation for the execution-attestation contract: writes
// consume the fault counter, reads do not. A wrapper over an inner that does
// not implement the contract fails closed with a diagnosable error.
func (f *FaultyStore) CommitExecutionAttestation(ctx context.Context, rec model.ExecutionAttestationRecord, event model.ExecutionEvent) (model.ExecutionAttestationRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail(); err != nil {
		return model.ExecutionAttestationRecord{}, false, err
	}
	inner, ok := f.Inner.(ExecutionAttestationStore)
	if !ok {
		return model.ExecutionAttestationRecord{}, false, errMissingInnerInterface("ExecutionAttestationStore")
	}
	return inner.CommitExecutionAttestation(ctx, rec, event)
}

func (f *FaultyStore) GetExecutionAttestation(ctx context.Context, jobID string, generation int64) (model.ExecutionAttestationRecord, bool, error) {
	inner, ok := f.Inner.(ExecutionAttestationStore)
	if !ok {
		return model.ExecutionAttestationRecord{}, false, errMissingInnerInterface("ExecutionAttestationStore")
	}
	return inner.GetExecutionAttestation(ctx, jobID, generation)
}

// ExecutionAttestationEvent builds the execution.attested semantic event for
// a committed attestation: attempt, status and the digest references only.
func ExecutionAttestationEvent(rec model.ExecutionAttestationRecord) model.ExecutionEvent {
	return model.ExecutionEvent{
		RunID:   rec.RunID,
		JobID:   rec.JobID,
		Attempt: rec.Generation,
		Type:    model.EventExecutionAttested,
		Actor:   "scheduler",
		Payload: map[string]string{
			"attempt":          model.AttemptID(rec.JobID, rec.Generation),
			"status":           rec.Status,
			"statement_sha256": rec.StatementSHA256,
			"envelope":         rec.EnvelopeRef,
			"generation":       fmt.Sprintf("%d", rec.Generation),
		},
	}
}
