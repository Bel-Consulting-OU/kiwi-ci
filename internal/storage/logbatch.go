package storage

import (
	"context"
	"fmt"
	"sync"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// LogBatchReceipt is the deterministic identity of one log batch: the runner
// assigns batch_id (and a monotonic sequence) per (job, lease generation), so
// a safely retried batch is recognized and NOT re-inserted.
type LogBatchReceipt struct {
	JobID      string `json:"job_id"`
	Generation int64  `json:"generation"`
	BatchID    string `json:"batch_id"`
}

// LogBatchStore appends a whole log batch in ONE transaction. The second
// return value reports whether this call actually inserted (false = the
// batch was already receipted, i.e. a duplicate delivery that must answer
// 204 without duplicating lines).
type LogBatchStore interface {
	AppendLogBatch(ctx context.Context, entries []model.LogEntry, r LogBatchReceipt) (bool, error)
}

var _ LogBatchStore = (*PostgresStore)(nil)

// AppendLogBatch inserts the receipt and all lines atomically. The receipt
// row is the idempotency key: an existing (job, generation, batch_id) means a
// retry of an already-persisted batch.
func (s *PostgresStore) AppendLogBatch(ctx context.Context, entries []model.LogEntry, r LogBatchReceipt) (bool, error) {
	if r.JobID == "" || r.BatchID == "" {
		return false, fmt.Errorf("storage: log batch requires job id and batch id")
	}
	if len(entries) == 0 {
		return false, fmt.Errorf("storage: empty log batch")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	tag, err := tx.Exec(ctx, `INSERT INTO log_batches (job_id, generation, batch_id, created_at) VALUES ($1, $2, $3, now()) ON CONFLICT (job_id, generation, batch_id) DO NOTHING`,
		r.JobID, r.Generation, r.BatchID)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		// Duplicate delivery: everything was persisted the first time.
		return false, nil
	}
	for _, e := range entries {
		if _, err := tx.Exec(ctx, `INSERT INTO logs (run_id, job_id, job_key, step, line, created_at) VALUES ($1, $2, $3, $4, $5, $6)`,
			e.RunID, e.JobID, e.JobKey, e.Step, e.Line, e.CreatedAt); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// memStore batch receipts (test/dev mirror).
type logBatchMem struct {
	mu sync.Mutex
	m  map[string]bool
}

func (l *logBatchMem) claim(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]bool{}
	}
	if l.m[key] {
		return false
	}
	l.m[key] = true
	return true
}
