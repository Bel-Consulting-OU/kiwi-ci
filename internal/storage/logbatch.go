package storage

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// LogBatchIdentity is the deterministic identity of one log batch: the runner
// assigns batch_id (and a monotonic sequence) per (job, lease generation), so
// a safely retried batch is recognized and NOT re-inserted.
type LogBatchIdentity struct {
	JobID      string `json:"job_id"`
	Generation int64  `json:"generation"`
	BatchID    string `json:"batch_id"`
}

// LogBatchReceipt is the historical spelling of LogBatchIdentity; it remains
// an alias so existing callers (and the server's DB path) share exactly one
// identity type with the fs batch API.
type LogBatchReceipt = LogBatchIdentity

// LogBatchPayloadDigest returns the canonical SHA-256 of one ORDERED batch
// payload, bound to the receipt identity. The canonicalization is
// length-prefixed (8-byte big-endian field length + field bytes) over the
// STABLE payload identity: the run_id, job_id, job_key and step of every
// ordered line plus the line text itself, and the job/generation/batch_id
// receipt identity. Length prefixes make the encoding unambiguous (no
// concatenation-collision between fields), the identity binding means a
// stored digest can only be reused for its own receipt key, and the per-entry
// order is significant because a batch is an ordered sequence of lines.
//
// Per-delivery metadata is deliberately NOT part of the digest:
//
//   - CreatedAt is minted per delivery (one time.Now() per HTTP request in
//     the DB and fs paths), so two deliveries of the same logical batch carry
//     different timestamps. Including it made the retry of a batch whose 204
//     response was lost look like a payload conflict (ErrLogBatchConflict)
//     even though every line was already durable, defeating the runner's
//     immutable-batch-id retry.
//   - Seq is allocated per delivery too (the log_entries identity column, or
//     the server's monotonic counter in fs mode), so it is excluded for the
//     same reason (see LogBatchStore: an identical ordered payload under the
//     same identity is an idempotent duplicate).
//
// The digest is therefore a pure function of the logical batch content:
// identical lines in the same order under the same identity always digest
// equal, regardless of arrival time, process restart or Seq allocation, while
// changed or reordered lines digest differently.
func LogBatchPayloadDigest(identity LogBatchIdentity, entries []model.LogEntry) string {
	h := sha256.New()
	var length [8]byte
	writeField := func(b []byte) {
		binary.BigEndian.PutUint64(length[:], uint64(len(b)))
		_, _ = h.Write(length[:])
		_, _ = h.Write(b)
	}
	writeString := func(s string) { writeField([]byte(s)) }
	writeString("kiwi-log-batch-v1")
	writeString(identity.JobID)
	writeString(strconv.FormatInt(identity.Generation, 10))
	writeString(identity.BatchID)
	binary.BigEndian.PutUint64(length[:], uint64(len(entries)))
	_, _ = h.Write(length[:])
	for _, e := range entries {
		writeString(e.RunID)
		writeString(e.JobID)
		writeString(e.JobKey)
		writeString(e.Step)
		writeString(e.Line)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// LogBatchStore appends a whole log batch in ONE transaction. The second
// return value reports whether this call actually inserted (false = the
// batch was already receipted with the SAME payload, i.e. a duplicate
// delivery that must answer 204 without duplicating lines). A reused
// identity with a DIFFERENT payload returns ErrLogBatchConflict and inserts
// nothing.
type LogBatchStore interface {
	AppendLogBatch(ctx context.Context, entries []model.LogEntry, r LogBatchIdentity) (bool, error)
}

var _ LogBatchStore = (*PostgresStore)(nil)

// AppendLogBatch inserts the receipt and all lines atomically. The receipt
// row is the idempotency key: an existing (job, generation, batch_id) with
// the same payload_sha256 is a retry of an already-persisted batch; a
// different digest is a conflicting reuse of the identity and fails closed
// with ErrLogBatchConflict (the whole transaction rolls back).
func (s *PostgresStore) AppendLogBatch(ctx context.Context, entries []model.LogEntry, r LogBatchIdentity) (bool, error) {
	if r.JobID == "" || r.BatchID == "" {
		return false, fmt.Errorf("storage: log batch requires job id and batch id")
	}
	if len(entries) == 0 {
		return false, fmt.Errorf("storage: empty log batch")
	}
	digest := LogBatchPayloadDigest(r, entries)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	tag, err := tx.Exec(ctx, `INSERT INTO log_batches (job_id, generation, batch_id, payload_sha256, created_at) VALUES ($1, $2, $3, $4, now()) ON CONFLICT (job_id, generation, batch_id) DO NOTHING`,
		r.JobID, r.Generation, r.BatchID, digest)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		// Duplicate delivery: only the SAME payload is an idempotent success.
		var stored string
		if err := tx.QueryRow(ctx, `SELECT payload_sha256 FROM log_batches WHERE job_id=$1 AND generation=$2 AND batch_id=$3`,
			r.JobID, r.Generation, r.BatchID).Scan(&stored); err != nil {
			return false, err
		}
		if stored != digest {
			return false, ErrLogBatchConflict
		}
		return false, nil
	}
	for _, e := range entries {
		if _, err := tx.Exec(ctx, `INSERT INTO log_entries (run_id, job_id, job_key, step, line, created_at) VALUES ($1, $2, $3, $4, $5, $6)`,
			e.RunID, e.JobID, e.JobKey, e.Step, e.Line, e.CreatedAt); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// memStore batch receipts (test/dev mirror). The value is the canonical
// payload digest, so a reused identity with a different payload is detected
// exactly like the SQL payload_sha256 comparison.
type logBatchMem struct {
	mu sync.Mutex
	m  map[string]string
}

// claim records key@digest. It reports claimed=true when the key was free,
// and conflict=true when the key already holds a DIFFERENT digest.
func (l *logBatchMem) claim(key, digest string) (claimed bool, conflict bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]string{}
	}
	if prev, ok := l.m[key]; ok {
		return false, prev != digest
	}
	l.m[key] = digest
	return true, false
}
