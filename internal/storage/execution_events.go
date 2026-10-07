package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// ExecutionEventStore is the durable canonical execution event stream
// contract: an ordered, cursorable lifecycle feed.
//
//   - ListExecutionEvents returns up to limit events with seq strictly
//     greater than afterSeq, ascending by seq, optionally filtered to one
//     run, plus the cursor a follow-up call must pass as afterSeq. The
//     cursor is the seq of the last returned event (afterSeq itself when
//     the page is empty), so paging with after=cursor is gap-free and
//     duplicate-free over COMMITTED events. seq is the canonical order:
//     events are appended in the same transaction as the state change they
//     describe (PostgreSQL: AFTER INSERT/UPDATE triggers on jobs and runs),
//     so a rolled-back transition never leaves an event behind.
//
//     Concurrency note: sequence values are allocated as statements execute,
//     so an in-flight transaction that already holds seq 5 can commit after
//     a reader has seen seq 6. Events are never reordered or duplicated, but
//     a reader that advances its cursor past 5 will not see it afterwards.
//     Consumers that must not miss a delayed event should, on a suspicious
//     gap, re-read from a cursor they already passed (for example the last
//     cursor observed before an idle gap) instead of assuming the stream is
//     complete. The SSE endpoint re-polls its last advanced cursor, so a
//     reconnect after a gap resumes from the client's own `after` value.
//
//   - AppendExecutionEvent persists one manually constructed event. It
//     exists for the filesystem/memory modes and tests; PostgreSQL
//     production writers never call it (the triggers own appends there).
type ExecutionEventStore interface {
	ListExecutionEvents(ctx context.Context, afterSeq int64, limit int, runID string) ([]model.ExecutionEvent, int64, error)
	AppendExecutionEvent(ctx context.Context, e model.ExecutionEvent) error
}

// Execution event page bounds, mirroring the audit/runs page conventions:
// a missing or out-of-range limit reads one default page and never more
// than the maximum.
const (
	DefaultExecutionEventLimit = 1000
	MaxExecutionEventLimit     = 10000
)

// ClampExecutionEventLimit applies the storage page bounds to a caller
// limit. It is exported so the HTTP layer can bound the request identically
// instead of duplicating the rule.
func ClampExecutionEventLimit(limit int) int {
	if limit <= 0 || limit > MaxExecutionEventLimit {
		return DefaultExecutionEventLimit
	}
	return limit
}

// ExecutionEventType derives the canonical event type for a status
// transition: "<scope>.<status>", except that success/failure spell the
// terminal job/run names (succeeded/failed) and a running->queued move is a
// requeue. It is the ONE mapping shared by the PostgreSQL trigger (which
// encodes the same CASE in SQL), the fs/memory appenders and consumers, so
// the stream vocabulary cannot drift between storage modes.
func ExecutionEventType(scope string, from, to model.Status) string {
	switch to {
	case model.StatusSuccess:
		return scope + ".succeeded"
	case model.StatusFailure:
		return scope + ".failed"
	case model.StatusQueued:
		if from == model.StatusRunning {
			return scope + ".requeued"
		}
		return scope + ".queued"
	default:
		return scope + "." + string(to)
	}
}

// ExecutionEventTerminalStatuses are the statuses whose event payload may
// carry run timings (started_at/finished_at). The PostgreSQL trigger embeds
// the same set.
var ExecutionEventTerminalStatuses = []model.Status{
	model.StatusSuccess,
	model.StatusFailure,
	model.StatusCancelled,
	model.StatusSkipped,
}

// ExecutionEventTimingPayload returns the timing entries (started_at,
// finished_at, duration_ms) a terminal job event carries, so the fs/memory
// stream and the PostgreSQL trigger payloads agree. A nil started/finished
// contributes no key.
func ExecutionEventTimingPayload(startedAt, finishedAt *time.Time) map[string]string {
	payload := map[string]string{}
	if startedAt != nil {
		payload["started_at"] = startedAt.UTC().Format(time.RFC3339Nano)
	}
	if finishedAt != nil {
		payload["finished_at"] = finishedAt.UTC().Format(time.RFC3339Nano)
	}
	if startedAt != nil && finishedAt != nil {
		payload["duration_ms"] = fmt.Sprintf("%d", finishedAt.Sub(*startedAt).Milliseconds())
	}
	return payload
}

var (
	_ ExecutionEventStore = (*PostgresStore)(nil)
	_ ExecutionEventStore = (*Repository)(nil)
)

// ListExecutionEvents implements ExecutionEventStore for PostgreSQL with a
// keyset scan over the BIGSERIAL cursor: seq > after, ascending, bounded by
// limit, optional run filter. The read is not schema-fenced: it mutates
// nothing.
func (s *PostgresStore) ListExecutionEvents(ctx context.Context, afterSeq int64, limit int, runID string) ([]model.ExecutionEvent, int64, error) {
	limit = ClampExecutionEventLimit(limit)
	rows, err := s.pool.Query(ctx, `
		SELECT seq, schema_version, COALESCE(run_id, ''), COALESCE(job_id, ''), attempt, event_type,
		       COALESCE(from_status, ''), COALESCE(to_status, ''), COALESCE(actor, ''),
		       COALESCE(payload, '{}'::jsonb), created_at
		FROM execution_events
		WHERE seq > $1 AND ($2 = '' OR run_id = $2)
		ORDER BY seq ASC
		LIMIT $3`, afterSeq, runID, limit)
	if err != nil {
		return nil, afterSeq, err
	}
	defer rows.Close()
	out := []model.ExecutionEvent{}
	cursor := afterSeq
	for rows.Next() {
		var (
			e       model.ExecutionEvent
			payload []byte
		)
		if err := rows.Scan(&e.Seq, &e.SchemaVersion, &e.RunID, &e.JobID, &e.Attempt, &e.Type,
			&e.FromStatus, &e.ToStatus, &e.Actor, &payload, &e.CreatedAt); err != nil {
			return nil, afterSeq, err
		}
		if len(payload) > 0 && string(payload) != "{}" {
			if err := json.Unmarshal(payload, &e.Payload); err != nil {
				return nil, afterSeq, err
			}
		}
		out = append(out, e)
		cursor = e.Seq
	}
	if err := rows.Err(); err != nil {
		return nil, afterSeq, err
	}
	return out, cursor, nil
}

// AppendExecutionEvent implements ExecutionEventStore for PostgreSQL. It is
// the manual escape hatch (tests, operator tooling): production DB-mode
// events are appended by the migration 0045 triggers in the same
// transaction as the state change, so no production writer calls this. The
// insert goes through the schema-compatible fence because it is a raw write.
func (s *PostgresStore) AppendExecutionEvent(ctx context.Context, e model.ExecutionEvent) error {
	if e.Type == "" {
		return errors.New("storage: execution event type is required")
	}
	schemaVersion := e.SchemaVersion
	if schemaVersion <= 0 {
		schemaVersion = 1
	}
	var payload []byte
	if len(e.Payload) > 0 {
		m, err := jsonMarshal(e.Payload)
		if err != nil {
			return err
		}
		payload = m
	}
	var createdAt *time.Time
	if !e.CreatedAt.IsZero() {
		t := e.CreatedAt.UTC()
		createdAt = &t
	}
	_, err := s.execSchemaFenced(ctx, `
		INSERT INTO execution_events (schema_version, run_id, job_id, attempt, event_type, from_status, to_status, actor, payload, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, COALESCE($10, clock_timestamp()))`,
		schemaVersion, nullText(e.RunID), nullText(e.JobID), e.Attempt, e.Type,
		nullText(e.FromStatus), nullText(e.ToStatus), nullText(e.Actor), payload, createdAt)
	return err
}
