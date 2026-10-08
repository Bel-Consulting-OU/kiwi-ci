package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

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
//     Commit-ordered cursor: seq is allocated from a single-row locked
//     cursor (migration 0046, execution_event_cursor) held until commit, so
//     a later event transaction blocks until the earlier one commits or
//     rolls back. Allocation order is therefore exactly the visible order:
//     a reader can never observe seq 6 while seq 5 is still in flight, and a
//     rollback also rolls back its allocation (no holes). The old BIGSERIAL
//     allocation could publish out of order and permanently lose an event
//     behind an advanced cursor; that history is impossible now.
//
//     Retention (migration 0049 / RetentionExecutionEventStore) prunes a
//     bounded contiguous PREFIX of the oldest events and advances the
//     retained_from watermark; the surviving stream keeps the same
//     "seq > after" addressing. A consumer whose after cursor is below
//     retainedFrom-1 has lost events: the API answers 410 cursor_expired
//     with the watermark so it can re-bootstrap via latest_cursor. after ==
//     retainedFrom-1 and after == retainedFrom stay valid.
//
//   - AppendExecutionEvent persists one manually constructed event. It
//     exists for the filesystem/memory modes and tests; PostgreSQL
//     production writers never call it (the triggers own status appends and
//     the store methods append semantic events inside their own
//     transactions via appendExecutionEventTx).
type ExecutionEventStore interface {
	ListExecutionEvents(ctx context.Context, afterSeq int64, limit int, runID string) ([]model.ExecutionEvent, int64, error)
	AppendExecutionEvent(ctx context.Context, e model.ExecutionEvent) error
}

// ExecutionEventCursorStore is the optional companion contract for reading
// the stream's latest committed cursor: MAX(seq) in PostgreSQL, the durable
// journal watermark for the filesystem repository. The list response's
// latest_cursor lets a consumer snapshot state, read the cursor, then poll
// after=latest without a bootstrap gap.
type ExecutionEventCursorStore interface {
	LatestExecutionEventSeq(ctx context.Context) (int64, error)
}

// RetentionExecutionEventStore is the optional windowed-retention contract.
// Events are pruned oldest-first as a contiguous prefix (see
// PruneExecutionEvents), and ExecutionEventRetainedFrom reports the highest
// pruned seq: 0 means nothing was ever pruned (the whole stream is
// retained). A consumer whose after cursor is below retainedFrom-1 has lost
// events and must re-bootstrap via latest_cursor; after == retainedFrom-1
// and after == retainedFrom stay valid (see ExecutionEventCursorExpired).
//
// Retention never rewrites seq or fills holes: the surviving stream is
// still an ascending subset addressed by "seq > after", so the cursor
// contract is unchanged for cursors at or above the retained prefix.
type RetentionExecutionEventStore interface {
	// PruneExecutionEvents deletes up to limit events older than olderThan
	// FROM THE OLDEST END, never crossing the first event at or after the
	// cutoff, and advances retained_from to the highest deleted seq in the
	// same transaction. pruned is the number of deleted events and
	// retainedFrom is the watermark AFTER the call.
	PruneExecutionEvents(ctx context.Context, olderThan time.Time, limit int) (pruned int64, retainedFrom int64, err error)
	// ExecutionEventRetainedFrom returns the durable retained_from
	// watermark: the highest seq pruned from the stream (0 when none).
	ExecutionEventRetainedFrom(ctx context.Context) (int64, error)
}

// ExecutionEventCursorExpired reports whether a list/stream consumer at
// after has lost events to retention. retainedFrom is the highest pruned
// seq: after == retainedFrom-1 (the last cursor position that could still
// name the pruned prefix without having consumed past it) and after ==
// retainedFrom (the prefix itself) remain valid; anything below is expired.
// A zero watermark (nothing pruned) can never expire a cursor.
func ExecutionEventCursorExpired(after, retainedFrom int64) bool {
	return retainedFrom > 0 && after < retainedFrom-1
}

// DefaultExecutionEventPruneLimit bounds one PruneExecutionEvents batch when
// the caller passes a non-positive limit.
const DefaultExecutionEventPruneLimit = 1000

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
// carry run timings (started_at/finished_at). The PostgreSQL trigger
// function embeds the same set, including blocked (terminal in the model),
// and a unit test pins the parity with model.Status.Terminal().
var ExecutionEventTerminalStatuses = []model.Status{
	model.StatusSuccess,
	model.StatusFailure,
	model.StatusCancelled,
	model.StatusSkipped,
	model.StatusBlocked,
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
	_ ExecutionEventStore          = (*PostgresStore)(nil)
	_ ExecutionEventStore          = (*Repository)(nil)
	_ RetentionExecutionEventStore = (*PostgresStore)(nil)
	_ RetentionExecutionEventStore = (*Repository)(nil)
	_ RetentionExecutionEventStore = (*memStore)(nil)
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
// insert goes through the schema-compatible fence (raw write) and allocates
// its seq from the SAME commit-ordered cursor the migration 0046 trigger
// function uses: the cursor row lock is held to commit, so this append and a
// concurrent trigger append can never publish out of allocation order and a
// rollback cannot leave a hole.
func (s *PostgresStore) AppendExecutionEvent(ctx context.Context, e model.ExecutionEvent) error {
	if e.Type == "" {
		return errors.New("storage: execution event type is required")
	}
	tx, err := s.beginSchemaCompatibleTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := appendExecutionEventTx(ctx, tx, e); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// appendExecutionEventTx appends one event INSIDE the caller's transaction,
// allocating its seq from the commit-ordered single-row cursor exactly like
// the migration 0046 trigger function: the cursor row lock is held to
// commit, so a semantic event emitted next to the mutation it describes is
// ordered with (and rolls back with) that mutation. It is the shared writer
// for every DB-mode semantic append, so the payload/seq rules cannot drift
// between call sites. A zero CreatedAt is stamped with the database clock
// (clock_timestamp()), never the application clock.
func appendExecutionEventTx(ctx context.Context, tx pgx.Tx, e model.ExecutionEvent) error {
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
	var seq int64
	if err := tx.QueryRow(ctx, `UPDATE execution_event_cursor SET value = value + 1 RETURNING value`).Scan(&seq); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO execution_events (seq, schema_version, run_id, job_id, attempt, event_type, from_status, to_status, actor, payload, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, COALESCE($11, clock_timestamp()))`,
		seq, schemaVersion, nullText(e.RunID), nullText(e.JobID), e.Attempt, e.Type,
		nullText(e.FromStatus), nullText(e.ToStatus), nullText(e.Actor), payload, createdAt)
	return err
}

// PruneExecutionEvents deletes a bounded, contiguous prefix of events older
// than olderThan. Only a prefix strictly below every event at or after the
// cutoff is deletable: the survivors stay addressable as "seq > after", so
// retention can never punch a hole that would resurrect a pruned event for
// a cursor at or above it. The retained_from watermark is advanced to the
// highest deleted seq under the same cursor row lock the appenders hold, so
// a prune can never interleave with an event allocation. Deleting up to
// limit rows per call keeps one maintenance tick bounded; callers repeat
// until pruned < limit.
func (s *PostgresStore) PruneExecutionEvents(ctx context.Context, olderThan time.Time, limit int) (int64, int64, error) {
	if limit <= 0 {
		limit = DefaultExecutionEventPruneLimit
	}
	tx, err := s.beginSchemaCompatibleTx(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO execution_event_cursor (id, value) VALUES (TRUE, 0) ON CONFLICT (id) DO NOTHING`); err != nil {
		return 0, 0, err
	}
	var retainedFrom int64
	if err := tx.QueryRow(ctx, `SELECT retained_from FROM execution_event_cursor WHERE id = TRUE FOR UPDATE`).Scan(&retainedFrom); err != nil {
		return 0, 0, err
	}
	rows, err := tx.Query(ctx, `
		WITH keep AS (
			SELECT COALESCE(MIN(seq), 9223372036854775807) AS keep_from
			FROM execution_events
			WHERE created_at >= $1
		), victims AS (
			SELECT e.seq
			FROM execution_events e, keep
			WHERE e.seq < keep.keep_from AND e.seq > $3
			ORDER BY e.seq ASC
			LIMIT $2
		)
		DELETE FROM execution_events WHERE seq IN (SELECT seq FROM victims)
		RETURNING seq`, olderThan, limit, retainedFrom)
	if err != nil {
		return 0, 0, err
	}
	var pruned, highest int64
	for rows.Next() {
		var seq int64
		if err := rows.Scan(&seq); err != nil {
			rows.Close()
			return 0, 0, err
		}
		pruned++
		if seq > highest {
			highest = seq
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, 0, err
	}
	rows.Close()
	if highest > retainedFrom {
		if _, err := tx.Exec(ctx, `UPDATE execution_event_cursor SET retained_from = $1 WHERE id = TRUE`, highest); err != nil {
			return 0, 0, err
		}
		retainedFrom = highest
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, err
	}
	return pruned, retainedFrom, nil
}

// ExecutionEventRetainedFrom returns the durable retained_from watermark
// (0 when nothing has been pruned): the highest seq removed by retention.
// It is a read-only raw SELECT and carries no schema fence.
func (s *PostgresStore) ExecutionEventRetainedFrom(ctx context.Context) (int64, error) {
	var retainedFrom int64
	err := s.pool.QueryRow(ctx, `SELECT COALESCE((SELECT retained_from FROM execution_event_cursor WHERE id = TRUE), 0)`).Scan(&retainedFrom)
	return retainedFrom, err
}

// LatestExecutionEventSeq returns MAX(seq) of the committed stream (0 when
// empty): the latest committed cursor, so a consumer can snapshot state,
// read this cursor, and poll after=latest without a bootstrap gap. It is a
// read-only raw SELECT and carries no schema fence.
func (s *PostgresStore) LatestExecutionEventSeq(ctx context.Context) (int64, error) {
	var max int64
	if err := s.pool.QueryRow(ctx, `SELECT COALESCE(MAX(seq), 0) FROM execution_events`).Scan(&max); err != nil {
		return 0, err
	}
	return max, nil
}

// ---------------------------------------------------------------------------
// semantic event builders
// ---------------------------------------------------------------------------
//
// The semantic event payloads are built in ONE place shared by the
// PostgreSQL store methods, the memStore mirror and the server's fs/memory
// append sites, so the three modes can never drift. Every payload is small
// and non-secret by construction: ids, names, generations, digests, phases
// and claim KEY names only. There is deliberately no builder that accepts a
// secret value, token or plaintext claim.

// ExecutionEventAttemptCreated builds the attempt.created event for a
// successful lease claim. Attempt carries the new lease generation and
// Actor the runner.
func ExecutionEventAttemptCreated(j model.Job, runnerID string) model.ExecutionEvent {
	return model.ExecutionEvent{
		RunID:   j.RunID,
		JobID:   j.ID,
		Attempt: j.LeaseGeneration,
		Type:    model.EventAttemptCreated,
		Actor:   runnerID,
		Payload: map[string]string{"job": j.Key, "runner": runnerID},
	}
}

// ExecutionEventGraphMutation builds the graph.mutation_committed (replayed
// false) or graph.mutation_replayed (replayed true) event for a dynamic
// fragment mutation keyed by (parent job, mutation slot). The fragment id is
// the digest that won the slot; children is the committed child count.
func ExecutionEventGraphMutation(replayed bool, parent model.Job, mutationSlot, fragmentID string, children int) model.ExecutionEvent {
	typ := model.EventGraphMutationCommitted
	if replayed {
		typ = model.EventGraphMutationReplayed
	}
	return model.ExecutionEvent{
		RunID:   parent.RunID,
		JobID:   parent.ID,
		Attempt: parent.LeaseGeneration,
		Type:    typ,
		Actor:   parent.LeaseRunnerID,
		Payload: map[string]string{
			"slot":     mutationSlot,
			"fragment": fragmentID,
			"children": strconv.Itoa(children),
		},
	}
}

// ExecutionEventArtifactPublished builds the artifact.published event for a
// newly committed artifact record. It never carries content or a path.
func ExecutionEventArtifactPublished(a model.ArtifactRecord, generation int64, actor string) model.ExecutionEvent {
	return model.ExecutionEvent{
		RunID:   a.RunID,
		JobID:   a.JobID,
		Attempt: generation,
		Type:    model.EventArtifactPublished,
		Actor:   actor,
		Payload: map[string]string{
			"name":       a.Name,
			"sha256":     a.SHA256,
			"size":       strconv.FormatInt(a.Size, 10),
			"generation": strconv.FormatInt(generation, 10),
		},
	}
}

// ExecutionEventCheckpointPublished builds the checkpoint.published event
// for a newly committed workspace snapshot record: snapshot id, phase,
// digest, generation and size, never contents.
func ExecutionEventCheckpointPublished(rec model.SnapshotRecord, generation int64, actor string) model.ExecutionEvent {
	return model.ExecutionEvent{
		RunID:   rec.RunID,
		JobID:   rec.JobID,
		Attempt: generation,
		Type:    model.EventCheckpointPublished,
		Actor:   actor,
		Payload: map[string]string{
			"snapshot":   rec.ID,
			"phase":      rec.Phase,
			"sha256":     rec.SHA256,
			"size":       strconv.FormatInt(rec.Size, 10),
			"generation": strconv.FormatInt(generation, 10),
		},
	}
}

// ExecutionEventApprovalGranted builds the approval.granted event with the
// acting principal and the resulting job status.
func ExecutionEventApprovalGranted(j model.Job, actor string) model.ExecutionEvent {
	return model.ExecutionEvent{
		RunID:   j.RunID,
		JobID:   j.ID,
		Attempt: j.LeaseGeneration,
		Type:    model.EventApprovalGranted,
		Actor:   actor,
		Payload: map[string]string{
			"environment": j.Environment,
			"status":      string(j.Status),
		},
	}
}

// ExecutionEventSecretIssued builds the secret.issued event for a committed
// secret delivery: the secret NAME and lease generation only. The sealed
// envelope, recipient key and plaintext never appear.
func ExecutionEventSecretIssued(req SecretIssuance, runID string) model.ExecutionEvent {
	return model.ExecutionEvent{
		RunID:   runID,
		JobID:   req.JobID,
		Attempt: req.LeaseGeneration,
		Type:    model.EventSecretIssued,
		Actor:   req.RunnerID,
		Payload: map[string]string{
			"secret":     req.SecretName,
			"generation": strconv.FormatInt(req.LeaseGeneration, 10),
		},
	}
}

// ExecutionEventOIDCIssued builds the oidc.issued event for a committed
// id_token issuance: audience, signing kid and the SORTED claim KEY names
// only. Claim values and the token never appear.
func ExecutionEventOIDCIssued(req OIDCIssuance, runID string) model.ExecutionEvent {
	keys := make([]string, 0, len(req.Claims))
	for k := range req.Claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return model.ExecutionEvent{
		RunID:   runID,
		JobID:   req.JobID,
		Attempt: req.LeaseGeneration,
		Type:    model.EventOIDCIssued,
		Actor:   req.RunnerID,
		Payload: map[string]string{
			"audience": req.Audience,
			"kid":      req.KID,
			"claims":   strings.Join(keys, ","),
		},
	}
}

// ExecutionEventDeploymentStarted builds the deployment.started event for a
// created deployment record.
func ExecutionEventDeploymentStarted(d model.Deployment) model.ExecutionEvent {
	return deploymentExecutionEvent(model.EventDeploymentStarted, d)
}

// ExecutionEventDeploymentCompleted builds the deployment.completed event
// for a finished deployment record (status is the final status).
func ExecutionEventDeploymentCompleted(d model.Deployment) model.ExecutionEvent {
	return deploymentExecutionEvent(model.EventDeploymentCompleted, d)
}

func deploymentExecutionEvent(typ string, d model.Deployment) model.ExecutionEvent {
	return model.ExecutionEvent{
		RunID: d.RunID,
		JobID: d.JobID,
		Type:  typ,
		Actor: "scheduler",
		Payload: map[string]string{
			"deployment":  d.ID,
			"environment": d.Environment,
			"status":      string(d.Status),
		},
	}
}
