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
//     retained_from watermark (the HIGHEST removed seq; 0 = none removed);
//     the surviving stream keeps the same "seq > after" addressing. A
//     consumer whose after cursor is strictly BELOW retainedFrom has lost
//     events: the API answers 410 cursor_expired with the watermark so it
//     can re-bootstrap via latest_cursor. after == retainedFrom stays valid
//     (the consumer has already consumed the removed prefix's last seq);
//     after == retainedFrom-1 is EXPIRED (seq retainedFrom was removed
//     unobserved).
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

// ExecutionEventRetentionReadStore is the ATOMIC retention read contract: it
// returns the page, the retention watermark and the latest monotonic cursor
// from ONE consistency point, so a concurrent prune can never produce a
// silently truncated page (rows missing while the watermark still reads old)
// or a regressed latest cursor.
//
// Readers MUST treat any error as unreadable state (fail closed, never
// default a watermark or cursor to 0): an unproven watermark could hide lost
// events. Expiry is decided by the caller from the returned retainedFrom
// with ExecutionEventCursorExpired; because the page and the watermark share
// one snapshot, a returned non-expired cursor guarantees every event above
// it that existed at the snapshot is returned or is beyond the page bound.
//
// The PostgreSQL implementation is one CTE statement (one snapshot);
// the filesystem implementation is one repository-lock read.
type ExecutionEventRetentionReadStore interface {
	ReadExecutionEventsRetention(ctx context.Context, afterSeq int64, limit int, runID string) (events []model.ExecutionEvent, nextCursor int64, retainedFrom int64, latestCursor int64, err error)
}

// ExecutionEventCursorStore is the optional companion contract for reading
// the stream's latest committed cursor: the monotonic commit-ordered cursor
// value in PostgreSQL, the durable journal watermark for the filesystem
// repository. The list response's latest_cursor lets a consumer snapshot
// state, read the cursor, then poll after=latest without a bootstrap gap.
type ExecutionEventCursorStore interface {
	LatestExecutionEventSeq(ctx context.Context) (int64, error)
}

// ExecutionSnapshotRun is one ACTIVE run in an execution bootstrap snapshot.
// Only the small identity/status fields a controller needs to start browsing
// are carried: the full run record is fetched per run through the existing
// routes.
type ExecutionSnapshotRun struct {
	ID        string       `json:"id"`
	RepoID    string       `json:"repo_id,omitempty"`
	Ref       string       `json:"ref,omitempty"`
	Status    model.Status `json:"status"`
	CreatedAt time.Time    `json:"created_at"`
}

// ExecutionSnapshot is the atomic bootstrap point of the execution event
// stream: one cursor, one generated_at and one active-run summary taken from
// ONE consistency point.
//
// Ordering contract: implementations read the event cursor FIRST and the
// state summary SECOND (PostgreSQL: the cursor SELECT before the state
// SELECTs inside one transaction, so under READ COMMITTED each statement has
// its own snapshot and a transition committed in between is visible to the
// state read). A transition that commits between the two reads is therefore
// ALWAYS included in state AND carries an event seq strictly greater than
// Cursor, so a consumer that starts from this snapshot and pages
// GET /api/v1/events?after=Cursor can never miss it. The reverse interleave
// (state read first, cursor second) would let such a transition appear in
// state with its event seq at or below the cursor, silently skipping it.
//
// Queued/Running count JOBS (not runs) in those statuses across all runs;
// Runs lists at most runLimit active (non-terminal) runs, newest first.
type ExecutionSnapshot struct {
	Cursor      int64                  `json:"cursor"`
	GeneratedAt time.Time              `json:"generated_at"`
	Runs        []ExecutionSnapshotRun `json:"runs"`
	Queued      int                    `json:"queued"`
	Running     int                    `json:"running"`
}

// Execution snapshot bounds: a bootstrap response carries at most this many
// active runs; the counts cover every job regardless of the bound.
const (
	DefaultExecutionSnapshotRuns = 1000
	MaxExecutionSnapshotRuns     = 1000
)

// ExecutionSnapshotStore is the atomic bootstrap contract implemented by
// PostgreSQL (one transaction, cursor first). The server builds the same
// snapshot under its state lock for fs/memory mode.
type ExecutionSnapshotStore interface {
	ExecutionSnapshot(ctx context.Context, runLimit int) (ExecutionSnapshot, error)
}

// RetentionExecutionEventStore is the optional windowed-retention contract.
// Events are pruned oldest-first as a contiguous prefix (see
// PruneExecutionEvents), and ExecutionEventRetainedFrom reports the highest
// pruned seq: 0 means nothing was ever pruned (the whole stream is
// retained). A consumer whose after cursor is strictly below retainedFrom
// has lost events and must re-bootstrap via latest_cursor; after ==
// retainedFrom stays valid (see ExecutionEventCursorExpired).
//
// Retention never rewrites seq or fills holes: the surviving stream is
// still an ascending subset addressed by "seq > after", so the cursor
// contract is unchanged for cursors at or above the retained prefix.
//
// The contract embeds ExecutionEventRetentionReadStore: the atomic page +
// watermark + latest read is the ONE read every list/stream consumer must
// use, so retention can never interleave between the watermark check and
// the page read.
type RetentionExecutionEventStore interface {
	ExecutionEventRetentionReadStore
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
// after has lost events to retention. retainedFrom is the HIGHEST removed
// seq: the removed prefix is exactly the seqs at or below retainedFrom
// (contiguous, commit-ordered), so after == retainedFrom means the consumer
// already consumed the last removed seq and stays VALID, while after <
// retainedFrom means at least seq retainedFrom (and everything above it up
// to retainedFrom) was removed unobserved and the cursor is expired. A zero
// watermark (nothing pruned) can never expire a cursor.
func ExecutionEventCursorExpired(after, retainedFrom int64) bool {
	return retainedFrom > 0 && after < retainedFrom
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
	_ ExecutionEventStore              = (*PostgresStore)(nil)
	_ ExecutionEventStore              = (*Repository)(nil)
	_ ExecutionEventRetentionReadStore = (*PostgresStore)(nil)
	_ ExecutionEventRetentionReadStore = (*Repository)(nil)
	_ RetentionExecutionEventStore     = (*PostgresStore)(nil)
	_ RetentionExecutionEventStore     = (*Repository)(nil)
	_ RetentionExecutionEventStore     = (*memStore)(nil)
	_ ExecutionSnapshotStore           = (*PostgresStore)(nil)
	_ ExecutionEventCursorStore        = (*PostgresStore)(nil)
	_ ExecutionEventCursorStore        = (*Repository)(nil)
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

// ReadExecutionEventsRetention implements ExecutionEventRetentionReadStore
// for PostgreSQL as ONE CTE statement: the cursor row (value, retained_from),
// the bounded page and the run filter are read from a single snapshot, so a
// concurrent prune transaction either commits entirely before the snapshot
// (page lacks the removed rows AND retained_from is already advanced: the
// caller sees a truthful expired cursor) or entirely after it (page still
// contains the rows AND the watermark is still old). The interleaving that
// produced the P1 (watermark read, then prune commits, then page read) is
// impossible.
//
// latestCursor comes from execution_event_cursor.value — the monotonic
// commit-ordered high-water written by every event transaction — never from
// MAX(seq) over retained rows, so pruning every row cannot make it regress.
// Any read/scan error is returned (fail closed): the caller must never
// treat an unreadable watermark as 0.
func (s *PostgresStore) ReadExecutionEventsRetention(ctx context.Context, afterSeq int64, limit int, runID string) ([]model.ExecutionEvent, int64, int64, int64, error) {
	limit = ClampExecutionEventLimit(limit)
	row := s.pool.QueryRow(ctx, `
		WITH cursor_state AS (
			SELECT COALESCE((SELECT value FROM execution_event_cursor WHERE id = TRUE), 0) AS value,
			       COALESCE((SELECT retained_from FROM execution_event_cursor WHERE id = TRUE), 0) AS retained_from
		), page AS (
			SELECT seq, schema_version, COALESCE(run_id, '') AS run_id, COALESCE(job_id, '') AS job_id,
			       attempt, event_type AS type, COALESCE(from_status, '') AS from_status, COALESCE(to_status, '') AS to_status,
			       COALESCE(actor, '') AS actor, COALESCE(payload, '{}'::jsonb) AS payload, created_at
			FROM execution_events
			WHERE seq > $1 AND ($2 = '' OR run_id = $2)
			ORDER BY seq ASC
			LIMIT $3
		)
		SELECT c.value, c.retained_from,
		       COALESCE(jsonb_agg(to_jsonb(p) ORDER BY p.seq) FILTER (WHERE p.seq IS NOT NULL), '[]'::jsonb)
		FROM cursor_state c
		LEFT JOIN page p ON TRUE
		GROUP BY c.value, c.retained_from`, afterSeq, runID, limit)
	var (
		latest, retained int64
		raw              []byte
	)
	if err := row.Scan(&latest, &retained, &raw); err != nil {
		return nil, afterSeq, 0, 0, err
	}
	out := []model.ExecutionEvent{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, afterSeq, 0, 0, err
		}
	}
	cursor := afterSeq
	if len(out) > 0 {
		cursor = out[len(out)-1].Seq
	}
	return out, cursor, retained, latest, nil
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

// LatestExecutionEventSeq returns the monotonic commit-ordered cursor value
// from execution_event_cursor.value (0 when the row is absent), NOT MAX(seq)
// over the surviving rows: retention prunes rows but never rewinds the
// cursor, so a consumer can snapshot state, read this cursor, and poll
// after=latest without a bootstrap gap even when every event in the window
// was pruned. It is a read-only raw SELECT and carries no schema fence.
func (s *PostgresStore) LatestExecutionEventSeq(ctx context.Context) (int64, error) {
	var latest int64
	if err := s.pool.QueryRow(ctx, `SELECT COALESCE((SELECT value FROM execution_event_cursor WHERE id = TRUE), 0)`).Scan(&latest); err != nil {
		return 0, err
	}
	return latest, nil
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
		RunID:   d.RunID,
		JobID:   d.JobID,
		Attempt: d.LeaseGeneration,
		Type:    typ,
		Actor:   "scheduler",
		Payload: map[string]string{
			"deployment":  d.ID,
			"environment": d.Environment,
			"status":      string(d.Status),
		},
	}
}

// ExecutionSnapshot implements ExecutionSnapshotStore for PostgreSQL in ONE
// schema-compatible transaction, reading the event cursor FIRST and the run
// summary SECOND (see the ExecutionSnapshot ordering contract). The
// transaction holds the shared schema lock, so a migration cannot commit
// between the reads and change the shape of the state being summarized.
func (s *PostgresStore) ExecutionSnapshot(ctx context.Context, runLimit int) (ExecutionSnapshot, error) {
	if runLimit <= 0 || runLimit > MaxExecutionSnapshotRuns {
		runLimit = DefaultExecutionSnapshotRuns
	}
	snap := ExecutionSnapshot{Runs: []ExecutionSnapshotRun{}}
	err := s.withSchemaCompatibleTx(ctx, func(tx pgx.Tx) error {
		// Cursor FIRST: every transition that commits after this read has a
		// seq strictly greater than snap.Cursor and is visible to the state
		// reads below, so a consumer starting at snap.Cursor cannot skip it.
		if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT value FROM execution_event_cursor WHERE id = TRUE), 0)`).Scan(&snap.Cursor); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&snap.GeneratedAt); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT id, COALESCE(payload->>'repo_id', ''), COALESCE(payload->>'ref', ''), status, created_at
			FROM runs
			WHERE status NOT IN ('success', 'failure', 'cancelled', 'skipped', 'blocked')
			ORDER BY created_at DESC, id ASC
			LIMIT $1`, runLimit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r ExecutionSnapshotRun
			if err := rows.Scan(&r.ID, &r.RepoID, &r.Ref, &r.Status, &r.CreatedAt); err != nil {
				return err
			}
			snap.Runs = append(snap.Runs, r)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status = 'queued'), count(*) FILTER (WHERE status = 'running') FROM jobs`).Scan(&snap.Queued, &snap.Running)
	})
	if err != nil {
		return ExecutionSnapshot{}, err
	}
	return snap, nil
}
