package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// executionEventsResponse is the GET /api/v1/events body: the ascending page
// plus the scope-bound typed cursors a follow-up call must send as ?after.
//
// Canonical is true only in DB mode, where the stream is the authoritative
// commit-ordered PostgreSQL feed. fs/memory mode reports false: its journal
// is BEST-EFFORT TELEMETRY, not the transactional record of the mutation —
// a failed fs append consumes a cursor but loses the record, so the state
// change wins over the stream, and consumers must treat fs events as a
// non-canonical mirror that may lag or omit events.
//
// NextCursor is the typed cursor (xe1:<seq>:<scope fingerprint>) of the last
// returned event; LatestCursor is the latest committed cursor in the SAME
// typed form: the monotonic commit-ordered cursor value in DB mode, the
// durable journal watermark in fs mode. A consumer can snapshot state, read
// latest_cursor, then poll after=latest_cursor and miss no event in between;
// it never regresses when retention removes rows. Both cursors are bound to
// the request's scope: presenting one under a different scope (repo, run or
// global) is refused with 409 cursor_scope_mismatch, while the timestamp of
// the principal's credentials plays no role.
//
// RetainedFrom is the SCOPED retention frontier: the highest seq pruned for
// this scope (0 when nothing was pruned). A cursor strictly BELOW the
// frontier has lost events; the endpoint answers 410 cursor_expired with
// reason cursor_expired_snapshot_required, the scoped frontier and
// latest_cursor so the consumer re-bootstraps via the (scope-matched)
// execution snapshot. after >= the scoped frontier always reports
// resume_status resume_ok, even when the GLOBAL watermark passed it: the
// consumer lost nothing visible of its own scope.
//
// The page, the scoped frontier and latest_cursor come from the store's
// ATOMIC retention read (page + frontier + latest from one consistency
// point), so a prune cannot interleave between the frontier check and the
// page read.
type executionEventsResponse struct {
	Events           []model.ExecutionEvent `json:"events"`
	NextCursor       string                 `json:"next_cursor"`
	Canonical        bool                   `json:"canonical"`
	LatestCursor     string                 `json:"latest_cursor"`
	RetainedFrom     string                 `json:"retained_from,omitempty"`
	ScopeFingerprint string                 `json:"scope_fingerprint"`
	ResumeStatus     string                 `json:"resume_status,omitempty"`
}

// executionSnapshotResponse is the GET /api/v1/execution-snapshot body: the
// atomic bootstrap point of the execution event stream.
//
// Contract: ThroughSequence (also rendered as the typed Cursor/ResumeCursor
// pair) and the state summary (Runs, Counts) are read from ONE consistency
// point, with the cursor read FIRST. A transition committed between the two
// reads is therefore included in the state summary AND has an event seq
// strictly greater than ThroughSequence, so starting from this snapshot and
// polling GET /api/v1/events?after=resume_cursor can never miss it. Runs
// carries at most the bounded active-run list (newest first); Counts covers
// every job in the snapshot's scope regardless of that bound.
//
// Scope: without repo_id the snapshot spans every repository and requires a
// GLOBAL execution.events:read (or admin); with repo_id it exposes only that
// repository's runs and jobs and is authorized exactly like a
// repository-scoped event read (capability for the repository or plain read
// access to it). ResumeCursor is typed for the request's scope, so a
// repo-scoped consumer can only resume the matching repo-scoped stream.
type executionSnapshotResponse struct {
	Cursor           string                         `json:"cursor"`
	ResumeCursor     string                         `json:"resume_cursor"`
	ThroughSequence  int64                          `json:"through_sequence"`
	ScopeFingerprint string                         `json:"scope_fingerprint"`
	GeneratedAt      time.Time                      `json:"generated_at"`
	Runs             []storage.ExecutionSnapshotRun `json:"runs"`
	Counts           executionSnapshotCounts        `json:"counts"`
}

// executionSnapshotCounts is the queued/running JOB count in the snapshot's
// scope (every run for the global form, the addressed repository's runs for
// the repo_id form).
type executionSnapshotCounts struct {
	Queued  int `json:"queued"`
	Running int `json:"running"`
}

// cursorExpiredResponse is the 410 body for a cursor below the SCOPED
// retention frontier (list and stream alike): the fixed wire error kept for
// compatibility, the machine-readable reason telling the consumer to
// re-bootstrap through the execution snapshot, the scoped frontier and the
// typed latest committed cursor of the request's scope.
type cursorExpiredResponse struct {
	Error            string `json:"error"`
	Reason           string `json:"reason"`
	RetainedFrom     string `json:"retained_from"`
	LatestCursor     string `json:"latest_cursor"`
	ScopeFingerprint string `json:"scope_fingerprint"`
}

// cursorScopeMismatchResponse is the 409 body for a cursor presented under a
// different scope than the one it was issued for (including a legacy bare
// integer under a repository or run scope): the consumer must re-bootstrap
// for the requested scope instead of silently paging the wrong stream.
type cursorScopeMismatchResponse struct {
	Error            string `json:"error"`
	ScopeFingerprint string `json:"scope_fingerprint"`
}

// Typed execution event cursors: the wire form is xe1:<seq>:<fingerprint>,
// where the fingerprint is the first 16 hex characters of
// sha256("kiwi-events-cursor-v1\x00" + scope key) and the scope key is
// "global", "repo:<repoID>" or "run:<repoID>/<runID>". The fingerprint
// binds a cursor to the SCOPE, never to the principal: token rotation on the
// same scope keeps every cursor valid, and presenting a cursor across scopes
// is refused.
const (
	executionEventCursorPrefix = "xe1:"
	executionEventCursorDomain = "kiwi-events-cursor-v1"
)

// executionEventScopeFingerprint renders the scope's typed-cursor
// fingerprint (16 hex characters).
func executionEventScopeFingerprint(scope storage.ExecutionEventScope) string {
	sum := sha256.Sum256([]byte(executionEventCursorDomain + "\x00" + scope.ScopeKey()))
	return hex.EncodeToString(sum[:])[:16]
}

// buildExecutionEventCursor renders the typed cursor for one sequence in one
// scope.
func buildExecutionEventCursor(seq int64, scope storage.ExecutionEventScope) string {
	return executionEventCursorPrefix + strconv.FormatInt(seq, 10) + ":" + executionEventScopeFingerprint(scope)
}

// Execution event stream tuning, mirroring logs_stream.go.
const (
	executionEventStreamPollInterval = 250 * time.Millisecond
	executionEventStreamIdleTimeout  = 30 * time.Second
	executionEventStreamMaxChunk     = storage.MaxExecutionEventLimit
)

// appendExecutionEventErrLocked appends one execution event in fs/memory mode
// and returns the durable append failure. It is a no-op in DB mode, where the
// migration 0045 triggers append in the same transaction as the state change
// (a server-side append there would duplicate the event). The caller holds
// s.mu, which serializes the fs sequence allocation with the state mutation
// it describes. ctx is the caller's request/detach context: a canceled request
// fails the append before the journal is touched, matching auditFirstLocked.
// The repository dimension is resolved here from the server's run/job state
// when the caller left it empty, so the fs journal carries the same repo
// dimension the PostgreSQL triggers write.
func (s *Server) appendExecutionEventErrLocked(ctx context.Context, e model.ExecutionEvent) error {
	if s.store == nil || s.DB != nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.SchemaVersion <= 0 {
		e.SchemaVersion = 1
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	if e.RepoID == "" {
		e.RepoID = s.executionEventRepoIDLocked(e)
	}
	return s.store.AppendExecutionEvent(ctx, e)
}

// executionEventRepoIDLocked resolves an event's repository dimension from
// the in-memory run/job maps (fs/memory mode), mirroring the PostgreSQL
// trigger: the owning run's immutable RepoID, resolved directly or through
// the job. An unknown owner stays empty and is therefore invisible to every
// repository scope.
func (s *Server) executionEventRepoIDLocked(e model.ExecutionEvent) string {
	if e.RunID != "" {
		if run, ok := s.runs[e.RunID]; ok {
			return run.RepoID
		}
	}
	if e.JobID != "" {
		if j, ok := s.jobs[e.JobID]; ok {
			if j.RepoID != "" {
				return j.RepoID
			}
			if run, ok := s.runs[j.RunID]; ok {
				return run.RepoID
			}
		}
	}
	return ""
}

// appendExecutionEventLocked is the best-effort sibling used next to
// auditLocked sites (transitions already applied in memory): a failed append
// is logged, never silently dropped, exactly like auditLocked. The caller
// holds s.mu.
func (s *Server) appendExecutionEventLocked(e model.ExecutionEvent) {
	//lint:ignore SA1012 sanctioned nil-origin boundedDetach root for the context-free best-effort append path
	ctx, cancel := boundedDetach(nil, auditDetachTimeout)
	defer cancel()
	if err := s.appendExecutionEventErrLocked(ctx, e); err != nil {
		s.logError("execution event append failed", "type", e.Type, "run", e.RunID, "job", e.JobID, "error", err.Error())
	}
}

// runExecutionEvent builds one run aggregate transition event.
func runExecutionEvent(runID string, from, to model.Status) model.ExecutionEvent {
	return model.ExecutionEvent{
		RunID:      runID,
		Type:       storage.ExecutionEventType("run", from, to),
		FromStatus: string(from),
		ToStatus:   string(to),
		CreatedAt:  time.Now().UTC(),
	}
}

// jobExecutionEvent builds one job transition event.
func jobExecutionEvent(j model.Job, from, to model.Status, actor string, payload map[string]string) model.ExecutionEvent {
	if payload == nil {
		payload = map[string]string{"job": j.Key}
	}
	return model.ExecutionEvent{
		RunID:      j.RunID,
		JobID:      j.ID,
		RepoID:     j.RepoID,
		Attempt:    j.LeaseGeneration,
		Type:       storage.ExecutionEventType("job", from, to),
		FromStatus: string(from),
		ToStatus:   string(to),
		Actor:      actor,
		CreatedAt:  time.Now().UTC(),
		Payload:    payload,
	}
}

// appendRunEventLocked records one run aggregate transition (best-effort).
func (s *Server) appendRunEventLocked(runID string, from, to model.Status) {
	if from == to {
		return
	}
	s.appendExecutionEventLocked(runExecutionEvent(runID, from, to))
}

// appendJobEventLocked records one job transition (best-effort). attempt is
// the job's lease generation, so a re-leased job's events are attributable to
// the exact attempt.
func (s *Server) appendJobEventLocked(j model.Job, from, to model.Status, actor string, payload map[string]string) {
	if from == to {
		return
	}
	s.appendExecutionEventLocked(jobExecutionEvent(j, from, to, actor, payload))
}

// listEvents serves GET /api/v1/events: the scope-filtered ascending event
// page plus its typed next cursor, the store's latest committed cursor
// (bootstrap reference, typed in the same scope), the scoped retention
// frontier and the canonical flag (true only in DB mode). The route is
// capability tier: admin keeps its existing access, and a controller
// principal needs execution.events:read — GLOBALLY for the unscoped read,
// for the addressed repository when repo_id is supplied, or scoped to the
// run's repository (or plain read access to it) when run_id is supplied.
// Enforcement runs before any store read.
func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireExecutionEventsRead(w, r)
	if !ok {
		return
	}
	if !s.executionEventsSupported(w) {
		return
	}
	after, ok := parseEventCursor(w, r, scope)
	if !ok {
		return
	}
	limit := storage.ClampExecutionEventLimit(queryInt(r, "limit"))
	// ONE atomic read: page + scoped frontier + latest cursor share one
	// consistency point, so a prune cannot interleave between the frontier
	// check and the page read. Any store error fails closed (500): an
	// unproven frontier or cursor must never be treated as 0.
	events, cursor, retained, latest, err := s.readExecutionEventsRetention(r.Context(), after, limit, scope)
	if err != nil {
		s.internalError(w, r, err, "")
		return
	}
	if storage.ExecutionEventCursorExpired(after, retained) {
		s.writeCursorExpired(w, retained, latest, scope)
		return
	}
	writeJSON(w, http.StatusOK, executionEventsResponse{
		Events:           filterExecutionEventsInScope(events, scope),
		NextCursor:       buildExecutionEventCursor(cursor, scope),
		Canonical:        s.DB != nil,
		LatestCursor:     buildExecutionEventCursor(latest, scope),
		RetainedFrom:     strconv.FormatInt(retained, 10),
		ScopeFingerprint: executionEventScopeFingerprint(scope),
		ResumeStatus:     "resume_ok",
	})
}

// executionEventRetentionStore resolves the optional retention contract of
// the configured store (PostgreSQL or the fs repository). A store without
// the contract simply has no retention watermark (0) and can never expire a
// cursor.
func (s *Server) executionEventRetentionStore() (storage.RetentionExecutionEventStore, bool) {
	if s.DB != nil {
		rs, ok := s.DB.(storage.RetentionExecutionEventStore)
		return rs, ok
	}
	if s.store == nil {
		return nil, false
	}
	rs, ok := any(s.store).(storage.RetentionExecutionEventStore)
	return rs, ok
}

// readExecutionEventsRetention is the ONE list/stream read. It prefers the
// store's atomic ExecutionEventRetentionReadStore (PostgreSQL single-snapshot
// CTE; fs one repository-lock read); a store that only implements the legacy
// split contracts (test fakes) falls back to frontier + page + latest reads
// that still fail closed on ANY error, never defaulting to 0. Because the
// legacy split contracts cannot filter by repository or prove a repository
// frontier, a repository scope WITHOUT the atomic contract fails closed
// (503) instead of leaking another repository's events or mis-expiring a
// cursor; a run scope needs the scoped frontier contract (ScopedRetainedFrom)
// and a global scope keeps the legacy ExecutionEventRetainedFrom fallback. A
// store that lacks the execution event contract fails closed.
func (s *Server) readExecutionEventsRetention(ctx context.Context, after int64, limit int, scope storage.ExecutionEventScope) ([]model.ExecutionEvent, int64, int64, int64, error) {
	if s.DB != nil {
		if rs, ok := s.DB.(storage.ExecutionEventRetentionReadStore); ok {
			return rs.ReadExecutionEventsRetention(ctx, after, limit, scope)
		}
		if scope.Kind == storage.ExecutionEventScopeRepo {
			return nil, after, 0, 0, errUnsupportedExecutionEvents
		}
		var retained int64
		if scope.Kind == storage.ExecutionEventScopeRun {
			rs, ok := s.DB.(storage.ExecutionEventScopedRetentionStore)
			if !ok {
				return nil, after, 0, 0, errUnsupportedExecutionEvents
			}
			r, err := rs.ScopedRetainedFrom(ctx, scope)
			if err != nil {
				return nil, after, 0, 0, err
			}
			retained = r
		} else if rs, ok := s.DB.(storage.RetentionExecutionEventStore); ok {
			r, err := rs.ExecutionEventRetainedFrom(ctx)
			if err != nil {
				return nil, after, 0, 0, err
			}
			retained = r
		}
		es, ok := s.DB.(storage.ExecutionEventStore)
		if !ok {
			return nil, after, 0, 0, errUnsupportedExecutionEvents
		}
		runFilter := ""
		if scope.Kind == storage.ExecutionEventScopeRun {
			runFilter = scope.RunID
		}
		events, cursor, err := es.ListExecutionEvents(ctx, after, limit, runFilter)
		if err != nil {
			return nil, after, 0, 0, err
		}
		latest := cursor
		if cs, ok := s.DB.(storage.ExecutionEventCursorStore); ok {
			l, err := cs.LatestExecutionEventSeq(ctx)
			if err != nil {
				return nil, after, 0, 0, err
			}
			latest = l
		}
		return filterExecutionEventsInScope(events, scope), cursor, retained, latest, nil
	}
	if s.store == nil {
		// Memory-only server: the event stream is unsupported (empty), and
		// the cursor is the caller's position.
		return []model.ExecutionEvent{}, after, 0, after, nil
	}
	return s.store.ReadExecutionEventsRetention(ctx, after, limit, scope)
}

// filterExecutionEventsInScope is the server-side defense-in-depth filter:
// the store already scopes its page, and scoping again here guarantees a
// repository- or run-scoped response can never contain another scope's event
// even through a buggy or legacy store implementation.
func filterExecutionEventsInScope(events []model.ExecutionEvent, scope storage.ExecutionEventScope) []model.ExecutionEvent {
	if scope.Kind == storage.ExecutionEventScopeGlobal || len(events) == 0 {
		return events
	}
	out := make([]model.ExecutionEvent, 0, len(events))
	for _, e := range events {
		if executionEventInScope(e, scope) {
			out = append(out, e)
		}
	}
	return out
}

// executionEventInScope reports whether one execution event is visible in
// the request's scope: global sees everything, a repository scope requires
// the persisted repository id (an event with none belongs to no repository),
// a run scope requires the run id.
func executionEventInScope(e model.ExecutionEvent, scope storage.ExecutionEventScope) bool {
	switch scope.Kind {
	case storage.ExecutionEventScopeRepo:
		return e.RepoID == scope.RepoID
	case storage.ExecutionEventScopeRun:
		return e.RunID == scope.RunID
	default:
		return true
	}
}

// writeCursorExpired answers the retention refusal for list and stream
// consumers: HTTP 410 with the fixed cursor_expired wire error, the
// snapshot-required reason, the SCOPED frontier and the typed latest_cursor
// of the request's scope. All values come from the atomic read that proved
// the expiry, so they cannot disagree with the page the consumer would have
// read.
func (s *Server) writeCursorExpired(w http.ResponseWriter, retainedFrom, latest int64, scope storage.ExecutionEventScope) {
	writeJSON(w, http.StatusGone, cursorExpiredResponse{
		Error:            "cursor_expired",
		Reason:           "cursor_expired_snapshot_required",
		RetainedFrom:     strconv.FormatInt(retainedFrom, 10),
		LatestCursor:     buildExecutionEventCursor(latest, scope),
		ScopeFingerprint: executionEventScopeFingerprint(scope),
	})
}

// writeCursorScopeMismatch answers a cursor bound to a different scope (or a
// legacy bare integer under a non-global scope): HTTP 409, so the consumer
// re-bootstraps for the requested scope instead of silently paging another
// scope's stream.
func writeCursorScopeMismatch(w http.ResponseWriter, scope storage.ExecutionEventScope) {
	writeJSON(w, http.StatusConflict, cursorScopeMismatchResponse{
		Error:            "cursor_scope_mismatch",
		ScopeFingerprint: executionEventScopeFingerprint(scope),
	})
}

// executionEventsSupported reports whether the configured store can serve the
// event stream and answers 503 when it cannot (a custom Store without the
// optional contract). The fs repository always can.
func (s *Server) executionEventsSupported(w http.ResponseWriter) bool {
	if s.DB == nil {
		return true
	}
	if _, ok := s.DB.(storage.ExecutionEventStore); !ok {
		http.Error(w, "store does not support the execution event stream", http.StatusServiceUnavailable)
		return false
	}
	return true
}

var errUnsupportedExecutionEvents = errors.New("server: store lacks the execution event stream contract")

var errUnsupportedExecutionSnapshot = errors.New("server: store lacks the execution snapshot contract")

// executionSnapshot serves GET /api/v1/execution-snapshot: the atomic
// bootstrap endpoint a controller starts from. It returns the event cursor
// and the active-run/state summary from ONE consistency point (cursor read
// FIRST; see ExecutionSnapshotStore) so a consumer that then pages
// GET /api/v1/events?after=resume_cursor cannot miss a transition committed
// between the two reads. The route is capability tier: without repo_id no
// repository is addressed, so execution.events:read must be held GLOBALLY
// (or admin); with repo_id the request is authorized exactly like a
// repository-scoped event read.
func (s *Server) executionSnapshot(w http.ResponseWriter, r *http.Request) {
	repoID, ok := s.requireExecutionSnapshotRead(w, r)
	if !ok {
		return
	}
	snap, err := s.buildExecutionSnapshot(r.Context(), storage.DefaultExecutionSnapshotRuns, repoID)
	if err != nil {
		if errors.Is(err, errUnsupportedExecutionSnapshot) {
			http.Error(w, "store does not support the execution snapshot", http.StatusServiceUnavailable)
			return
		}
		s.internalError(w, r, err, "")
		return
	}
	if snap.Runs == nil {
		snap.Runs = []storage.ExecutionSnapshotRun{}
	}
	scope := storage.ExecutionEventScope{Kind: storage.ExecutionEventScopeGlobal}
	if repoID != "" {
		scope = storage.ExecutionEventScope{Kind: storage.ExecutionEventScopeRepo, RepoID: repoID}
	}
	resume := buildExecutionEventCursor(snap.Cursor, scope)
	writeJSON(w, http.StatusOK, executionSnapshotResponse{
		Cursor:           resume,
		ResumeCursor:     resume,
		ThroughSequence:  snap.Cursor,
		ScopeFingerprint: executionEventScopeFingerprint(scope),
		GeneratedAt:      snap.GeneratedAt,
		Runs:             snap.Runs,
		Counts: executionSnapshotCounts{
			Queued:  snap.Queued,
			Running: snap.Running,
		},
	})
}

// buildExecutionSnapshot resolves the atomic snapshot for the configured
// mode. DB mode delegates to the store's one-transaction implementation; a
// DB store without the contract fails closed (503) rather than serving a
// non-atomic summary. fs/memory mode builds it under s.mu (the same lock
// every transition and fs event append takes), reading the cursor FIRST from
// the repository's monotonic watermark. repoID empty keeps the global
// summary; otherwise only runs (and jobs of runs) with that repository
// identity are included.
func (s *Server) buildExecutionSnapshot(ctx context.Context, runLimit int, repoID string) (storage.ExecutionSnapshot, error) {
	if s.DB != nil {
		ss, ok := s.DB.(storage.ExecutionSnapshotStore)
		if !ok {
			return storage.ExecutionSnapshot{}, errUnsupportedExecutionSnapshot
		}
		return ss.ExecutionSnapshot(ctx, runLimit, repoID)
	}
	if runLimit <= 0 || runLimit > storage.MaxExecutionSnapshotRuns {
		runLimit = storage.DefaultExecutionSnapshotRuns
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Cursor FIRST, then the state summary: both mutation and event append
	// happen under s.mu in fs/memory mode, so no transition can commit in
	// between and the ordering is trivially consistent.
	var cursor int64
	if s.store != nil {
		latest, err := s.store.LatestExecutionEventSeq(ctx)
		if err != nil {
			return storage.ExecutionSnapshot{}, err
		}
		cursor = latest
	}
	snap := storage.ExecutionSnapshot{Cursor: cursor, GeneratedAt: time.Now().UTC(), Runs: []storage.ExecutionSnapshotRun{}}
	runs := make([]storage.ExecutionSnapshotRun, 0, len(s.runs))
	matching := make(map[string]bool, len(s.runs))
	for _, run := range s.runs {
		if repoID != "" && executionSnapshotRunRepoID(run) != repoID {
			continue
		}
		matching[run.ID] = true
		if run.Status.Terminal() {
			continue
		}
		runs = append(runs, storage.ExecutionSnapshotRun{
			ID: run.ID, RepoID: run.RepoID, Ref: run.Ref, Status: run.Status, CreatedAt: run.CreatedAt,
		})
	}
	sort.Slice(runs, func(i, j int) bool {
		if !runs[i].CreatedAt.Equal(runs[j].CreatedAt) {
			return runs[i].CreatedAt.After(runs[j].CreatedAt)
		}
		return runs[i].ID < runs[j].ID
	})
	if len(runs) > runLimit {
		runs = runs[:runLimit]
	}
	for _, j := range s.jobs {
		if repoID != "" && !matching[j.RunID] {
			continue
		}
		switch j.Status {
		case model.StatusQueued:
			snap.Queued++
		case model.StatusRunning:
			snap.Running++
		}
	}
	snap.Runs = runs
	return snap, nil
}

// executionSnapshotRunRepoID is the repository dimension of one fs/memory
// run for the snapshot filter, matching the stored payload repo_id the SQL
// form filters on: the immutable RepoID when present, otherwise the derived
// canonical identity.
func executionSnapshotRunRepoID(run model.Run) string {
	return repoIDFor(run.RepoID, run.Repo, run.RepoFullName)
}

// parseEventCursor parses the optional ?after cursor for the request's
// scope:
//
//   - empty starts fresh (0);
//   - a typed xe1:<seq>:<fingerprint> cursor must match the request scope's
//     fingerprint, otherwise 409 cursor_scope_mismatch (a cursor must never
//     be replayed against a different visibility scope);
//   - a legacy bare integer is accepted ONLY for the global scope and is
//     treated as unbound, so consumers that never left the global stream
//     keep working;
//   - anything else is a 400 (a cursor typo must never silently restart the
//     stream).
func parseEventCursor(w http.ResponseWriter, r *http.Request, scope storage.ExecutionEventScope) (int64, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("after"))
	if raw == "" {
		return 0, true
	}
	if strings.HasPrefix(raw, executionEventCursorPrefix) {
		seqPart, fingerprint, ok := strings.Cut(strings.TrimPrefix(raw, executionEventCursorPrefix), ":")
		if !ok || seqPart == "" || fingerprint == "" {
			http.Error(w, "invalid after cursor", http.StatusBadRequest)
			return 0, false
		}
		seq, err := strconv.ParseInt(seqPart, 10, 64)
		if err != nil || seq < 0 {
			http.Error(w, "invalid after cursor", http.StatusBadRequest)
			return 0, false
		}
		if fingerprint != executionEventScopeFingerprint(scope) {
			writeCursorScopeMismatch(w, scope)
			return 0, false
		}
		return seq, true
	}
	after, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || after < 0 {
		http.Error(w, "invalid after cursor", http.StatusBadRequest)
		return 0, false
	}
	if scope.Kind != storage.ExecutionEventScopeGlobal {
		writeCursorScopeMismatch(w, scope)
		return 0, false
	}
	return after, true
}

func queryInt(r *http.Request, key string) int {
	v, _ := strconv.Atoi(r.URL.Query().Get(key))
	return v
}

// streamExecutionEvents serves GET /api/v1/events/stream as Server-Sent
// Events, reusing the logs stream pattern: one `event: execution` frame per
// event carrying the ExecutionEvent JSON, `id: <typed cursor>` (the SAME
// xe1:<seq>:<fingerprint> form the list endpoint issues, so a reconnect with
// ?after=<last id> is valid for the stream's scope) and a 250ms poll, and a
// 30s idle timeout. The route is capability tier with the same
// run_id/repo_id scope as the cursor-pull list endpoint; authorization runs
// before any streaming begins (before the 200 is committed), and the store
// read is scope-filtered (plus a defensive server-side scope predicate), so
// a repository-scoped stream can never emit another repository's events.
//
// Retention is checked ATOMICALLY against the SCOPED frontier both at
// establishment (before the 200, so an expired reconnect observes HTTP 410
// cursor_expired with the scoped frontier and latest cursor) and on every
// poll: a live tail whose cursor falls below a newly advanced SCOPE frontier
// receives a terminal `event: cursor_expired` frame instead of silently
// skipping the pruned prefix. A global prune that removed only other scopes'
// events leaves the scoped frontier unchanged, so the tail keeps
// streaming.
func (s *Server) streamExecutionEvents(w http.ResponseWriter, r *http.Request) {
	scope, ok := s.requireExecutionEventsRead(w, r)
	if !ok {
		return
	}
	if s.DB == nil && s.store == nil {
		http.Error(w, "event streaming requires a persistent server", http.StatusServiceUnavailable)
		return
	}
	if !s.executionEventsSupported(w) {
		return
	}
	after, ok := parseEventCursor(w, r, scope)
	if !ok {
		return
	}
	// Retention refusal BEFORE the 200 is committed, through the atomic read:
	// an SSE reconnect with an expired cursor must observe HTTP 410
	// cursor_expired (with the scoped frontier and the latest cursor from the
	// same consistency point), never a stream that silently resumes past the
	// lost prefix. The page read is discarded; the loop re-reads from
	// `after`.
	_, _, retained, latest, err := s.readExecutionEventsRetention(r.Context(), after, 1, scope)
	if err != nil {
		s.internalError(w, r, err, "")
		return
	}
	if storage.ExecutionEventCursorExpired(after, retained) {
		s.writeCursorExpired(w, retained, latest, scope)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fl.Flush()

	last := time.Now()
	for {
		events, cursor, retained, latest, err := s.readExecutionEventsRetention(r.Context(), after, executionEventStreamMaxChunk, scope)
		if err != nil {
			if r.Context().Err() != nil {
				return
			}
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", jsonQuote(err.Error()))
			fl.Flush()
			return
		}
		if storage.ExecutionEventCursorExpired(after, retained) {
			// A prune advanced the SCOPED frontier past this live tail's
			// cursor: terminate with the same cursor_expired contract the
			// HTTP entry uses (the status cannot change after the 200).
			body, _ := jsonMarshal(cursorExpiredResponse{
				Error:            "cursor_expired",
				Reason:           "cursor_expired_snapshot_required",
				RetainedFrom:     strconv.FormatInt(retained, 10),
				LatestCursor:     buildExecutionEventCursor(latest, scope),
				ScopeFingerprint: executionEventScopeFingerprint(scope),
			})
			fmt.Fprintf(w, "event: cursor_expired\ndata: %s\n\n", body)
			fl.Flush()
			return
		}
		if len(events) > 0 {
			for _, e := range events {
				if !executionEventInScope(e, scope) {
					continue
				}
				b, merr := jsonMarshal(e)
				if merr != nil {
					continue
				}
				// The SSE id is the SAME typed cursor the list endpoint
				// issues, so a reconnect with ?after=<last id> is valid for
				// the stream's scope (a numeric id could not be replayed
				// under a repository or run scope).
				fmt.Fprintf(w, "id: %s\nevent: execution\ndata: %s\n\n", buildExecutionEventCursor(e.Seq, scope), b)
			}
			after = cursor
			fl.Flush()
			last = time.Now()
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(executionEventStreamPollInterval):
		}
		if time.Since(last) >= executionEventStreamIdleTimeout {
			fmt.Fprint(w, "event: done\ndata: idle timeout\n\n")
			fl.Flush()
			return
		}
	}
}

// requireExecutionEventsRead enforces GET /api/v1/events and
// /api/v1/events/stream and returns the resolved storage scope the read (and
// every cursor it issues or accepts) is bound to:
//
//   - run_id resolves a run scope: the run's canonical repository identity is
//     used for the authorization decision, which is accepted with the
//     capability scoped to that repository OR plain READ access to it; a
//     run_id that cannot be resolved (unknown run, store error) fails closed
//     — only a global capability (or admin) covers a scope that cannot be
//     established;
//   - without run_id, a repo_id query parameter resolves a repository scope
//     with the same decision (capability for that repository or read access
//     to it);
//   - with neither, the read spans every repository and only a GLOBAL
//     execution.events:read capability (or admin) is accepted.
func (s *Server) requireExecutionEventsRead(w http.ResponseWriter, r *http.Request) (storage.ExecutionEventScope, bool) {
	runID := strings.TrimSpace(r.URL.Query().Get("run_id"))
	repoID := strings.TrimSpace(r.URL.Query().Get("repo_id"))
	p, ok := auth.PrincipalFrom(r)
	if !ok {
		// Legacy/admin/web-session access: the tier gate already decided.
		// The scope is still resolved so typed cursors bind consistently.
		return s.executionRequestScope(r, runID, repoID), true
	}
	if runID != "" {
		// A global execution.events:read capability keeps the existing
		// tolerant behavior, including the unknown-run empty read: it already
		// sees every repository's stream, so no existence can be leaked.
		if auth.AuthorizeCapability(p, auth.CapExecutionEventsRead, "") {
			scope := storage.ExecutionEventScope{Kind: storage.ExecutionEventScopeRun, RunID: runID}
			if run, err := s.runForAuth(r.Context(), runID); err == nil {
				scope.RepoID = repoIDForRun(run)
			}
			return scope, true
		}
		// Otherwise an unknown run_id and a run the caller cannot see are the
		// SAME masked 404 (never the old fail-closed 403, which let a caller
		// distinguish another repository's run from a missing id).
		run, ok := s.requireRunVisible(w, r, runID)
		if !ok {
			return storage.ExecutionEventScope{}, false
		}
		repo := repoIDForRun(run)
		if auth.AuthorizeCapability(p, auth.CapExecutionEventsRead, repo) || auth.CanReadRepo(p, repo) {
			return storage.ExecutionEventScope{Kind: storage.ExecutionEventScopeRun, RepoID: repo, RunID: runID}, true
		}
		s.writeMaskedRunNotFound(w)
		return storage.ExecutionEventScope{}, false
	}
	if repoID != "" {
		if auth.AuthorizeCapability(p, auth.CapExecutionEventsRead, repoID) || auth.CanReadRepo(p, repoID) {
			return storage.ExecutionEventScope{Kind: storage.ExecutionEventScopeRepo, RepoID: repoID}, true
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return storage.ExecutionEventScope{}, false
	}
	if auth.AuthorizeCapability(p, auth.CapExecutionEventsRead, "") {
		return storage.ExecutionEventScope{Kind: storage.ExecutionEventScopeGlobal}, true
	}
	http.Error(w, "forbidden", http.StatusForbidden)
	return storage.ExecutionEventScope{}, false
}

// executionRequestScope resolves the request's storage scope without an
// authorization decision (the no-principal path): run_id wins, then repo_id,
// then global. The run's repository is resolved best-effort for cursor
// binding; an unknown run yields an empty repository in the run scope.
func (s *Server) executionRequestScope(r *http.Request, runID, repoID string) storage.ExecutionEventScope {
	if runID != "" {
		scope := storage.ExecutionEventScope{Kind: storage.ExecutionEventScopeRun, RunID: runID}
		if run, err := s.runForAuth(r.Context(), runID); err == nil {
			scope.RepoID = repoIDForRun(run)
		}
		return scope
	}
	if repoID != "" {
		return storage.ExecutionEventScope{Kind: storage.ExecutionEventScopeRepo, RepoID: repoID}
	}
	return storage.ExecutionEventScope{Kind: storage.ExecutionEventScopeGlobal}
}

// requireExecutionSnapshotRead enforces GET /api/v1/execution-snapshot and
// returns the repository scope ("" = global). A repo_id parameter is
// authorized exactly like a repository-scoped event read (capability for
// that repository OR plain read access to it), so the snapshot can never
// expose more than the event stream of the same repository; the unscoped
// form spans every repository and requires a GLOBAL capability (or admin).
func (s *Server) requireExecutionSnapshotRead(w http.ResponseWriter, r *http.Request) (string, bool) {
	repoID := strings.TrimSpace(r.URL.Query().Get("repo_id"))
	p, ok := auth.PrincipalFrom(r)
	if !ok {
		return repoID, true
	}
	if repoID == "" {
		if auth.AuthorizeCapability(p, auth.CapExecutionEventsRead, "") {
			return "", true
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return "", false
	}
	if auth.AuthorizeCapability(p, auth.CapExecutionEventsRead, repoID) || auth.CanReadRepo(p, repoID) {
		return repoID, true
	}
	http.Error(w, "forbidden", http.StatusForbidden)
	return "", false
}
