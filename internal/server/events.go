package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// executionEventsResponse is the GET /api/v1/events body: the ascending page
// plus the cursor a follow-up call must send as ?after.
//
// Canonical is true only in DB mode, where the stream is the authoritative
// commit-ordered PostgreSQL feed. fs/memory mode reports false: its journal
// is BEST-EFFORT TELEMETRY, not the transactional record of the mutation —
// a failed fs append consumes a cursor but loses the record, so the state
// change wins over the stream, and consumers must treat fs events as a
// non-canonical mirror that may lag or omit events.
//
// LatestCursor is the latest committed cursor: the monotonic commit-ordered
// cursor value in DB mode, the durable journal watermark in fs mode. A
// consumer can snapshot state, read latest_cursor, then poll
// after=latest_cursor and miss no event in between; it never regresses when
// retention removes rows.
//
// RetainedFrom is the retention watermark: the HIGHEST seq already pruned
// from the stream (0 when nothing was pruned). A cursor strictly BELOW
// retained_from has lost events; the endpoint answers 410 cursor_expired
// with the watermark and latest_cursor so the consumer re-bootstraps.
// after == retained_from stays valid (the consumer consumed the removed
// prefix's last seq).
//
// Both values come from the store's ATOMIC retention read (watermark + page
// + latest from one consistency point), so a prune cannot interleave between
// the watermark check and the page read.
type executionEventsResponse struct {
	Events       []model.ExecutionEvent `json:"events"`
	NextCursor   string                 `json:"next_cursor"`
	Canonical    bool                   `json:"canonical"`
	LatestCursor string                 `json:"latest_cursor"`
	RetainedFrom string                 `json:"retained_from,omitempty"`
}

// executionSnapshotResponse is the GET /api/v1/execution-snapshot body: the
// atomic bootstrap point of the execution event stream.
//
// Contract: Cursor and the state summary (Runs, Counts) are read from ONE
// consistency point, with the cursor read FIRST. A transition committed
// between the two reads is therefore included in the state summary AND has
// an event seq strictly greater than Cursor, so starting from this snapshot
// and polling GET /api/v1/events?after=Cursor can never miss it. Runs carries
// at most the bounded active-run list (newest first); Counts covers every
// job in the store regardless of that bound.
type executionSnapshotResponse struct {
	Cursor      string                         `json:"cursor"`
	GeneratedAt time.Time                      `json:"generated_at"`
	Runs        []storage.ExecutionSnapshotRun `json:"runs"`
	Counts      executionSnapshotCounts        `json:"counts"`
}

// executionSnapshotCounts is the queued/running JOB count across every run.
type executionSnapshotCounts struct {
	Queued  int `json:"queued"`
	Running int `json:"running"`
}

// cursorExpiredResponse is the 410 body for a cursor below the retention
// watermark (list and stream alike): the fixed reason plus the watermark and
// the latest committed cursor the consumer must re-bootstrap from.
type cursorExpiredResponse struct {
	Error        string `json:"error"`
	RetainedFrom string `json:"retained_from"`
	LatestCursor string `json:"latest_cursor"`
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
	return s.store.AppendExecutionEvent(ctx, e)
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

// listEvents serves GET /api/v1/events: the canonical ascending event page
// plus its next cursor, the store's latest committed cursor (bootstrap
// reference) and the canonical flag (true only in DB mode). The route is
// capability tier: admin keeps its existing access, and a controller
// principal needs execution.events:read — GLOBALLY for the unscoped cursor
// read, or scoped to the run's repository (or plain read access to that
// repository) when run_id is supplied. Enforcement runs before any store
// read.
func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	if !s.requireExecutionEventsRead(w, r) {
		return
	}
	if !s.executionEventsSupported(w) {
		return
	}
	after, ok := parseEventCursor(w, r)
	if !ok {
		return
	}
	limit := storage.ClampExecutionEventLimit(queryInt(r, "limit"))
	runID := strings.TrimSpace(r.URL.Query().Get("run_id"))
	// ONE atomic read: page + retained_from + latest cursor share one
	// consistency point, so a prune cannot interleave between the watermark
	// check and the page read. Any store error fails closed (500): an
	// unproven watermark or cursor must never be treated as 0.
	events, cursor, retained, latest, err := s.readExecutionEventsRetention(r.Context(), after, limit, runID)
	if err != nil {
		s.internalError(w, r, err, "")
		return
	}
	if storage.ExecutionEventCursorExpired(after, retained) {
		s.writeCursorExpired(w, retained, latest)
		return
	}
	writeJSON(w, http.StatusOK, executionEventsResponse{
		Events:       events,
		NextCursor:   strconv.FormatInt(cursor, 10),
		Canonical:    s.DB != nil,
		LatestCursor: strconv.FormatInt(latest, 10),
		RetainedFrom: strconv.FormatInt(retained, 10),
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
// split contracts (test fakes) falls back to watermark + page + latest reads
// that still fail closed on ANY error, never defaulting to 0. A store that
// lacks the execution event contract fails closed.
func (s *Server) readExecutionEventsRetention(ctx context.Context, after int64, limit int, runID string) ([]model.ExecutionEvent, int64, int64, int64, error) {
	if s.DB != nil {
		if rs, ok := s.DB.(storage.ExecutionEventRetentionReadStore); ok {
			return rs.ReadExecutionEventsRetention(ctx, after, limit, runID)
		}
		var retained int64
		if rs, ok := s.DB.(storage.RetentionExecutionEventStore); ok {
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
		events, cursor, err := es.ListExecutionEvents(ctx, after, limit, runID)
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
		return events, cursor, retained, latest, nil
	}
	if s.store == nil {
		// Memory-only server: the event stream is unsupported (empty), and
		// the cursor is the caller's position.
		return []model.ExecutionEvent{}, after, 0, after, nil
	}
	return s.store.ReadExecutionEventsRetention(ctx, after, limit, runID)
}

// writeCursorExpired answers the retention refusal for list and stream
// consumers: HTTP 410 with the fixed cursor_expired reason and the watermark
// plus latest_cursor the consumer must re-bootstrap from. Both values come
// from the atomic read that proved the expiry, so they cannot disagree with
// the page the consumer would have read.
func (s *Server) writeCursorExpired(w http.ResponseWriter, retainedFrom, latest int64) {
	writeJSON(w, http.StatusGone, cursorExpiredResponse{
		Error:        "cursor_expired",
		RetainedFrom: strconv.FormatInt(retainedFrom, 10),
		LatestCursor: strconv.FormatInt(latest, 10),
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
// GET /api/v1/events?after=cursor cannot miss a transition committed between
// the two reads. The route is capability tier: no repository is addressed,
// so execution.events:read must be held GLOBALLY (or admin).
func (s *Server) executionSnapshot(w http.ResponseWriter, r *http.Request) {
	if !s.requireExecutionEventsRead(w, r) {
		return
	}
	snap, err := s.buildExecutionSnapshot(r.Context(), storage.DefaultExecutionSnapshotRuns)
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
	writeJSON(w, http.StatusOK, executionSnapshotResponse{
		Cursor:      strconv.FormatInt(snap.Cursor, 10),
		GeneratedAt: snap.GeneratedAt,
		Runs:        snap.Runs,
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
// the repository's monotonic watermark.
func (s *Server) buildExecutionSnapshot(ctx context.Context, runLimit int) (storage.ExecutionSnapshot, error) {
	if s.DB != nil {
		ss, ok := s.DB.(storage.ExecutionSnapshotStore)
		if !ok {
			return storage.ExecutionSnapshot{}, errUnsupportedExecutionSnapshot
		}
		return ss.ExecutionSnapshot(ctx, runLimit)
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
	for _, run := range s.runs {
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

// parseEventCursor parses the optional ?after cursor: empty or "0" starts
// from the oldest retained event, a negative or non-numeric value is a 400
// (a cursor typo must never silently restart the stream).
func parseEventCursor(w http.ResponseWriter, r *http.Request) (int64, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("after"))
	if raw == "" {
		return 0, true
	}
	after, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || after < 0 {
		http.Error(w, "invalid after cursor", http.StatusBadRequest)
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
// event carrying the ExecutionEvent JSON, `id: <seq>` so a reconnect can
// resume with ?after=<last-id> without gaps or duplicates, a 250ms poll, and
// a 30s idle timeout. The route is capability tier with the same run_id scope
// as the cursor-pull list endpoint; authorization runs before any streaming
// begins (before the 200 is committed).
//
// Retention is checked ATOMICALLY both at establishment (before the 200, so
// an expired reconnect observes HTTP 410 cursor_expired with the watermark
// and latest cursor) and on every poll: a live tail whose cursor falls below
// a newly advanced watermark receives a terminal `event: cursor_expired`
// frame instead of silently skipping the pruned prefix. A non-expired cursor
// keeps streaming normally.
func (s *Server) streamExecutionEvents(w http.ResponseWriter, r *http.Request) {
	if !s.requireExecutionEventsRead(w, r) {
		return
	}
	if s.DB == nil && s.store == nil {
		http.Error(w, "event streaming requires a persistent server", http.StatusServiceUnavailable)
		return
	}
	if !s.executionEventsSupported(w) {
		return
	}
	after, ok := parseEventCursor(w, r)
	if !ok {
		return
	}
	// Retention refusal BEFORE the 200 is committed, through the atomic read:
	// an SSE reconnect with an expired cursor must observe HTTP 410
	// cursor_expired (with the watermark and the latest cursor from the same
	// consistency point), never a stream that silently resumes past the lost
	// prefix. The page read is discarded; the loop re-reads from `after`.
	_, _, retained, latest, err := s.readExecutionEventsRetention(r.Context(), after, 1, "")
	if err != nil {
		s.internalError(w, r, err, "")
		return
	}
	if storage.ExecutionEventCursorExpired(after, retained) {
		s.writeCursorExpired(w, retained, latest)
		return
	}
	runID := strings.TrimSpace(r.URL.Query().Get("run_id"))
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
		events, cursor, retained, latest, err := s.readExecutionEventsRetention(r.Context(), after, executionEventStreamMaxChunk, runID)
		if err != nil {
			if r.Context().Err() != nil {
				return
			}
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", jsonQuote(err.Error()))
			fl.Flush()
			return
		}
		if storage.ExecutionEventCursorExpired(after, retained) {
			// A prune advanced the watermark past this live tail's cursor:
			// terminate with the same cursor_expired contract the HTTP entry
			// uses (the status cannot change after the 200).
			body, _ := jsonMarshal(cursorExpiredResponse{
				Error:        "cursor_expired",
				RetainedFrom: strconv.FormatInt(retained, 10),
				LatestCursor: strconv.FormatInt(latest, 10),
			})
			fmt.Fprintf(w, "event: cursor_expired\ndata: %s\n\n", body)
			fl.Flush()
			return
		}
		if len(events) > 0 {
			for _, e := range events {
				b, merr := jsonMarshal(e)
				if merr != nil {
					continue
				}
				fmt.Fprintf(w, "id: %d\nevent: execution\ndata: %s\n\n", e.Seq, b)
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
