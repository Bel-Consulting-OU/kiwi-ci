package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// executionEventsResponse is the GET /api/v1/events body: the ascending page
// plus the cursor a follow-up call must send as ?after.
type executionEventsResponse struct {
	Events     []model.ExecutionEvent `json:"events"`
	NextCursor string                 `json:"next_cursor"`
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
// plus its next cursor. The route is admin tier (same as /api/v1/audit:
// auth.ActionFor does not map it, so classifyRoute sends it to the blanket
// admin gate).
func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	if !s.executionEventsSupported(w) {
		return
	}
	after, ok := parseEventCursor(w, r)
	if !ok {
		return
	}
	limit := storage.ClampExecutionEventLimit(queryInt(r, "limit"))
	runID := strings.TrimSpace(r.URL.Query().Get("run_id"))
	events, cursor, err := s.readExecutionEvents(r.Context(), after, limit, runID)
	if err != nil {
		s.internalError(w, r, err, "")
		return
	}
	writeJSON(w, http.StatusOK, executionEventsResponse{Events: events, NextCursor: strconv.FormatInt(cursor, 10)})
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

// readExecutionEvents resolves the configured store and applies the same
// bounded read for the list and stream handlers. A store that is neither the
// fs repository nor an ExecutionEventStore-capable DB store fails closed
// (503): answering an empty stream would look like "no events happened".
func (s *Server) readExecutionEvents(ctx context.Context, after int64, limit int, runID string) ([]model.ExecutionEvent, int64, error) {
	if s.DB != nil {
		es, ok := s.DB.(storage.ExecutionEventStore)
		if !ok {
			return nil, after, errUnsupportedExecutionEvents
		}
		return es.ListExecutionEvents(ctx, after, limit, runID)
	}
	if s.store == nil {
		return []model.ExecutionEvent{}, after, nil
	}
	return s.store.ListExecutionEvents(ctx, after, limit, runID)
}

var errUnsupportedExecutionEvents = errors.New("server: store lacks the execution event stream contract")

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
// a 30s idle timeout. The route is admin tier, so authorization runs before
// any streaming begins.
func (s *Server) streamExecutionEvents(w http.ResponseWriter, r *http.Request) {
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
		events, cursor, err := s.readExecutionEvents(r.Context(), after, executionEventStreamMaxChunk, runID)
		if err != nil {
			if r.Context().Err() != nil {
				return
			}
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", jsonQuote(err.Error()))
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
