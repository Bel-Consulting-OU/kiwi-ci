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

const (
	// logStreamPollInterval is how often the stream re-reads the log store.
	logStreamPollInterval = 250 * time.Millisecond
	// logStreamIdleTimeout closes the stream after this long without new
	// entries (overridable per-server via LogStreamIdleTimeout).
	logStreamIdleTimeout = 30 * time.Second
	// logStreamMaxChunk bounds entries per poll so a backlog cannot
	// stall the stream.
	logStreamMaxChunk = 2000
)

// parseLogCursor parses the optional ?after log cursor: empty means "from
// the beginning", a negative or non-numeric value is a 400 (a cursor typo
// must never silently replay the whole run). It is shared by the log list
// and the SSE stream so both answer identically.
func parseLogCursor(w http.ResponseWriter, r *http.Request) (int64, bool) {
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

// latestLogSeq resolves the RUN's monotonic log high-water for the stream's
// advisory header: PostgreSQL's per-run log_cursors row, or the addressed
// run's maximum durable seq in fs mode (single-line journal plus committed
// batch records). A store without the contract simply gets no header; an
// error also omits it (the header is advisory metadata, never a read
// precondition).
func (s *Server) latestLogSeq(ctx context.Context, runID string) (int64, bool) {
	if s.DB != nil {
		cs, ok := s.DB.(storage.LogCursorStore)
		if !ok {
			return 0, false
		}
		v, err := cs.LatestLogSeq(ctx, runID)
		return v, err == nil
	}
	if s.store != nil {
		v, err := s.store.LatestLogSeq(ctx, runID)
		return v, err == nil
	}
	return 0, false
}

// streamLogs serves GET /api/v1/runs/{id}/logs/stream as Server-Sent
// Events. Each log entry is one `data:` event carrying the LogEntry JSON
// line; the SSE event id is the entry's Seq so a reconnecting client can
// resume with ?after=<last-id> without gaps or duplicates. The stream
// polls the store every 250ms, flushes each chunk, and ends after 30s
// without new entries (or when the client disconnects).
//
// A malformed ?after is refused with HTTP 400 before any byte of the stream
// is committed. The response carries X-Kiwi-Log-Latest, the run's monotonic
// log high-water from the store's log cursor (when the store exposes it), so
// a client can tell how far the committed stream reaches without racing the
// poll loop.
//
// Streaming requires a persistent store; in-memory servers answer 503.
func (s *Server) streamLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.DB == nil && s.store == nil {
		http.Error(w, "log streaming requires a persistent server", http.StatusServiceUnavailable)
		return
	}
	run, err := s.runForAuth(r.Context(), id)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.internalError(w, r, err, "")
		return
	}
	if !s.requireRunRead(w, r, run) {
		return
	}
	after, ok := parseLogCursor(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > logStreamMaxChunk {
		limit = logStreamMaxChunk
	}
	read := func() ([]model.LogEntry, error) {
		if s.DB != nil {
			return s.DB.ReadLogs(r.Context(), id, after, limit)
		}
		if s.store != nil {
			return s.store.ReadLogs(id, after, limit)
		}
		return nil, storage.ErrNotFound
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	if latest, ok := s.latestLogSeq(r.Context(), id); ok {
		w.Header().Set("X-Kiwi-Log-Latest", strconv.FormatInt(latest, 10))
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fl.Flush()

	idle := s.LogStreamIdleTimeout
	if idle <= 0 {
		idle = logStreamIdleTimeout
	}
	last := time.Now()
	for {
		entries, err := read()
		if err != nil {
			if r.Context().Err() != nil {
				return
			}
			if errors.Is(err, storage.ErrNotFound) {
				fmt.Fprint(w, "event: done\ndata: run not found\n\n")
				fl.Flush()
				return
			}
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", jsonQuote(err.Error()))
			fl.Flush()
			return
		}
		if len(entries) > 0 {
			for _, e := range entries {
				b, merr := jsonMarshal(e)
				if merr != nil {
					continue
				}
				fmt.Fprintf(w, "id: %d\ndata: %s\n\n", e.Seq, b)
				if e.Seq > after {
					after = e.Seq
				}
			}
			fl.Flush()
			last = time.Now()
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(logStreamPollInterval):
		}
		if time.Since(last) >= idle {
			fmt.Fprint(w, "event: done\ndata: idle timeout\n\n")
			fl.Flush()
			return
		}
	}
}

// jsonQuote returns the JSON-encoded form of s.
func jsonQuote(s string) string {
	b, _ := jsonMarshal(s)
	return string(b)
}
