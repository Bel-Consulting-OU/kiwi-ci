package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
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

// streamLogs serves GET /api/v1/runs/{id}/logs/stream as Server-Sent
// Events. Each log entry is one `data:` event carrying the LogEntry JSON
// line; the SSE event id is the entry's Seq so a reconnecting client can
// resume with ?after=<last-id> without gaps or duplicates. The stream
// polls the store every 250ms, flushes each chunk, and ends after 30s
// without new entries (or when the client disconnects).
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
		http.Error(w, err.Error(), 500)
		return
	}
	if !s.requireRunRead(w, r, run) {
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
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
				http.Error(w, "run not found", http.StatusNotFound)
				return
			}
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", jsonQuote(err.Error()))
			fl.Flush()
			return
		}
		if len(entries) > 0 {
			for _, e := range entries {
				b, merr := json.Marshal(e)
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
	b, _ := json.Marshal(s)
	return string(b)
}
