package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Probe 1 (fixed): Run()'s initial page loop must advance `after` from EVERY
// entry, not only the entries the active job filter keeps. The pre-fix code
// left `after` at 0 after a full page of non-matching entries, so the same
// page was re-fetched forever and the TUI never reached the next page.
func TestAuditRunNonMatchingFullPageAdvances(t *testing.T) {
	page := make([]model.LogEntry, 1000)
	for i := range page {
		page[i] = model.LogEntry{Seq: int64(i + 1), JobKey: "other", Step: "s", Line: "x"}
	}
	first, _ := json.Marshal(page)
	second, _ := json.Marshal([]model.LogEntry{{Seq: 1001, JobKey: "other", Step: "s", Line: "tail"}})

	var served int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&served, 1)
		if n > 25 {
			cancel()
			return
		}
		after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		if after >= 1000 {
			_, _ = w.Write(second)
			return
		}
		_, _ = w.Write(first)
	}))
	defer srv.Close()

	cfg := Config{Server: srv.URL, RunID: "run-1", JobKey: "target"}
	if err := Run(ctx, cfg, ioDiscard{}, nil); err != nil {
		t.Fatalf("Run did not complete after the last page: %v (served %d)", err, atomic.LoadInt64(&served))
	}
	if got := atomic.LoadInt64(&served); got > 3 {
		t.Fatalf("Run refetched the full non-matching page: served %d requests", got)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

// Probe 2 (fixed): chunkReader.readLine must bound the line it buffers. A
// hostile SSE peer that streams bytes without a newline now gets a typed
// error past the cap instead of an unbounded allocation.
func TestAuditChunkReaderLineBounded(t *testing.T) {
	r := &auditOneShot{buf: make([]byte, 4<<20), err: errEOFAfter}
	for i := range r.buf {
		r.buf[i] = 'a'
	}
	line, err := newChunkReader(r).readLine()
	if err == nil {
		t.Fatalf("readLine returned len=%d, want a length error", len(line))
	}
	if err != errChunkLineTooLong {
		t.Fatalf("readLine err = %v, want errChunkLineTooLong", err)
	}
	// A line at the cap is still accepted.
	ok := &auditOneShot{buf: append(make([]byte, maxChunkLineBytes), '\n'), err: errEOFAfter}
	if line, err := newChunkReader(ok).readLine(); err != nil || len(line) != maxChunkLineBytes {
		t.Fatalf("boundary line = len %d, err %v; want %d, nil", len(line), err, maxChunkLineBytes)
	}
}

var errEOFAfter = fmt.Errorf("eof")

type auditOneShot struct {
	buf []byte
	err error
}

func (o *auditOneShot) Read(p []byte) (int, error) {
	if len(o.buf) == 0 {
		e := o.err
		o.err = nil
		return 0, e
	}
	n := copy(p, o.buf)
	o.buf = o.buf[n:]
	return n, nil
}

// Probe 3 (cleared): redirects during log reads are refused rather than
// followed with the bearer token.
func TestAuditLogRedirectRefused(t *testing.T) {
	var targetHits int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&targetHits, 1)
	}))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c := &Client{Server: srv.URL, Token: "tok"}
	_, err := c.ReadPage(context.Background(), "run", 0, 10)
	t.Logf("ReadPage err=%v targetHits=%d", err, atomic.LoadInt64(&targetHits))
	if atomic.LoadInt64(&targetHits) != 0 {
		t.Fatal("redirect was followed to the attacker origin")
	}
	_ = time.Second
}
