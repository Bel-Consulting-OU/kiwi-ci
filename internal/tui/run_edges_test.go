package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// logsServer serves a paginated /logs endpoint: no after parameter returns
// the first page, after=1000 returns the second page, and any other cursor
// returns an empty page. It is stateless, so one server can serve repeated
// full scans.
func logsServer(t *testing.T, pages [][]map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/logs") || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		var page []map[string]any
		switch r.URL.Query().Get("after") {
		case "":
			if len(pages) > 0 {
				page = pages[0]
			}
		case "1000":
			if len(pages) > 1 {
				page = pages[1]
			} else {
				t.Errorf("unexpected paged request: %s", r.URL)
			}
		default:
			t.Errorf("unexpected cursor %q", r.URL.Query().Get("after"))
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
}

func TestRunPlainReadsAllPages(t *testing.T) {
	page1 := make([]map[string]any, 0, 1000)
	for i := 1; i <= 1000; i++ {
		page1 = append(page1, map[string]any{"seq": i, "job_key": "build", "step": "s", "line": fmt.Sprintf("line-%d", i)})
	}
	page2 := []map[string]any{
		{"seq": 1001, "job_key": "test", "step": "s", "line": "tail-one"},
		{"seq": 1002, "job_key": "test", "step": "s", "line": "tail-two"},
	}
	ts := logsServer(t, [][]map[string]any{page1, page2})
	defer ts.Close()

	var buf bytes.Buffer
	cfg := Config{Server: ts.URL, RunID: "run-1"}
	if err := Run(context.Background(), cfg, &buf, strings.NewReader("")); err != nil {
		t.Fatalf("Run: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1002 {
		t.Fatalf("rendered %d lines, want 1002", len(lines))
	}
	if lines[0] != "build > s | line-1" || lines[1001] != "test > s | tail-two" {
		t.Fatalf("first/last = %q / %q", lines[0], lines[1001])
	}
}

func TestRunPlainJobFilterAndSearch(t *testing.T) {
	page := []map[string]any{
		{"seq": 1, "job_key": "build", "step": "compile", "line": "building"},
		{"seq": 2, "job_key": "test", "step": "run", "line": "testing"},
		{"seq": 3, "job_key": "build", "step": "compile", "line": "done"},
	}
	ts := logsServer(t, [][]map[string]any{page})
	defer ts.Close()

	var buf bytes.Buffer
	cfg := Config{Server: ts.URL, RunID: "run-1", JobKey: "build", Search: "build"}
	if err := Run(context.Background(), cfg, &buf, strings.NewReader("")); err != nil {
		t.Fatalf("Run: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("filtered lines = %q", buf.String())
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "build >") {
			t.Fatalf("job filter leaked: %q", l)
		}
	}
}

func TestRunReadError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer ts.Close()
	var buf bytes.Buffer
	err := Run(context.Background(), Config{Server: ts.URL, RunID: "run-1"}, &buf, strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), "tui: read logs") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunFollowNonTerminalDegrades(t *testing.T) {
	if isTerminal(os.Stdout.Fd()) {
		t.Skip("stdout is a terminal; the interactive path would block")
	}
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/logs/stream") {
			w.(http.Flusher).Flush()
			<-release
			_, _ = w.Write([]byte("event: done\n\n"))
			w.(http.Flusher).Flush()
			return
		}
		_, _ = w.Write([]byte(`[{"seq":1,"job_key":"build","step":"s","line":"only"}]`))
	}))
	defer ts.Close()
	t.Cleanup(func() { close(release) })

	var buf bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Run(ctx, Config{Server: ts.URL, RunID: "run-1", Follow: true}, &buf, strings.NewReader("")); err != nil {
		t.Fatalf("Run(follow): %v", err)
	}
	if !strings.Contains(buf.String(), "build > s | only") {
		t.Fatalf("output = %q", buf.String())
	}
}

func TestRefetchLogsPagesAndFilter(t *testing.T) {
	page1 := make([]map[string]any, 0, 1000)
	for i := 1; i <= 1000; i++ {
		key := "build"
		if i%2 == 0 {
			key = "test"
		}
		page1 = append(page1, map[string]any{"seq": i, "job_key": key, "step": "s", "line": fmt.Sprintf("l%d", i)})
	}
	page2 := []map[string]any{
		{"seq": 1001, "job_key": "build", "step": "s", "line": "kept"},
		{"seq": 1002, "job_key": "test", "step": "s", "line": "dropped"},
	}
	ts := logsServer(t, [][]map[string]any{page1, page2})
	defer ts.Close()

	ring := NewRing[string](5000)
	state := &logState{}
	if err := refetchLogs(context.Background(), &Client{Server: ts.URL}, "run-1", "build", ring, state); err != nil {
		t.Fatalf("refetchLogs: %v", err)
	}
	if state.get() != 1002 {
		t.Fatalf("state = %d, want the highest sequence seen (1002)", state.get())
	}
	got := ring.Slice()
	if len(got) != 501 {
		t.Fatalf("kept %d lines, want 501 build lines", len(got))
	}
	if !strings.HasSuffix(got[len(got)-1], "kept") {
		t.Fatalf("last kept line = %q", got[len(got)-1])
	}

	// Without a filter every line is kept.
	ring.Reset()
	if err := refetchLogs(context.Background(), &Client{Server: ts.URL}, "run-1", "", ring, &logState{}); err != nil {
		t.Fatalf("refetchLogs(unfiltered): %v", err)
	}
	if ring.Len() != 1002 {
		t.Fatalf("unfiltered kept %d lines", ring.Len())
	}
}

func TestRefetchLogsError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer ts.Close()
	err := refetchLogs(context.Background(), &Client{Server: ts.URL}, "run-1", "", NewRing[string](10), &logState{})
	if err == nil {
		t.Fatal("refetchLogs must surface read errors")
	}
}

// interactiveServer serves the jobs and logs endpoints used by the "j" key.
func interactiveServer(t *testing.T, jobsStatus, logsStatus int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/jobs"):
			if jobsStatus != http.StatusOK {
				http.Error(w, "jobs down", jobsStatus)
				return
			}
			_, _ = w.Write([]byte(`[{"key":"build"},{"key":"test"}]`))
		case strings.HasSuffix(r.URL.Path, "/logs"):
			if logsStatus != http.StatusOK {
				http.Error(w, "logs down", logsStatus)
				return
			}
			_, _ = w.Write([]byte(`[{"seq":1,"job_key":"build","step":"compile","line":"ok"},
				{"seq":2,"job_key":"build","step":"test","line":"fail: err here"},
				{"seq":3,"job_key":"build","step":"test","line":"error: bad"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func interactiveRing() *Ring[string] {
	lines := NewRing[string](128)
	lines.Append("build > compile | ok")
	lines.Append("build > test | fail: boom")
	lines.Append("build > test | error: bad")
	return lines
}

func TestRunInteractiveKeyHandling(t *testing.T) {
	ts := interactiveServer(t, http.StatusOK, http.StatusOK)
	defer ts.Close()
	// No clipboard tool on PATH: "y" must print the raw permalink.
	t.Setenv("PATH", t.TempDir())

	var out bytes.Buffer
	ring := interactiveRing()
	cfg := Config{Server: ts.URL, RunID: "run-1"}
	errCh := make(chan error, 1)
	filter := newJobFilter(&Client{Server: ts.URL}, "run-1", "")

	// Each group is exactly 8 bytes so no escape sequence is split by the
	// key reader's 8-byte buffer.
	keys := "j\n\n\n\n\n\n\n" +
		"\x1b[B\n\n\n\n\n" +
		"\x1b[A\n\n\n\n\n" +
		"\x1b[6~\n\n\n\n" +
		"\x1b[5~\n\n\n\n" +
		"\x1b[H\n\n\n\n\n" +
		"\x1b[F\n\n\n\n\n" +
		"\t\n\n\n\n\n\n\n" +
		"f\n\n\n\n\n\n\n" +
		"/err\n\n\n\n" +
		"n\n\n\n\n\n\n\n" +
		"\x1b[F\n\n\n\n\n" +
		"N\n\n\n\n\n\n\n" +
		"y\n\n\n\n\n\n\n" +
		"q\n\n\n\n\n\n\n"

	if err := runInteractive(context.Background(), ring, &cfg, &out, strings.NewReader(keys), errCh, filter, &logState{}); err != nil {
		t.Fatalf("runInteractive: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "run run-1 | job build") {
		t.Fatalf("filter cycle did not update the header: %q", got)
	}
	if !strings.Contains(got, "permalink: "+ts.URL+"/?run=run-1") {
		t.Fatalf("permalink fallback missing: %q", got)
	}
	if cfg.JobKey != "build" {
		t.Fatalf("job key after one cycle = %q, want build", cfg.JobKey)
	}
}

func TestRunInteractiveJobFetchFailure(t *testing.T) {
	ts := interactiveServer(t, http.StatusInternalServerError, http.StatusOK)
	defer ts.Close()
	t.Setenv("PATH", t.TempDir())

	var out bytes.Buffer
	cfg := Config{Server: ts.URL, RunID: "run-1"}
	errCh := make(chan error, 1)
	filter := newJobFilter(&Client{Server: ts.URL}, "run-1", "")

	keys := "j\n\n\n\n\n\n\nq\n\n\n\n\n\n\n"
	if err := runInteractive(context.Background(), interactiveRing(), &cfg, &out, strings.NewReader(keys), errCh, filter, &logState{}); err != nil {
		t.Fatalf("runInteractive: %v", err)
	}
	if !strings.Contains(out.String(), "job list fetch failed") {
		t.Fatalf("output = %q", out.String())
	}
	if cfg.JobKey != "" {
		t.Fatalf("failed fetch must not change the filter, got %q", cfg.JobKey)
	}
}

func TestRunInteractiveRefetchFailure(t *testing.T) {
	ts := interactiveServer(t, http.StatusOK, http.StatusInternalServerError)
	defer ts.Close()
	t.Setenv("PATH", t.TempDir())

	var out bytes.Buffer
	cfg := Config{Server: ts.URL, RunID: "run-1"}
	errCh := make(chan error, 1)
	filter := newJobFilter(&Client{Server: ts.URL}, "run-1", "")

	keys := "j\n\n\n\n\n\n\nq\n\n\n\n\n\n\n"
	if err := runInteractive(context.Background(), interactiveRing(), &cfg, &out, strings.NewReader(keys), errCh, filter, &logState{}); err != nil {
		t.Fatalf("runInteractive: %v", err)
	}
	if !strings.Contains(out.String(), "log refetch failed") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestRunInteractivePermalinkCopied(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pbcopy"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	var out bytes.Buffer
	cfg := Config{Server: "http://ci.example", RunID: "run-9"}
	errCh := make(chan error, 1)
	filter := newJobFilter(&Client{Server: "http://ci.example"}, "run-9", "")
	keys := "y\n\n\n\n\n\n\nq\n\n\n\n\n\n\n"
	if err := runInteractive(context.Background(), interactiveRing(), &cfg, &out, strings.NewReader(keys), errCh, filter, &logState{}); err != nil {
		t.Fatalf("runInteractive: %v", err)
	}
	if !strings.Contains(out.String(), "permalink copied: http://ci.example/?run=run-9") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestRunInteractiveContextAndErrorChannels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if err := runInteractive(ctx, interactiveRing(), &Config{}, &out, strings.NewReader(""), make(chan error, 1), newJobFilter(&Client{}, "", ""), &logState{}); err != nil {
		t.Fatalf("cancelled runInteractive = %v", err)
	}

	errCh := make(chan error, 1)
	want := errors.New("stream failed")
	errCh <- want
	if err := runInteractive(context.Background(), interactiveRing(), &Config{}, &out, strings.NewReader(""), errCh, newJobFilter(&Client{}, "", ""), &logState{}); !errors.Is(err, want) {
		t.Fatalf("error = %v, want stream error", err)
	}

	clean := make(chan error, 1)
	clean <- nil
	if err := runInteractive(context.Background(), interactiveRing(), &Config{}, &out, strings.NewReader(""), clean, newJobFilter(&Client{}, "", ""), &logState{}); err != nil {
		t.Fatalf("clean stream end = %v", err)
	}
}

// TestRunInteractiveTickerRepaint blocks the key reader past the 2s repaint
// tick so the ticker branch is exercised, then cancels the context.
func TestRunInteractiveTickerRepaint(t *testing.T) {
	gate := make(chan struct{})
	reader := &gatedReader{gate: gate}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	var out bytes.Buffer
	go func() {
		done <- runInteractive(ctx, interactiveRing(), &Config{RunID: "r"}, &out, reader, make(chan error, 1), newJobFilter(&Client{}, "", ""), &logState{})
	}()
	time.Sleep(2200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runInteractive = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runInteractive did not return after cancellation")
	}
	close(gate)
	if !strings.Contains(out.String(), "run r |") {
		t.Fatalf("repaint output = %q", out.String())
	}
}

type gatedReader struct{ gate chan struct{} }

func (r *gatedReader) Read([]byte) (int, error) {
	<-r.gate
	return 0, errors.New("closed")
}

func TestJobFilterCycleEmptyJobList(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	defer ts.Close()
	f := newJobFilter(&Client{Server: ts.URL}, "run-1", "")
	key, err := f.cycle(context.Background())
	if err != nil || key != "" {
		t.Fatalf("cycle on an empty job list = %q (err %v)", key, err)
	}
	if !f.loaded {
		t.Fatal("an empty job list must still mark the filter loaded")
	}
}

// TestRunFollowDeliversFrames drives the follow callback while Run is still
// alive (stdout is not a terminal, so Run only waits for renderPlain).
//
// The frames are chosen so the callback takes its guard branches only: a
// stale sequence (already consumed by the initial read) and a job-filtered
// entry. The follow goroutine appending while the renderer reads is covered
// by TestRingConcurrentAppendAndSlice under -race; here the callback never
// reaches Append so the delivered-frame accounting stays deterministic.
func TestRunFollowDeliversFrames(t *testing.T) {
	if isTerminal(os.Stdout.Fd()) {
		t.Skip("stdout is a terminal; Run would enter the interactive path")
	}
	allowReturn := make(chan struct{})
	streamDone := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/logs/stream") {
			flush := w.(http.Flusher)
			for _, frame := range []string{
				`data: {"seq":5,"job_key":"build","step":"s","line":"stale"}` + "\n\n",
				`data: {"seq":6,"job_key":"other","step":"s","line":"filtered"}` + "\n\n",
			} {
				_, _ = w.Write([]byte(frame))
				flush.Flush()
			}
			<-streamDone
			_, _ = w.Write([]byte("event: done\n\n"))
			flush.Flush()
			return
		}
		_, _ = w.Write([]byte(`[{"seq":5,"job_key":"build","step":"s","line":"stale"}]`))
	}))
	// Unblock the streaming handler before closing the test server, then
	// close the server: ts.Close waits for outstanding handlers.
	defer func() {
		close(streamDone)
		ts.Close()
	}()

	out := &gateWriter{gate: allowReturn}
	go func() {
		time.Sleep(400 * time.Millisecond)
		close(allowReturn)
	}()
	if err := Run(context.Background(), Config{Server: ts.URL, RunID: "run-1", JobKey: "build", Follow: true}, out, strings.NewReader("")); err != nil {
		t.Fatalf("Run(follow): %v", err)
	}
	if !out.wrote {
		t.Fatal("Run did not render the initial backlog")
	}
}

type gateWriter struct {
	gate  chan struct{}
	wrote bool
	buf   bytes.Buffer
}

func (w *gateWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		<-w.gate
		w.wrote = true
	}
	w.buf.Write(p)
	return len(p), nil
}
