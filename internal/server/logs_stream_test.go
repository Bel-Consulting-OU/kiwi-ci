package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

type sseFrame struct {
	event string
	id    string
	data  string
}

func TestStreamLogsDeliversAndResumes(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runID := "run1"
	appendLog := func(seq int64, line string) {
		t.Helper()
		if err := s.store.AppendLog(model.LogEntry{Seq: seq, RunID: runID, JobID: "j1", JobKey: "build", Step: "s", Line: line, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	for i := int64(1); i <= 3; i++ {
		appendLog(i, fmt.Sprintf("line %d", i))
	}

	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	frames := startStream(t, ctx, srv.URL+"/api/v1/runs/"+runID+"/logs/stream?after=1", "secret")

	// The after=1 cursor skips seq 1 and delivers the backlog.
	expectSeq(t, frames, 2, "line 2")
	expectSeq(t, frames, 3, "line 3")

	// Lines appended while the stream is open arrive live.
	appendLog(4, "line 4")
	appendLog(5, "line 5")
	expectSeq(t, frames, 4, "line 4")
	expectSeq(t, frames, 5, "line 5")

	cancel()
}

func TestStreamLogsIdleTimeout(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.LogStreamIdleTimeout = 200 * time.Millisecond
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	frames := startStream(t, ctx, srv.URL+"/api/v1/runs/nope/logs/stream", "secret")
	select {
	case f, ok := <-frames:
		if !ok || f.event != "done" {
			t.Fatalf("want done event on idle timeout, got %+v (closed=%v)", f, !ok)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not close after idle timeout")
	}
}

func TestStreamLogsRequiresPersistentStore(t *testing.T) {
	s := New("token")
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/r1/logs/stream", "token", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("in-memory stream = %d, want 503", w.Code)
	}
}

func TestStreamLogsRequiresAuth(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/r1/logs/stream", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated stream = %d, want 401", w.Code)
	}
}

// startStream opens an SSE stream and returns parsed frames.
func startStream(t *testing.T, ctx context.Context, url, bearer string) <-chan sseFrame {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("stream status = %d, want 200", resp.StatusCode)
	}
	frames := make(chan sseFrame, 64)
	go func() {
		defer resp.Body.Close()
		defer close(frames)
		sc := bufio.NewScanner(resp.Body)
		var f sseFrame
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "id: "):
				f.id = strings.TrimPrefix(line, "id: ")
			case strings.HasPrefix(line, "event: "):
				f.event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				f.data = strings.TrimPrefix(line, "data: ")
			case line == "":
				if f.data != "" || f.event != "" {
					frames <- f
					f = sseFrame{}
				}
			}
		}
	}()
	return frames
}

// expectSeq waits for a frame whose SSE id and LogEntry Seq/Line match.
func expectSeq(t *testing.T, frames <-chan sseFrame, seq int64, line string) {
	t.Helper()
	select {
	case f, ok := <-frames:
		if !ok {
			t.Fatalf("stream closed before seq %d (%s) arrived", seq, line)
		}
		if f.id != fmt.Sprint(seq) {
			t.Fatalf("SSE id = %q, want %d", f.id, seq)
		}
		var e model.LogEntry
		if err := json.Unmarshal([]byte(f.data), &e); err != nil {
			t.Fatalf("data is not a LogEntry: %v: %q", err, f.data)
		}
		if e.Seq != seq || e.Line != line {
			t.Fatalf("entry = seq %d line %q, want seq %d line %q", e.Seq, e.Line, seq, line)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for seq %d (%s)", seq, line)
	}
}
