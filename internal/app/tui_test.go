package app

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTUICommandRoutesToDegradedTail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/runs/run1/logs" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"seq":1,"run_id":"run1","job_id":"j1","job_key":"build","step":"step-1","line":"hello world","created_at":"2026-09-14T00:00:00Z"},
			{"seq":2,"run_id":"run1","job_id":"j2","job_key":"test","step":"step-1","line":"second line","created_at":"2026-09-14T00:00:01Z"}
		]`))
	}))
	defer ts.Close()

	var buf bytes.Buffer
	err := tuiWithIO(context.Background(), []string{"--server", ts.URL, "run1"}, &buf, strings.NewReader(""))
	if err != nil {
		t.Fatalf("tui: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "build > step-1 | hello world") || !strings.Contains(out, "test > step-1 | second line") {
		t.Fatalf("tui output missing entries: %q", out)
	}

	// --job filters to one job key.
	buf.Reset()
	if err := tuiWithIO(context.Background(), []string{"--server", ts.URL, "--job", "test", "run1"}, &buf, strings.NewReader("")); err != nil {
		t.Fatalf("tui --job: %v", err)
	}
	if out = buf.String(); strings.Contains(out, "hello world") || !strings.Contains(out, "second line") {
		t.Fatalf("tui --job filter broken: %q", out)
	}

	// --search filters rendered lines.
	buf.Reset()
	if err := tuiWithIO(context.Background(), []string{"--server", ts.URL, "--search", "hello", "run1"}, &buf, strings.NewReader("")); err != nil {
		t.Fatalf("tui --search: %v", err)
	}
	if out = buf.String(); strings.Contains(out, "second line") || !strings.Contains(out, "hello world") {
		t.Fatalf("tui --search filter broken: %q", out)
	}
}

func TestTUIRequiresRunID(t *testing.T) {
	if err := tuiWithIO(context.Background(), nil, &bytes.Buffer{}, strings.NewReader("")); err == nil {
		t.Fatal("tui without a run ID succeeded")
	}
}

func TestLogsInteractiveRoutesToTUI(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/runs/run1/logs" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"seq":1,"run_id":"run1","job_id":"j1","job_key":"build","step":"s","line":"interactive line","created_at":"2026-09-14T00:00:00Z"}]`))
	}))
	defer ts.Close()
	err := Ops(context.Background(), "logs", []string{"--server", ts.URL, "--token", "tok", "--interactive", "run1"})
	if err != nil {
		t.Fatalf("logs --interactive: %v", err)
	}
}
