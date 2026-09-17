package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// scriptedServer answers every request through fn.
func scriptedServer(t *testing.T, fn http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(fn)
	t.Cleanup(ts.Close)
	return ts
}

func jsonServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return scriptedServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

func TestOpsUnknownSubcommand(t *testing.T) {
	if err := Ops(context.Background(), "bogus", nil); err == nil {
		t.Fatal("unknown ops subcommand succeeded")
	}
}

func TestOpsRunsErrors(t *testing.T) {
	if err := Ops(context.Background(), "runs", []string{"--bogus"}); err == nil {
		t.Fatal("bad flag accepted")
	}
	if err := Ops(context.Background(), "runs", []string{"extra"}); err == nil {
		t.Fatal("positional argument accepted")
	}
	empty := jsonServer(t, http.StatusOK, `[]`)
	if err := Ops(context.Background(), "runs", []string{"--server", empty.URL}); err != nil {
		t.Fatalf("empty runs: %v", err)
	}
	failing := jsonServer(t, http.StatusInternalServerError, "boom")
	err := Ops(context.Background(), "runs", []string{"--server", failing.URL})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("runs 500 = %v", err)
	}
	badJSON := jsonServer(t, http.StatusOK, `{`)
	if err := Ops(context.Background(), "runs", []string{"--server", badJSON.URL}); err == nil {
		t.Fatal("malformed runs response accepted")
	}
	if err := Ops(context.Background(), "runs", []string{"--server", "http://[::1"}); err == nil {
		t.Fatal("malformed server URL accepted")
	}
	if err := Ops(context.Background(), "runs", []string{"--server", "http://127.0.0.1:1"}); err == nil {
		t.Fatal("unreachable server accepted")
	}
}

func TestOpsJobsErrors(t *testing.T) {
	if err := Ops(context.Background(), "jobs", []string{"--bogus"}); err == nil {
		t.Fatal("bad flag accepted")
	}
	empty := jsonServer(t, http.StatusOK, `[]`)
	if err := Ops(context.Background(), "jobs", []string{"--server", empty.URL, "run1"}); err != nil {
		t.Fatalf("empty jobs: %v", err)
	}
	failing := jsonServer(t, http.StatusTeapot, "nope")
	if err := Ops(context.Background(), "jobs", []string{"--server", failing.URL, "run1"}); err == nil {
		t.Fatal("non-2xx jobs response accepted")
	}
}

func TestOpsLogsErrorsAndFiltering(t *testing.T) {
	if err := Ops(context.Background(), "logs", []string{"--bogus"}); err == nil {
		t.Fatal("bad flag accepted")
	}
	body := `[
		{"seq":1,"job_key":"build","step":"s","line":"one"},
		{"seq":2,"job_key":"test","step":"s","line":"two"}
	]`
	ts := jsonServer(t, http.StatusOK, body)
	if err := Ops(context.Background(), "logs", []string{"--server", ts.URL, "--job", "build", "run1"}); err != nil {
		t.Fatalf("logs --job: %v", err)
	}
	// The backlog fetch fails.
	logsFail := jsonServer(t, http.StatusInternalServerError, "boom")
	if err := Ops(context.Background(), "logs", []string{"--server", logsFail.URL, "run1"}); err == nil {
		t.Fatal("logs backlog 500 accepted")
	}
	// An SSE stream that fails at the transport level.
	failingStream := scriptedServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/logs/stream") {
			http.Error(w, "no stream", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	err := Ops(context.Background(), "logs", []string{"--server", failingStream.URL, "--follow", "run1"})
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("follow stream 502 = %v", err)
	}
	// An SSE stream with one job-matching frame, one other job and one
	// malformed frame: only the matching frame renders and the scanner ends
	// cleanly on stream close.
	streamTS := scriptedServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/logs/stream") {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"seq\":3,\"job_key\":\"build\",\"step\":\"s\",\"line\":\"kept\"}\n\n")
			fmt.Fprint(w, "data: {\"seq\":4,\"job_key\":\"test\",\"step\":\"s\",\"line\":\"skipped\"}\n\n")
			fmt.Fprint(w, "data: not-json\n\n")
			fmt.Fprint(w, ": comment\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	})
	if err := Ops(context.Background(), "logs", []string{"--server", streamTS.URL, "--follow", "--job", "build", "run1"}); err != nil {
		t.Fatalf("logs --follow stream: %v", err)
	}
	// The follow request cannot be built for a malformed base URL.
	c := newOpsClient("http://[::1", "tok")
	if err := followLogs(context.Background(), c, "run1", 0, ""); err == nil {
		t.Fatal("malformed follow URL accepted")
	}
	// The stream connection fails outright.
	c = newOpsClient("http://127.0.0.1:1", "tok")
	if err := followLogs(context.Background(), c, "run1", 0, ""); err == nil {
		t.Fatal("unreachable stream accepted")
	}
	// A line exceeding the scanner buffer surfaces bufio.ErrTooLong.
	huge := scriptedServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/logs/stream") {
			fmt.Fprintf(w, "data: %s\n\n", strings.Repeat("x", 200_000))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	})
	err = Ops(context.Background(), "logs", []string{"--server", huge.URL, "--follow", "run1"})
	if err == nil {
		t.Fatal("oversized SSE frame did not surface a scanner error")
	}
}

func TestOpsMutateAndApproveErrors(t *testing.T) {
	if err := Ops(context.Background(), "cancel", []string{"--bogus"}); err == nil {
		t.Fatal("bad flag accepted")
	}
	if err := Ops(context.Background(), "cancel", []string{"a", "b"}); err == nil {
		t.Fatal("extra run IDs accepted")
	}
	failing := jsonServer(t, http.StatusConflict, "conflict")
	if err := Ops(context.Background(), "cancel", []string{"--server", failing.URL, "run1"}); err == nil {
		t.Fatal("conflicting cancel accepted")
	}
	if err := Ops(context.Background(), "approve", []string{"--bogus"}); err == nil {
		t.Fatal("bad approve flag accepted")
	}
	if err := Ops(context.Background(), "approve", []string{"a", "b"}); err == nil {
		t.Fatal("extra job IDs accepted")
	}
	if err := Ops(context.Background(), "approve", []string{"--server", failing.URL, "job1"}); err == nil {
		t.Fatal("conflicting approve accepted")
	}
}

func TestOpsArtifactsErrorsAndEmpty(t *testing.T) {
	if err := Ops(context.Background(), "artifacts", []string{"--bogus"}); err == nil {
		t.Fatal("bad flag accepted")
	}
	empty := jsonServer(t, http.StatusOK, `[]`)
	if err := Ops(context.Background(), "artifacts", []string{"--server", empty.URL, "run1"}); err != nil {
		t.Fatalf("empty artifacts: %v", err)
	}
	failing := jsonServer(t, http.StatusNotFound, "missing")
	if err := Ops(context.Background(), "artifacts", []string{"--server", failing.URL, "run1"}); err == nil {
		t.Fatal("404 artifacts accepted")
	}
}

func TestOpsSchedulesErrorsAndEmpty(t *testing.T) {
	if err := Ops(context.Background(), "schedules", []string{"list", "--bogus"}); err == nil {
		t.Fatal("bad list flag accepted")
	}
	if err := Ops(context.Background(), "schedules", []string{"list", "extra"}); err == nil {
		t.Fatal("extra list arguments accepted")
	}
	empty := jsonServer(t, http.StatusOK, `[]`)
	if err := Ops(context.Background(), "schedules", []string{"list", "--server", empty.URL}); err != nil {
		t.Fatalf("empty schedules: %v", err)
	}
	failing := jsonServer(t, http.StatusInternalServerError, "boom")
	if err := Ops(context.Background(), "schedules", []string{"list", "--server", failing.URL}); err == nil {
		t.Fatal("failing schedules list accepted")
	}
	if err := Ops(context.Background(), "schedules", []string{"trigger", "--bogus"}); err == nil {
		t.Fatal("bad trigger flag accepted")
	}
	if err := Ops(context.Background(), "schedules", []string{"trigger", "--server", failing.URL, "sch1"}); err == nil {
		t.Fatal("failing trigger accepted")
	}
	// A schedule with a last-run timestamp renders it.
	withLast := jsonServer(t, http.StatusOK, `[{"id":"sch1","repository":"acme/app","spec":"@daily","enabled":true,"last_run":"2026-09-14T00:00:00Z"}]`)
	if err := Ops(context.Background(), "schedules", []string{"list", "--server", withLast.URL}); err != nil {
		t.Fatalf("schedules with last run: %v", err)
	}
	shortIDs := jsonServer(t, http.StatusOK, `[{"id":"a","repository":"r","spec":"s","enabled":false}]`)
	if err := Ops(context.Background(), "schedules", []string{"list", "--server", shortIDs.URL}); err != nil {
		t.Fatalf("short schedule IDs: %v", err)
	}
}

func TestOpsPolicyErrors(t *testing.T) {
	if err := Ops(context.Background(), "policy", nil); err == nil {
		t.Fatal("policy without a subcommand succeeded")
	}
	if err := Ops(context.Background(), "policy", []string{"bogus"}); err == nil {
		t.Fatal("unknown policy subcommand succeeded")
	}
	if err := Ops(context.Background(), "policy", []string{"check", "--bogus"}); err == nil {
		t.Fatal("bad policy flag accepted")
	}
	if err := Ops(context.Background(), "policy", []string{"check", "-f", "/nonexistent/pipeline.yaml"}); err == nil {
		t.Fatal("missing pipeline accepted")
	}
}

func TestNetworkNameAndTruncate(t *testing.T) {
	cases := map[pipeline.NetworkPolicy]string{
		pipeline.NetworkPolicyNone:         "none",
		pipeline.NetworkPolicyServicesOnly: "services-only",
		pipeline.NetworkPolicyInternet:     "internet",
		pipeline.NetworkPolicyDefault:      "default",
	}
	for n, want := range cases {
		if got := networkName(n); got != want {
			t.Fatalf("networkName(%d) = %q, want %q", n, got, want)
		}
	}
	if truncate("abc", 5) != "abc" {
		t.Fatal("short truncate changed the string")
	}
	if truncate("abcdef", 4) != "abc…" {
		t.Fatalf("truncate = %q", truncate("abcdef", 4))
	}
	if truncate("abc", 0) != "" {
		t.Fatal("zero-width truncate")
	}
	if truncate("abc", 1) != "a" {
		t.Fatal("single-width truncate")
	}
}

func TestOpsLogsInteractiveFollowRoutesToTUI(t *testing.T) {
	ts := scriptedServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/logs/stream") {
			// End the stream immediately: the degraded renderer returns
			// before the follow goroutine result is consumed.
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"seq":1,"run_id":"run1","job_id":"j1","job_key":"build","step":"s","line":"interactive","created_at":"2026-09-14T00:00:00Z"}]`))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Ops(ctx, "logs", []string{"--server", ts.URL, "--interactive", "--follow", "--job", "build", "run1"}); err != nil {
		t.Fatalf("logs --interactive --follow: %v", err)
	}
}
