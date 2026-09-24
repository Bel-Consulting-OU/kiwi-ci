package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func TestOpsPolicyCheck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pipeline.yaml")
	native := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n"
	if err := os.WriteFile(path, []byte(native), 0o644); err != nil {
		t.Fatal(err)
	}
	// Native execution is denied for untrusted pipelines.
	err := Ops(context.Background(), "policy", []string{"check", "-f", path})
	if err == nil || !strings.Contains(err.Error(), "admission failed") {
		t.Fatalf("untrusted native policy check = %v, want admission failure", err)
	}
	// Trusted defaults permit it.
	if err := Ops(context.Background(), "policy", []string{"check", "-f", path, "--trusted"}); err != nil {
		t.Fatalf("trusted policy check: %v", err)
	}
}

func TestOpsSchedulesHitsEndpoints(t *testing.T) {
	srv, seen := fakeAPIServer(t)
	flags := []string{"--server", srv.URL, "--token", "admin-token"}
	if err := Ops(context.Background(), "schedules", append([]string{"list"}, flags...)); err != nil {
		t.Fatalf("schedules list: %v", err)
	}
	if err := Ops(context.Background(), "schedules", []string{"trigger", "--server", srv.URL, "--token", "admin-token", "sch1"}); err != nil {
		t.Fatalf("schedules trigger: %v", err)
	}
	want := []string{
		"GET /api/v1/schedules",
		"POST /api/v1/schedules/sch1/trigger",
	}
	if len(*seen) != len(want) {
		t.Fatalf("requests = %v, want %v", *seen, want)
	}
	for i, w := range want {
		if (*seen)[i] != w {
			t.Fatalf("request %d = %q, want %q", i, (*seen)[i], w)
		}
	}
}

func TestOpsSchedulesArgumentErrors(t *testing.T) {
	if err := Ops(context.Background(), "schedules", nil); err == nil {
		t.Fatal("schedules without a subcommand succeeded")
	}
	if err := Ops(context.Background(), "schedules", []string{"bogus"}); err == nil {
		t.Fatal("unknown schedules subcommand succeeded")
	}
	srv, _ := fakeAPIServer(t)
	if err := Ops(context.Background(), "schedules", []string{"trigger", "--server", srv.URL, "--token", "admin-token"}); err == nil {
		t.Fatal("trigger without a schedule ID succeeded")
	}
}

// fakeAPIServer serves canned JSON and records the requests so the ops
// commands' paths, methods and auth headers are verifiable.
func fakeAPIServer(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer admin-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		seen = append(seen, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/runs" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`[{"id":"run1","status":"success","event":"push","repo":"example/repo","trusted":true,"created_at":"2026-09-14T00:00:00Z"}]`))
		case strings.HasSuffix(r.URL.Path, "/jobs") && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`[{"id":"job1","key":"test","status":"success","attempts":1}]`))
		case strings.HasSuffix(r.URL.Path, "/cancel") && r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`{"id":"run1","status":"cancelled"}`))
		case strings.HasSuffix(r.URL.Path, "/rerun") && r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`{"id":"run2","status":"queued"}`))
		case strings.HasSuffix(r.URL.Path, "/approve") && r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`{"id":"job1","key":"test","approved_by":"admin"}`))
		case strings.HasSuffix(r.URL.Path, "/artifacts") && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`[{"id":"art1","job_key":"test","name":"bin.tar.gz","size":42,"sha256":"abc"}]`))
		case strings.HasSuffix(r.URL.Path, "/logs") && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`[{"seq":1,"job_key":"test","step":"s","line":"hello","run_id":"run1","job_id":"job1"}]`))
		case r.URL.Path == "/api/v1/schedules" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`[{"id":"sch1","repository":"acme/app","spec":"0 * * * *","enabled":true,"created_at":"2026-09-14T00:00:00Z"}]`))
		case strings.HasSuffix(r.URL.Path, "/trigger") && r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`{"id":"run9","status":"queued"}`))
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, &seen
}

func TestOpsServerCommands(t *testing.T) {
	srv, seen := fakeAPIServer(t)
	url := srv.URL

	run := func(sub string, args ...string) error {
		return Ops(context.Background(), sub, append([]string{"--server", url, "--token", "admin-token"}, args...))
	}

	if err := run("runs"); err != nil {
		t.Fatalf("runs: %v", err)
	}
	if err := run("jobs", "run1"); err != nil {
		t.Fatalf("jobs: %v", err)
	}
	if err := run("cancel", "run1"); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if err := run("rerun", "run1"); err != nil {
		t.Fatalf("rerun: %v", err)
	}
	if err := run("approve", "job1"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := run("artifacts", "run1"); err != nil {
		t.Fatalf("artifacts: %v", err)
	}
	if err := run("logs", "run1"); err != nil {
		t.Fatalf("logs: %v", err)
	}
	if err := Ops(context.Background(), "schedules", []string{"list", "--server", url, "--token", "admin-token"}); err != nil {
		t.Fatalf("schedules list: %v", err)
	}
	if err := Ops(context.Background(), "schedules", []string{"trigger", "--server", url, "--token", "admin-token", "sch1"}); err != nil {
		t.Fatalf("schedules trigger: %v", err)
	}

	want := []string{
		"GET /api/v1/runs",
		"GET /api/v1/runs/run1/jobs",
		"POST /api/v1/runs/run1/cancel",
		"POST /api/v1/runs/run1/rerun",
		"POST /api/v1/jobs/job1/approve",
		"GET /api/v1/runs/run1/artifacts",
		"GET /api/v1/runs/run1/logs",
		"GET /api/v1/schedules",
		"POST /api/v1/schedules/sch1/trigger",
	}
	if len(*seen) != len(want) {
		t.Fatalf("requests = %v, want %v", *seen, want)
	}
	for i, w := range want {
		if (*seen)[i] != w {
			t.Fatalf("request %d = %q, want %q", i, (*seen)[i], w)
		}
	}
}

func TestOpsRequiresRunID(t *testing.T) {
	srv, _ := fakeAPIServer(t)
	for _, sub := range []string{"jobs", "cancel", "rerun", "artifacts", "logs"} {
		err := Ops(context.Background(), sub, []string{"--server", srv.URL, "--token", "admin-token"})
		if err == nil {
			t.Fatalf("%s without a run ID succeeded", sub)
		}
	}
}

// TestOpsAcceptsFlagsAfterPositionals locks the F6-E fix: the documented
// `COMMAND RUN [--flags]` form must work, not only undocumented flags-first.
func TestOpsAcceptsFlagsAfterPositionals(t *testing.T) {
	srv, seen := fakeAPIServer(t)
	flags := []string{"--server", srv.URL, "--token", "admin-token"}

	run := func(sub string, args ...string) {
		t.Helper()
		if err := Ops(context.Background(), sub, append(append([]string{}, args...), flags...)); err != nil {
			t.Fatalf("%s %v: %v", sub, args, err)
		}
	}
	run("jobs", "run1")
	run("cancel", "run1")
	run("rerun", "run1")
	run("approve", "job1")
	run("artifacts", "run1")
	run("logs", "run1")
	if err := Ops(context.Background(), "schedules", append([]string{"trigger", "sch1"}, flags...)); err != nil {
		t.Fatalf("schedules trigger sch1 [flags]: %v", err)
	}

	want := []string{
		"GET /api/v1/runs/run1/jobs",
		"POST /api/v1/runs/run1/cancel",
		"POST /api/v1/runs/run1/rerun",
		"POST /api/v1/jobs/job1/approve",
		"GET /api/v1/runs/run1/artifacts",
		"GET /api/v1/runs/run1/logs",
		"POST /api/v1/schedules/sch1/trigger",
	}
	if len(*seen) != len(want) {
		t.Fatalf("requests = %v, want %v", *seen, want)
	}
	for i, w := range want {
		if (*seen)[i] != w {
			t.Fatalf("request %d = %q, want %q", i, (*seen)[i], w)
		}
	}
}

// TestOpsLogsFollow runs the full logs+SSE path against a real Kiwi server
// with a persistent store: the paginated backlog prints once and the
// follow stream drains until the idle timeout closes it.
func TestOpsLogsFollow(t *testing.T) {
	dataDir := t.TempDir()
	st := storage.New(dataDir)
	srv, err := server.NewPersistent("secret", "secret", dataDir)
	if err != nil {
		t.Fatal(err)
	}
	// Seed a real run through the API so the scoped read path (which
	// resolves the run's repository before serving logs) authorizes it.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/runs",
		strings.NewReader(`{"repo_url":"https://github.com/acme/app.git","repo_full_name":"acme/app","ref":"refs/heads/main","sha":"abc","event":"push","pipeline":"version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine\n    steps:\n      - run: echo ok\n"}`))
	req.Header.Set("Authorization", "Bearer secret")
	submit := httptest.NewRecorder()
	srv.Handler().ServeHTTP(submit, req)
	if submit.Code != http.StatusOK && submit.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", submit.Code, submit.Body.String())
	}
	var run struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(submit.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	for i := int64(1); i <= 3; i++ {
		if err := st.AppendLog(model.LogEntry{Seq: i, RunID: run.ID, JobID: "j1", JobKey: "build", Step: "s", Line: "line", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	srv.LogStreamIdleTimeout = 300 * time.Millisecond
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = Ops(ctx, "logs", []string{"--server", ts.URL, "--token", "secret", "--follow", run.ID})
	if err != nil {
		t.Fatalf("logs --follow: %v", err)
	}
}
