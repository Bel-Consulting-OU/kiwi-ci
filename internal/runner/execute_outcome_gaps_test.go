package runner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestExecuteMaskerRejectsUnmaskableLeaseToken: an ID-token job whose lease
// token is too short to register with the masker must fail before running any
// step (the token would otherwise leak into logs unmasked).
func TestExecuteMaskerRejectsUnmaskableLeaseToken(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	base := "version: 1\njobs:\n  build:\n    permissions:\n      id_token: true\n    steps:\n      - run: echo hi\n"
	task := basicTask(base)
	task.LeaseToken = "x"

	r := testRunnerFor(t, ts, Config{CaptureSnapshots: false})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644)
	}
	r.execute(context.Background(), task)

	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded")
	}
	if c.Status != model.StatusFailure || !strings.Contains(c.Error, "masker") {
		t.Fatalf("completion = %s (%s), want the masker refusal", c.Status, c.Error)
	}
}

// TestExecuteJournalOpenFailureFailsJob: when a durable state directory is
// configured but unusable, the job fails closed instead of running without
// the batch journal.
func TestExecuteJournalOpenFailureFailsJob(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	stateFile := filepath.Join(t.TempDir(), "state-file")
	if err := os.WriteFile(stateFile, []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}

	task := basicTask("version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n")
	r := testRunnerFor(t, ts, Config{CaptureSnapshots: false, StateDir: stateFile})
	r.journalOptOut = false
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644)
	}
	r.execute(context.Background(), task)

	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded")
	}
	if c.Status != model.StatusFailure || !strings.Contains(c.Error, "log journal") {
		t.Fatalf("completion = %s (%s), want the journal-open refusal", c.Status, c.Error)
	}
}

// TestExecuteLogDeliveryFailureTaintsOutcome: a permanently rejected log
// batch must surface as a failed job whose error names the unsent lines and
// the delivery failure, never a clean success with lost logs.
func TestExecuteLogDeliveryFailureTaintsOutcome(t *testing.T) {
	var completes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/complete") {
			b, _ := io.ReadAll(r.Body)
			completes = append(completes, string(b))
		}
		if strings.HasSuffix(r.URL.Path, "/log/batch") || strings.HasSuffix(r.URL.Path, "/log") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "rejected")
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	task := basicTask("version: 1\njobs:\n  build:\n    steps:\n      - run: echo hello-logs\n")
	r := &Runner{Cfg: Config{Server: srv.URL, CacheRoot: t.TempDir()}, ID: "runner-1",
		Client: &http.Client{}, Metrics: NewMetrics(), journalOptOut: true}
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644)
	}
	r.execute(context.Background(), task)

	if len(completes) != 1 {
		t.Fatalf("completions = %d, want 1", len(completes))
	}
	body := completes[0]
	if !strings.Contains(body, `"status":"failure"`) {
		t.Fatalf("completion body = %s, want failure", body)
	}
	if !strings.Contains(body, "unsent at completion") || !strings.Contains(body, "log delivery error") {
		t.Fatalf("completion body = %s, want the log-outcome detail", body)
	}
}
