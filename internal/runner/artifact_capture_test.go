package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// writeCaptureBytes writes n incompressible bytes so capture-size assertions
// do not depend on gzip ratios.
func writeCaptureBytes(t *testing.T, path string, n int) {
	t.Helper()
	data := make([]byte, n)
	state := uint32(0x9e3779b9)
	for i := range data {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		data[i] = byte(state)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// artifactPipeline declares one native job that captures out.bin as the
// named artifact; the step itself is a no-op because the checkout hook
// creates the file (so tests control its exact compressibility and size).
// maxSize, when non-empty, becomes max_size.
func artifactPipeline(name, maxSize string) string {
	step := nativeScript("true", "exit 0")
	text := "version: 1\njobs:\n  build:\n    steps:\n      - run: " + step + "\n    artifacts:\n      - name: " + name + "\n        paths: [out.bin]\n"
	if maxSize != "" {
		text += "        max_size: " + maxSize + "\n"
	}
	return text
}

// artifactUploads returns the artifact PUT names the fake server recorded.
func artifactUploads(f *fakeRunnerServer) []string {
	return f.pathsFor("/api/v1/jobs/job-1/artifacts/")
}

// fakeLogs returns a snapshot of the fake server's recorded log lines.
func fakeLogs(f *fakeRunnerServer) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.logLines...)
}

// TestRunnerArtifactCaptureGlobalCeiling pins the global capture ceiling with
// the test seam: an archive above runnerArtifactMaxBytes is refused locally
// (no upload, warning logged) and its staging reservation is released.
func TestRunnerArtifactCaptureGlobalCeiling(t *testing.T) {
	prev := runnerArtifactMaxBytes
	runnerArtifactMaxBytes = 2048
	t.Cleanup(func() { runnerArtifactMaxBytes = prev })

	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		writeCaptureBytes(t, filepath.Join(dir, "out.bin"), 64<<10)
		return nil
	}
	r.execute(context.Background(), basicTask(artifactPipeline("big", "")))

	if up := artifactUploads(fsrv); len(up) != 0 {
		t.Fatalf("over-ceiling artifact was uploaded: %v", up)
	}
	joined := strings.Join(fakeLogs(fsrv), "\n")
	if !strings.Contains(joined, "save warning") {
		t.Fatalf("ceiling refusal not surfaced in the job log:\n%s", joined)
	}
	budget, err := r.dependencyStaging()
	if err != nil {
		t.Fatal(err)
	}
	if used := budget.Used(); used != 0 {
		t.Fatalf("staging ledger = %d after the refused capture, want 0", used)
	}
}

// TestRunnerArtifactCaptureLeavesNoLocalArchive pins the temporary publication
// path: a successful distributed artifact upload leaves no archive, no
// capture directory and no staging reservation behind.
func TestRunnerArtifactCaptureLeavesNoLocalArchive(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	workDir := t.TempDir()
	r := testRunnerFor(t, ts, Config{WorkDir: workDir})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		writeCaptureBytes(t, filepath.Join(dir, "out.bin"), 2048)
		return nil
	}
	r.execute(context.Background(), basicTask(artifactPipeline("art", "")))

	if up := artifactUploads(fsrv); len(up) != 1 {
		t.Fatalf("artifact uploads = %v, want exactly one", up)
	}
	entries, err := os.ReadDir(workDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "kiwi-artifacts-") {
			t.Fatalf("capture directory left behind: %s", e.Name())
		}
	}
	// The old persistent tree under CacheRoot is not used at all anymore.
	if _, err := os.Stat(filepath.Join(r.Cfg.CacheRoot, "artifacts")); !os.IsNotExist(err) {
		t.Fatalf("persistent artifact tree was written (err=%v)", err)
	}
	budget, err := r.dependencyStaging()
	if err != nil {
		t.Fatal(err)
	}
	if used := budget.Used(); used != 0 {
		t.Fatalf("staging ledger = %d after delivery, want 0", used)
	}
}

// TestRunnerArtifactCapturesRespectAggregateBudget runs several concurrent
// artifact captures whose per-archive reserve equals the whole runner staging
// budget: they must serialize without deadlocking, never exceed the ledger
// bound, and all deliver.
func TestRunnerArtifactCapturesRespectAggregateBudget(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	const reserve = 4096
	r := testRunnerFor(t, ts, Config{StagingMaxBytes: reserve})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		writeCaptureBytes(t, filepath.Join(dir, "out.bin"), 2048)
		return nil
	}
	budget, err := r.dependencyStaging()
	if err != nil {
		t.Fatal(err)
	}
	stopPoll := make(chan struct{})
	var maxSeen int64
	var pollErr error
	go func() {
		for {
			select {
			case <-stopPoll:
				return
			default:
			}
			if used := budget.Used(); used > maxSeen {
				if used > budget.MaxBytes() {
					pollErr = fmt.Errorf("ledger %d exceeded budget %d", used, budget.MaxBytes())
					return
				}
				maxSeen = used
			}
			time.Sleep(time.Millisecond)
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.execute(context.Background(), basicTask(artifactPipeline("art", "4096")))
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		close(stopPoll)
		t.Fatal("concurrent artifact captures deadlocked on the staging budget")
	}
	close(stopPoll)
	if pollErr != nil {
		t.Fatal(pollErr)
	}
	if up := artifactUploads(fsrv); len(up) != 3 {
		t.Fatalf("artifact uploads = %v, want 3", up)
	}
	if used := budget.Used(); used != 0 {
		t.Fatalf("staging ledger = %d after all captures, want 0", used)
	}
}

// TestRunnerShutdownDoesNotWaitCleanupTimeout is the Run-level lifecycle
// regression: a cancelled() cleanup step that blocks must not delay a runner
// shutdown. The default cleanup grace is 60s and the drain grace 30s, so with
// the cleanup context detached from the runner lifecycle this test would
// block for the full drain grace; with the lifecycle tie it returns at once.
func TestRunnerShutdownDoesNotWaitCleanupTimeout(t *testing.T) {
	dir := t.TempDir()
	mainMarker := filepath.Join(dir, "main-started")
	cleanupMarker := filepath.Join(dir, "cleanup-ran")
	mainStep := nativeScript(
		"printf x > '"+mainMarker+"' && sleep 30",
		"Set-Content -LiteralPath '"+mainMarker+"' -Value x; Start-Sleep -Seconds 30",
	)
	cleanupStep := nativeScript(
		"printf x > '"+cleanupMarker+"' && sleep 30",
		"Set-Content -LiteralPath '"+cleanupMarker+"' -Value x; Start-Sleep -Seconds 30",
	)
	pipelineText := "version: 1\njobs:\n  build:\n    steps:\n      - run: " + mainStep + "\n      - run: " + cleanupStep + "\n        if: cancelled()\n"

	task := basicTask(pipelineText)
	jobJSON, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	var served atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/register"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
		case strings.HasSuffix(r.URL.Path, "/next"):
			if served.CompareAndSwap(false, true) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(jobJSON)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/complete"):
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	r := &Runner{ID: "runner-1", Cfg: Config{
		Server: ts.URL, Poll: time.Millisecond, Concurrency: 1,
		IdentityDir: t.TempDir(), WorkDir: t.TempDir(),
		CheckoutFn: func(context.Context, model.Job, string) error { return nil },
	}, Client: ts.Client(), Metrics: NewMetrics()}
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(mainMarker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("main step never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	start := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return: cleanup escaped runner shutdown")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Run shutdown waited %v for a blocking cleanup step", elapsed)
	}
	if _, err := os.Stat(cleanupMarker); !os.IsNotExist(err) {
		t.Fatalf("cleanup step ran after runner shutdown (err=%v)", err)
	}
}

// TestExecuteArtifactCaptureDirFailure pins the checked failure branch when
// the per-job capture directory cannot be created (for example WorkDir is a
// regular file): the job completes as a failure before any step runs.
func TestExecuteArtifactCaptureDirFailure(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := testRunnerFor(t, ts, Config{WorkDir: blocked})
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }
	r.execute(context.Background(), basicTask(artifactPipeline("art", "")))
	c, ok := fsrv.lastComplete()
	if !ok || c.Status != model.StatusFailure || !strings.Contains(c.Error, "artifact capture directory") {
		t.Fatalf("complete = %+v ok=%v", c, ok)
	}
}
