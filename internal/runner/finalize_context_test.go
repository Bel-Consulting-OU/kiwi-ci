package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestExecuteBoundsArtifactUploadByJobTimeout is the P2 lifecycle regression:
// an in-job artifact upload runs under the DECLARED JOB LIFETIME, not the
// process lifetime. The artifact endpoint here never answers; if the reporter
// still used the runner parent context, execute would block on the upload
// forever. With the job context, the declared timeout tears the upload down
// and the job completes as cancelled.
func TestExecuteBoundsArtifactUploadByJobTimeout(t *testing.T) {
	artifactSeen := make(chan struct{}, 1)
	release := make(chan struct{})
	var completeCalls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/artifacts/"):
			select {
			case artifactSeen <- struct{}{}:
			default:
			}
			// The client abort cancels r.Context(); the release channel is
			// the test-teardown escape so httptest.Server.Close can never be
			// held by a handler whose connection stayed half-open.
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return
		case strings.HasSuffix(r.URL.Path, "/complete"):
			completeCalls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()
	defer close(release)

	step := nativeScript(
		"mkdir -p out && printf hi > out/f",
		"New-Item -ItemType Directory -Force -Path out | Out-Null; Set-Content -LiteralPath out/f -Value hi",
	)
	pipelineText := "version: 1\njobs:\n  build:\n    steps:\n      - run: " + step + "\n    artifacts:\n      - name: app\n        paths: [out]\n"
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error { return nil }
	task := basicTask(pipelineText)
	task.Job.JobTimeout = 500 * time.Millisecond

	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		r.execute(context.Background(), task)
	}()
	select {
	case <-artifactSeen:
	case <-time.After(15 * time.Second):
		t.Fatalf("job never attempted its artifact upload; execute state unknown")
	}
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatalf("execute did not return within 15s while the job timeout was 500ms: the artifact upload is not bounded by the job lifetime")
	}
	elapsed := time.Since(start)
	if elapsed > 10*time.Second {
		t.Fatalf("execute took %v; the artifact upload was not torn down by the job deadline", elapsed)
	}
	if completeCalls.Load() == 0 {
		t.Fatal("job never completed")
	}
}

// TestExecuteBoundsSnapshotUploadByFinalizeTimeout is the post-job
// counterpart: snapshot capture runs after the executor returns, on the
// explicitly bounded finalization context. The snapshot endpoint never
// answers; with the bound the upload is aborted and the job still completes.
func TestExecuteBoundsSnapshotUploadByFinalizeTimeout(t *testing.T) {
	snapshotSeen := make(chan struct{}, 1)
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/snapshots"):
			select {
			case snapshotSeen <- struct{}{}:
			default:
			}
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()
	defer close(release)

	step := nativeScript("printf hi > f", "Set-Content -LiteralPath f -Value hi")
	pipelineText := "version: 1\njobs:\n  build:\n    steps:\n      - run: " + step + "\n"
	r := testRunnerFor(t, ts, Config{CaptureSnapshots: true, FinalizeTimeout: 300 * time.Millisecond})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error { return nil }
	task := basicTask(pipelineText)

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.execute(context.Background(), task)
	}()
	select {
	case <-snapshotSeen:
	case <-time.After(15 * time.Second):
		t.Fatal("job never attempted its snapshot upload")
	}
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("execute did not return: the snapshot upload is not bounded by the finalization grace")
	}
}

// TestCompleteBoundedByCompletionGrace pins the completion contract: a timed
// out/cancelled job still gets to report, but a wedged control plane cannot
// pin the runner slot. completionGrace is shrunk to 100ms and the endpoint
// never answers; complete must return near the grace, not at the 65s control
// client timeout or later.
func TestCompleteBoundedByCompletionGrace(t *testing.T) {
	orig := completionGrace
	completionGrace = 100 * time.Millisecond
	t.Cleanup(func() { completionGrace = orig })

	blocked := make(chan struct{}, 1)
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case blocked <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer ts.Close()
	defer close(release)

	r := testRunnerFor(t, ts, Config{})
	task := basicTask(payloadPipeline)
	start := time.Now()
	r.complete(context.Background(), task, model.StatusCancelled, nil, nil)
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("complete took %v with a %v grace; it is not bounded", elapsed, completionGrace)
	}
	select {
	case <-blocked:
	default:
		t.Fatal("completion endpoint was never called")
	}
}
