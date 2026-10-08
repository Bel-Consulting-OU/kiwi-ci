package runner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestCompletionSurvivesJobTimeout proves the completion contract on the
// right cancellation axis: every production caller passes the RUNNER context
// to complete(), so a job whose own deadline expired still gets its terminal
// report delivered while the runner context is alive. The checkout hook
// blocks until the job deadline, so execute reaches completion exactly when
// the job context is dead.
func TestCompletionSurvivesJobTimeout(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(ctx context.Context, _ model.Job, _ string) error {
		<-ctx.Done()
		return ctx.Err()
	}
	task := basicTask(payloadPipeline)
	task.Job.JobTimeout = 150 * time.Millisecond

	start := time.Now()
	r.execute(context.Background(), task)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("execute took %v; completion did not run promptly after the job deadline", elapsed)
	}
	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("job timeout left the job unreported: no completion was delivered")
	}
	if c.Status != model.StatusCancelled {
		t.Fatalf("completion status = %q, want cancelled for a deadline-expired job", c.Status)
	}
}

// TestCompletionAbortsOnRunnerShutdown pins the other axis: complete() must
// honor the cancellation of the context it is given, because that context is
// the runner lifecycle (runCtx) in production. completionGrace is set to 10s
// so a return near the grace cannot be mistaken for prompt cancellation.
func TestCompletionAbortsOnRunnerShutdown(t *testing.T) {
	orig := completionGrace
	completionGrace = 10 * time.Second
	t.Cleanup(func() { completionGrace = orig })

	release := make(chan struct{})
	blocked := make(chan struct{}, 1)
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
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	r.complete(ctx, basicTask(payloadPipeline), model.StatusCancelled, nil, nil, nil)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("complete with a canceled runner context took %v (grace %v); shutdown cancellation was ignored", elapsed, completionGrace)
	}
}

// TestRunnerShutdownDoesNotWaitCompletionGrace is the end-to-end lifecycle
// regression: Run()'s stop() cancels runCtx, which must abort an in-flight
// terminal completion immediately. The fake control plane never answers
// /complete, the task fails the pre-checkout quota gate so execute reaches
// completion without a checkout, and completionGrace is 6s. With completion
// derived from the passed runner context Run returns in milliseconds; with
// the previous context.WithoutCancel(parent) it would wait the whole grace.
func TestRunnerShutdownDoesNotWaitCompletionGrace(t *testing.T) {
	origGrace := completionGrace
	completionGrace = 6 * time.Second
	t.Cleanup(func() { completionGrace = origGrace })

	installs, cleanups := 0, 0
	var limitSeen int64
	var dirSeen string
	stubWorkspaceQuota(t, executor.DiskQuotaStatus{Detail: "no delegated quota here"}, nil, &installs, &cleanups, &limitSeen, &dirSeen)

	task := untrustedContainerTask(t)
	jobJSON, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	completeSeen := make(chan struct{}, 1)
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
			select {
			case completeSeen <- struct{}{}:
			default:
			}
			select {
			case <-r.Context().Done():
			case <-release:
			}
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL, Poll: time.Millisecond, Concurrency: 1, IdentityDir: t.TempDir(), WorkDir: t.TempDir()}, Client: ts.Client(), Metrics: NewMetrics()}
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	select {
	case <-completeSeen:
	case <-time.After(15 * time.Second):
		cancel()
		t.Fatal("job never reached the completion post")
	}
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Fatalf("Run = %v, want context cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return promptly after cancellation: completion ignored runner shutdown")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Run shutdown waited %v on an in-flight completion (grace %v)", elapsed, completionGrace)
	}
}
