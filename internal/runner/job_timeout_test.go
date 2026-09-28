package runner

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestExecuteStartsJobTimeoutBeforeCheckout is the P2 regression: the
// persisted JobTimeout bounds the WHOLE execute lifecycle, starting before
// workspace/quota setup and checkout, not only the executor's step phase. A
// checkout that hangs (git clone alive but stalled) is torn down by the
// declared job deadline and reported as cancelled.
func TestExecuteStartsJobTimeoutBeforeCheckout(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{})
	checkoutEntered := make(chan context.Context, 1)
	r.Cfg.CheckoutFn = func(ctx context.Context, _ model.Job, _ string) error {
		checkoutEntered <- ctx
		<-ctx.Done()
		return ctx.Err()
	}
	task := basicTask(payloadPipeline)
	task.Job.JobTimeout = 120 * time.Millisecond

	start := time.Now()
	r.execute(context.Background(), task)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("execute took %v; the job timeout did not bound checkout", elapsed)
	}
	select {
	case ctx := <-checkoutEntered:
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("checkout context error = %v, want DeadlineExceeded (the job timeout must be its parent)", ctx.Err())
		}
	default:
		t.Fatal("checkout hook never ran")
	}
	c, ok := fsrv.lastComplete()
	if !ok || c.Status != model.StatusCancelled {
		t.Fatalf("complete = %+v ok=%v, want cancelled", c, ok)
	}
}

// TestExecuteLegacySetupCeilingBoundsCheckout proves the legacy fallback: a
// record with no persisted JobTimeout (JobTimeout==0) still gets a bounded
// setup phase from Config.SetupTimeout, so "no user job timeout" cannot mean
// "git may hang forever". Modern records take the persisted timeout instead.
func TestExecuteLegacySetupCeilingBoundsCheckout(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	r := testRunnerFor(t, ts, Config{SetupTimeout: 100 * time.Millisecond})
	checkoutEntered := make(chan context.Context, 1)
	r.Cfg.CheckoutFn = func(ctx context.Context, _ model.Job, _ string) error {
		checkoutEntered <- ctx
		<-ctx.Done()
		return ctx.Err()
	}
	task := basicTask(payloadPipeline)
	task.Job.JobTimeout = 0

	start := time.Now()
	r.execute(context.Background(), task)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("execute took %v; the setup ceiling did not bound checkout", elapsed)
	}
	select {
	case ctx := <-checkoutEntered:
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatalf("checkout context error = %v, want DeadlineExceeded (the setup ceiling must be its parent)", ctx.Err())
		}
	default:
		t.Fatal("checkout hook never ran")
	}
	if c, ok := fsrv.lastComplete(); !ok || c.Status != model.StatusCancelled {
		t.Fatalf("complete = %+v ok=%v, want cancelled", c, ok)
	}
}
