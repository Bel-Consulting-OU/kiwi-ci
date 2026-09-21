package storage

// Real-PostgreSQL integration coverage for the bounded fence release
// (S2-C): a wedged unlock or close call must not pin the release closure or
// its dedicated advisory-pool connection. The blocking calls are injected
// through the sanctioned fenceReleaseFn/fenceCloseFn seams (the "connection
// whose call blocks" form), with the hard bounds shrunk so the test is fast;
// the underlying session close is REAL, so the advisory lock is genuinely
// released and the pool slot genuinely replaced.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresIntegrationFenceReleaseBoundedAndIdempotent(t *testing.T) {
	env := pgITSetup(t)
	st := env.open(t)
	env.migrate(t, st)
	ctx := context.Background()

	oldReleaseTimeout, oldCloseTimeout := fenceReleaseTimeout, fenceCloseTimeout
	oldReleaseFn, oldCloseFn := fenceReleaseFn, fenceCloseFn
	fenceReleaseTimeout, fenceCloseTimeout = 150*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() {
		fenceReleaseTimeout, fenceCloseTimeout = oldReleaseTimeout, oldCloseTimeout
		fenceReleaseFn, fenceCloseFn = oldReleaseFn, oldCloseFn
	})

	// (a) A black-holed unlock call: the release must return within the
	// unlock bound even though the origin context is already canceled, close
	// the session for real (releasing the advisory lock), and be idempotent.
	digestA := strings.Repeat("a", 64)
	fenceReleaseFn = func(ctx context.Context, conn *pgxpool.Conn, key int64) error {
		<-ctx.Done()
		return ctx.Err()
	}
	acquireCtx, cancelAcquire := context.WithCancel(ctx)
	releaseA, err := st.AcquireDigestFence(acquireCtx, digestA)
	if err != nil {
		t.Fatalf("AcquireDigestFence: %v", err)
	}
	cancelAcquire() // the request that acquired the fence is gone
	start := time.Now()
	releaseA()
	elapsed := time.Since(start)
	if elapsed < fenceReleaseTimeout {
		t.Fatalf("release returned in %v, before the %v unlock bound (cancellation not detached?)", elapsed, fenceReleaseTimeout)
	}
	if elapsed > fenceReleaseTimeout+time.Second {
		t.Fatalf("release took %v, beyond the %v hard bound", elapsed, fenceReleaseTimeout)
	}
	second := time.Now()
	releaseA()
	if d := time.Since(second); d > 50*time.Millisecond {
		t.Fatalf("idempotent second release took %v", d)
	}

	// The real session close released the lock: the same digest is
	// immediately acquirable again.
	fenceReleaseFn = oldReleaseFn
	reacquired, err := st.AcquireDigestFence(ctx, digestA)
	if err != nil {
		t.Fatalf("re-acquire after bounded release: %v", err)
	}
	reacquired()

	// (b) A failing unlock plus a blocking close: the release returns within
	// the close's own bound.
	fenceReleaseFn = func(ctx context.Context, conn *pgxpool.Conn, key int64) error {
		return errors.New("unlock refused")
	}
	fenceCloseFn = func(ctx context.Context, conn *pgx.Conn) error {
		<-ctx.Done()
		return ctx.Err()
	}
	releaseB, err := st.AcquireNamedFence(ctx, "check-run", "fence-release-b")
	if err != nil {
		t.Fatalf("AcquireNamedFence: %v", err)
	}
	start = time.Now()
	releaseB()
	elapsed = time.Since(start)
	if elapsed < fenceCloseTimeout {
		t.Fatalf("release returned in %v, before the %v close bound", elapsed, fenceCloseTimeout)
	}
	if elapsed > fenceCloseTimeout+time.Second {
		t.Fatalf("release took %v, beyond the %v close bound", elapsed, fenceCloseTimeout)
	}
	second = time.Now()
	releaseB()
	if d := time.Since(second); d > 50*time.Millisecond {
		t.Fatalf("idempotent second release took %v", d)
	}
	fenceCloseFn = oldCloseFn

	// (c) No advisory-pool slot may leak: the pool caps at 4 connections and
	// every released slot must be returned/replaced, or the sixth acquire
	// (with a bounded context) would block forever.
	fenceReleaseFn = func(ctx context.Context, conn *pgxpool.Conn, key int64) error {
		<-ctx.Done()
		return ctx.Err()
	}
	for i := 0; i < 6; i++ {
		actx, cancel := context.WithTimeout(ctx, 5*time.Second)
		rel, err := st.AcquireDigestFence(actx, fmt.Sprintf("%064d", i))
		cancel()
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		rel()
	}
	pool, err := st.advisoryPool()
	if err != nil {
		t.Fatalf("advisory pool: %v", err)
	}
	// The pool's background maintenance may momentarily check out the idle
	// connection, so give the slot back a bounded grace window before
	// declaring a leak.
	deadline := time.Now().Add(2 * time.Second)
	for pool.Stat().AcquiredConns() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("advisory pool leaked %d acquired connections", pool.Stat().AcquiredConns())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
