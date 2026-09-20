package storage

// Concurrency and throttle coverage for the scheduler leadership hot path:
// cached calls must not serialize behind the liveness probe, and the probe
// throttle must still detect a dead session within its bounded window.
// Real-PostgreSQL tests gated on KIWI_TEST_POSTGRES_URL like every
// *_it_test.go here.

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestPostgresIntegrationLeadershipHotPathNotSerializedBehindProbe proves the
// cached-success path is lock-local. With a slow probe seam installed, N
// concurrent cached calls must all return within a fraction of the probe bound
// and the probe must not run at all while the last successful proof is fresh.
// Before the throttle, every cached call executed the probe synchronously
// under leaderMu, so the calls serialized behind N slow probes. The stale
// phase additionally pins single-flight: one slow probe serves every
// concurrent caller instead of each stacking its own probe.
func TestPostgresIntegrationLeadershipHotPathNotSerializedBehindProbe(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	key := "kiwi-it-leader-hotpath"
	if got, err := st.TryAcquireLeadership(ctx, key, time.Minute); err != nil || !got {
		t.Fatalf("acquire = %v, %v", got, err)
	}

	const probeDelay = 300 * time.Millisecond
	var probeCalls atomic.Int64
	oldProbe := leaderProbeFn
	leaderProbeFn = func(context.Context, *pgx.Conn) error {
		probeCalls.Add(1)
		time.Sleep(probeDelay)
		return nil
	}
	defer func() { leaderProbeFn = oldProbe }()

	callConcurrently := func(n int) time.Duration {
		start := make(chan struct{})
		results := make(chan error, n)
		var wg sync.WaitGroup
		begin := time.Now()
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				ok, err := st.TryAcquireLeadership(ctx, key, time.Minute)
				if err != nil {
					results <- err
					return
				}
				if !ok {
					results <- fmt.Errorf("cached call = false; want true")
					return
				}
				results <- nil
			}()
		}
		close(start)
		wg.Wait()
		close(results)
		for err := range results {
			if err != nil {
				t.Fatalf("concurrent cached call: %v", err)
			}
		}
		return time.Since(begin)
	}

	// Fresh proof: the hot path must be pure cached state, no probe at all.
	const callers = 8
	if elapsed := callConcurrently(callers); elapsed >= probeDelay/2 {
		t.Fatalf("%d fresh cached calls took %v; they serialized behind the %v probe (the hot path must be lock-local)", callers, elapsed, probeDelay)
	}
	if n := probeCalls.Load(); n != 0 {
		t.Fatalf("liveness probe ran %d times on the fresh cached path; want 0 (the throttle must skip it)", n)
	}

	// Stale proof: exactly one slow probe must serve all concurrent callers.
	time.Sleep(leaderProbeInterval(time.Minute) + 100*time.Millisecond)
	probeCalls.Store(0)
	if elapsed := callConcurrently(callers); elapsed > 2*probeDelay {
		t.Fatalf("%d stale-proof calls took %v; want at most one %v probe, not one per caller", callers, elapsed, probeDelay)
	}
	if n := probeCalls.Load(); n != 1 {
		t.Fatalf("stale-proof calls ran %d probes; want exactly 1 (single-flight)", n)
	}
}

// TestPostgresIntegrationLeadershipThrottleBoundedDeadSessionDetection proves
// the throttle cannot mask a dead session past its bound: the cached proof is
// trusted only for leaderProbeInterval, after which a probe runs and a dead
// session is dropped. The session is killed at the socket level (not via
// (*pgx.Conn).Close, which the cached path's IsClosed check detects without
// I/O) so liveness can only come from the probe round-trip. Two stores are two
// pools, mirroring two control-plane replicas.
func TestPostgresIntegrationLeadershipThrottleBoundedDeadSessionDetection(t *testing.T) {
	env := pgITSetup(t)
	a := env.open(t)
	b := env.open(t)
	env.migrate(t, a)
	ctx := context.Background()
	key := "kiwi-it-leader-throttle"
	ttl := 30 * time.Second

	if got, err := a.TryAcquireLeadership(ctx, key, ttl); err != nil || !got {
		t.Fatalf("A acquire = %v, %v", got, err)
	}
	// Kill A's session at the socket level: pgx has not observed an error, so
	// IsClosed() stays false and only a probe can falsify the cached proof.
	if err := a.leaderConn.PgConn().Conn().Close(); err != nil {
		t.Fatalf("close A's raw socket: %v", err)
	}
	if a.leaderConn.IsClosed() {
		t.Fatal("raw socket close marked A's connection locally closed; the probe path would not be exercised")
	}

	// B can only take the lock once the server has dropped A's dead session.
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := b.TryAcquireLeadership(ctx, key, ttl)
		if err != nil {
			t.Fatalf("B acquire = %v, %v", got, err)
		}
		if got {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("B never acquired after A's session death")
		}
		time.Sleep(25 * time.Millisecond)
	}

	// A's cached true may survive while its proof is younger than the
	// throttle, but never past it: after interval + margin, A must probe,
	// fail, drop the cache and lose the (now B-held) lock.
	var probes atomic.Int64
	oldProbe := leaderProbeFn
	leaderProbeFn = func(ctx context.Context, conn *pgx.Conn) error {
		probes.Add(1)
		return oldProbe(ctx, conn)
	}
	defer func() { leaderProbeFn = oldProbe }()

	time.Sleep(leaderProbeInterval(ttl) + 150*time.Millisecond)
	start := time.Now()
	got, err := a.TryAcquireLeadership(ctx, key, ttl)
	elapsed := time.Since(start)
	if err != nil || got {
		t.Fatalf("A cached call after the throttle window = %v, %v; want false, nil (B holds the lock)", got, err)
	}
	if probes.Load() == 0 {
		t.Fatal("A never probed the cached session; detection did not come from the liveness proof")
	}
	if elapsed > leaderProbeTimeout+time.Second {
		t.Fatalf("A's dead-session detection took %v; want at most the probe bound", elapsed)
	}
	if a.leaderConn != nil || a.leaderKey != "" || !a.leaderHeldUntil.IsZero() {
		t.Fatalf("A kept a stale leader cache after detection: conn=%v key=%q", a.leaderConn != nil, a.leaderKey)
	}
}
