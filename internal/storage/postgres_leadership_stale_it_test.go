package storage

// Real-PostgreSQL regression for the S1A split-brain leadership cache: a
// leader whose dedicated advisory-lock session dies must never keep returning
// true from its local (key, held-until) cache while another replica holds the
// lock. Gated on KIWI_TEST_POSTGRES_URL like every *_it_test.go here; two
// stores are two pools, mirroring two control-plane replicas.

import (
	"context"
	"runtime"
	"testing"
	"time"
)

// TestPostgresIntegrationLeadershipDeadSessionNoCachedTrue is the S1A
// regression: A acquires, A's dedicated leader session is closed (the
// technique used by the squeeze test for a broken leader connection), B
// immediately acquires the freed lock, and A's TryAcquireLeadership BEFORE
// its former TTL expiry must return false. The previous cached-success path
// returned true without any round-trip, splitting leadership. It also covers
// connection death mid-TTL on the true-acquire path and shows repeated
// acquisition failures leave no cached connection/goroutine behind.
func TestPostgresIntegrationLeadershipDeadSessionNoCachedTrue(t *testing.T) {
	env := pgITSetup(t)
	a := env.open(t)
	b := env.open(t)
	env.migrate(t, a)
	ctx := context.Background()
	key := "kiwi-it-leader-stale-cache"

	if got, err := a.TryAcquireLeadership(ctx, key, time.Minute); err != nil || !got {
		t.Fatalf("A acquire = %v, %v", got, err)
	}
	if a.leaderConn == nil {
		t.Fatal("A did not open its dedicated leader session")
	}
	// Kill A's session the way a crashed backend does: closing the dedicated
	// connection drops its session advisory lock server-side while A's local
	// cache still claims leadership until the TTL.
	_ = a.leaderConn.Close(ctx)

	if got, err := b.TryAcquireLeadership(ctx, key, time.Minute); err != nil || !got {
		t.Fatalf("B acquire after A session death = %v, %v; want true (the lock died with A's session)", got, err)
	}
	// THE REGRESSION: well inside A's original TTL, the cached true must be
	// rejected. A pings its session, sees it is gone, clears the cache and
	// runs a real acquisition, which B's live lock refuses.
	if got, err := a.TryAcquireLeadership(ctx, key, time.Minute); err != nil || got {
		t.Fatalf("A cached re-acquire after session death = %v, %v; want false (B holds the lock)", got, err)
	}
	if a.leaderConn != nil || a.leaderKey != "" || !a.leaderHeldUntil.IsZero() {
		t.Fatalf("A kept a stale leader cache: conn=%v key=%q until=%v",
			a.leaderConn != nil, a.leaderKey, a.leaderHeldUntil)
	}

	// After B releases, A can reacquire normally.
	if err := b.ReleaseLeadership(ctx, key); err != nil {
		t.Fatalf("B release: %v", err)
	}
	if got, err := a.TryAcquireLeadership(ctx, key, time.Minute); err != nil || !got {
		t.Fatalf("A reacquire after B release = %v, %v", got, err)
	}
	// Connection death mid-TTL on the true-acquire path: A's new session is
	// killed and the next call must reconnect and take the free lock rather
	// than trust the dead session.
	_ = a.leaderConn.Close(ctx)
	if got, err := a.TryAcquireLeadership(ctx, key, time.Minute); err != nil || !got {
		t.Fatalf("A reacquire after second session death = %v, %v", got, err)
	}
	if a.leaderConn == nil {
		t.Fatal("A did not reconnect its leader session")
	}
	// Hand the lock back before the contention phase.
	if err := a.ReleaseLeadership(ctx, key); err != nil {
		t.Fatalf("A release after reconnect: %v", err)
	}

	// Repeated contended failures must not leak the candidate connections:
	// every rejected attempt closes its connection and leaves no cache, so a
	// leaking session holding the lock would surface as a failed reacquire.
	if got, err := b.TryAcquireLeadership(ctx, key, time.Minute); err != nil || !got {
		t.Fatalf("B reacquire = %v, %v", got, err)
	}
	before := runtime.NumGoroutine()
	for i := 0; i < 25; i++ {
		got, err := a.TryAcquireLeadership(ctx, key, time.Minute)
		if err != nil || got {
			t.Fatalf("contended attempt %d = %v, %v; want false, nil", i, got, err)
		}
		if a.leaderConn != nil || a.leaderKey != "" || !a.leaderHeldUntil.IsZero() {
			t.Fatalf("contended attempt %d leaked leader cache: conn=%v key=%q", i, a.leaderConn != nil, a.leaderKey)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("contended acquisition failures leaked goroutines: before=%d after=%d", before, after)
	}
	if err := b.ReleaseLeadership(ctx, key); err != nil {
		t.Fatalf("B final release: %v", err)
	}
	if got, err := a.TryAcquireLeadership(ctx, key, time.Minute); err != nil || !got {
		t.Fatalf("A final reacquire = %v, %v; want true (no leaked session holds the lock)", got, err)
	}
	if err := a.ReleaseLeadership(ctx, key); err != nil {
		t.Fatalf("A final release: %v", err)
	}
}

// TestPostgresIntegrationReleaseLeadershipClearsDeadSession covers the other
// half of the invariant: ReleaseLeadership over a session that already died
// reports the failed round-trip AND clears the cache, so a later
// TryAcquireLeadership cannot resurrect the dead session as proof.
func TestPostgresIntegrationReleaseLeadershipClearsDeadSession(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	key := "kiwi-it-release-dead-session"

	if got, err := st.TryAcquireLeadership(ctx, key, time.Minute); err != nil || !got {
		t.Fatalf("acquire = %v, %v", got, err)
	}
	_ = st.leaderConn.Close(ctx)
	if err := st.ReleaseLeadership(ctx, key); err == nil {
		t.Fatal("ReleaseLeadership over a dead session = nil error; want the failed unlock round-trip")
	}
	if st.leaderConn != nil || st.leaderKey != "" || !st.leaderHeldUntil.IsZero() {
		t.Fatalf("ReleaseLeadership kept a dead session cached: conn=%v key=%q until=%v",
			st.leaderConn != nil, st.leaderKey, st.leaderHeldUntil)
	}
	// The dead session is gone, so a fresh acquisition on the free lock
	// succeeds.
	if got, err := st.TryAcquireLeadership(ctx, key, time.Minute); err != nil || !got {
		t.Fatalf("reacquire after release of dead session = %v, %v", got, err)
	}
}
