package server

// K2-A regression tests: the in-fence ring re-read must be positively
// confirmed before a due rotation may rebuild the shared ring. The defect
// this pins: a replica that waited for the rotation fence, had its fence
// context expire during the wait (or could not reach the key store), re-read
// nothing, and then rotated from its own stale signer — publishing a ring
// that DROPPED the peer's freshly published active key from the ring and the
// JWKS.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// gatedClusterStore models the K2-A hazard deterministically. Its fence
// serializes callers exactly like the PostgreSQL advisory lock, but, like a
// plain in-process mutex, it cannot interrupt a waiter whose context expires:
// the body runs after the caller's fence deadline is gone. Its context-aware
// lookup refuses an already-expired read context (the pre-fix in-fence
// refresh passed the dead fence context straight to the key store) and can be
// switched to report the store as unreachable for the unconfirmed-refresh
// case.
type gatedClusterStore struct {
	*fencedClusterStore
	waiting     chan struct{}
	unavailable atomic.Bool
}

func newGatedClusterStore() *gatedClusterStore {
	return &gatedClusterStore{fencedClusterStore: newFencedClusterStore(), waiting: make(chan struct{}, 1)}
}

func (g *gatedClusterStore) WithClusterKeyRotationFence(_ context.Context, _ string, fn func() error) error {
	select {
	case g.waiting <- struct{}{}:
	default:
	}
	g.fence.Lock()
	defer g.fence.Unlock()
	return fn()
}

func (g *gatedClusterStore) LookupContext(ctx context.Context, kind string) ([]byte, bool, error) {
	if g.unavailable.Load() {
		return nil, false, errors.New("cluster key store unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	return g.Lookup(kind)
}

// TestOIDCRotationFenceStaleInFenceRefreshDoesNotOverwrite is the K2-A core
// regression: a peer rotates and publishes K1 while this replica is blocked
// waiting for the fence, and this replica's fence deadline expires before it
// is admitted. The pre-fix code re-read the ring under the dead fence context,
// got nothing back, and rotated from its own stale K0 — publishing K2 and
// dropping K1 from the shared ring. With the fix the in-fence re-read runs
// under its own bounded context, positively confirms K1, sees a young active
// key, and does not rotate: the peer's ring wins, exactly one write happened,
// and the token this replica issues is signed under the published K1.
func TestOIDCRotationFenceStaleInFenceRefreshDoesNotOverwrite(t *testing.T) {
	oldMax := oidcActiveKeyMaxAge
	oldFence := clusterKeyRotationFenceTimeout
	oidcActiveKeyMaxAge = time.Hour
	clusterKeyRotationFenceTimeout = 50 * time.Millisecond
	defer func() {
		oidcActiveKeyMaxAge = oldMax
		clusterKeyRotationFenceTimeout = oldFence
	}()

	store := newGatedClusterStore()
	waiter, err := NewPersistentWithCluster("t", "t", t.TempDir(), store)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := NewPersistentWithCluster("t", "t", t.TempDir(), store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	makeOIDCDue(waiter, now)
	makeOIDCDue(peer, now)
	stale := oidcKID(t, waiter)
	if peerKID := oidcKID(t, peer); peerKID != stale {
		t.Fatalf("setup: replicas started on different rings: %q vs %q", peerKID, stale)
	}

	// The fence is unavailable to the waiter (held here) while the peer
	// rotates and publishes.
	store.fence.Lock()
	done := make(chan *oidcSigner, 1)
	go func() { done <- waiter.ensureOIDCSigner(context.Background(), now) }()
	<-store.waiting // the waiter is at the fence and will block on acquisition
	peer.mu.Lock()
	peer.rotateOIDCKeyLocked(now)
	peer.mu.Unlock()
	rotated := oidcKID(t, peer)
	if rotated == stale {
		t.Fatal("setup: peer rotation did not change the key")
	}
	// Let the waiter's own fence deadline expire while it is still blocked.
	time.Sleep(4 * clusterKeyRotationFenceTimeout)
	store.fence.Unlock()

	var signer *oidcSigner
	select {
	case signer = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("ensureOIDCSigner never returned")
	}

	published := store.storedOIDC(t)
	if published.KID != rotated {
		t.Fatalf("published active kid = %q, want the peer's %q (a stale rebuild overwrote it)", published.KID, rotated)
	}
	if signer == nil || signer.KID != rotated {
		t.Fatalf("replica resolved signer %v, want the peer's published key %q", signer, rotated)
	}
	if store.stores != 1 {
		t.Fatalf("rotation writes = %d, want exactly the peer's 1 (no overwrite)", store.stores)
	}
	if !containsKID(oidcJWKSKids(t, waiter), rotated) {
		t.Fatalf("waiter JWKS lacks the published key %q", rotated)
	}
	// The waiter must not issue under a key the shared ring dropped. The
	// signed header's kid must equal the published active kid.
	if tok, err := waiter.signJWT(signer, map[string]any{"sub": "stale-refresh"}); err != nil {
		t.Fatal(err)
	} else if kid := pgITJWTKID(t, tok); kid != rotated {
		t.Fatalf("issued token kid = %q, want the published %q", kid, rotated)
	}
}

// slowLookupClusterStore models a key store with NO context-aware lookup
// surface (the PostgreSQL store's shape): its plain Lookup blocks until the
// test releases it, so an in-fence re-read can only be bounded by the context
// the caller passes. With the old code the fence context was already expired
// when the body ran, the select in lookupOIDCRingBytes took the ctx.Done arm
// while this Lookup was still blocked, and the replica rotated from stale
// local state.
type slowLookupClusterStore struct {
	*fencedClusterStore
	waiting chan struct{}
	block   atomic.Bool
	release chan struct{}
}

func newSlowLookupClusterStore() *slowLookupClusterStore {
	return &slowLookupClusterStore{fencedClusterStore: newFencedClusterStore(), waiting: make(chan struct{}, 1), release: make(chan struct{})}
}

func (s *slowLookupClusterStore) WithClusterKeyRotationFence(_ context.Context, _ string, fn func() error) error {
	select {
	case s.waiting <- struct{}{}:
	default:
	}
	s.fence.Lock()
	defer s.fence.Unlock()
	return fn()
}

func (s *slowLookupClusterStore) Lookup(kind string) ([]byte, bool, error) {
	if s.block.Load() {
		<-s.release
	}
	return s.fencedClusterStore.Lookup(kind)
}

// TestOIDCRotationFenceExpiredFenceContextNeverRotates is the fence-deadline
// half of K2-A on the plain-lookup path: the waiter's fence context expires
// while the fence is contended, and its in-fence re-read can only complete if
// it runs under its own fresh bound. The pre-fix code passed the dead fence
// context to the read, gave up while the store was still answering, and
// rotated — overwriting the peer's published key. With the fix the read is
// bounded independently, confirms the peer's ring, and no rotation happens.
func TestOIDCRotationFenceExpiredFenceContextNeverRotates(t *testing.T) {
	oldMax := oidcActiveKeyMaxAge
	oldFence := clusterKeyRotationFenceTimeout
	oidcActiveKeyMaxAge = time.Hour
	clusterKeyRotationFenceTimeout = time.Second
	defer func() {
		oidcActiveKeyMaxAge = oldMax
		clusterKeyRotationFenceTimeout = oldFence
	}()

	store := newSlowLookupClusterStore()
	waiter, err := NewPersistentWithCluster("t", "t", t.TempDir(), store)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := NewPersistentWithCluster("t", "t", t.TempDir(), store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	makeOIDCDue(waiter, now)
	makeOIDCDue(peer, now)
	stale := oidcKID(t, waiter)

	store.fence.Lock()
	done := make(chan *oidcSigner, 1)
	go func() { done <- waiter.ensureOIDCSigner(context.Background(), now) }()
	<-store.waiting
	// From here the store answers only when released: the in-fence read is
	// in flight across the fence deadline.
	store.block.Store(true)
	peer.mu.Lock()
	peer.rotateOIDCKeyLocked(now)
	peer.mu.Unlock()
	rotated := oidcKID(t, peer)
	if rotated == stale {
		t.Fatal("setup: peer rotation did not change the key")
	}
	time.Sleep(3 * clusterKeyRotationFenceTimeout)
	store.fence.Unlock()
	// The blocked read completes shortly AFTER the fence body starts, so the
	// pre-fix attempt (whose context is already dead) gives up while the read
	// is in flight, and the fixed attempt (with its fresh bound) still
	// receives the peer's ring.
	go func() {
		time.Sleep(clusterKeyRotationFenceTimeout / 2)
		close(store.release)
	}()

	var signer *oidcSigner
	select {
	case signer = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("ensureOIDCSigner never returned")
	}
	published := store.storedOIDC(t)
	if published.KID != rotated {
		t.Fatalf("published active kid = %q, want the peer's %q (expired fence context rebuilt the ring)", published.KID, rotated)
	}
	if signer == nil || signer.KID != rotated {
		t.Fatalf("replica resolved signer %v, want the peer's published key %q", signer, rotated)
	}
	if store.stores != 1 {
		t.Fatalf("rotation writes = %d, want exactly the peer's 1", store.stores)
	}
}

// TestOIDCRotationFenceUnconfirmedRefreshNeverRotates pins the other half of
// the K2-A rule: when the in-fence re-read cannot reach the store at all, the
// replica must serve the key it currently holds and skip the rotation instead
// of rebuilding the shared ring from unconfirmed local state. The gate is
// fail-safe, not sticky: once the store is reachable again a due key still
// rotates normally.
func TestOIDCRotationFenceUnconfirmedRefreshNeverRotates(t *testing.T) {
	oldMax := oidcActiveKeyMaxAge
	oidcActiveKeyMaxAge = time.Hour
	defer func() { oidcActiveKeyMaxAge = oldMax }()

	store := newGatedClusterStore()
	store.unavailable.Store(true)
	s, err := NewPersistentWithCluster("t", "t", t.TempDir(), store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	makeOIDCDue(s, now)
	before := store.storedOIDC(t).KID
	if inMemory := oidcKID(t, s); inMemory != before {
		t.Fatalf("setup: in-memory %q != published %q", inMemory, before)
	}

	got := s.ensureOIDCSigner(context.Background(), now)
	if got == nil || got.KID != before {
		t.Fatalf("unconfirmed refresh resolved %v, want the published key %q", got, before)
	}
	if store.stores != 0 {
		t.Fatalf("rotation writes without a confirmed refresh = %d, want 0", store.stores)
	}
	if published := store.storedOIDC(t); published.KID != before {
		t.Fatalf("published ring changed to %q despite the unconfirmed refresh", published.KID)
	}
	if !containsKID(oidcJWKSKids(t, s), before) {
		t.Fatalf("JWKS lacks the still-published key %q", before)
	}

	// Reachable again: the now-confirmed re-check still rotates the aged key.
	store.unavailable.Store(false)
	next := s.ensureOIDCSigner(context.Background(), now)
	if next == nil || next.KID == before {
		t.Fatalf("confirmed refresh did not rotate: got %v, want a fresh key", next)
	}
	if store.stores != 1 {
		t.Fatalf("rotation writes after recovery = %d, want 1", store.stores)
	}
	if published := store.storedOIDC(t); published.KID != next.KID {
		t.Fatalf("published active kid = %q, want the rotated %q", published.KID, next.KID)
	}
}
