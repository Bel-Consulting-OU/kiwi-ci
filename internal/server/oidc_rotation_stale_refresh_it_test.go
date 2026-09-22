package server

// Real-PostgreSQL integration tests for the K2-A rotation rule: an in-fence
// ring refresh that cannot be POSITIVELY confirmed must not be followed by a
// rotation. The pre-fix code re-read through the (possibly expired) fence
// context, swallowed the failure, and rebuilt the shared ring from this
// replica's own signer — dropping a peer's freshly published active key from
// the ring and the JWKS. Every test here runs two replicas over ONE schema
// and one shared cluster_keys table, like clusterkeys_rotation_it_test.go.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// pgITUnconfirmableKeyStore wraps the real DB-backed cluster key store and
// can make every read surface (the plain Lookup and the context-aware
// LookupContext) report the store as unreachable, modeling the in-fence
// re-read that returns nothing because the store is down or the fence
// context expired during a contended acquisition. Writes still land in the
// real cluster_keys table through the embedded store, and the rotation fence
// is the real PostgreSQL advisory lock.
type pgITUnconfirmableKeyStore struct {
	*DBClusterKeyStore
	unavailable atomic.Bool
}

var _ contextClusterKeyLookup = (*pgITUnconfirmableKeyStore)(nil)

func (p *pgITUnconfirmableKeyStore) SetUnavailable(v bool) { p.unavailable.Store(v) }

func (p *pgITUnconfirmableKeyStore) Lookup(kind string) ([]byte, bool, error) {
	if p.unavailable.Load() {
		return nil, false, errors.New("cluster key store unavailable")
	}
	return p.DBClusterKeyStore.Lookup(kind)
}

func (p *pgITUnconfirmableKeyStore) LookupContext(ctx context.Context, kind string) ([]byte, bool, error) {
	if p.unavailable.Load() {
		return nil, false, errors.New("cluster key store unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	return p.DBClusterKeyStore.Lookup(kind)
}

// pgITStaleRefreshServer builds a server over the given shared cluster key
// store without switching the scheduler to DB mode (rotation is a key-store
// concern): the preferred HA topology for the OIDC ring.
func pgITStaleRefreshServer(t *testing.T, store ClusterKeyStore) *Server {
	t.Helper()
	s, err := NewPersistent("token", "admin-token", t.TempDir())
	if err != nil {
		t.Fatalf("NewPersistent: %v", err)
	}
	if err := s.UseClusterKeyStore(store); err != nil {
		t.Fatalf("UseClusterKeyStore: %v", err)
	}
	return s
}

// pgITPublishedOIDC reads and parses the durable shared ring.
func pgITPublishedOIDC(t *testing.T, blobs storage.ClusterKeyBlobStore) *oidcSigner {
	t.Helper()
	b, found, err := blobs.GetClusterKey(context.Background(), clusterKindOIDC)
	if err != nil || !found {
		t.Fatalf("published ring: found=%v err=%v", found, err)
	}
	signer, err := oidcSignerFromRing(b)
	if err != nil {
		t.Fatalf("published ring parse: %v", err)
	}
	return signer
}

// pgITSignedKIDVerifiableByRing asserts the token's kid is advertised by the
// published ring (the active key or a retired-but-live previous key): the
// exact "never issue under a key the shared ring dropped" property.
func pgITSignedKIDVerifiableByRing(t *testing.T, ring *oidcSigner, token string) string {
	t.Helper()
	kid := pgITJWTKID(t, token)
	if kid != ring.KID {
		for _, prev := range ring.Previous {
			if prev.KID == kid {
				return kid
			}
		}
		t.Fatalf("issued token kid %q is not advertised by the published ring (active %q)", kid, ring.KID)
	}
	return kid
}

// TestIntegrationOIDCRotationFenceStaleRefreshNoOverwritePostgres is the
// K2-A real-PostgreSQL regression: replica A rotates and publishes K1; when
// replica B (whose in-memory ring is the superseded K0) is due and its
// in-fence re-read cannot confirm the published ring, B must NOT rotate from
// its stale K0. Before the fix B published a fresh ring that dropped K1
// entirely (not even retired into Previous), orphaning every token signed
// under it. After the fix the durable version stays at the peer's write, K1
// stays active, and B's own issued token stays verifiable (K0 is still
// advertised in Previous).
func TestIntegrationOIDCRotationFenceStaleRefreshNoOverwritePostgres(t *testing.T) {
	oldMax := oidcActiveKeyMaxAge
	oidcActiveKeyMaxAge = time.Hour
	defer func() { oidcActiveKeyMaxAge = oldMax }()

	env := pgITServerSetup(t)
	blobs := pgITClusterKeyBlobs(t, env)
	peer := pgITStaleRefreshServer(t, &DBClusterKeyStore{Blobs: blobs})
	waiterStore := &pgITUnconfirmableKeyStore{DBClusterKeyStore: &DBClusterKeyStore{Blobs: blobs}}
	waiter := pgITStaleRefreshServer(t, waiterStore)
	shared := oidcKID(t, peer)
	if got := oidcKID(t, waiter); got != shared {
		t.Fatalf("replicas started on different shared rings: %q vs %q", got, shared)
	}

	now := time.Now().UTC()
	makeOIDCDue(peer, now)
	// The peer rotates through the REAL PostgreSQL fence and publishes K1.
	rotated := peer.ensureOIDCSigner(context.Background(), now)
	if rotated == nil || rotated.KID == shared {
		t.Fatalf("peer rotation did not change the key: %v", rotated)
	}

	// The waiter is due, and its re-read cannot reach the store: it must
	// serve its current signer instead of rebuilding the ring.
	makeOIDCDue(waiter, now)
	waiterStore.SetUnavailable(true)
	got := waiter.ensureOIDCSigner(context.Background(), now)
	waiterStore.SetUnavailable(false)

	ring := pgITPublishedOIDC(t, blobs)
	if ring.KID != rotated.KID {
		t.Fatalf("published active kid = %q, want the peer's %q (a stale rebuild overwrote it)", ring.KID, rotated.KID)
	}
	if version, found, err := blobs.ClusterKeyVersion(context.Background(), clusterKindOIDC); err != nil || !found || version != 2 {
		t.Fatalf("durable version = %d (found=%v err=%v), want 2 (create + exactly one rotation)", version, found, err)
	}
	if got == nil {
		t.Fatal("ensureOIDCSigner returned nil for the unconfirmed replica")
	}
	if got.KID != shared {
		t.Fatalf("unconfirmed replica resolved %q, want its last published key %q (never a fresh ring)", got.KID, shared)
	}
	tok, err := waiter.signJWT(got, map[string]any{"sub": "it-stale-refresh"})
	if err != nil {
		t.Fatal(err)
	}
	if kid := pgITSignedKIDVerifiableByRing(t, ring, tok); kid != shared {
		t.Fatalf("signed kid = %q, want %q", kid, shared)
	}
	if !containsKID(oidcJWKSKids(t, waiter), rotated.KID) {
		t.Fatalf("waiter JWKS lacks the peer-published key %q after recovery", rotated.KID)
	}

	// The single-winner property still holds: with the store reachable again
	// the waiter observes the young published key and does not rotate.
	adopted := waiter.ensureOIDCSigner(context.Background(), now)
	if adopted == nil || adopted.KID != rotated.KID {
		t.Fatalf("waiter adopted %v, want the peer's %q", adopted, rotated.KID)
	}
	if version, _, err := blobs.ClusterKeyVersion(context.Background(), clusterKindOIDC); err != nil || version != 2 {
		t.Fatalf("durable version after recovery = %d (err=%v), want the peer's single write", version, err)
	}
}

// TestIntegrationOIDCRotationFencePeerRotateWhileWaitingPostgres is the
// contended-acquisition half of K2-A: replica B waits on the real PostgreSQL
// advisory fence while replica A rotates and publishes K1, and B's fence
// deadline expires during the wait. B gets no fence, so it must not rebuild
// the ring; the peer's K1 stays active, B keeps serving the key that is still
// advertised in the ring's Previous, and no write is added.
func TestIntegrationOIDCRotationFencePeerRotateWhileWaitingPostgres(t *testing.T) {
	oldMax := oidcActiveKeyMaxAge
	oldFence := clusterKeyRotationFenceTimeout
	oidcActiveKeyMaxAge = time.Hour
	clusterKeyRotationFenceTimeout = 500 * time.Millisecond
	defer func() {
		oidcActiveKeyMaxAge = oldMax
		clusterKeyRotationFenceTimeout = oldFence
	}()

	env := pgITServerSetup(t)
	blobs := pgITClusterKeyBlobs(t, env)
	peer := pgITStaleRefreshServer(t, &DBClusterKeyStore{Blobs: blobs})
	waiter := pgITStaleRefreshServer(t, &DBClusterKeyStore{Blobs: blobs})
	shared := oidcKID(t, peer)
	now := time.Now().UTC()
	makeOIDCDue(peer, now)
	makeOIDCDue(waiter, now)

	held := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- blobs.WithClusterKeyRotationFence(context.Background(), clusterKindOIDC, func() error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held

	done := make(chan *oidcSigner, 1)
	go func() { done <- waiter.ensureOIDCSigner(context.Background(), now) }()
	// Let the waiter block on the PostgreSQL lock, then publish the peer's
	// rotation while it waits.
	time.Sleep(100 * time.Millisecond)
	peer.mu.Lock()
	peer.rotateOIDCKeyLocked(now)
	peer.mu.Unlock()
	rotated := oidcKID(t, peer)
	if rotated == shared {
		t.Fatal("peer rotation did not change the key")
	}
	// The waiter's fence deadline expires while the lock is still held.
	time.Sleep(clusterKeyRotationFenceTimeout)
	close(release)
	if err := <-holderDone; err != nil {
		t.Fatalf("fence holder: %v", err)
	}

	var signer *oidcSigner
	select {
	case signer = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("ensureOIDCSigner never returned after the fence deadline")
	}
	ring := pgITPublishedOIDC(t, blobs)
	if ring.KID != rotated {
		t.Fatalf("published active kid = %q, want the peer's %q", ring.KID, rotated)
	}
	if version, _, err := blobs.ClusterKeyVersion(context.Background(), clusterKindOIDC); err != nil || version != 2 {
		t.Fatalf("durable version = %d (err=%v), want 2", version, err)
	}
	if signer == nil || signer.KID != shared {
		t.Fatalf("waiter resolved %v, want its still-advertised key %q", signer, shared)
	}
	tok, err := waiter.signJWT(signer, map[string]any{"sub": "it-contended"})
	if err != nil {
		t.Fatal(err)
	}
	if kid := pgITSignedKIDVerifiableByRing(t, ring, tok); kid != shared {
		t.Fatalf("signed kid = %q, want %q", kid, shared)
	}
	if !containsKID(oidcJWKSKids(t, waiter), rotated) {
		t.Fatalf("waiter JWKS lacks the peer-published key %q", rotated)
	}
}
