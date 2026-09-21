package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fencedClusterStore is an in-memory ClusterKeyStore that also models the
// cross-replica rotation fence: fence serializes
// WithClusterKeyRotationFence callers exactly like the PostgreSQL advisory
// lock does, while mu guards the key blobs themselves.
type fencedClusterStore struct {
	mu       sync.Mutex
	keys     map[string][]byte
	fence    sync.Mutex
	stores   int
	storeErr error
}

func newFencedClusterStore() *fencedClusterStore {
	return &fencedClusterStore{keys: map[string][]byte{}}
}

func (f *fencedClusterStore) LoadOrCreate(kind string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if b, ok := f.keys[kind]; ok {
		return append([]byte(nil), b...), nil
	}
	b, err := f.createKey(kind)
	if err != nil {
		return nil, err
	}
	f.keys[kind] = append([]byte(nil), b...)
	return append([]byte(nil), b...), nil
}

// createKey mirrors the StaticClusterKeyStore default creator, including the
// web-session env override and the raw 32-byte layout.
func (f *fencedClusterStore) createKey(kind string) ([]byte, error) {
	if kind == clusterKindWebSession {
		return createWebSessionKey()
	}
	return createClusterKey(kind)
}

func (f *fencedClusterStore) Lookup(kind string) ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.keys[kind]
	if !ok {
		return nil, false, nil
	}
	return append([]byte(nil), b...), true, nil
}

func (f *fencedClusterStore) Store(kind string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.storeErr != nil {
		return f.storeErr
	}
	f.stores++
	f.keys[kind] = append([]byte(nil), data...)
	return nil
}

func (f *fencedClusterStore) WithClusterKeyRotationFence(_ context.Context, kind string, fn func() error) error {
	f.fence.Lock()
	defer f.fence.Unlock()
	return fn()
}

func (f *fencedClusterStore) storedOIDC(t *testing.T) *oidcSigner {
	t.Helper()
	b, ok, err := f.Lookup(clusterKindOIDC)
	if err != nil || !ok {
		t.Fatalf("stored oidc ring: ok=%v err=%v", ok, err)
	}
	signer, err := oidcSignerFromRing(b)
	if err != nil {
		t.Fatalf("stored oidc ring parse: %v", err)
	}
	return signer
}

// makeOIDCDue ages a server's active key past any positive max age so the
// next issue attempts a rotation.
func makeOIDCDue(s *Server, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.oidc.NotBefore = now.Add(-2 * time.Hour)
}

// oidcJWKSKids serves the JWKS handler and returns the advertised kids.
func oidcJWKSKids(t *testing.T, s *Server) []string {
	t.Helper()
	w := httptest.NewRecorder()
	s.oidcJWKS(w, httptest.NewRequest(http.MethodGet, "/api/v1/oidc/jwks", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("JWKS = %d, body %s", w.Code, w.Body.String())
	}
	var body struct {
		Keys []struct {
			KID string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("JWKS decode: %v", err)
	}
	out := make([]string, 0, len(body.Keys))
	for _, k := range body.Keys {
		out = append(out, k.KID)
	}
	return out
}

func containsKID(kids []string, kid string) bool {
	for _, k := range kids {
		if k == kid {
			return true
		}
	}
	return false
}

// TestOIDCRotationFenceSingleWinner drives two replicas that share one fenced
// store and both observe an expired active key: the fence plus the post-fence
// reload/re-check must produce exactly ONE rotation, and both replicas and the
// published ring must agree on the winning key.
func TestOIDCRotationFenceSingleWinner(t *testing.T) {
	oldMax := oidcActiveKeyMaxAge
	oidcActiveKeyMaxAge = time.Hour
	defer func() { oidcActiveKeyMaxAge = oldMax }()

	store := newFencedClusterStore()
	s1, err := NewPersistentWithCluster("t", "t", t.TempDir(), store)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := NewPersistentWithCluster("t", "t", t.TempDir(), store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	makeOIDCDue(s1, now)
	makeOIDCDue(s2, now)

	var wg sync.WaitGroup
	kids := make([]string, 2)
	for i, s := range []*Server{s1, s2} {
		wg.Add(1)
		go func(i int, s *Server) {
			defer wg.Done()
			signer := s.ensureOIDCSigner(context.Background(), time.Now().UTC())
			if signer == nil {
				t.Error("ensureOIDCSigner returned nil")
				return
			}
			kids[i] = signer.KID
		}(i, s)
	}
	wg.Wait()

	if kids[0] == "" || kids[0] != kids[1] {
		t.Fatalf("replicas disagree on the winning key: %q vs %q", kids[0], kids[1])
	}
	stored := store.storedOIDC(t)
	if stored.KID != kids[0] {
		t.Fatalf("published ring active kid = %q, replicas issue under %q", stored.KID, kids[0])
	}
	if store.stores != 1 {
		t.Fatalf("rotation writes = %d, want exactly 1 (the fence must produce a single winner)", store.stores)
	}
	if len(stored.Previous) != 1 {
		t.Fatalf("published ring previous keys = %d, want 1", len(stored.Previous))
	}
	for i, s := range []*Server{s1, s2} {
		if !containsKID(oidcJWKSKids(t, s), kids[0]) {
			t.Fatalf("replica %d JWKS does not advertise the winning key %q", i, kids[0])
		}
	}
}

// TestOIDCJWKSReloadsPeerRotation proves the JWKS handler reloads the shared
// ring before serving: a non-issuing replica whose in-memory ring predates a
// peer's rotation must advertise the peer's new key.
func TestOIDCJWKSReloadsPeerRotation(t *testing.T) {
	oldMax := oidcActiveKeyMaxAge
	oidcActiveKeyMaxAge = time.Hour
	defer func() { oidcActiveKeyMaxAge = oldMax }()

	store := newFencedClusterStore()
	issuer, err := NewPersistentWithCluster("t", "t", t.TempDir(), store)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewPersistentWithCluster("t", "t", t.TempDir(), store)
	if err != nil {
		t.Fatal(err)
	}
	// Both start on the same ring; the issuing replica rotates.
	now := time.Now().UTC()
	makeOIDCDue(issuer, now)
	winner := issuer.ensureOIDCSigner(context.Background(), time.Now().UTC())
	if winner == nil {
		t.Fatal("ensureOIDCSigner returned nil")
	}
	// The stale replica must NOT have the key in memory yet; otherwise the
	// test would prove nothing.
	other.mu.Lock()
	stale := other.oidc.KID
	other.mu.Unlock()
	if stale == winner.KID {
		t.Fatal("test setup: replicas already agree, nothing to reload")
	}
	if kids := oidcJWKSKids(t, other); !containsKID(kids, winner.KID) {
		t.Fatalf("non-issuing replica JWKS %v lacks the peer-issued key %q", kids, winner.KID)
	}
	other.mu.Lock()
	adopted := other.oidc.KID
	other.mu.Unlock()
	if adopted != winner.KID {
		t.Fatalf("after JWKS reload the replica still holds %q, want %q", adopted, winner.KID)
	}
}

// TestOIDCRotationPersistFailureKeepsPublishedKey proves rotation fails
// closed: when the shared ring cannot be written, the current PUBLISHED key
// stays active and no token can be issued under a replacement that no peer
// can verify.
func TestOIDCRotationPersistFailureKeepsPublishedKey(t *testing.T) {
	oldMax := oidcActiveKeyMaxAge
	oidcActiveKeyMaxAge = time.Hour
	defer func() { oidcActiveKeyMaxAge = oldMax }()

	store := newFencedClusterStore()
	store.storeErr = errors.New("ring write unavailable")
	s, err := NewPersistentWithCluster("t", "t", t.TempDir(), store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	makeOIDCDue(s, now)
	s.mu.Lock()
	before := s.oidc.KID
	s.mu.Unlock()

	got := s.ensureOIDCSigner(context.Background(), now)
	if got == nil || got.KID != before {
		t.Fatalf("failed rotation activated %v, want the published key %q", got, before)
	}
	if stored := store.storedOIDC(t); stored.KID != before {
		t.Fatalf("published ring changed to %q despite the write failure", stored.KID)
	}
	if !containsKID(oidcJWKSKids(t, s), before) {
		t.Fatal("published key missing from the JWKS after a failed rotation")
	}
}

// blockingFencerStore blocks fence acquisition until the context expires,
// modeling a replica that cannot get the cross-replica lock.
type blockingFencerStore struct {
	*fencedClusterStore
}

func (b *blockingFencerStore) WithClusterKeyRotationFence(ctx context.Context, _ string, _ func() error) error {
	<-ctx.Done()
	return ctx.Err()
}

// TestOIDCRotationFenceContentionBounded proves lock contention is bounded
// and fail-safe: when the fence cannot be acquired, the rotation is skipped
// and the replica keeps serving the current published key instead of
// rotating without the fence.
func TestOIDCRotationFenceContentionBounded(t *testing.T) {
	oldMax := oidcActiveKeyMaxAge
	oldFence := clusterKeyRotationFenceTimeout
	oidcActiveKeyMaxAge = time.Hour
	clusterKeyRotationFenceTimeout = 50 * time.Millisecond
	defer func() {
		oidcActiveKeyMaxAge = oldMax
		clusterKeyRotationFenceTimeout = oldFence
	}()

	store := &blockingFencerStore{newFencedClusterStore()}
	s, err := NewPersistentWithCluster("t", "t", t.TempDir(), store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	makeOIDCDue(s, now)
	s.mu.Lock()
	before := s.oidc.KID
	s.mu.Unlock()

	start := time.Now()
	got := s.ensureOIDCSigner(context.Background(), now)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("fence contention took %s, want the bounded timeout to apply", elapsed)
	}
	if got == nil || got.KID != before {
		t.Fatalf("contended rotation changed the signer to %v, want the published key %q", got, before)
	}
	if store.stores != 0 {
		t.Fatalf("rotation persisted %d times without the fence, want 0", store.stores)
	}
}

// TestOIDCJWTAlwaysUsesPublishedActiveKey simulates the HA interleaving: a
// replica whose in-memory ring is stale signs only after re-reading the
// shared ring, so the token's kid always matches the published active key.
func TestOIDCJWTAlwaysUsesPublishedActiveKey(t *testing.T) {
	oldMax := oidcActiveKeyMaxAge
	oidcActiveKeyMaxAge = time.Hour
	defer func() { oidcActiveKeyMaxAge = oldMax }()

	store := newFencedClusterStore()
	rotator, err := NewPersistentWithCluster("t", "t", t.TempDir(), store)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := NewPersistentWithCluster("t", "t", t.TempDir(), store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	makeOIDCDue(rotator, now)
	if winner := rotator.ensureOIDCSigner(context.Background(), now); winner == nil {
		t.Fatal("rotation returned nil signer")
	}
	signer := issuer.ensureOIDCSigner(context.Background(), time.Now().UTC())
	if signer == nil {
		t.Fatal("issuer returned nil signer")
	}
	tok, err := issuer.signJWT(signer, map[string]any{"sub": "test"})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt parts = %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatal(err)
	}
	published := store.storedOIDC(t)
	if header.KID != published.KID {
		t.Fatalf("issued token kid %q != published active kid %q", header.KID, published.KID)
	}
}
