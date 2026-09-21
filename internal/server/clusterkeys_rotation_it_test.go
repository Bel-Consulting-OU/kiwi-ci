package server

// Real-PostgreSQL integration tests for the HA cluster-key store and OIDC
// rotation fence (D3-B/D3-C), plus the production runner-token policy over
// the durable runner_bearer_tokens table (D3-A/D3-D). Gated on
// KIWI_TEST_POSTGRES_URL like postgres_integration_test.go; every test opens
// its own throwaway schema, and the rotation tests run TWO servers with TWO
// separate PostgresStore connections over the same schema (the real HA
// topology: node-local key dirs, one shared database).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// pgITClusterKeyBlobs returns env's schema as a ClusterKeyBlobStore with the
// shared table ensured.
func pgITClusterKeyBlobs(t *testing.T, env *pgITServerEnv) storage.ClusterKeyBlobStore {
	t.Helper()
	st := env.open(t)
	blobs, ok := any(st).(storage.ClusterKeyBlobStore)
	if !ok {
		t.Fatalf("PostgresStore does not implement ClusterKeyBlobStore")
	}
	if err := blobs.EnsureClusterKeySchema(context.Background()); err != nil {
		t.Fatalf("ensure cluster key schema: %v", err)
	}
	return blobs
}

// pgITClusterKeyServer builds a server on env's schema whose cluster keys
// come from the DB-backed store (the preferred HA provider), seeding the
// shared table from its own node-local data dir.
func pgITClusterKeyServer(t *testing.T, env *pgITServerEnv, dataDir string) (*Server, storage.ClusterKeyBlobStore) {
	t.Helper()
	blobs := pgITClusterKeyBlobs(t, env)
	st, ok := blobs.(*storage.PostgresStore)
	if !ok {
		t.Fatalf("blob store = %T, want *storage.PostgresStore", blobs)
	}
	s, err := NewPersistent("token", "admin-token", dataDir)
	if err != nil {
		t.Fatalf("NewPersistent: %v", err)
	}
	if err := s.UseClusterKeyStore(&DBClusterKeyStore{Blobs: blobs, Seed: s.ClusterKeys}); err != nil {
		t.Fatalf("UseClusterKeyStore: %v", err)
	}
	if err := s.SwitchToDB(st); err != nil {
		t.Fatalf("SwitchToDB: %v", err)
	}
	if err := s.ValidateHAReady(); err != nil {
		t.Fatalf("ValidateHAReady with the DB key store: %v", err)
	}
	return s, blobs
}

// oidcKID returns the server's in-memory active OIDC key id.
func oidcKID(t *testing.T, s *Server) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.oidc == nil {
		t.Fatal("server has no OIDC signer")
	}
	return s.oidc.KID
}

// pgITJWTKID extracts the kid from a signed JWT header.
func pgITJWTKID(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
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
	return header.KID
}

// TestIntegrationClusterKeyStoreCASCreation proves cross-replica creation is
// create-if-absent over real PostgreSQL: two stores racing to create the same
// kind converge on one blob (version 1) and both return the winner's bytes.
func TestIntegrationClusterKeyStoreCASCreation(t *testing.T) {
	env := pgITServerSetup(t)
	blobsA := pgITClusterKeyBlobs(t, env)
	blobsB := pgITClusterKeyBlobs(t, env)
	a := &DBClusterKeyStore{Blobs: blobsA}
	b := &DBClusterKeyStore{Blobs: blobsB}
	var wg sync.WaitGroup
	out := make([][]byte, 2)
	for i, store := range []*DBClusterKeyStore{a, b} {
		wg.Add(1)
		go func(i int, store *DBClusterKeyStore) {
			defer wg.Done()
			got, err := store.LoadOrCreate(clusterKindOIDC)
			if err != nil {
				t.Error(err)
				return
			}
			out[i] = got
		}(i, store)
	}
	wg.Wait()
	if len(out[0]) == 0 || string(out[0]) != string(out[1]) {
		t.Fatalf("CAS creators diverged: %d vs %d bytes", len(out[0]), len(out[1]))
	}
	version, found, err := blobsA.ClusterKeyVersion(context.Background(), clusterKindOIDC)
	if err != nil || !found {
		t.Fatalf("version = %d found=%v err=%v", version, found, err)
	}
	if version != 1 {
		t.Fatalf("row version after creation = %d, want 1 (one winner)", version)
	}
	stored, ok, err := blobsB.GetClusterKey(context.Background(), clusterKindOIDC)
	if err != nil || !ok || string(stored) != string(out[0]) {
		t.Fatalf("shared row mismatch: ok=%v err=%v", ok, err)
	}
}

// TestIntegrationClusterKeyRotationFenceSingleWinner is the D3-B HA proof:
// two replicas over the same database both observe an expired active key,
// and the PostgreSQL advisory fence plus post-fence reload/re-check produces
// exactly ONE rotation. Both replicas, the JWKS of both, and every issued
// token agree on the winning key, and the durable version proves only one
// write happened.
func TestIntegrationClusterKeyRotationFenceSingleWinner(t *testing.T) {
	oldMax := oidcActiveKeyMaxAge
	oidcActiveKeyMaxAge = time.Hour
	defer func() { oidcActiveKeyMaxAge = oldMax }()

	env := pgITServerSetup(t)
	s1, blobs := pgITClusterKeyServer(t, env, t.TempDir())
	s2, _ := pgITClusterKeyServer(t, env, t.TempDir())
	if k1, k2 := oidcKID(t, s1), oidcKID(t, s2); k1 != k2 {
		t.Fatalf("replicas started on different shared rings: %q vs %q", k1, k2)
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
	body, ok, err := blobs.GetClusterKey(context.Background(), clusterKindOIDC)
	if err != nil || !ok {
		t.Fatalf("published ring: ok=%v err=%v", ok, err)
	}
	published, err := oidcSignerFromRing(body)
	if err != nil {
		t.Fatal(err)
	}
	if published.KID != kids[0] {
		t.Fatalf("published active kid %q, replicas issued under %q", published.KID, kids[0])
	}
	version, found, err := blobs.ClusterKeyVersion(context.Background(), clusterKindOIDC)
	if err != nil || !found {
		t.Fatalf("version: found=%v err=%v", found, err)
	}
	if version != 2 {
		t.Fatalf("durable version = %d, want 2 (one create + exactly one rotation)", version)
	}
	for i, s := range []*Server{s1, s2} {
		if !containsKID(oidcJWKSKids(t, s), kids[0]) {
			t.Fatalf("replica %d JWKS does not advertise the winning key %q", i, kids[0])
		}
	}
	// No token is issued under an unpublished key: the signed header's kid
	// equals the durable active kid.
	signer := s2.ensureOIDCSigner(context.Background(), time.Now().UTC())
	tok, err := s2.signJWT(signer, map[string]any{"sub": "it"})
	if err != nil {
		t.Fatal(err)
	}
	if kid := pgITJWTKID(t, tok); kid != published.KID {
		t.Fatalf("issued token kid %q != published kid %q", kid, published.KID)
	}
}

// TestIntegrationClusterKeyRotationFenceContentionBounded proves the fence
// does not block indefinitely: a replica that cannot acquire the lock within
// its bound gives up (and therefore keeps its current published key) instead
// of rotating without the fence.
func TestIntegrationClusterKeyRotationFenceContentionBounded(t *testing.T) {
	env := pgITServerSetup(t)
	blobsA := pgITClusterKeyBlobs(t, env)
	blobsB := pgITClusterKeyBlobs(t, env)

	release := make(chan struct{})
	held := make(chan struct{})
	heldDone := make(chan error, 1)
	go func() {
		heldDone <- blobsA.WithClusterKeyRotationFence(context.Background(), clusterKindOIDC, func() error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	ran := false
	err := blobsB.WithClusterKeyRotationFence(ctx, clusterKindOIDC, func() error {
		ran = true
		return nil
	})
	close(release)
	if cerr := <-heldDone; cerr != nil {
		t.Fatalf("fence holder failed: %v", cerr)
	}
	if err == nil {
		t.Fatal("contended fence acquired without waiting for release")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended fence error = %v, want the bounded context deadline", err)
	}
	if ran {
		t.Fatal("contended fence ran its function without the lock")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("contended fence took %s, want the bound to apply", elapsed)
	}
}

// TestIntegrationOIDCJWKSReloadsPeerRotation proves the JWKS handler reloads
// the shared ring: a non-issuing replica serves the key the other replica
// rotated to, not its stale in-memory ring.
func TestIntegrationOIDCJWKSReloadsPeerRotation(t *testing.T) {
	oldMax := oidcActiveKeyMaxAge
	oidcActiveKeyMaxAge = time.Hour
	defer func() { oidcActiveKeyMaxAge = oldMax }()

	env := pgITServerSetup(t)
	issuer, _ := pgITClusterKeyServer(t, env, t.TempDir())
	other, _ := pgITClusterKeyServer(t, env, t.TempDir())
	stale := oidcKID(t, other)

	now := time.Now().UTC()
	makeOIDCDue(issuer, now)
	winner := issuer.ensureOIDCSigner(context.Background(), time.Now().UTC())
	if winner == nil {
		t.Fatal("rotation returned nil signer")
	}
	if winner.KID == stale {
		t.Fatal("test setup: rotation did not change the key")
	}
	if kids := oidcJWKSKids(t, other); !containsKID(kids, winner.KID) {
		t.Fatalf("non-issuing replica JWKS %v lacks the peer-rotated key %q", kids, winner.KID)
	}
	if got := oidcKID(t, other); got != winner.KID {
		t.Fatalf("non-issuing replica adopted %q, want %q", got, winner.KID)
	}
}

// pgITFailingRunnerTokens wraps a real store and fails the per-runner token
// surface, modeling an auth-store outage at the runner tier.
type pgITFailingRunnerTokens struct{ storage.Store }

func (pgITFailingRunnerTokens) UpsertRunnerToken(context.Context, string, string) error {
	return errors.New("runner token table unavailable")
}

func (pgITFailingRunnerTokens) RunnerIDForToken(context.Context, string) (string, bool, error) {
	return "", false, errors.New("runner token table unavailable")
}

func (pgITFailingRunnerTokens) HasRunnerTokens(context.Context) (bool, error) {
	return false, errors.New("runner token table unavailable")
}

// TestIntegrationRunnerTokenSharedRejectedWithProvisionedCredentials covers
// the durable credential path end to end: once per-runner bearer credentials
// exist in runner_bearer_tokens, the shared token is rejected (and in
// production-identity mode it can never authenticate); the per-runner token
// works; and an auth-store outage answers 503 instead of falling back to the
// shared token.
func TestIntegrationRunnerTokenSharedRejectedWithProvisionedCredentials(t *testing.T) {
	s, _ := pgITServer(t, t.TempDir())
	ctx := context.Background()
	perRunner := "per-runner-token"
	perRunnerID := pgITServerRandomHex(t, 32)
	if err := s.ProvisionRunnerTokensDB(ctx, map[string]string{perRunnerID: auth.TokenDigest(perRunner)}); err != nil {
		t.Fatalf("provision per-runner token: %v", err)
	}
	s.runnerTokensDBAt = time.Time{}
	register := `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`

	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/register", "token", register, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("shared token with per-runner credentials = %d %s, want 401", w.Code, w.Body.String())
	}
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/register", perRunner, register, nil); w.Code != http.StatusOK {
		t.Fatalf("per-runner token = %d %s, want 200", w.Code, w.Body.String())
	}

	// Production identity mode: the shared token is disabled outright.
	s.RunnerToken = ""
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/register", "token", register, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("shared token in production identity mode = %d, want 401", w.Code)
	}
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/register", perRunner, register, nil); w.Code != http.StatusOK {
		t.Fatalf("per-runner token in production identity mode = %d, want 200", w.Code)
	}

	// Auth-store outage: 503, never the shared-token fallback.
	s.DB = pgITFailingRunnerTokens{Store: s.DB}
	s.runnerTokensDBAt = time.Time{}
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/register", "token", register, nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("shared token during store outage = %d, want 503", w.Code)
	}
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/register", perRunner, register, nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("per-runner token during store outage = %d, want 503", w.Code)
	}
}
