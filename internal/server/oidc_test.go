package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func newOIDCTestServer(t *testing.T, persistent bool) *Server {
	t.Helper()
	var s *Server
	if persistent {
		var err error
		s, err = NewPersistent("secret", "secret", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
	} else {
		s = New("secret")
	}
	s.ExternalURL = "https://ci.example.com"
	return s
}

// seedOIDCJob installs a trusted, running job with an active lease so the
// OIDC issuance endpoint authorizes it.
func seedOIDCJob(t *testing.T, s *Server, leaseToken string) (runID, jobID string) {
	t.Helper()
	runID, jobID = "run-oidc", "job-oidc"
	exp := time.Now().Add(time.Minute)
	s.mu.Lock()
	s.runs[runID] = model.Run{ID: runID, RepoFullName: "kiwi/repo", Ref: "main", SHA: "abc123", Event: "push", Status: model.StatusRunning}
	s.jobs[jobID] = model.Job{ID: jobID, RunID: runID, Key: "build", Status: model.StatusRunning, Trusted: true, OIDCAllowed: true, LeaseExpiresAt: &exp, LeaseTokenHash: hashLeaseToken(s.leaseKey, leaseToken), LeaseRunnerID: "runner-1"}
	s.mu.Unlock()
	return runID, jobID
}

func issueOIDCToken(t *testing.T, s *Server, jobID, leaseToken, audience string) string {
	t.Helper()
	c := newTestClient(t, s.Handler(), leaseToken)
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/oidc", map[string]any{"audience": audience}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("issue oidc: want 200 got %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Value
}

type parsedJWT struct {
	headerKID    string
	signingInput string
	sig          []byte
}

func parseTestJWT(t *testing.T, token string) parsedJWT {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed jwt: %q", token)
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var h struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &h); err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	return parsedJWT{headerKID: h.KID, signingInput: parts[0] + "." + parts[1], sig: sig}
}

type jwk struct {
	KID string `json:"kid"`
	X   string `json:"x"`
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

func fetchJWKS(t *testing.T, s *Server) []jwk {
	t.Helper()
	c := newTestClient(t, s.Handler(), "")
	w := c.do(http.MethodGet, "/api/v1/oidc/jwks", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("jwks: want 200 got %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Keys
}

func findJWK(keys []jwk, kid string) (bool, jwk) {
	for _, k := range keys {
		if k.KID == kid {
			return true, k
		}
	}
	return false, jwk{}
}

func TestOIDCTokenKidMatchesActiveKey(t *testing.T) {
	s := newOIDCTestServer(t, false)
	_, jobID := seedOIDCJob(t, s, "lease1")
	tok := issueOIDCToken(t, s, jobID, "lease1", "https://aud.example.com")
	jwt := parseTestJWT(t, tok)

	s.mu.Lock()
	signer := s.oidc
	s.mu.Unlock()
	if jwt.headerKID != signer.KID {
		t.Fatalf("token kid %q != active kid %q", jwt.headerKID, signer.KID)
	}
	keys := fetchJWKS(t, s)
	found, k := findJWK(keys, signer.KID)
	if !found {
		t.Fatalf("jwks missing active kid %q: %+v", signer.KID, keys)
	}
	if k.X != base64.RawURLEncoding.EncodeToString(signer.Public) {
		t.Fatal("jwks x does not match active public key")
	}
	if k.Use != "sig" || k.Alg != "EdDSA" || k.CRV != "Ed25519" || k.KTY != "OKP" {
		t.Fatalf("bad jwk fields: %+v", k)
	}
	pub, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, []byte(jwt.signingInput), jwt.sig) {
		t.Fatal("token does not verify with the advertised active key")
	}
}

func TestOIDCActiveKeyRotatesAfterMaxAge(t *testing.T) {
	s := newOIDCTestServer(t, false)
	s.mu.Lock()
	old := s.oidc
	s.mu.Unlock()
	oldKid := old.KID
	oldPub := append(ed25519.PublicKey(nil), old.Public...)

	oldMax := oidcActiveKeyMaxAge
	oidcActiveKeyMaxAge = 0
	defer func() { oidcActiveKeyMaxAge = oldMax }()

	_, jobID := seedOIDCJob(t, s, "lease1")
	tok := issueOIDCToken(t, s, jobID, "lease1", "https://aud.example.com")
	jwt := parseTestJWT(t, tok)

	s.mu.Lock()
	active := s.oidc
	s.mu.Unlock()
	if jwt.headerKID != active.KID {
		t.Fatalf("token kid %q != new active kid %q", jwt.headerKID, active.KID)
	}
	if active.KID == oldKid {
		t.Fatal("active key did not rotate")
	}
	keys := fetchJWKS(t, s)
	found, k := findJWK(keys, active.KID)
	if !found || k.X != base64.RawURLEncoding.EncodeToString(active.Public) {
		t.Fatal("jwks does not advertise the new active key")
	}
	foundPrev, pk := findJWK(keys, oldKid)
	if !foundPrev {
		t.Fatalf("jwks missing rotated-out key %q: %+v", oldKid, keys)
	}
	prevPub, err := base64.RawURLEncoding.DecodeString(pk.X)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.PublicKey(prevPub).Equal(oldPub) {
		t.Fatal("jwks previous key public material changed")
	}
	pub, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, []byte(jwt.signingInput), jwt.sig) {
		t.Fatal("token does not verify with the new active key")
	}
}

func TestOIDCPreviousKeyStillVerifies(t *testing.T) {
	s := newOIDCTestServer(t, false)
	s.mu.Lock()
	oldPriv := append(ed25519.PrivateKey(nil), s.oidc.Private...)
	oldKid := s.oidc.KID
	rotatedAt := time.Now().UTC()
	s.rotateOIDCKeyLocked(rotatedAt)
	signer := s.oidc
	s.mu.Unlock()

	if len(signer.Previous) != 1 {
		t.Fatalf("previous = %d entries, want 1", len(signer.Previous))
	}
	prev := signer.Previous[0]
	if prev.KID != oldKid {
		t.Fatalf("previous kid %q != old active kid %q", prev.KID, oldKid)
	}
	wantRetire := rotatedAt.Add(oidcPreviousKeyRetireAfter)
	if prev.RetireAfter.Before(wantRetire.Add(-time.Minute)) || prev.RetireAfter.After(wantRetire.Add(time.Minute)) {
		t.Fatalf("retire_after = %v, want ~%v", prev.RetireAfter, wantRetire)
	}

	// Craft a token signed by the rotated-out private key.
	hb, _ := json.Marshal(map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": oldKid})
	cb, _ := json.Marshal(map[string]any{"iss": "https://ci.example.com", "sub": "s", "aud": "a", "exp": time.Now().Add(time.Minute).Unix()})
	enc := base64.RawURLEncoding.EncodeToString
	input := enc(hb) + "." + enc(cb)
	sig := ed25519.Sign(oldPriv, []byte(input))

	keys := fetchJWKS(t, s)
	found, k := findJWK(keys, oldKid)
	if !found {
		t.Fatalf("jwks no longer advertises previous kid %q: %+v", oldKid, keys)
	}
	pub, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, []byte(input), sig) {
		t.Fatal("previous-key token does not verify with the advertised key")
	}
}

func TestOIDCRetiredPreviousKeyRemovedFromJWKS(t *testing.T) {
	s := newOIDCTestServer(t, false)
	s.mu.Lock()
	oldKid := s.oidc.KID
	s.rotateOIDCKeyLocked(time.Now().UTC())
	s.oidc.Previous[0].RetireAfter = time.Now().UTC().Add(-time.Minute)
	s.mu.Unlock()

	keys := fetchJWKS(t, s)
	if found, _ := findJWK(keys, oldKid); found {
		t.Fatal("retired previous key is still advertised in the JWKS")
	}
}

func TestOIDCJWKSETagAndCacheControl(t *testing.T) {
	s := newOIDCTestServer(t, false)
	c := newTestClient(t, s.Handler(), "")
	w := c.do(http.MethodGet, "/api/v1/oidc/jwks", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("jwks: want 200 got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("cache-control = %q", got)
	}
	etag := w.Header().Get("ETag")
	if etag == "" || !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) {
		t.Fatalf("etag = %q", etag)
	}
	w2 := c.do(http.MethodGet, "/api/v1/oidc/jwks", nil, map[string]string{"If-None-Match": etag})
	if w2.Code != http.StatusNotModified {
		t.Fatalf("if-none-match: want 304 got %d", w2.Code)
	}
	if w2.Body.Len() != 0 {
		t.Fatalf("304 must not carry a body: %s", w2.Body.String())
	}
	w3 := c.do(http.MethodGet, "/api/v1/oidc/jwks", nil, map[string]string{"If-None-Match": `"stale"`})
	if w3.Code != http.StatusOK {
		t.Fatalf("stale etag: want 200 got %d", w3.Code)
	}
}

func TestOIDCConfigurationCacheControl(t *testing.T) {
	s := newOIDCTestServer(t, false)
	c := newTestClient(t, s.Handler(), "")
	w := c.do(http.MethodGet, "/.well-known/openid-configuration", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("configuration: want 200 got %d: %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("cache-control = %q", got)
	}
	var cfg map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["issuer"] != "https://ci.example.com" || cfg["jwks_uri"] != "https://ci.example.com/api/v1/oidc/jwks" {
		t.Fatalf("unexpected configuration: %+v", cfg)
	}
}

func TestOIDCIssuanceAudited(t *testing.T) {
	s := newOIDCTestServer(t, true)
	_, jobID := seedOIDCJob(t, s, "lease1")
	issueOIDCToken(t, s, jobID, "lease1", "https://aud.example.com")

	c := newTestClient(t, s.Handler(), "secret")
	w := c.do(http.MethodGet, "/api/v1/audit?limit=100", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list audit: want 200 got %d: %s", w.Code, w.Body.String())
	}
	var events []struct {
		Action string            `json:"action"`
		JobID  string            `json:"job_id"`
		Meta   map[string]string `json:"metadata"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &events); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "oidc.issued" && e.JobID == jobID && e.Meta["kid"] != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no oidc.issued audit event: %+v", events)
	}
}

func TestOIDCKeyRingPersistenceAndRestart(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	ringFile := filepath.Join(dir, oidcKeyRingFile)
	if _, err := os.Stat(ringFile); err != nil {
		t.Fatalf("ring file not created on first start: %v", err)
	}
	info, err := os.Stat(ringFile)
	if err != nil {
		t.Fatal(err)
	}
	// Windows file modes do not encode access control; the 0600 assertion
	// is POSIX-only. Content and readability are asserted everywhere.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("ring file perms = %v, want 0600", info.Mode().Perm())
	}
	s1.mu.Lock()
	first := s1.oidc
	if len(first.KID) != 32 {
		t.Fatalf("fresh kid = %q, want 32 hex chars", first.KID)
	}
	s1.rotateOIDCKeyLocked(time.Now().UTC())
	second := s1.oidc
	s1.mu.Unlock()

	raw, err := os.ReadFile(ringFile)
	if err != nil {
		t.Fatal(err)
	}
	var rf oidcKeyRingJSON
	if err := json.Unmarshal(raw, &rf); err != nil {
		t.Fatal(err)
	}
	if rf.Active.KID != second.KID {
		t.Fatalf("persisted active kid %q != %q", rf.Active.KID, second.KID)
	}
	if len(rf.Previous) != 1 || rf.Previous[0].KID != first.KID {
		t.Fatalf("persisted previous keys = %+v", rf.Previous)
	}

	s2, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	if s2.oidc.KID != second.KID {
		t.Fatalf("active kid lost across restart: %q != %q", s2.oidc.KID, second.KID)
	}
	if len(s2.oidc.Previous) != 1 || s2.oidc.Previous[0].KID != first.KID {
		t.Fatalf("previous keys lost across restart: %+v", s2.oidc.Previous)
	}
	s2.mu.Unlock()
}

func TestOIDCLegacyKeyMigration(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, oidcLegacyKeyFile), []byte(base64.RawStdEncoding.EncodeToString(priv)), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	got := s.oidc
	s.mu.Unlock()
	want := signerFromKeys(pub, priv).KID
	if got.KID != want {
		t.Fatalf("migrated kid %q != %q", got.KID, want)
	}
	if !got.Public.Equal(pub) {
		t.Fatal("migrated public key mismatch")
	}
	if _, err := os.Stat(filepath.Join(dir, oidcKeyRingFile)); err != nil {
		t.Fatalf("ring file not created on legacy migration: %v", err)
	}
}

// seedDBOIDCJob installs a trusted running job into the DB-fake store ONLY:
// if issuance read the in-memory maps it would 404, proving the DB-mode
// accessors are used.
func seedDBOIDCJob(t *testing.T, f *dbFakeStore, s *Server, leaseToken string) (runID, jobID string) {
	t.Helper()
	runID, jobID = "run-oidc", "job-oidc"
	exp := time.Now().Add(time.Minute)
	f.mu.Lock()
	f.runs[runID] = model.Run{ID: runID, RepoFullName: "kiwi/repo", Ref: "main", SHA: "abc123", Event: "push", Status: model.StatusRunning}
	f.jobs[jobID] = model.Job{ID: jobID, RunID: runID, Key: "build", Status: model.StatusRunning, Trusted: true, OIDCAllowed: true, LeaseExpiresAt: &exp, LeaseTokenHash: hashLeaseToken(s.leaseKey, leaseToken), LeaseRunnerID: "runner-1"}
	f.mu.Unlock()
	return runID, jobID
}

// TestOIDCIssuanceDBModeReadsStore proves DB-mode issuance authorizes the
// lease and builds the claims from the SQL store, not the in-memory maps.
func TestOIDCIssuanceDBModeReadsStore(t *testing.T) {
	f := newDBFakeStore()
	s := New("secret")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.ExternalURL = "https://ci.example.com"
	_, jobID := seedDBOIDCJob(t, f, s, "lease1")

	tok := issueOIDCToken(t, s, jobID, "lease1", "https://aud.example.com")
	jwt := parseTestJWT(t, tok)
	s.mu.Lock()
	signer := s.oidc
	s.mu.Unlock()
	if jwt.headerKID != signer.KID {
		t.Fatalf("token kid %q != active kid %q", jwt.headerKID, signer.KID)
	}
	// The claims carry the store's run coordinates.
	parts := strings.Split(tok, ".")
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(cb, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["repository"] != "kiwi/repo" || claims["job_id"] != "job-oidc" {
		t.Fatalf("claims not derived from the store: %v", claims)
	}
	// A job that exists only in the memory maps must not authorize.
	ghostExp := time.Now().Add(time.Minute)
	s.mu.Lock()
	s.jobs["job-ghost"] = model.Job{ID: "job-ghost", RunID: "run-oidc", Key: "ghost", Status: model.StatusRunning, Trusted: true, OIDCAllowed: true, LeaseExpiresAt: &ghostExp, LeaseTokenHash: hashLeaseToken(s.leaseKey, "lease1"), LeaseRunnerID: "runner-1"}
	s.mu.Unlock()
	c := newTestClient(t, s.Handler(), "lease1")
	w := c.do(http.MethodPost, "/api/v1/jobs/job-ghost/oidc", map[string]any{"audience": "a"}, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("memory-only job issuance = %d, want 404 (store is the source of truth)", w.Code)
	}
}

// TestOIDCIssuanceFailsClosedOnAuditFailure proves an audit persistence
// failure fails the issuance (500) instead of log-and-continue.
func TestOIDCIssuanceFailsClosedOnAuditFailure(t *testing.T) {
	f := newDBFakeStore()
	s := New("secret")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.ExternalURL = "https://ci.example.com"
	_, jobID := seedDBOIDCJob(t, f, s, "lease1")
	f.mu.Lock()
	f.auditErr = fmt.Errorf("audit: injected failure")
	f.mu.Unlock()
	c := newTestClient(t, s.Handler(), "lease1")
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/oidc", map[string]any{"audience": "https://aud.example.com"}, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("issuance with audit failure = %d, want 500: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"value"`) {
		t.Fatalf("token returned despite audit failure: %s", w.Body.String())
	}
}

// failingWriteClusterStore wraps the static store and injects write
// failures for rotation-coordination tests.
type failingWriteClusterStore struct {
	*StaticClusterKeyStore
	FailStore bool
}

func (f *failingWriteClusterStore) Store(kind string, data []byte) error {
	if f.FailStore {
		return fmt.Errorf("injected store failure")
	}
	return f.StaticClusterKeyStore.Store(kind, data)
}

// TestOIDCRotationPersistBeforeActivate proves the new ring is persisted
// BEFORE activation: an interrupted write leaves the old ring active.
func TestOIDCRotationPersistBeforeActivate(t *testing.T) {
	shared := &failingWriteClusterStore{StaticClusterKeyStore: &StaticClusterKeyStore{Keys: map[string][]byte{}}}
	s, err := NewPersistentWithCluster("t", "t", t.TempDir(), shared)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	oldKID := s.oidc.KID
	s.mu.Unlock()
	shared.FailStore = true
	s.mu.Lock()
	s.rotateOIDCKeyLocked(time.Now().UTC())
	active := s.oidc.KID
	s.mu.Unlock()
	if active != oldKID {
		t.Fatalf("rotation activated despite failed persistence: active %q != old %q", active, oldKID)
	}
	// The JWKS still advertises only the old key.
	keys := fetchJWKS(t, s)
	if len(keys) != 1 || keys[0].KID != oldKID {
		t.Fatalf("JWKS = %+v, want only the old active key %q", keys, oldKID)
	}
	// Once persistence recovers, the next rotation activates.
	shared.FailStore = false
	s.mu.Lock()
	s.rotateOIDCKeyLocked(time.Now().UTC())
	active = s.oidc.KID
	s.mu.Unlock()
	if active == oldKID {
		t.Fatal("rotation did not activate after persistence recovered")
	}
}

// TestOIDCReplicaReloadsRotatedRing proves a second replica reloads the
// ring from the shared cluster store on token issuance (check-on-issue).
func TestOIDCReplicaReloadsRotatedRing(t *testing.T) {
	shared := &StaticClusterKeyStore{Keys: map[string][]byte{}}
	s1, err := NewPersistentWithCluster("t", "t", t.TempDir(), shared)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := NewPersistentWithCluster("t", "t", t.TempDir(), shared)
	if err != nil {
		t.Fatal(err)
	}
	s2.ExternalURL = "https://ci.example.com"
	_, jobID := seedOIDCJob(t, s2, "lease1")

	// Rotate on the first replica (persist through the shared store).
	s1.mu.Lock()
	s1.rotateOIDCKeyLocked(time.Now().UTC())
	newKID := s1.oidc.KID
	s1.mu.Unlock()

	// The second replica's next issuance reloads the ring and signs with
	// the rotated key.
	tok := issueOIDCToken(t, s2, jobID, "lease1", "https://aud.example.com")
	jwt := parseTestJWT(t, tok)
	if jwt.headerKID != newKID {
		t.Fatalf("replica signed with kid %q, want reloaded %q", jwt.headerKID, newKID)
	}
	s2.mu.Lock()
	if s2.oidc.KID != newKID {
		t.Fatalf("replica active kid %q, want %q", s2.oidc.KID, newKID)
	}
	s2.mu.Unlock()
}

// TestOIDCRotationPersistBeforeActivateFileMode is the file-mode variant:
// making the ring file unwritable keeps the old ring active.
func TestOIDCRotationPersistBeforeActivateFileMode(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("t", "t", dir)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	oldKID := s.oidc.KID
	s.mu.Unlock()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	s.mu.Lock()
	s.rotateOIDCKeyLocked(time.Now().UTC())
	active := s.oidc.KID
	s.mu.Unlock()
	if active != oldKID {
		t.Fatalf("rotation activated despite failed ring write: active %q != old %q", active, oldKID)
	}
}
