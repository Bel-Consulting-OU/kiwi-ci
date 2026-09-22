package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// idcovNilProfilesStore makes ListProfiles answer with a nil slice.
type idcovNilProfilesStore struct {
	*dbFakeStore
}

func (idcovNilProfilesStore) ListProfiles(context.Context) ([]model.RunnerProfile, error) {
	return nil, nil
}

// idcovProfileErrStore fails profile writes.
type idcovProfileErrStore struct {
	*dbFakeStore
}

func (idcovProfileErrStore) UpsertProfile(context.Context, model.RunnerProfile) error {
	return errors.New("profile write failed")
}

func (idcovProfileErrStore) ProfileForSerial(context.Context, string) (model.RunnerProfile, bool, error) {
	return model.RunnerProfile{}, false, errors.New("profile serial lookup failed")
}

// idcovPrincipal builds a request carrying a store principal.
func idcovPrincipal(t *testing.T, p auth.Principal) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	return r.WithContext(auth.WithPrincipal(context.Background(), p))
}

// TestIDCovTiersPureHelpers walks the pure authorization helpers.
func TestIDCovTiersPureHelpers(t *testing.T) {
	s := New("t")

	// canReadRepo: a canonical run identity matches a bare alias. The full
	// name deliberately differs from the alias so the canonical bare-part
	// resolution is the branch under test.
	run := model.Run{ID: "r1", RepoID: "github.com/acme/service", RepoFullName: "acme/service-full"}
	alias := auth.Principal{Subject: "u", Repositories: map[string]auth.RepositoryPermission{"acme/service": {Read: true}}}
	if !s.canReadRepo(idcovPrincipal(t, alias), repoIDForRun(run)) {
		t.Fatal("bare alias did not match the canonical run identity")
	}
	canonOnly := auth.Principal{Subject: "u", Repositories: map[string]auth.RepositoryPermission{"github.com/acme/service": {Read: true}}}
	if !s.canReadRepo(idcovPrincipal(t, canonOnly), repoIDForRun(run)) {
		t.Fatal("canonical key did not match")
	}
	if !s.canReadRepo(idcovPrincipal(t, alias), repoIDForRun(model.Run{ID: "r2", RepoID: "github.com/acme/service", RepoFullName: "acme/service-full"})) {
		t.Fatal("bare alias did not match the canonical bare part")
	}
	other := auth.Principal{Subject: "u", Repositories: map[string]auth.RepositoryPermission{"github.com/other/repo": {Read: true}}}
	if s.canReadRepo(idcovPrincipal(t, other), repoIDForRun(run)) {
		t.Fatal("unrelated repository was readable")
	}
	// The no-principal path (legacy/web session) is decided by the outer
	// tier and must stay open.
	if !s.canReadRepo(httptest.NewRequest(http.MethodGet, "/", nil), repoIDForRun(run)) {
		t.Fatal("no-principal request must pass the repository check")
	}

	// repoVisibleByName: canonical input matches a bare alias, and the
	// whitespace-padded name resolves through the trimmed canonical form.
	if !s.repoVisibleByName(idcovPrincipal(t, alias), "github.com/acme/service") {
		t.Fatal("bare alias did not match the canonical name")
	}
	if !s.repoVisibleByName(idcovPrincipal(t, alias), " acme/service") {
		t.Fatal("padded name did not resolve through the canonical form")
	}
	if s.repoVisibleByName(idcovPrincipal(t, other), "github.com/acme/service") {
		t.Fatal("unrelated name was visible")
	}

	// auth.Authorize: trusted run resolution, unknown actions and the
	// per-repository permission table (resolved only in internal/auth).
	trustedPrincipal := auth.Principal{Subject: "u", Roles: []auth.Role{auth.RoleTrustedRun}}
	if !auth.Authorize(trustedPrincipal, auth.ActionRun, "", true) {
		t.Fatal("trusted run role rejected for a trusted action")
	}
	if auth.Authorize(trustedPrincipal, auth.Action("unknown_action"), "", false) {
		t.Fatal("unknown action authorized")
	}
	perm := auth.Principal{Subject: "u", Repositories: map[string]auth.RepositoryPermission{
		"github.com/acme/service": {Run: true, TrustedRun: true, Approve: true, Cancel: true, Rerun: true, ArtifactRead: true},
	}}
	for _, action := range []auth.Action{auth.ActionRun, auth.ActionTrustedRun, auth.ActionApprove, auth.ActionCancel, auth.ActionRerun, auth.ActionArtifactRead, auth.ActionRead} {
		want := action != auth.ActionRead
		if got := auth.Authorize(perm, action, "github.com/acme/service", action == auth.ActionRun); got != want {
			t.Fatalf("Authorize(%s) = %v, want %v", action, got, want)
		}
	}
	if !auth.Authorize(perm, auth.ActionRun, "github.com/acme/service", false) {
		t.Fatal("untrusted run permission rejected")
	}
	if auth.Authorize(perm, auth.Action("unknown"), "github.com/acme/service", false) {
		t.Fatal("unknown action authorized through the repo table")
	}

	// requireRunRead / requireRunArtifactRead: a repo-only read principal
	// scoped away from the run is refused.
	scoped := auth.Principal{Subject: "u", Repositories: map[string]auth.RepositoryPermission{"github.com/other/repo": {Read: true, ArtifactRead: true}}}
	w := httptest.NewRecorder()
	if s.requireRunRead(w, idcovPrincipal(t, scoped), run) || w.Code != http.StatusForbidden {
		t.Fatalf("requireRunRead scoped out = %v/%d", false, w.Code)
	}
	w = httptest.NewRecorder()
	if s.requireRunArtifactRead(w, idcovPrincipal(t, scoped), run) || w.Code != http.StatusForbidden {
		t.Fatalf("requireRunArtifactRead scoped out = %d", w.Code)
	}
	w = httptest.NewRecorder()
	if !s.requireRunRead(w, idcovPrincipal(t, canonOnly), run) {
		t.Fatalf("requireRunRead in scope = %d", w.Code)
	}
	// A principal with no read role is refused by the action gate (and the
	// artifact-read gate) before any scope check.
	noRoles := auth.Principal{Subject: "u"}
	w = httptest.NewRecorder()
	if s.requireRunRead(w, idcovPrincipal(t, noRoles), run) || w.Code != http.StatusForbidden {
		t.Fatalf("requireRunRead without the read role = %d", w.Code)
	}
	w = httptest.NewRecorder()
	if s.requireRunArtifactRead(w, idcovPrincipal(t, noRoles), run) || w.Code != http.StatusForbidden {
		t.Fatalf("requireRunArtifactRead without the artifact-read role = %d", w.Code)
	}
	// The artifact-record variant denies unresolved runs outright (rather
	// than silently scoping them away) and otherwise applies the same gate.
	w = httptest.NewRecorder()
	if s.requireArtifactRead(w, idcovPrincipal(t, canonOnly), model.ArtifactRecord{RunID: "missing-run"}) || w.Code != http.StatusForbidden {
		t.Fatalf("requireArtifactRead with an unknown run = %d", w.Code)
	}
	s.mu.Lock()
	s.runs["run-art"] = run
	s.mu.Unlock()
	w = httptest.NewRecorder()
	if !s.requireArtifactRead(w, idcovPrincipal(t, perm), model.ArtifactRecord{RunID: "run-art"}) {
		t.Fatalf("requireArtifactRead in scope = %d", w.Code)
	}
}

// TestIDCovSessionHandlerGaps covers the login decode guard and the
// malformed-token helpers.
func TestIDCovSessionHandlerGaps(t *testing.T) {
	testutil.UnixChmod(t)
	s := testWebServer(t, "admin")
	if w := doJSON(t, s, http.MethodPost, "/api/v1/login", "", `{`); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed login body = %d, want 400", w.Code)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/login", "", `{"token":`+`"admin"}`+`junk`); w.Code != http.StatusBadRequest {
		t.Fatalf("trailing login body = %d, want 400", w.Code)
	}
	// A server whose session secret was never initialized rejects sessions.
	s2 := New("admin")
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: webSessionCookie, Value: "a|b|1"})
	if s2.webSessionOK(r) {
		t.Fatal("webSessionOK accepted an uninitialized secret")
	}
	// A request without a session cookie fails the CSRF helper.
	s3 := testWebServer(t, "admin")
	if s3.webCSRFOK(httptest.NewRequest(http.MethodPost, "/", nil)) {
		t.Fatal("webCSRFOK accepted a request without a session cookie")
	}
	// A structurally invalid cookie value fails the CSRF helper.
	r2 := httptest.NewRequest(http.MethodPost, "/", nil)
	r2.AddCookie(&http.Cookie{Name: webSessionCookie, Value: "no-pipes-here"})
	if s3.webCSRFOK(r2) {
		t.Fatal("webCSRFOK accepted a malformed cookie")
	}
	// With a well-formed cookie but a malformed header the helper fails too.
	nonce, _, expStr, _ := parseWebToken("aabb|cc|" + "9999999999")
	_ = nonce
	_ = expStr
	r3 := httptest.NewRequest(http.MethodPost, "/", nil)
	r3.AddCookie(&http.Cookie{Name: webSessionCookie, Value: "aabb|cc|9999999999"})
	if s3.webCSRFOK(r3) {
		t.Fatal("webCSRFOK accepted a missing header")
	}
}

// TestIDCovProfileRemainingGaps covers the nil list, malformed update body
// and store write failure.
func TestIDCovProfileRemainingGaps(t *testing.T) {
	// listProfiles normalizes a nil store result to an empty slice.
	s := New("admin")
	s.DB = idcovNilProfilesStore{dbFakeStore: newDBFakeStore()}
	w := doJSON(t, s, http.MethodGet, "/api/v1/runner-profiles", "admin", "")
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("nil profile list = %d: %q", w.Code, w.Body.String())
	}

	// updateRunnerProfile: malformed body.
	s2 := New("admin")
	if w := doJSON(t, s2, http.MethodPut, "/api/v1/runner-profiles/p", "admin", `{`); w.Code != http.StatusBadRequest {
		t.Fatalf("update malformed body = %d, want 400", w.Code)
	}
	// A store whose profile write fails surfaces 500 (the profile exists).
	f := newDBFakeStore()
	f.mu.Lock()
	f.profiles["p"] = model.RunnerProfile{ID: "p", MaxCapacity: 1}
	f.mu.Unlock()
	s3 := New("admin")
	s3.DB = idcovProfileErrStore{dbFakeStore: f}
	if w := doJSON(t, s3, http.MethodPut, "/api/v1/runner-profiles/p", "admin", `{"id":"p","max_capacity":1}`); w.Code != http.StatusInternalServerError {
		t.Fatalf("update with a failing store = %d, want 500", w.Code)
	}
}

// TestIDCovLoadEnrollGrantsIntoNilMap covers the nil-map initialization.
func TestIDCovLoadEnrollGrantsIntoNilMap(t *testing.T) {
	dir := t.TempDir()
	live := EnrollGrant{ExpiresAt: time.Now().Add(time.Hour)}
	b, err := json.Marshal(map[string]EnrollGrant{"k": live})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, enrollGrantsFile), b)
	s := &Server{}
	if err := s.loadEnrollGrants(dir); err != nil {
		t.Fatal(err)
	}
	if s.EnrollGrants == nil || len(s.EnrollGrants) != 1 {
		t.Fatalf("nil-map load = %v", s.EnrollGrants)
	}
}

// TestIDCovVerifyRunnerIdentityEmptyClaim covers the constrained identity
// mismatch when no runner id is claimed.
func TestIDCovVerifyRunnerIdentityEmptyClaim(t *testing.T) {
	s, _, cert := idcovCARunnerFixture(t)
	if s.verifyRunnerIdentity(crlRequestWithCert(t, cert), "") {
		t.Fatal("empty claimed id accepted under a constrained identity")
	}
}

// TestIDCovSignJWMarshalError covers the claim-marshal failure.
func TestIDCovSignJWMarshalError(t *testing.T) {
	s := New("t")
	if _, err := s.signJWT(newOIDCSigner(), map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatal("unmarshalable claims = nil error")
	}
}

// TestIDCovReloadOIDCRingFileModeSuccess covers the successful file-mode
// reload that swaps the signer.
func TestIDCovReloadOIDCRingFileModeSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, oidcKeyRingFile)
	s := New("t")
	s.mu.Lock()
	s.oidc = newOIDCSigner()
	s.oidc.ringPath = path
	if err := persistOIDCKeyRing(s.oidc); err != nil {
		t.Fatal(err)
	}
	firstKID := s.oidc.KID
	s.mu.Unlock()
	// An external writer installs a different ring (different size/mtime).
	other := newOIDCSigner()
	other.ringPath = path
	if err := persistOIDCKeyRing(other); err != nil {
		t.Fatal(err)
	}
	// Back-to-back writes of equal length can land on the same mtime tick on
	// a coarse filesystem, which would hide the rotation from the
	// mtime/size change detector. The external writer is modeled as strictly
	// later so the reload assertion is deterministic.
	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	// The refresh takes s.mu internally: call it without holding the lock.
	s.refreshOIDCRing(context.Background())
	s.mu.Lock()
	gotKID := s.oidc.KID
	gotPath := s.oidc.ringPath
	s.mu.Unlock()
	if gotKID != other.KID || gotKID == firstKID {
		t.Fatalf("file reload kept kid %q, want the external %q", gotKID, other.KID)
	}
	if gotPath != path {
		t.Fatalf("reloaded signer lost its ring path: %q", gotPath)
	}
}

// TestIDCovSignJWTNil checks the nil-signer refusal (already covered) and
// the successful signature shape.
func TestIDCovSignJWTNil(t *testing.T) {
	s := New("t")
	if _, err := s.signJWT(nil, nil); err == nil {
		t.Fatal("nil signer = nil error")
	}
	tok, err := s.signJWT(newOIDCSigner(), map[string]any{"a": 1})
	if err != nil || strings.Count(tok, ".") != 2 {
		t.Fatalf("signed token = %q, %v", tok, err)
	}
}

// chmodReadOnly makes a directory unreadable-for-writes and returns a
// restore function; tests using it skip when running as root.
func chmodReadOnly(t *testing.T, dir string) func() {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: directory permissions are not enforced")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	return func() { _ = os.Chmod(dir, 0o700) }
}

// TestIDCovCacheSignerWriteFailures covers the generation-time write
// failures of loadCacheSigner.
func TestIDCovCacheSignerWriteFailures(t *testing.T) {
	// A regular file as the data dir fails MkdirAll after the reads report
	// the files missing.
	file := filepath.Join(t.TempDir(), "file")
	writeTestFile(t, file, []byte("x"))
	if err := New("t").loadCacheSigner(file); err == nil {
		t.Fatal("file as data dir = nil error")
	}
	// A read-only directory fails the key write.
	dir := t.TempDir()
	restore := chmodReadOnly(t, dir)
	defer restore()
	if err := New("t").loadCacheSigner(dir); err == nil {
		t.Fatal("read-only data dir = nil error")
	}
	// A directory in the public key's place fails only the public write.
	dir2 := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir2, cacheSigningPubFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := New("t").loadCacheSigner(dir2); err == nil {
		t.Fatal("public key write failure = nil error")
	}
}

// TestIDCovWebSessionSecretWriteFailure covers the persistence failure of a
// generated secret.
func TestIDCovWebSessionSecretWriteFailure(t *testing.T) {
	dir := t.TempDir()
	restore := chmodReadOnly(t, dir)
	defer restore()
	s := New("t")
	if err := s.loadWebSessionSecret(dir); err == nil {
		t.Fatal("read-only data dir = nil error")
	}
	if len(s.WebSessionSecret) != 32 {
		t.Fatal("generated secret not installed in memory")
	}
}

// TestIDCovClusterKeyFSFailures covers the filesystem failure branches of
// the cluster key store.
func TestIDCovClusterKeyFSFailures(t *testing.T) {
	t.Run("lookup path error", func(t *testing.T) {
		if _, _, err := (&FSClusterKeyStore{}).Lookup(clusterKindProvenance); err == nil {
			t.Fatal("empty dir provenance lookup = nil error")
		}
	})
	t.Run("runner-ca dangling symlink", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Symlink(filepath.Join(dir, "missing"), filepath.Join(dir, runnerCAObjectFile)); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		s := &FSClusterKeyStore{Dir: dir}
		if _, err := s.LoadOrCreate(clusterKindRunnerCA); err == nil {
			t.Fatal("runner CA over a dangling symlink = nil error")
		}
	})
	t.Run("runner-ca sidecar failure", func(t *testing.T) {
		dir := t.TempDir()
		// ca.crt as a directory makes the sidecar rename fail after the
		// object was published.
		if err := os.Mkdir(filepath.Join(dir, "ca.crt"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := (&FSClusterKeyStore{Dir: dir}).LoadOrCreate(clusterKindRunnerCA); err == nil {
			t.Fatal("sidecar failure = nil error")
		}
	})
	t.Run("runner-ca sidecar key failure", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "ca.key"), 0o700); err != nil {
			t.Fatal(err)
		}
		s := &FSClusterKeyStore{Dir: dir}
		obj, err := createClusterKey(clusterKindRunnerCA)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Store(clusterKindRunnerCA, obj); err == nil {
			t.Fatal("ca.key sidecar failure = nil error")
		}
	})
	t.Run("provenance public sidecar failure", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "provenance.pub"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := (&FSClusterKeyStore{Dir: dir}).LoadOrCreate(clusterKindProvenance); err == nil {
			t.Fatal("public sidecar failure = nil error")
		}
	})
	t.Run("store invalid provenance", func(t *testing.T) {
		dir := t.TempDir()
		if err := (&FSClusterKeyStore{Dir: dir}).Store(clusterKindProvenance, []byte("junk")); err == nil {
			t.Fatal("invalid provenance material = nil error")
		}
	})
	t.Run("store invalid cache signing", func(t *testing.T) {
		dir := t.TempDir()
		if err := (&FSClusterKeyStore{Dir: dir}).Store(clusterKindCacheSigning, []byte("junk")); err == nil {
			t.Fatal("invalid cache material = nil error")
		}
	})
	t.Run("read-only create", func(t *testing.T) {
		dir := t.TempDir()
		restore := chmodReadOnly(t, dir)
		defer restore()
		if _, err := (&FSClusterKeyStore{Dir: dir}).LoadOrCreate(clusterKindLease); err == nil {
			t.Fatal("read-only create = nil error")
		}
	})
	t.Run("read-only runner-ca store", func(t *testing.T) {
		dir := t.TempDir()
		restore := chmodReadOnly(t, dir)
		defer restore()
		obj, err := createClusterKey(clusterKindRunnerCA)
		if err != nil {
			t.Fatal(err)
		}
		if err := (&FSClusterKeyStore{Dir: dir}).Store(clusterKindRunnerCA, obj); err == nil {
			t.Fatal("read-only runner-ca store = nil error")
		}
	})
	t.Run("read-only runner-ca create", func(t *testing.T) {
		dir := t.TempDir()
		restore := chmodReadOnly(t, dir)
		defer restore()
		if _, err := (&FSClusterKeyStore{Dir: dir}).LoadOrCreate(clusterKindRunnerCA); err == nil {
			t.Fatal("read-only runner-ca create = nil error")
		}
	})
	t.Run("read-only key material stores", func(t *testing.T) {
		privPEM, _, _ := testKeyPairPEM(t)
		dir := t.TempDir()
		restore := chmodReadOnly(t, dir)
		defer restore()
		store := &FSClusterKeyStore{Dir: dir}
		if err := store.Store(clusterKindProvenance, privPEM); err == nil {
			t.Fatal("read-only provenance store = nil error")
		}
		if err := store.Store(clusterKindCacheSigning, privPEM); err == nil {
			t.Fatal("read-only cache-signing store = nil error")
		}
	})
	t.Run("legacy oidc migration write failure", func(t *testing.T) {
		dir := t.TempDir()
		_, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(dir, oidcLegacyKeyFile), []byte(base64RawStd(priv)))
		restore := chmodReadOnly(t, dir)
		defer restore()
		if _, _, err := (&FSClusterKeyStore{Dir: dir}).Lookup(clusterKindOIDC); err == nil {
			t.Fatal("read-only legacy migration = nil error")
		}
	})
	t.Run("legacy runner-ca migration write failure", func(t *testing.T) {
		dir := t.TempDir()
		writeTestFile(t, filepath.Join(dir, "ca.crt"), []byte("cert"))
		writeTestFile(t, filepath.Join(dir, "ca.key"), []byte("key"))
		restore := chmodReadOnly(t, dir)
		defer restore()
		if _, _, err := (&FSClusterKeyStore{Dir: dir}).Lookup(clusterKindRunnerCA); err == nil {
			t.Fatal("read-only runner-ca migration = nil error")
		}
	})
}

// TestIDCovOIDCKeyRingWriteFailures covers the ring persistence failures
// for the legacy-migration and first-use paths.
func TestIDCovOIDCKeyRingWriteFailures(t *testing.T) {
	// Legacy migration cannot persist the migrated ring.
	legacyDir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(legacyDir, oidcLegacyKeyFile), []byte(base64RawStd(priv)))
	restore := chmodReadOnly(t, legacyDir)
	if _, err := loadOIDCSigner(legacyDir); err == nil {
		restore()
		t.Fatal("read-only legacy migration = nil error")
	}
	restore()

	// First use cannot persist the fresh ring.
	fresh := t.TempDir()
	restore = chmodReadOnly(t, fresh)
	defer restore()
	if _, err := loadOIDCSigner(fresh); err == nil {
		t.Fatal("read-only first use = nil error")
	}
}

// TestIDCovLabelsForTart covers the tart runtime label expansion.
func TestIDCovLabelsForTart(t *testing.T) {
	labels := labelsForJob(pipeline.Job{Runtime: "tart"})
	if !containsLabel(labels, "tart") || !containsLabel(labels, "os:darwin") {
		t.Fatalf("tart labels = %v", labels)
	}
	labels = labelsForJob(pipeline.Job{Runtime: "", Runner: []string{"custom"}})
	if !containsLabel(labels, "native") || !containsLabel(labels, "custom") {
		t.Fatalf("default labels = %v", labels)
	}
}

// TestIDCovGetRunAndListJobsDBBranches covers the DB read failures of the
// run/jobs endpoints.
func TestIDCovGetRunAndListJobsDBBranches(t *testing.T) {
	f := newDBFakeStore()
	s := New("admin")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	// Memory-mode fallthrough is not reachable with DB set; unknown run is
	// a 404 from the store.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/ghost", "admin", ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown run = %d, want 404", w.Code)
	}
	fault := &idcovFaultStore{dbFakeStore: f, getRunErr: errors.New("run down")}
	s.DB = fault
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/r1", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("failing getRun = %d, want 500", w.Code)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/r1/jobs", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("failing listJobs = %d, want 500", w.Code)
	}
	fault.getRunErr = nil
	f.mu.Lock()
	f.runs["r1"] = model.Run{ID: "r1", RepoID: "github.com/kiwi/repo", RepoFullName: "kiwi/repo", Status: model.StatusRunning}
	f.mu.Unlock()
	// A repo-only read principal restricted to another repository is refused
	// on both endpoints.
	scoped := storeServer(t, "", map[string]auth.Principal{
		"read-token": {Subject: "reader", Repositories: map[string]auth.RepositoryPermission{"github.com/other/repo": {Read: true}}},
	})
	if err := scoped.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, scoped.Handler(), "read-token")
	if w := c.do(http.MethodGet, "/api/v1/runs/r1", nil, nil); w.Code != http.StatusForbidden {
		t.Fatalf("scoped-out getRun = %d, want 403", w.Code)
	}
	if w := c.do(http.MethodGet, "/api/v1/runs/r1/jobs", nil, nil); w.Code != http.StatusForbidden {
		t.Fatalf("scoped-out listJobs = %d, want 403", w.Code)
	}
}

// TestIDCovGetRunMemoryNotFoundAndEqualPrioritySort covers the memory miss
// and the same-priority job ordering.
func TestIDCovGetRunMemoryNotFoundAndEqualPrioritySort(t *testing.T) {
	s := New("admin")
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/ghost", "admin", ""); w.Code != http.StatusNotFound {
		t.Fatalf("memory unknown run = %d, want 404", w.Code)
	}
	base := time.Now().UTC()
	idcovSeedQueuedJob(t, s, "job-older", "run-eq", func(j *model.Job) { j.Priority = 3; j.CreatedAt = base })
	idcovSeedQueuedJob(t, s, "job-newer", "run-eq", func(j *model.Job) { j.Priority = 3; j.CreatedAt = base.Add(time.Second) })
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-eq/jobs", "admin", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "job-older") {
		t.Fatalf("equal-priority jobs = %d: %s", w.Code, w.Body.String())
	}
	var out []map[string]any
	if err := jsonUnmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0]["id"] != "job-older" {
		t.Fatalf("FIFO order wrong: %v", out)
	}
}

// TestIDCovGetLogsStoreFailure covers the persistent-store read failure.
func TestIDCovGetLogsStoreFailure(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("admin", "admin", dir)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.runs["run-x"] = model.Run{ID: "run-x", Status: model.StatusRunning}
	s.mu.Unlock()
	blocker := filepath.Join(dir, "blocker")
	writeTestFile(t, blocker, []byte("x"))
	s.store.Root = blocker
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-x/logs", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("broken log store = %d, want 500", w.Code)
	}
}

// TestIDCovRegisterIdentityAndPreservation covers the registration identity
// derivation and preserved admin/state fields.
func TestIDCovRegisterIdentityAndPreservation(t *testing.T) {
	// Bearer-derived ID and defaulted name (memory mode).
	s := New("shared")
	s.LoadRunnerTokens(map[string]string{"runner-bearer": auth.TokenDigest("tok-b")})
	body := map[string]any{"capacity": 1, "protocol_min": 3, "protocol_max": 3}
	w := pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/register", body, "tok-b", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("bearer register = %d: %s", w.Code, w.Body.String())
	}
	var got model.Runner
	decodeJSONBody(t, w, &got)
	if got.ID != "runner-bearer" || got.Name != "runner-bearer" {
		t.Fatalf("registered runner = %+v", got)
	}

	// Re-registration preserves admin state, counters and the legacy
	// current job.
	s.mu.Lock()
	old := s.runners["runner-bearer"]
	old.Disabled = true
	old.Completed = 7
	old.Failed = 2
	old.CurrentJob = "job-legacy"
	s.runners["runner-bearer"] = old
	s.mu.Unlock()
	w = pkiRequest(t, s.Handler(), http.MethodPost, "/api/v1/runners/register", body, "tok-b", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("re-register = %d: %s", w.Code, w.Body.String())
	}
	decodeJSONBody(t, w, &got)
	if !got.Disabled || got.Completed != 7 || got.Failed != 2 {
		t.Fatalf("admin state not preserved: %+v", got)
	}
	if len(got.ActiveJobs) != 1 || got.ActiveJobs[0] != "job-legacy" || got.CurrentJob != "job-legacy" {
		t.Fatalf("legacy current job not migrated: %+v", got)
	}
}

// TestIDCovRegisterDBBranches covers the DB-mode registration branches.
func TestIDCovRegisterDBBranches(t *testing.T) {
	f := newDBFakeStore()
	s := New("admin")
	fault := &idcovFaultStore{dbFakeStore: f}
	if err := s.SwitchToDB(fault); err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	body := `{"id":"db-r1","name":"r1","capacity":1,"protocol_min":3,"protocol_max":3}`
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "admin", body); w.Code != http.StatusOK {
		t.Fatalf("db register = %d: %s", w.Code, w.Body.String())
	}
	// A second registration must preserve the persisted state.
	f.mu.Lock()
	stored := f.runners["db-r1"]
	stored.Completed = 5
	stored.Failed = 1
	stored.Disabled = true
	stored.CurrentJob = "job-persisted"
	f.runners["db-r1"] = stored
	f.mu.Unlock()
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "admin", body)
	if w.Code != http.StatusOK {
		t.Fatalf("db re-register = %d: %s", w.Code, w.Body.String())
	}
	var got model.Runner
	decodeJSONBody(t, w, &got)
	if !got.Disabled || got.Completed != 5 || got.Failed != 1 {
		t.Fatalf("db admin state not preserved: %+v", got)
	}
	if len(got.ActiveJobs) != 1 || got.ActiveJobs[0] != "job-persisted" || got.CurrentJob != "job-persisted" {
		t.Fatalf("db legacy current job not migrated: %+v", got)
	}
	// Store read and write failures surface as 500.
	fault.getRunnerErr = errors.New("runner read failed")
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "admin", body); w.Code != http.StatusInternalServerError {
		t.Fatalf("db register read failure = %d, want 500", w.Code)
	}
	fault.getRunnerErr = nil
	fault.upsertRunErr = errors.New("runner write failed")
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "admin", body); w.Code != http.StatusInternalServerError {
		t.Fatalf("db register write failure = %d, want 500", w.Code)
	}
	fault.upsertRunErr = nil
	_ = h

	// Profile resolution failures are logged but do not fail registration.
	faultProfile := &idcovProfileErrStore{dbFakeStore: f}
	s2 := New("admin")
	if err := s2.SwitchToDB(faultProfile); err != nil {
		t.Fatal(err)
	}
	profBody := `{"id":"db-r2","name":"r2","capacity":1,"protocol_min":3,"protocol_max":3,"cert_serial":"ser-1"}`
	if w := doJSON(t, s2, http.MethodPost, "/api/v1/runners/register", "admin", profBody); w.Code != http.StatusOK {
		t.Fatalf("register with failing profile lookup = %d: %s", w.Code, w.Body.String())
	}
	// listRunners store failure.
	fault.listRunnerErr = errors.New("runners down")
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runners", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("failing listRunners = %d, want 500", w.Code)
	}
}

// TestIDCovRunnerAdminForbiddenAndMemory covers the role gate and the memory
// disable/enable transitions.
func TestIDCovRunnerAdminForbiddenAndMemory(t *testing.T) {
	restricted := storeServer(t, "", map[string]auth.Principal{
		"read-token": {Subject: "reader", Roles: []auth.Role{auth.RoleRead}},
	})
	c := newTestClient(t, restricted.Handler(), "read-token")
	for _, path := range []string{"/api/v1/runners/r1/drain", "/api/v1/runners/r1/disable", "/api/v1/runners/r1/enable"} {
		if w := c.do(http.MethodPost, path, map[string]any{}, nil); w.Code != http.StatusForbidden {
			t.Fatalf("%s without runner_manage = %d, want 403", path, w.Code)
		}
	}
	noRole := storeServer(t, "", map[string]auth.Principal{"none-token": {Subject: "none"}})
	if w := newTestClient(t, noRole.Handler(), "none-token").do(http.MethodGet, "/api/v1/runners/serving", nil, nil); w.Code != http.StatusForbidden {
		t.Fatalf("serving without any role = %d, want 403", w.Code)
	}

	s := New("admin")
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/ghost/enable", "admin", ""); w.Code != http.StatusNotFound {
		t.Fatalf("memory enable unknown = %d, want 404", w.Code)
	}
	// Disable cancels the runner's running jobs and revokes nothing without
	// a serial.
	idcovSeedMemoryJob(t, s, "job-kill", "run-kill", "r-kill", "tok", nil)
	s.mu.Lock()
	s.runners["r-kill"] = model.Runner{ID: "r-kill", Name: "rk", Capacity: 1, ActiveJobs: []string{"job-kill"}}
	s.mu.Unlock()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r-kill/disable", "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("memory disable = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	killed := s.jobs["job-kill"]
	ri := s.runners["r-kill"]
	s.mu.Unlock()
	if killed.Status != model.StatusCancelled || len(ri.ActiveJobs) != 0 || ri.Busy {
		t.Fatalf("kill switch state: job=%+v runner=%+v", killed, ri)
	}
}

// TestIDCovRunnerDisableDBErrors covers the store-failure branches of the
// DB kill switch.
func TestIDCovRunnerDisableDBErrors(t *testing.T) {
	f := newDBFakeStore()
	fault := &idcovFaultStore{dbFakeStore: f}
	s := New("admin")
	if err := s.SwitchToDB(fault); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/ghost/disable", "admin", ""); w.Code != http.StatusNotFound {
		t.Fatalf("disable unknown = %d, want 404", w.Code)
	}
	fault.getRunnerErr = errors.New("runner read failed")
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r1/disable", "admin", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("disable read failure = %d, want 500", w.Code)
	}
	fault.getRunnerErr = nil
	f.mu.Lock()
	f.runners["r1"] = model.Runner{ID: "r1", Name: "r1", Capacity: 1, CertSerial: "serial-r1"}
	f.mu.Unlock()
	// ADAPTATION (S6-B): the handler no longer composes UpsertRunner +
	// RevokeRunnerLeases + best-effort RevokeCert; the whole disable is the
	// atomic RunnerDisableStore transaction, so a failing transaction fails
	// the request closed with an opaque 503 and NO partial state. The old
	// upsert/revoke injections are therefore replaced by the atomic seam.
	fault.disableAtomicErr = errors.New("atomic disable failed")
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r1/disable", "admin", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("disable atomic failure = %d, want 503", w.Code)
	}
	if strings.Contains(w.Body.String(), "atomic disable failed") {
		t.Fatalf("disable failure leaked the raw store error: %q", w.Body.String())
	}
	f.mu.Lock()
	unchanged := f.runners["r1"]
	revoked := f.revocations["serial-r1"]
	f.mu.Unlock()
	if unchanged.Disabled || revoked != "" {
		t.Fatalf("failed disable left partial state: runner=%+v revocation=%q", unchanged, revoked)
	}
	fault.disableAtomicErr = nil
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/r1/disable", "admin", ""); w.Code != http.StatusOK {
		t.Fatalf("healed disable = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	healed := f.runners["r1"]
	revoked = f.revocations["serial-r1"]
	f.mu.Unlock()
	if !healed.Disabled || revoked != "r1" {
		t.Fatalf("healed disable = disabled %v revocation %q, want true/r1", healed.Disabled, revoked)
	}
}

// TestIDCovServingRunnersAliasAndMissingRun covers the bare-alias visibility
// and the stale active-job skip.
func TestIDCovServingRunnersAliasAndMissingRun(t *testing.T) {
	s := New("admin")
	s.mu.Lock()
	s.runners["r-serv"] = model.Runner{ID: "r-serv", Name: "rs", Capacity: 1, ActiveJobs: []string{"job-missing-run", "job-alias"}}
	s.jobs["job-missing-run"] = model.Job{ID: "job-missing-run", RunID: "run-gone", Key: "build", Status: model.StatusRunning}
	s.jobs["job-alias"] = model.Job{ID: "job-alias", RunID: "run-alias", Key: "build", Status: model.StatusRunning}
	s.runs["run-alias"] = model.Run{ID: "run-alias", RepoID: "github.com/acme/service", RepoFullName: "acme/service", Status: model.StatusRunning}
	s.mu.Unlock()

	principal := auth.Principal{Subject: "u", Roles: []auth.Role{auth.RoleRead}, Repositories: map[string]auth.RepositoryPermission{"acme/service": {Read: true}}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/runners/serving", nil)
	req = req.WithContext(auth.WithPrincipal(context.Background(), principal))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("serving = %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "job-alias") {
		t.Fatalf("bare-alias job missing from serving: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "job-missing-run") {
		t.Fatalf("stale active job leaked into serving: %s", w.Body.String())
	}
}

// TestIDCovServingRunnersEmptyDBList covers the nil-DTO normalization.
func TestIDCovServingRunnersEmptyDBList(t *testing.T) {
	f := newDBFakeStore()
	s := New("admin")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodGet, "/api/v1/runners/serving", "admin", "")
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("empty serving list = %d: %q", w.Code, w.Body.String())
	}
}

// TestIDCovApproveForbidden covers the role gate on approval.
func TestIDCovApproveForbidden(t *testing.T) {
	restricted := storeServer(t, "", map[string]auth.Principal{
		"read-token": {Subject: "reader", Roles: []auth.Role{auth.RoleRead}},
	})
	restricted.mu.Lock()
	restricted.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-a", Key: "deploy", Status: model.StatusWaitingApproval, ApprovalRequired: true}
	restricted.runs["run-a"] = model.Run{ID: "run-a", Status: model.StatusRunning}
	restricted.mu.Unlock()
	c := newTestClient(t, restricted.Handler(), "read-token")
	if w := c.do(http.MethodPost, "/api/v1/jobs/job-a/approve", map[string]any{}, nil); w.Code != http.StatusForbidden {
		t.Fatalf("approve without approve role = %d, want 403", w.Code)
	}
}

// TestIDCovMaintainLifecycle covers Maintain's context exit and the DB
// leader/standby transitions.
func TestIDCovMaintainLifecycle(t *testing.T) {
	// A cancelled context returns immediately.
	s := New("t")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.Maintain(ctx)

	// Standby, promotion, demotion and the leader tick.
	f := newDBFakeStore()
	sd := New("t")
	if err := sd.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	f.setLeader(false)
	sd.mu.Lock()
	sd.leader = false
	sd.mu.Unlock()
	sd.maintainDB(context.Background(), now) // stays standby

	f.setLeader(true)
	sd.mu.Lock()
	sd.leader = false
	sd.mu.Unlock()
	sd.maintainDB(context.Background(), now) // promoted
	sd.mu.Lock()
	leader := sd.leader
	sd.mu.Unlock()
	if !leader {
		t.Fatal("promotion did not set the leader flag")
	}
	sd.maintainDB(context.Background(), now) // leader tick

	f.setLeader(false)
	sd.maintainDB(context.Background(), now) // demoted
	sd.mu.Lock()
	leader = sd.leader
	sd.mu.Unlock()
	if leader {
		t.Fatal("demotion did not clear the leader flag")
	}
}

// TestIDCovReceiptEviction covers the bounded completion receipt cache: with
// the table full, the receipt carrying the oldest recorded timestamp is
// evicted and every newer receipt survives. Each seeded receipt carries a
// distinct, strictly increasing timestamp so the assertion does not depend on
// map iteration order.
func TestIDCovReceiptEviction(t *testing.T) {
	s := New("t")
	base := time.Now().UTC().Add(-time.Hour)
	s.mu.Lock()
	keys := make([]string, 0, maxCompletionReceipts)
	for i := 0; i < maxCompletionReceipts; i++ {
		id := "job-" + strconv.Itoa(i)
		key := completionReceiptKey(id, 1, "r")
		keys = append(keys, key)
		s.completions[key] = model.CompletionReceipt{JobID: id, Generation: 1, RunnerID: "r", ResultHash: "hash"}
		s.completionReceiptAt[key] = base.Add(time.Duration(i) * time.Second)
	}
	s.recordCompletionReceiptLocked("new-job", 1, "r", "hash")
	n := len(s.completions)
	_, hasNew := s.completions[completionReceiptKey("new-job", 1, "r")]
	_, hasOldest := s.completions[keys[0]]
	_, hasSecondOldest := s.completions[keys[1]]
	_, hasNewest := s.completions[keys[len(keys)-1]]
	s.mu.Unlock()
	if !hasNew || n != maxCompletionReceipts {
		t.Fatalf("eviction: n=%d has=%v", n, hasNew)
	}
	if hasOldest {
		t.Fatalf("timestamp-oldest receipt %q survived eviction", keys[0])
	}
	if !hasSecondOldest || !hasNewest {
		t.Fatalf("eviction removed newer receipts: second-oldest=%v newest=%v", hasSecondOldest, hasNewest)
	}
}
