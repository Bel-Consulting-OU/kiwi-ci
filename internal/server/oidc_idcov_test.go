package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// oidcFaultStore lets a dbFakeStore fail GetJob/GetRun on demand.
type oidcFaultStore struct {
	*dbFakeStore
	getJobErr error
	getRunErr error
}

func (f *oidcFaultStore) GetJob(ctx context.Context, id string) (model.Job, error) {
	if f.getJobErr != nil {
		return model.Job{}, f.getJobErr
	}
	return f.dbFakeStore.GetJob(ctx, id)
}

func (f *oidcFaultStore) GetRun(ctx context.Context, id string) (model.Run, error) {
	if f.getRunErr != nil {
		return model.Run{}, f.getRunErr
	}
	return f.dbFakeStore.GetRun(ctx, id)
}

// TestIDCovParseOIDCTime pins the empty/valid/invalid cases.
func TestIDCovParseOIDCTime(t *testing.T) {
	if got, err := parseOIDCTime(""); err != nil || !got.IsZero() {
		t.Fatalf("parseOIDCTime(\"\") = %v, %v", got, err)
	}
	want := time.Date(2024, 5, 4, 3, 2, 1, 42, time.UTC)
	got, err := parseOIDCTime(want.Format(time.RFC3339Nano))
	if err != nil || !got.Equal(want) {
		t.Fatalf("parseOIDCTime(valid) = %v, %v", got, err)
	}
	if _, err := parseOIDCTime("yesterday"); err == nil {
		t.Fatal("parseOIDCTime(invalid) = nil error")
	}
}

// ringJSON renders an OIDC key ring body for the parser table.
func ringJSON(active map[string]string, previous ...map[string]string) []byte {
	var b strings.Builder
	b.WriteString(`{"active":{`)
	first := true
	for k, v := range active {
		if !first {
			b.WriteString(",")
		}
		first = false
		b.WriteString(`"` + k + `":"` + v + `"`)
	}
	b.WriteString(`},"previous":[`)
	for i, p := range previous {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("{")
		pf := true
		for k, v := range p {
			if !pf {
				b.WriteString(",")
			}
			pf = false
			b.WriteString(`"` + k + `":"` + v + `"`)
		}
		b.WriteString("}")
	}
	b.WriteString("]}")
	return []byte(b.String())
}

// TestIDCovOIDCSignerFromRingErrors walks every malformed ring shape.
func TestIDCovOIDCSignerFromRingErrors(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawStdEncoding.EncodeToString
	valid := map[string]string{
		"kid":        "kid-1",
		"pub":        enc(pub),
		"priv":       enc(priv),
		"not_before": time.Now().UTC().Format(time.RFC3339Nano),
	}
	cases := []struct {
		name string
		body []byte
		want string
	}{
		{"invalid json", []byte("{"), "invalid OIDC key ring"},
		{"priv base64", ringJSON(map[string]string{"priv": "!!!"}), "invalid OIDC active private key"},
		{"priv size", ringJSON(map[string]string{"priv": enc([]byte("short"))}), "invalid OIDC signing key size"},
		{"pub base64", ringJSON(map[string]string{"priv": enc(priv), "pub": "!!!"}), "invalid OIDC active public key"},
		{"pub mismatch", ringJSON(map[string]string{"priv": enc(priv), "pub": enc(ed25519.PublicKey(otherPriv.Public().(ed25519.PublicKey)))}), "does not match private key"},
		{"not_before", ringJSON(map[string]string{"priv": enc(priv), "not_before": "nope"}), "invalid OIDC active not_before"},
		{"previous pub base64", ringJSON(map[string]string{"priv": enc(priv)}, map[string]string{"pub": "!!!"}), "invalid OIDC previous public key"},
		{"previous pub size", ringJSON(map[string]string{"priv": enc(priv)}, map[string]string{"pub": enc([]byte("nope"))}), "invalid OIDC previous public key size"},
		{"previous not_before", ringJSON(map[string]string{"priv": enc(priv)}, map[string]string{"pub": enc(pub), "not_before": "nope"}), "invalid OIDC previous not_before"},
		{"previous retire_after", ringJSON(map[string]string{"priv": enc(priv)}, map[string]string{"pub": enc(pub), "retire_after": "nope"}), "invalid OIDC previous retire_after"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := oidcSignerFromRing(tc.body)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("oidcSignerFromRing = %v, want %q", err, tc.want)
			}
		})
	}

	// A ring with no kid and no not_before derives the key id and leaves the
	// zero time: parseOIDCTime("") and signerFromKeys are both exercised.
	s, err := oidcSignerFromRing(ringJSON(map[string]string{"priv": enc(priv)}))
	if err != nil {
		t.Fatal(err)
	}
	if s.KID != signerFromKeys(pub, priv).KID {
		t.Fatalf("derived kid = %q", s.KID)
	}
	if !s.NotBefore.IsZero() {
		t.Fatalf("missing not_before = %v, want zero", s.NotBefore)
	}
	// A previous entry with empty timestamps parses to zero times.
	s2, err := oidcSignerFromRing(ringJSON(map[string]string{"priv": enc(priv)}, map[string]string{"kid": "old", "pub": enc(pub)}))
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.Previous) != 1 || !s2.Previous[0].RetireAfter.IsZero() || !s2.Previous[0].NotBefore.IsZero() {
		t.Fatalf("previous zero times = %+v", s2.Previous)
	}
	// The fully-specified round trip keeps every field.
	s3, err := oidcSignerFromRing(ringJSON(valid, map[string]string{"kid": "old", "pub": enc(pub), "not_before": valid["not_before"], "retire_after": valid["not_before"]}))
	if err != nil || s3.KID != "kid-1" || len(s3.Previous) != 1 || s3.Previous[0].KID != "old" {
		t.Fatalf("valid ring = %+v, %v", s3, err)
	}
}

// TestIDCovPersistOIDCKeyRing covers the no-op, cluster-error, cluster and
// file-mode persistence branches of persistOIDCKeyRing.
func TestIDCovPersistOIDCKeyRing(t *testing.T) {
	// No ring path and no cluster: a no-op.
	if err := persistOIDCKeyRing(&oidcSigner{}); err != nil {
		t.Fatalf("persistOIDCKeyRing(no sink) = %v", err)
	}
	// Cluster store without ClusterKeyWriter support refuses.
	noWriter := &oidcSigner{cluster: failingClusterStore{}}
	if err := persistOIDCKeyRing(noWriter); err == nil {
		t.Fatal("persist without a writer-capable store = nil error")
	}
	// Cluster store with writer support records the ring digest.
	shared := &StaticClusterKeyStore{Keys: map[string][]byte{}}
	clusterSigner := &oidcSigner{cluster: shared}
	clusterSigner.Public, clusterSigner.Private, _ = ed25519.GenerateKey(nil)
	clusterSigner.KID = "cluster-kid"
	if err := persistOIDCKeyRing(clusterSigner); err != nil {
		t.Fatal(err)
	}
	stored, ok, err := shared.Lookup(clusterKindOIDC)
	if err != nil || !ok || !strings.Contains(string(stored), "cluster-kid") {
		t.Fatalf("cluster ring not stored: ok=%v err=%v", ok, err)
	}
	sum := sha256.Sum256(stored)
	if clusterSigner.ringDigest != hex.EncodeToString(sum[:]) {
		t.Fatal("cluster ring digest not recorded")
	}

	// File mode: the ring is written and stat metadata recorded.
	dir := t.TempDir()
	path := filepath.Join(dir, oidcKeyRingFile)
	fileSigner := &oidcSigner{ringPath: path}
	fileSigner.Public, fileSigner.Private, _ = ed25519.GenerateKey(nil)
	fileSigner.KID = "file-kid"
	fileSigner.Previous = []oidcPreviousKey{{KID: "prev", Public: fileSigner.Public, NotBefore: time.Now().UTC(), RetireAfter: time.Now().Add(time.Hour).UTC()}}
	if err := persistOIDCKeyRing(fileSigner); err != nil {
		t.Fatal(err)
	}
	if fileSigner.ringSize == 0 || fileSigner.ringMod.IsZero() {
		t.Fatal("file ring stat metadata not recorded")
	}
	reloaded, err := oidcSignerFromRing(mustReadFile(t, path))
	if err != nil || reloaded.KID != "file-kid" || len(reloaded.Previous) != 1 {
		t.Fatalf("persisted file ring = %+v, %v", reloaded, err)
	}
	// A write failure propagates.
	bad := &oidcSigner{ringPath: filepath.Join(dir, "missing", oidcKeyRingFile), KID: "x"}
	bad.Public, bad.Private, _ = ed25519.GenerateKey(nil)
	if err := persistOIDCKeyRing(bad); err == nil {
		t.Fatal("persist into a missing directory = nil error")
	}
	// A directory at the ring path makes the rename step fail.
	dirAtPath := t.TempDir()
	dirSigner := &oidcSigner{ringPath: dirAtPath, KID: "y"}
	dirSigner.Public, dirSigner.Private, _ = ed25519.GenerateKey(nil)
	if err := persistOIDCKeyRing(dirSigner); err == nil {
		t.Fatal("persist over a directory = nil error")
	}
}

// TestIDCovLoadOIDCSignerPaths covers ring load, corrupt ring, legacy
// migration, corrupt legacy material and first-use generation.
func TestIDCovLoadOIDCSignerPaths(t *testing.T) {
	// First use generates and persists a ring.
	dir := t.TempDir()
	s, err := loadOIDCSigner(dir)
	if err != nil || s.KID == "" || s.ringPath == "" {
		t.Fatalf("loadOIDCSigner(fresh) = %+v, %v", s, err)
	}
	if _, err := os.Stat(filepath.Join(dir, oidcKeyRingFile)); err != nil {
		t.Fatalf("generated ring not persisted: %v", err)
	}
	// Reload keeps the kid.
	s2, err := loadOIDCSigner(dir)
	if err != nil || s2.KID != s.KID {
		t.Fatalf("reload = %v (kid %q vs %q)", err, s2.KID, s.KID)
	}
	// A corrupt ring is a hard error.
	badRing := t.TempDir()
	writeTestFile(t, filepath.Join(badRing, oidcKeyRingFile), []byte("{"))
	if _, err := loadOIDCSigner(badRing); err == nil {
		t.Fatal("corrupt ring = nil error")
	}
	// A directory at the ring path is a read error.
	dirRing := t.TempDir()
	if err := os.Mkdir(filepath.Join(dirRing, oidcKeyRingFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOIDCSigner(dirRing); err == nil {
		t.Fatal("ring path directory = nil error")
	}
	// A valid legacy key file migrates into the ring format.
	legacyDir := t.TempDir()
	_, legacyPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(legacyDir, oidcLegacyKeyFile), []byte(base64RawStd(legacyPriv)))
	migrated, err := loadOIDCSigner(legacyDir)
	if err != nil || migrated.KID != signerFromKeys(legacyPriv.Public().(ed25519.PublicKey), legacyPriv).KID {
		t.Fatalf("legacy migration = %+v, %v", migrated, err)
	}
	if _, err := os.Stat(filepath.Join(legacyDir, oidcKeyRingFile)); err != nil {
		t.Fatalf("migrated ring not persisted: %v", err)
	}
	// Corrupt legacy material is refused.
	legacyBad := t.TempDir()
	writeTestFile(t, filepath.Join(legacyBad, oidcLegacyKeyFile), []byte("!!!"))
	if _, err := loadOIDCSigner(legacyBad); err == nil {
		t.Fatal("corrupt legacy key = nil error")
	}
	legacyShort := t.TempDir()
	writeTestFile(t, filepath.Join(legacyShort, oidcLegacyKeyFile), []byte("abcd"))
	if _, err := loadOIDCSigner(legacyShort); err == nil || !strings.Contains(err.Error(), "invalid OIDC signing key size") {
		t.Fatalf("short legacy key error = %v", err)
	}
	// A directory at the legacy path is a read error (not "missing").
	legacyDirPath := t.TempDir()
	if err := os.Mkdir(filepath.Join(legacyDirPath, oidcLegacyKeyFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOIDCSigner(legacyDirPath); err == nil {
		t.Fatal("legacy path directory = nil error")
	}
}

// TestIDCovRefreshOIDCRing covers both refresh modes and every early-return
// branch. The refresh takes s.mu internally, so the fixtures are installed
// under a short lock and the refresh is then called without one.
func TestIDCovRefreshOIDCRing(t *testing.T) {
	setSigner := func(s *Server, signer *oidcSigner) {
		s.mu.Lock()
		s.oidc = signer
		s.mu.Unlock()
	}
	kid := func(s *Server) string {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.oidc == nil {
			return "<nil>"
		}
		return s.oidc.KID
	}

	// Nil signer: no-op.
	s := New("t")
	setSigner(s, nil)
	if got := s.refreshOIDCRing(context.Background()); got != nil {
		t.Fatalf("nil signer refresh = %+v", got)
	}

	// Cluster store without Lookup support: no-op.
	s2 := New("t")
	setSigner(s2, &oidcSigner{cluster: fixedClusterStore{b: []byte("x")}})
	s2.refreshOIDCRing(context.Background())
	if got := kid(s2); got != "" {
		t.Fatalf("lookup-less store swapped the signer: %q", got)
	}

	// Lookup error and not-found are tolerated.
	s3 := New("t")
	setSigner(s3, &oidcSigner{cluster: lookupErrorStore{failingClusterStore{err: errors.New("down")}}})
	s3.refreshOIDCRing(context.Background())
	setSigner(s3, &oidcSigner{cluster: fixedLookupStore{found: false}})
	s3.refreshOIDCRing(context.Background())
	if got := kid(s3); got != "" {
		t.Fatalf("failed lookup swapped the signer: %q", got)
	}

	// Unchanged digest is a no-op; changed valid bytes swap the signer;
	// changed invalid bytes keep the current signer.
	pubA, privA, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ringA := ringJSON(map[string]string{"kid": "a", "pub": base64RawStd(pubA), "priv": base64RawStd(privA), "not_before": time.Now().UTC().Format(time.RFC3339Nano)})
	store := &StaticClusterKeyStore{Keys: map[string][]byte{clusterKindOIDC: ringA}}
	sumA := sha256.Sum256(ringA)
	s4 := New("t")
	setSigner(s4, &oidcSigner{cluster: store, ringDigest: hex.EncodeToString(sumA[:])})
	s4.refreshOIDCRing(context.Background())
	if got := kid(s4); got != "" {
		t.Fatal("unchanged digest swapped the signer")
	}
	s4.mu.Lock()
	s4.oidc.ringDigest = "different"
	s4.mu.Unlock()
	s4.refreshOIDCRing(context.Background())
	if got := kid(s4); got != "a" {
		t.Fatalf("changed ring not loaded: kid %q", got)
	}
	s4.mu.Lock()
	s4.oidc.ringDigest = "different-again"
	s4.mu.Unlock()
	if err := store.Store(clusterKindOIDC, []byte("{")); err != nil {
		t.Fatal(err)
	}
	s4.refreshOIDCRing(context.Background())
	if got := kid(s4); got != "a" {
		t.Fatal("invalid changed ring replaced the signer")
	}

	// A canceled context gives up on the stalled key-store read and keeps the
	// signer.
	stalled := newCountingOIDCClusterStore()
	stalled.mu.Lock()
	stalled.block = true
	stalled.mu.Unlock()
	s4b := New("t")
	setSigner(s4b, &oidcSigner{cluster: stalled, ringDigest: "stale"})
	deadlineCtx, cancelDeadline := context.WithCancel(context.Background())
	cancelDeadline()
	if got := s4b.refreshOIDCRing(deadlineCtx); got == nil || got.KID != "" {
		t.Fatalf("canceled refresh = %+v, want the current signer", got)
	}
	close(stalled.release)

	// File mode: no path, stat failure, unchanged, changed-invalid. The
	// fixture signer carries no KID so an accidental swap is visible.
	s5 := New("t")
	setSigner(s5, &oidcSigner{})
	s5.refreshOIDCRing(context.Background()) // ringPath == ""
	s5.mu.Lock()
	s5.oidc.ringPath = filepath.Join(t.TempDir(), "missing.json")
	s5.mu.Unlock()
	s5.refreshOIDCRing(context.Background()) // stat failure
	if got := kid(s5); got != "" {
		t.Fatalf("missing file swapped the signer: %q", got)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, oidcKeyRingFile)
	s6 := New("t")
	signer6 := newOIDCSigner()
	signer6.Public, signer6.Private, _ = ed25519.GenerateKey(nil)
	signer6.KID = "file-a"
	signer6.ringPath = path
	if err := persistOIDCKeyRing(signer6); err != nil {
		t.Fatal(err)
	}
	setSigner(s6, signer6)
	s6.refreshOIDCRing(context.Background()) // unchanged mtime/size
	if got := kid(s6); got != "file-a" {
		t.Fatal("unchanged file ring reloaded")
	}
	writeTestFile(t, path, []byte("{"))
	os.Chtimes(path, time.Now(), time.Now())
	s6.mu.Lock()
	s6.oidc.ringMod = time.Time{}
	s6.mu.Unlock()
	s6.refreshOIDCRing(context.Background()) // parse failure keeps the signer
	if got := kid(s6); got != "file-a" {
		t.Fatal("invalid file ring replaced the signer")
	}
	// A directory at the ring path makes the post-stat read fail.
	s6.mu.Lock()
	s6.oidc.ringPath = dir
	s6.oidc.ringMod = time.Time{}
	s6.oidc.ringSize = 0
	s6.mu.Unlock()
	s6.refreshOIDCRing(context.Background())
	if got := kid(s6); got != "file-a" {
		t.Fatal("unreadable ring replaced the signer")
	}
}

// TestIDCovOIDCJWKSUnavailable pins the 503 when no signer is installed.
func TestIDCovOIDCJWKSUnavailable(t *testing.T) {
	s := New("t")
	s.mu.Lock()
	s.oidc = nil
	s.mu.Unlock()
	w := doJSON(t, s, http.MethodGet, "/api/v1/oidc/jwks", "", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("jwks without signer = %d, want 503", w.Code)
	}
}

// TestIDCovIssueOIDCEdgeCases covers the request-shape and store-failure
// branches of issueOIDC.
func TestIDCovIssueOIDCEdgeCases(t *testing.T) {
	// Missing issuer.
	s := New("secret")
	_, jobID := seedOIDCJob(t, s, "lease1")
	w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/oidc", "lease1", `{"audience":"a"}`)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("issuance without external URL = %d, want 503", w.Code)
	}

	// Malformed JSON body.
	s.ExternalURL = "https://ci.example.com"
	w = doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+jobID+"/oidc", "lease1", `{`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed body = %d, want 400", w.Code)
	}

	// DB mode: store read failures and a job whose run is missing.
	base := newDBFakeStore()
	fault := &oidcFaultStore{dbFakeStore: base, getJobErr: errors.New("job read failed")}
	s2 := New("secret")
	if err := s2.SwitchToDB(fault); err != nil {
		t.Fatal(err)
	}
	s2.ExternalURL = "https://ci.example.com"
	w = doJSON(t, s2, http.MethodPost, "/api/v1/jobs/job-x/oidc", "lease1", `{"audience":"a"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("GetJob failure = %d, want 500", w.Code)
	}
	fault.getJobErr = nil
	exp0 := time.Now().Add(time.Minute)
	base.mu.Lock()
	base.runs["run-x"] = model.Run{ID: "run-x", RepoFullName: "kiwi/repo", Ref: "main", Status: model.StatusRunning}
	base.jobs["job-x"] = model.Job{ID: "job-x", RunID: "run-x", Key: "build", Status: model.StatusRunning, Trusted: true, OIDCAllowed: true, LeaseExpiresAt: &exp0, LeaseTokenHash: hashLeaseToken(s2.leaseKey, "lease1")}
	base.mu.Unlock()
	fault.getRunErr = errors.New("run read failed")
	w = doJSON(t, s2, http.MethodPost, "/api/v1/jobs/job-x/oidc", "lease1", `{"audience":"a"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("GetRun failure = %d, want 500", w.Code)
	}
	// A job row whose run row is absent is a 404.
	fault.getRunErr = nil
	exp := time.Now().Add(time.Minute)
	base.mu.Lock()
	base.jobs["job-orphan"] = model.Job{ID: "job-orphan", RunID: "run-missing", Key: "build", Status: model.StatusRunning, Trusted: true, OIDCAllowed: true, LeaseExpiresAt: &exp, LeaseTokenHash: hashLeaseToken(s2.leaseKey, "lease1")}
	base.mu.Unlock()
	w = doJSON(t, s2, http.MethodPost, "/api/v1/jobs/job-orphan/oidc", "lease1", `{"audience":"a"}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("orphan job = %d, want 404", w.Code)
	}
}

// TestIDCovAuditOIDCIssuancePaths covers the no-sink success and the
// store-failure branch.
func TestIDCovAuditOIDCIssuancePaths(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job/oidc", nil)
	s := New("t")
	if err := s.auditOIDCIssuance(req, "actor", "run", "job", "kid", "key", "aud"); err != nil {
		t.Fatalf("no-sink audit = %v, want nil", err)
	}
	f := newDBFakeStore()
	f.auditErr = errors.New("audit down")
	s2 := New("t")
	if err := s2.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if err := s2.auditOIDCIssuance(req, "actor", "run", "job", "kid", "key", "aud"); err == nil {
		t.Fatal("audit store failure = nil error")
	}
	// The success path through a store sink appends one event.
	s3 := NewPersistentServerForTest(t)
	if err := s3.auditOIDCIssuance(req, "actor", "run", "job", "kid", "key", "aud"); err != nil {
		t.Fatalf("store audit = %v", err)
	}
	if _, err := os.Stat(filepath.Join(s3.store.Root, "audit.jsonl")); err != nil {
		t.Fatalf("store audit did not append: %v", err)
	}
}

// TestIDCovSignJWTNilSigner covers the missing-signer refusal.
func TestIDCovSignJWTNilSigner(t *testing.T) {
	s := New("t")
	if _, err := s.signJWT(nil, map[string]any{"a": 1}); err == nil {
		t.Fatal("signJWT(nil) = nil error")
	}
	if _, err := s.signJWT(newOIDCSigner(), map[string]any{"a": 1}); err != nil {
		t.Fatalf("signJWT = %v", err)
	}
}

// TestIDCovRotateOIDCKeyNilSigner covers the lazy bootstrap branch.
func TestIDCovRotateOIDCKeyNilSigner(t *testing.T) {
	s := New("t")
	s.mu.Lock()
	s.oidc = nil
	s.rotateOIDCKeyLocked(time.Now().UTC())
	got := s.oidc
	s.mu.Unlock()
	if got == nil || got.KID == "" {
		t.Fatal("rotateOIDCKeyLocked did not bootstrap a signer")
	}
}

// TestIDCovRotateOIDCKeyPrunesRetired covers the previous-key pruning when
// a retired key is rotated out again.
func TestIDCovRotateOIDCKeyPrunesRetired(t *testing.T) {
	s := New("t")
	now := time.Now().UTC()
	s.mu.Lock()
	s.rotateOIDCKeyLocked(now)
	s.oidc.Previous[0].RetireAfter = now.Add(-time.Minute)
	s.rotateOIDCKeyLocked(now)
	prev := len(s.oidc.Previous)
	s.mu.Unlock()
	if prev != 1 {
		t.Fatalf("retired previous keys kept: %d, want 1", prev)
	}
}

// TestIDCovNewOIDCKID pins the random key id shape.
func TestIDCovNewOIDCKID(t *testing.T) {
	a, err := newOIDCKID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newOIDCKID()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 || a == b {
		t.Fatalf("newOIDCKID = %q / %q", a, b)
	}
}

// TestIDCovLoadOIDCSignerClusterDigest pins the digest recorded by the
// cluster loader.
func TestIDCovLoadOIDCSignerClusterDigest(t *testing.T) {
	shared := &StaticClusterKeyStore{Keys: map[string][]byte{}}
	s := New("t")
	signer, err := s.loadOIDCSignerCluster(shared)
	if err != nil {
		t.Fatal(err)
	}
	b, ok, err := shared.Lookup(clusterKindOIDC)
	if err != nil || !ok {
		t.Fatalf("cluster ring not stored: %v %v", ok, err)
	}
	sum := sha256.Sum256(b)
	if signer.ringDigest != hex.EncodeToString(sum[:]) || signer.cluster == nil {
		t.Fatal("cluster loader did not record digest/store")
	}
}

// mustReadFile reads a fixture file, failing the test on error.
func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// NewPersistentServerForTest builds a persistent server on a temp data dir.
func NewPersistentServerForTest(t *testing.T) *Server {
	t.Helper()
	s, err := NewPersistent("t", "t", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var _ storage.Store = (*oidcFaultStore)(nil)
