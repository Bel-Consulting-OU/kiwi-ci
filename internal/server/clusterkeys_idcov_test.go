package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// base64RawStd renders raw key bytes in the OIDC ring's encoding.
func base64RawStd(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

// caPEMsForTest renders a runner CA as its certificate and PKCS8 key PEMs.
func caPEMsForTest(ca *runnerpki.CA) (certPEM, keyPEM []byte, err error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// failingClusterStore is a ClusterKeyStore whose LoadOrCreate always fails
// and which implements none of the optional interfaces.
type failingClusterStore struct{ err error }

func (f failingClusterStore) LoadOrCreate(string) ([]byte, error) { return nil, f.err }

// lookupErrorStore is a ClusterKeyLookup whose Lookup always fails.
type lookupErrorStore struct{ failingClusterStore }

func (l lookupErrorStore) Lookup(string) ([]byte, bool, error) { return nil, false, l.err }

// fixedClusterStore returns fixed bytes (no Lookup support).
type fixedClusterStore struct{ b []byte }

func (f fixedClusterStore) LoadOrCreate(string) ([]byte, error) { return f.b, nil }

// fixedLookupStore returns fixed bytes with Lookup support.
type fixedLookupStore struct {
	b     []byte
	found bool
}

func (f fixedLookupStore) LoadOrCreate(string) ([]byte, error) { return f.b, nil }
func (f fixedLookupStore) Lookup(string) ([]byte, bool, error) { return f.b, f.found, nil }

// TestIDCovCreateClusterKey covers every creator branch plus the unknown
// kind refusal.
func TestIDCovCreateClusterKey(t *testing.T) {
	for _, kind := range []string{clusterKindLease, clusterKindOIDC, clusterKindProvenance, clusterKindCacheSigning, clusterKindWebSession, clusterKindRunnerCA} {
		b, err := createClusterKey(kind)
		if err != nil || len(b) == 0 {
			t.Fatalf("createClusterKey(%s) = %v (%d bytes)", kind, err, len(b))
		}
	}
	if _, err := createClusterKey("bogus"); err == nil {
		t.Fatal("createClusterKey(bogus) = nil, want error")
	}

	// The web-session creator honors the env override first.
	t.Setenv("KIWI_WEB_SESSION_SECRET", strings.Repeat("ef", 32))
	hexKey, err := createWebSessionKey()
	if err != nil || len(hexKey) != 32 {
		t.Fatalf("createWebSessionKey(env) = %v (%d bytes)", err, len(hexKey))
	}
	if hexKey[0] != 0xef {
		t.Fatalf("createWebSessionKey ignored the env override: %x", hexKey)
	}
	// An invalid override falls back to fresh random material.
	t.Setenv("KIWI_WEB_SESSION_SECRET", "not-hex")
	fresh, err := createWebSessionKey()
	if err != nil || len(fresh) != 32 {
		t.Fatalf("createWebSessionKey(fallback) = %v (%d bytes)", err, len(fresh))
	}
	t.Setenv("KIWI_WEB_SESSION_SECRET", "")
}

// TestIDCovFSClusterStorePathAndEncodedBytes covers the path/encoding
// helpers, including unknown kinds and the empty-directory refusal.
func TestIDCovFSClusterStorePathAndEncodedBytes(t *testing.T) {
	store := &FSClusterKeyStore{Dir: t.TempDir()}
	for _, kind := range []string{clusterKindLease, clusterKindOIDC, clusterKindProvenance, clusterKindCacheSigning, clusterKindWebSession, clusterKindRunnerCA} {
		p, err := store.path(kind)
		if err != nil || p == "" {
			t.Fatalf("path(%s) = %q, %v", kind, p, err)
		}
	}
	if _, err := store.path("bogus"); err == nil {
		t.Fatal("path(bogus) = nil, want error")
	}
	if _, err := (&FSClusterKeyStore{}).path(clusterKindLease); err == nil {
		t.Fatal("path with empty dir = nil, want error")
	}
	if _, err := store.encodedBytes("bogus", nil); err == nil {
		t.Fatal("encodedBytes(bogus) = nil, want error")
	}
	if b, err := store.encodedBytes(clusterKindLease, []byte{1, 2}); err != nil || string(b) != "0102" {
		t.Fatalf("encodedBytes(lease) = %q, %v", b, err)
	}
	if b, err := store.encodedBytes(clusterKindOIDC, []byte("raw")); err != nil || string(b) != "raw" {
		t.Fatalf("encodedBytes(oidc) = %q, %v", b, err)
	}
}

// TestIDCovFSClusterStoreLoadOrCreateErrors covers the failure paths of
// LoadOrCreate for unknown kinds, missing directories and file-as-directory
// layouts.
func TestIDCovFSClusterStoreLoadOrCreateErrors(t *testing.T) {
	if _, err := (&FSClusterKeyStore{Dir: t.TempDir()}).LoadOrCreate("bogus"); err == nil {
		t.Fatal("LoadOrCreate(bogus) = nil, want error")
	}
	// An empty dir fails at path lookup (covered via Lookup inside
	// LoadOrCreate).
	if _, err := (&FSClusterKeyStore{}).LoadOrCreate(clusterKindLease); err == nil {
		t.Fatal("LoadOrCreate with empty dir = nil, want error")
	}
	// A regular file where the store directory should be fails MkdirAll.
	file := filepath.Join(t.TempDir(), "file")
	writeTestFile(t, file, []byte("x"))
	if _, err := (&FSClusterKeyStore{Dir: filepath.Join(file, "sub")}).LoadOrCreate(clusterKindProvenance); err == nil {
		t.Fatal("LoadOrCreate under a file path = nil, want error")
	}
	// A dangling symlink at the target path makes Lookup report absent while
	// the CAS link hits EEXIST; the store must fail closed because the
	// winner cannot be read.
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "missing-target"), filepath.Join(dir, "lease.key")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := (&FSClusterKeyStore{Dir: dir}).LoadOrCreate(clusterKindLease); err == nil {
		t.Fatal("LoadOrCreate over a dangling symlink = nil, want error")
	}
}

// TestIDCovFSClusterStoreLookupBranches walks the Lookup switch: invalid
// lease material, read errors, invalid PEMs, mismatched pairs and the
// runner-CA object forms.
func TestIDCovFSClusterStoreLookupBranches(t *testing.T) {
	// Lease: read error (directory) and invalid hex/size.
	dirErr := t.TempDir()
	if err := os.Mkdir(filepath.Join(dirErr, "lease.key"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := (&FSClusterKeyStore{Dir: dirErr}).Lookup(clusterKindLease); err == nil {
		t.Fatal("Lookup(lease, directory) = nil error")
	}
	dirBad := t.TempDir()
	writeTestFile(t, filepath.Join(dirBad, "lease.key"), []byte("zz"))
	if _, _, err := (&FSClusterKeyStore{Dir: dirBad}).Lookup(clusterKindLease); err == nil {
		t.Fatal("Lookup(lease, invalid hex) = nil error")
	}
	dirShort := t.TempDir()
	writeTestFile(t, filepath.Join(dirShort, "lease.key"), []byte("abcd"))
	if _, _, err := (&FSClusterKeyStore{Dir: dirShort}).Lookup(clusterKindLease); err == nil {
		t.Fatal("Lookup(lease, short) = nil error")
	}
	// Empty dir: path error.
	if _, _, err := (&FSClusterKeyStore{}).Lookup(clusterKindLease); err == nil {
		t.Fatal("Lookup(lease, empty dir) = nil error")
	}

	// OIDC: read error (directory).
	oidcErr := t.TempDir()
	if err := os.Mkdir(filepath.Join(oidcErr, oidcKeyRingFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := (&FSClusterKeyStore{Dir: oidcErr}).Lookup(clusterKindOIDC); err == nil {
		t.Fatal("Lookup(oidc, directory) = nil error")
	}
	// OIDC legacy migration: valid legacy material is migrated and persisted.
	legacyDir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	legacyBytes := []byte(base64RawStd(priv))
	writeTestFile(t, filepath.Join(legacyDir, oidcLegacyKeyFile), legacyBytes)
	b, ok, err := (&FSClusterKeyStore{Dir: legacyDir}).Lookup(clusterKindOIDC)
	if err != nil || !ok || !bytes.Contains(b, []byte("\"active\"")) {
		t.Fatalf("legacy OIDC migration = ok=%v err=%v body=%q", ok, err, b)
	}
	if _, err := os.Stat(filepath.Join(legacyDir, oidcKeyRingFile)); err != nil {
		t.Fatalf("migrated ring not persisted: %v", err)
	}
	// OIDC legacy migration: corrupt legacy material is an error.
	legacyBad := t.TempDir()
	writeTestFile(t, filepath.Join(legacyBad, oidcLegacyKeyFile), []byte("!!!"))
	if _, _, err := (&FSClusterKeyStore{Dir: legacyBad}).Lookup(clusterKindOIDC); err == nil {
		t.Fatal("Lookup(oidc, corrupt legacy) = nil error")
	}

	// Provenance: read error, invalid PEM, mismatched pair, missing sidecar.
	provErr := t.TempDir()
	if err := os.Mkdir(filepath.Join(provErr, "provenance.key"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := (&FSClusterKeyStore{Dir: provErr}).Lookup(clusterKindProvenance); err == nil {
		t.Fatal("Lookup(provenance, directory) = nil error")
	}
	provBad := t.TempDir()
	writeTestFile(t, filepath.Join(provBad, "provenance.key"), []byte("junk"))
	if _, _, err := (&FSClusterKeyStore{Dir: provBad}).Lookup(clusterKindProvenance); err == nil {
		t.Fatal("Lookup(provenance, invalid PEM) = nil error")
	}
	privPEM, pubPEM, _ := testKeyPairPEM(t)
	_, otherPubPEM, _ := testKeyPairPEM(t)
	provMismatch := t.TempDir()
	writeTestFile(t, filepath.Join(provMismatch, "provenance.key"), privPEM)
	writeTestFile(t, filepath.Join(provMismatch, "provenance.pub"), otherPubPEM)
	if _, _, err := (&FSClusterKeyStore{Dir: provMismatch}).Lookup(clusterKindProvenance); err == nil {
		t.Fatal("Lookup(provenance, mismatched sidecar) = nil error")
	}
	provNoSide := t.TempDir()
	writeTestFile(t, filepath.Join(provNoSide, "provenance.key"), privPEM)
	if b, ok, err := (&FSClusterKeyStore{Dir: provNoSide}).Lookup(clusterKindProvenance); err != nil || !ok || len(b) == 0 {
		t.Fatalf("Lookup(provenance, no sidecar) = ok=%v err=%v", ok, err)
	}
	// Cache-signing mirrors the provenance loader; cover its bad sidecar path.
	cacheMismatch := t.TempDir()
	writeTestFile(t, filepath.Join(cacheMismatch, cacheSigningKeyFile), privPEM)
	writeTestFile(t, filepath.Join(cacheMismatch, cacheSigningPubFile), otherPubPEM)
	if _, _, err := (&FSClusterKeyStore{Dir: cacheMismatch}).Lookup(clusterKindCacheSigning); err == nil {
		t.Fatal("Lookup(cache-signing, mismatched sidecar) = nil error")
	}
	_ = pubPEM

	// Runner CA: corrupt object, directory object, half a legacy pair.
	caBad := t.TempDir()
	writeTestFile(t, filepath.Join(caBad, runnerCAObjectFile), []byte("no pem here"))
	if _, _, err := (&FSClusterKeyStore{Dir: caBad}).Lookup(clusterKindRunnerCA); err == nil {
		t.Fatal("Lookup(runner-ca, corrupt object) = nil error")
	}
	caDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(caDir, runnerCAObjectFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := (&FSClusterKeyStore{Dir: caDir}).Lookup(clusterKindRunnerCA); err == nil {
		t.Fatal("Lookup(runner-ca, directory) = nil error")
	}
	caHalf := t.TempDir()
	writeTestFile(t, filepath.Join(caHalf, "ca.crt"), []byte("cert"))
	if _, ok, err := (&FSClusterKeyStore{Dir: caHalf}).Lookup(clusterKindRunnerCA); err != nil || ok {
		t.Fatalf("Lookup(runner-ca, half pair) = ok=%v err=%v, want absent", ok, err)
	}

	if _, _, err := (&FSClusterKeyStore{Dir: t.TempDir()}).Lookup("bogus"); err == nil {
		t.Fatal("Lookup(bogus) = nil error")
	}
}

// TestIDCovFSClusterStoreStore covers Store for every kind: raw-hex kinds,
// the OIDC ring, PEM key pairs, the runner CA (create + overwrite) and the
// unknown-kind refusal.
func TestIDCovFSClusterStoreStore(t *testing.T) {
	dir := t.TempDir()
	store := &FSClusterKeyStore{Dir: dir}

	key := bytes.Repeat([]byte{7}, 32)
	if err := store.Store(clusterKindLease, key); err != nil {
		t.Fatal(err)
	}
	if err := store.Store(clusterKindWebSession, key); err != nil {
		t.Fatal(err)
	}
	if err := store.Store(clusterKindOIDC, []byte(`{"active":{}}`)); err != nil {
		t.Fatal(err)
	}
	privPEM, pubPEM, _ := testKeyPairPEM(t)
	if err := store.Store(clusterKindProvenance, privPEM); err != nil {
		t.Fatal(err)
	}
	if err := store.Store(clusterKindCacheSigning, privPEM); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"provenance.pub", cacheSigningPubFile} {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err != nil || !bytes.Equal(bytes.TrimSpace(b), bytes.TrimSpace(pubPEM)) {
			t.Fatalf("%s sidecar mismatch: %v", name, err)
		}
	}
	if err := store.Store("bogus", nil); err == nil {
		t.Fatal("Store(bogus) = nil, want error")
	}
	blocker := filepath.Join(dir, "blocker")
	writeTestFile(t, blocker, []byte("x"))
	if err := (&FSClusterKeyStore{Dir: filepath.Join(blocker, "sub")}).Store(clusterKindLease, key); err == nil {
		t.Fatal("Store with uncreatable dir = nil, want error")
	}

	// Runner CA: a fresh object publishes the sidecars; a second Store with
	// a DIFFERENT object exercises the overwrite path.
	ca1, err := runnerpki.NewCA("ca-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := runnerpki.NewCA("ca-2", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	obj1 := runnerCAObjectForTest(t, ca1)
	obj2 := runnerCAObjectForTest(t, ca2)
	if err := store.Store(clusterKindRunnerCA, obj1); err != nil {
		t.Fatal(err)
	}
	if b, ok, err := store.Lookup(clusterKindRunnerCA); err != nil || !ok || !bytes.Equal(b, obj1) {
		t.Fatalf("stored runner CA not readable: ok=%v err=%v", ok, err)
	}
	if err := store.Store(clusterKindRunnerCA, obj2); err != nil {
		t.Fatalf("runner CA overwrite: %v", err)
	}
	if b, _, err := store.Lookup(clusterKindRunnerCA); err != nil || !bytes.Equal(b, obj2) {
		t.Fatalf("runner CA overwrite not applied: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "ca.crt")); err != nil || !bytes.Contains(b, []byte("CERTIFICATE")) {
		t.Fatalf("ca.crt sidecar not republished: %v", err)
	}
	// An invalid object fails at the sidecar publication step.
	if err := store.Store(clusterKindRunnerCA, []byte("garbage")); err == nil {
		t.Fatal("Store(runner-ca, garbage) = nil, want error")
	}
	if err := store.publishRunnerCASidecars([]byte("garbage")); err == nil {
		t.Fatal("publishRunnerCASidecars(garbage) = nil, want error")
	}
}

// TestIDCovStaticClusterKeyStore covers the in-memory store: creation with a
// custom creator, the stored-value-wins race resolution, nil-map Lookup and
// Store initialization, and creator failures.
func TestIDCovStaticClusterKeyStore(t *testing.T) {
	// Creation with the default creator and with a custom one.
	var store StaticClusterKeyStore
	b, err := store.LoadOrCreate(clusterKindWebSession)
	if err != nil || len(b) != 32 {
		t.Fatalf("default creator = %v (%d bytes)", err, len(b))
	}
	if _, ok, err := store.Lookup(clusterKindWebSession); err != nil || !ok {
		t.Fatalf("Lookup after create = ok=%v err=%v", ok, err)
	}
	if b, ok, err := (&StaticClusterKeyStore{}).Lookup(clusterKindLease); err != nil || ok || b != nil {
		t.Fatalf("Lookup on nil map = %v %v %v", b, ok, err)
	}
	custom := &StaticClusterKeyStore{New: func(kind string) ([]byte, error) { return []byte("custom"), nil }}
	if b, err := custom.LoadOrCreate("any"); err != nil || string(b) != "custom" {
		t.Fatalf("custom creator = %q %v", b, err)
	}
	failing := &StaticClusterKeyStore{New: func(string) ([]byte, error) { return nil, errors.New("nope") }}
	if _, err := failing.LoadOrCreate("any"); err == nil {
		t.Fatal("failing creator = nil error")
	}

	// A creator that itself installs the value: the stored material wins.
	winner := []byte("winner")
	racestore := &StaticClusterKeyStore{}
	racestore.New = func(kind string) ([]byte, error) {
		racestore.mu.Lock()
		racestore.Keys = map[string][]byte{kind: append([]byte(nil), winner...)}
		racestore.mu.Unlock()
		return []byte("loser"), nil
	}
	got, err := racestore.LoadOrCreate("k")
	if err != nil || !bytes.Equal(got, winner) {
		t.Fatalf("stored value did not win: %q %v", got, err)
	}
	// Store initializes a nil map and copies defensively.
	var store2 StaticClusterKeyStore
	src := []byte("abc")
	if err := store2.Store("k", src); err != nil {
		t.Fatal(err)
	}
	src[0] = 'z'
	if b, _, _ := store2.Lookup("k"); string(b) != "abc" {
		t.Fatalf("Store did not copy: %q", b)
	}
	// Lookup/Store copies are independent of the caller's slice.
	if b, _, _ := store2.Lookup("k"); b != nil {
		b[0] = 'q'
		if again, _, _ := store2.Lookup("k"); again[0] != 'a' {
			t.Fatal("Lookup returned an aliased slice")
		}
	}
}

// TestIDCovLegacyOIDCRingBytes covers the legacy single-key migration
// helper.
func TestIDCovLegacyOIDCRingBytes(t *testing.T) {
	dir := t.TempDir()
	if _, err := legacyOIDCRingBytes(dir); !os.IsNotExist(err) {
		t.Fatalf("missing legacy file = %v, want IsNotExist", err)
	}
	writeTestFile(t, filepath.Join(dir, oidcLegacyKeyFile), []byte("!!!"))
	if _, err := legacyOIDCRingBytes(dir); err == nil {
		t.Fatal("corrupt legacy file = nil error")
	}
	writeTestFile(t, filepath.Join(dir, oidcLegacyKeyFile), []byte("abcd"))
	if _, err := legacyOIDCRingBytes(dir); err == nil || !strings.Contains(err.Error(), "invalid OIDC signing key size") {
		t.Fatalf("short legacy key error = %v", err)
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, oidcLegacyKeyFile), []byte(base64RawStd(priv)))
	b, err := legacyOIDCRingBytes(dir)
	if err != nil || !bytes.Contains(b, []byte("\"active\"")) {
		t.Fatalf("legacy ring bytes = %q %v", b, err)
	}
}

// TestIDCovSplitRunnerCAPEMs covers both object formats and every malformed
// shape.
func TestIDCovSplitRunnerCAPEMs(t *testing.T) {
	cert := "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"
	key := "-----BEGIN PRIVATE KEY-----\nBBB\n-----END PRIVATE KEY-----\n"

	c, k, err := splitRunnerCAPEMs([]byte(cert + key))
	if err != nil || string(c) != cert || string(k) != key {
		t.Fatalf("legacy split = %q %q %v", c, k, err)
	}
	if _, _, err := splitRunnerCAPEMs([]byte("cert\x00key")); err != nil {
		t.Fatalf("NUL split = %v", err)
	}
	if _, _, err := splitRunnerCAPEMs([]byte("\x00key")); err == nil {
		t.Fatal("empty left side = nil error")
	}
	if _, _, err := splitRunnerCAPEMs([]byte("cert\x00")); err == nil {
		t.Fatal("empty right side = nil error")
	}
	if _, _, err := splitRunnerCAPEMs([]byte("nothing")); err == nil {
		t.Fatal("missing certificate = nil error")
	}
	if _, _, err := splitRunnerCAPEMs([]byte(key)); err == nil {
		t.Fatal("missing certificate (key only) = nil error")
	}
	if _, _, err := splitRunnerCAPEMs([]byte(cert)); err == nil {
		t.Fatal("missing private key = nil error")
	}
	if _, _, err := splitRunnerCAPEMs([]byte(key + cert)); err == nil {
		t.Fatal("malformed (key before cert) = nil error")
	}
	if got := indexOfPEMBoundary([]byte(cert), "CERTIFICATE"); got < 0 {
		t.Fatalf("indexOfPEMBoundary = %d", got)
	}
	if got := indexOfPEMBoundary([]byte(cert), "PRIVATE KEY"); got != -1 {
		t.Fatalf("indexOfPEMBoundary(missing) = %d, want -1", got)
	}
}

// TestIDCovClusterServerLoaders covers the server-side cluster loaders for
// every kind, including store failures, invalid material and the
// absent-vs-present runner CA decision.
func TestIDCovClusterServerLoaders(t *testing.T) {
	boom := errors.New("store down")
	// Lease.
	if err := New("t").loadLeaseKeyCluster(failingClusterStore{err: boom}); err == nil {
		t.Fatal("lease loader store failure = nil error")
	}
	if err := New("t").loadLeaseKeyCluster(fixedClusterStore{b: []byte{1}}); err == nil {
		t.Fatal("lease loader short key = nil error")
	}
	s := New("t")
	if err := s.loadLeaseKeyCluster(fixedClusterStore{b: bytes.Repeat([]byte{3}, 32)}); err != nil || len(s.leaseKey) != 32 {
		t.Fatalf("lease loader = %v (%d bytes)", err, len(s.leaseKey))
	}

	// OIDC.
	if _, err := New("t").loadOIDCSignerCluster(failingClusterStore{err: boom}); err == nil {
		t.Fatal("oidc loader store failure = nil error")
	}
	if _, err := New("t").loadOIDCSignerCluster(fixedClusterStore{b: []byte("{")}); err == nil {
		t.Fatal("oidc loader invalid ring = nil error")
	}

	// Provenance and cache signer.
	if err := New("t").loadProvenanceCluster(failingClusterStore{err: boom}); err == nil {
		t.Fatal("provenance loader store failure = nil error")
	}
	if err := New("t").loadProvenanceCluster(fixedClusterStore{b: []byte("junk")}); err == nil {
		t.Fatal("provenance loader invalid PEM = nil error")
	}
	if err := New("t").loadCacheSignerCluster(failingClusterStore{err: boom}); err == nil {
		t.Fatal("cache loader store failure = nil error")
	}
	if err := New("t").loadCacheSignerCluster(fixedClusterStore{b: []byte("junk")}); err == nil {
		t.Fatal("cache loader invalid PEM = nil error")
	}

	// Web session.
	if err := New("t").loadWebSessionCluster(failingClusterStore{err: boom}); err == nil {
		t.Fatal("web session loader store failure = nil error")
	}
	if err := New("t").loadWebSessionCluster(fixedClusterStore{b: []byte{1, 2}}); err == nil {
		t.Fatal("web session loader short secret = nil error")
	}
	ws := New("t")
	if err := ws.loadWebSessionCluster(fixedClusterStore{b: bytes.Repeat([]byte{5}, 32)}); err != nil || len(ws.WebSessionSecret) != 32 {
		t.Fatalf("web session loader = %v", err)
	}

	// Runner CA: Lookup error, absent, present-but-bad, present-and-good.
	if err := New("t").loadRunnerCACluster(lookupErrorStore{failingClusterStore{err: boom}}); err == nil {
		t.Fatal("runner CA lookup error = nil error")
	}
	absent := New("t")
	if err := absent.loadRunnerCACluster(fixedLookupStore{found: false}); err != nil || absent.RunnerCA != nil {
		t.Fatalf("absent runner CA = %v (ca=%v)", err, absent.RunnerCA)
	}
	bad := New("t")
	if err := bad.loadRunnerCACluster(fixedLookupStore{b: []byte("garbage"), found: true}); err == nil {
		t.Fatal("bad runner CA blob = nil error")
	}
	// A store without Lookup support goes through LoadOrCreate.
	ca, err := runnerpki.NewCA("cluster-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	loadCreate := New("t")
	obj := runnerCAObjectForTest(t, ca)
	if err := loadCreate.loadRunnerCACluster(fixedClusterStore{b: obj}); err != nil || loadCreate.RunnerCA == nil {
		t.Fatalf("runner CA via LoadOrCreate = %v", err)
	}
	if err := New("t").loadRunnerCACluster(failingClusterStore{err: boom}); err == nil {
		t.Fatal("runner CA LoadOrCreate failure = nil error")
	}
	// setRunnerCAFromBlob propagates parse errors.
	if err := New("t").setRunnerCAFromBlob([]byte("garbage")); err == nil {
		t.Fatal("setRunnerCAFromBlob(garbage) = nil error")
	}
	if _, err := New("t").parseRunnerCABlob([]byte("garbage")); err == nil {
		t.Fatal("parseRunnerCABlob(garbage) = nil error")
	}
	// A well-formed blob that is not a CA fails at LoadCA.
	privPEM, _, _ := testKeyPairPEM(t)
	if _, err := New("t").parseRunnerCABlob([]byte(string(privPEM) + "\x00" + string(privPEM))); err == nil {
		t.Fatal("parseRunnerCABlob(non-CA PEMs) = nil error")
	}
}

// TestIDCovValidateHAReadyRunnerCA covers the runner-CA half of HA
// validation: non-lookup stores, lookup errors, missing shared material and
// divergent CAs.
func TestIDCovValidateHAReadyRunnerCA(t *testing.T) {
	ca, err := runnerpki.NewCA("loaded-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other, err := runnerpki.NewCA("other-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Non-lookup cluster store: LoadOrCreate is used.
	s := New("t")
	s.RunnerCA = ca
	s.ClusterKeys = fixedClusterStore{b: runnerCAObjectForTest(t, ca)}
	if err := s.ValidateHAReady(); err != nil {
		t.Fatalf("matching CA through LoadOrCreate = %v", err)
	}
	// Lookup error.
	s2 := New("t")
	s2.RunnerCA = ca
	s2.ClusterKeys = lookupErrorStore{failingClusterStore{err: errors.New("down")}}
	if err := s2.ValidateHAReady(); err == nil {
		t.Fatal("lookup error = nil")
	}
	// No shared material.
	s3 := New("t")
	s3.RunnerCA = ca
	s3.ClusterKeys = fixedLookupStore{found: false}
	if err := s3.ValidateHAReady(); err == nil {
		t.Fatal("missing shared CA = nil")
	}
	// Shared material that does not parse.
	s4 := New("t")
	s4.RunnerCA = ca
	s4.ClusterKeys = fixedLookupStore{b: []byte("garbage"), found: true}
	if err := s4.ValidateHAReady(); err == nil {
		t.Fatal("unparsable shared CA = nil")
	}
	// Divergent CA.
	s5 := New("t")
	s5.RunnerCA = ca
	s5.ClusterKeys = fixedLookupStore{b: runnerCAObjectForTest(t, other), found: true}
	if err := s5.ValidateHAReady(); err == nil {
		t.Fatal("divergent shared CA = nil")
	}
}

// TestIDCovKeyFingerprintsEmptyServer pins the no-material fingerprint set.
func TestIDCovKeyFingerprintsEmptyServer(t *testing.T) {
	s := &Server{}
	fp := s.KeyFingerprints()
	if len(fp) != 0 {
		t.Fatalf("empty server fingerprints = %v", fp)
	}
}

// TestIDCovCreateFileCASError covers the createFileCAS failure path for a
// non-existent parent directory.
func TestIDCovCreateFileCASError(t *testing.T) {
	dir := t.TempDir()
	if err := createFileCAS(filepath.Join(dir, "missing", "x"), []byte("data")); err == nil {
		t.Fatal("createFileCAS with missing parent = nil error")
	}
	// A successful CAS then a second identical call reports os.ErrExist.
	path := filepath.Join(dir, "obj")
	if err := createFileCAS(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	err := createFileCAS(path, []byte("second"))
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("second createFileCAS = %v, want os.ErrExist", err)
	}
}

// runnerCAObjectForTest builds the canonical runner CA cluster object (cert
// PEM + NUL + key PEM).
func runnerCAObjectForTest(t *testing.T, ca *runnerpki.CA) []byte {
	t.Helper()
	certPEM, keyPEM, err := caPEMsForTest(ca)
	if err != nil {
		t.Fatal(err)
	}
	return append(append(append([]byte{}, certPEM...), 0), keyPEM...)
}
