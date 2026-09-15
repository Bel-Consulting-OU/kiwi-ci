package server

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestClusterKeysSharedAcrossInstances(t *testing.T) {
	shared := &StaticClusterKeyStore{Keys: map[string][]byte{}}
	s1, err := NewPersistentWithCluster("runner-tok", "admin-tok", t.TempDir(), shared)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := NewPersistentWithCluster("runner-tok", "admin-tok", t.TempDir(), shared)
	if err != nil {
		t.Fatal(err)
	}
	// Identical lease token hashes under the shared key.
	const raw = "lease-token-material"
	if !reflect.DeepEqual(hashLeaseToken(s1.leaseKey, raw), hashLeaseToken(s2.leaseKey, raw)) {
		t.Fatal("lease HMAC keys differ across instances sharing the cluster store")
	}
	// Identical OIDC JWKS kids.
	s1.mu.Lock()
	k1 := s1.oidc.KID
	s1.mu.Unlock()
	s2.mu.Lock()
	k2 := s2.oidc.KID
	s2.mu.Unlock()
	if k1 != k2 {
		t.Fatalf("OIDC kids differ: %q vs %q", k1, k2)
	}
	// Identical web session secrets, provenance and cache signer keys.
	if !reflect.DeepEqual(s1.WebSessionSecret, s2.WebSessionSecret) {
		t.Fatal("web session secrets differ")
	}
	if s1.ensureProvenanceKey().KID != s2.ensureProvenanceKey().KID {
		t.Fatal("provenance key ids differ")
	}
	if s1.ensureCacheSigner().KID != s2.ensureCacheSigner().KID {
		t.Fatal("cache signer key ids differ")
	}
	// Fingerprints are stable and identical.
	fp1 := s1.KeyFingerprints()
	fp2 := s2.KeyFingerprints()
	if !reflect.DeepEqual(fp1, fp2) {
		t.Fatalf("fingerprints differ: %v vs %v", fp1, fp2)
	}
	for _, kind := range []string{"lease", "oidc", "provenance", "cache-signing", "web-session"} {
		if fp1[kind] == "" {
			t.Fatalf("missing fingerprint for %q", kind)
		}
	}
}

func TestClusterKeysStaticStoreReusesMaterial(t *testing.T) {
	shared := &StaticClusterKeyStore{Keys: map[string][]byte{}}
	s1, err := NewPersistentWithCluster("t", "t", t.TempDir(), shared)
	if err != nil {
		t.Fatal(err)
	}
	fp1 := s1.KeyFingerprints()
	s2, err := NewPersistentWithCluster("t", "t", t.TempDir(), shared)
	if err != nil {
		t.Fatal(err)
	}
	fp2 := s2.KeyFingerprints()
	if !reflect.DeepEqual(fp1, fp2) {
		t.Fatalf("restarted instance with shared static store changed keys: %v vs %v", fp1, fp2)
	}
}

func TestFSClusterKeyStoreMatchesLegacyLayout(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewPersistent("t", "t", dir)
	if err != nil {
		t.Fatal(err)
	}
	// The legacy files must exist after first construction.
	for _, name := range []string{"lease.key", "oidc-keyring.json", "provenance.key", "provenance.pub", "cache-signing.key", "cache-signing.pem", "web-session.key"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("legacy key file %s missing: %v", name, err)
		}
	}
	// A second instance on the same dir reuses the exact key material.
	s2, err := NewPersistent("t", "t", dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s1.KeyFingerprints(), s2.KeyFingerprints()) {
		t.Fatal("restarted server on same data dir changed key fingerprints")
	}
}

func TestFSClusterKeyStoreRunnerCACompatible(t *testing.T) {
	dir := t.TempDir()
	// Create the CA the legacy way and make sure NewPersistent picks it up
	// through the FS cluster store.
	if err := (&Server{}).EnsureRunnerCA(dir); err != nil {
		t.Fatal(err)
	}
	s, err := NewPersistent("t", "t", dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.RunnerCA == nil {
		t.Fatal("runner CA not loaded through the FS cluster key store")
	}
	// Without a CA, NewPersistent must not materialize one (legacy
	// behavior: mTLS stays disabled unless configured).
	dir2 := t.TempDir()
	s2, err := NewPersistent("t", "t", dir2)
	if err != nil {
		t.Fatal(err)
	}
	if s2.RunnerCA != nil {
		t.Fatal("NewPersistent materialized a runner CA that was never configured")
	}
	if _, err := os.Stat(filepath.Join(dir2, "ca.crt")); err == nil {
		t.Fatal("runner CA files must not be created implicitly")
	}
}

func TestValidateHAReady(t *testing.T) {
	s := New("t")
	if err := s.ValidateHAReady(); err != nil {
		t.Fatalf("dev server must be HA-ready: %v", err)
	}
	// DB without a cluster key store must refuse HA.
	f := newDBFakeStore()
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateHAReady(); err == nil {
		t.Fatal("DB mode without a cluster key store must fail HA validation")
	}
	// A cluster key store satisfies it.
	shared := &StaticClusterKeyStore{Keys: map[string][]byte{}}
	s2, err := NewPersistentWithCluster("t", "t", t.TempDir(), shared)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.SwitchToDB(newDBFakeStore()); err != nil {
		t.Fatal(err)
	}
	if err := s2.ValidateHAReady(); err != nil {
		t.Fatalf("DB mode with a cluster key store must be HA-ready: %v", err)
	}
}

func TestOIDCRotationPersistsThroughClusterStore(t *testing.T) {
	shared := &StaticClusterKeyStore{Keys: map[string][]byte{}}
	s, err := NewPersistentWithCluster("t", "t", t.TempDir(), shared)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	oldKID := s.oidc.KID
	s.mu.Unlock()
	// Rotate the signing key directly.
	s.mu.Lock()
	s.rotateOIDCKeyLocked(time.Now().UTC())
	newKID := s.oidc.KID
	s.mu.Unlock()
	if oldKID == newKID {
		t.Fatal("rotation did not change the OIDC kid")
	}
	// The rotated ring is stored in the shared cluster store, so a second
	// instance loading now sees the new kid.
	s2, err := NewPersistentWithCluster("t", "t", t.TempDir(), shared)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	got := s2.oidc.KID
	s2.mu.Unlock()
	if got != newKID {
		t.Fatalf("second instance loaded kid %q, want rotated %q", got, newKID)
	}
}

func TestKeyFingerprintsIncludesAllMaterials(t *testing.T) {
	dir := t.TempDir()
	if err := (&Server{}).EnsureRunnerCA(dir); err != nil {
		t.Fatal(err)
	}
	s, err := NewPersistent("t", "t", dir)
	if err != nil {
		t.Fatal(err)
	}
	fp := s.KeyFingerprints()
	for _, kind := range []string{"lease", "oidc", "provenance", "cache-signing", "web-session", "runner-ca"} {
		if fp[kind] == "" {
			t.Fatalf("missing fingerprint for %q: %v", kind, fp)
		}
	}
}

func TestStaticClusterKeyStoreCreatesMissingKinds(t *testing.T) {
	shared := &StaticClusterKeyStore{}
	b, err := shared.LoadOrCreate(clusterKindLease)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 32 {
		t.Fatalf("lease key size = %d, want 32", len(b))
	}
	if again, err := shared.LoadOrCreate(clusterKindLease); err != nil || !reflect.DeepEqual(b, again) {
		t.Fatalf("LoadOrCreate not stable: %v %v", again, err)
	}
}

func TestFSClusterKeyStoreConcurrentCreatorsIdentical(t *testing.T) {
	dir := t.TempDir()
	store := &FSClusterKeyStore{Dir: dir}
	const n = 16
	results := make(chan []byte, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := store.LoadOrCreate(clusterKindLease)
			if err != nil {
				t.Errorf("LoadOrCreate: %v", err)
				return
			}
			results <- b
		}()
	}
	wg.Wait()
	close(results)
	var first []byte
	for b := range results {
		if first == nil {
			first = b
			continue
		}
		if !bytes.Equal(first, b) {
			t.Fatal("concurrent creators returned different key material")
		}
	}
	if len(first) != 32 {
		t.Fatalf("lease key size = %d, want 32", len(first))
	}
}

func TestFSClusterKeyStorePreExistingFileWins(t *testing.T) {
	dir := t.TempDir()
	want := make([]byte, 32)
	for i := range want {
		want[i] = byte(i + 1)
	}
	if err := os.WriteFile(filepath.Join(dir, "lease.key"), []byte(hex.EncodeToString(want)), 0o600); err != nil {
		t.Fatal(err)
	}
	store := &FSClusterKeyStore{Dir: dir}
	got, err := store.LoadOrCreate(clusterKindLease)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("pre-existing key file was replaced by freshly generated material")
	}
	// The file still holds the pre-existing material.
	raw, err := os.ReadFile(filepath.Join(dir, "lease.key"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != hex.EncodeToString(want) {
		t.Fatal("pre-existing key file was overwritten")
	}
}

func TestStaticClusterKeyStoreConcurrentCreatorsIdentical(t *testing.T) {
	shared := &StaticClusterKeyStore{}
	const n = 16
	results := make(chan []byte, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := shared.LoadOrCreate(clusterKindLease)
			if err != nil {
				t.Errorf("LoadOrCreate: %v", err)
				return
			}
			results <- b
		}()
	}
	wg.Wait()
	close(results)
	var first []byte
	for b := range results {
		if first == nil {
			first = b
			continue
		}
		if !bytes.Equal(first, b) {
			t.Fatal("concurrent creators returned different key material")
		}
	}
	if len(first) != 32 {
		t.Fatalf("lease key size = %d, want 32", len(first))
	}
}
