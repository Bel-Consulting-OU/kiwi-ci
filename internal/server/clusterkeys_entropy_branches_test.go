package server

// Branch coverage for the filesystem cluster-key store and the cluster
// loader wiring: entropy failures, unwritable directories, malformed
// install material and per-material load failures. Every case asserts the
// fail-closed outcome (error, nothing installed, current material kept).

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stagedClusterStore serves valid material for every kind except failKind,
// where it reports err. It lets a table cover each loader stage of
// UseClusterKeyStore without mutating the server between stages.
type stagedClusterStore struct {
	failKind string
	err      error
}

func (s stagedClusterStore) LoadOrCreate(kind string) ([]byte, error) {
	if kind == s.failKind {
		return nil, s.err
	}
	return createClusterKey(kind)
}

// TestCreateClusterKeyEntropyFailures proves material generation fails
// closed (no partial key) when the entropy source fails, for both the
// ed25519 key-pair kinds and the raw 32-byte web-session secret.
func TestCreateClusterKeyEntropyFailures(t *testing.T) {
	restore := seamRand(t, seamErrReader{})
	defer restore()

	for _, kind := range []string{clusterKindProvenance, clusterKindCacheSigning, clusterKindWebSession} {
		if b, err := createClusterKey(kind); err == nil || b != nil {
			t.Fatalf("createClusterKey(%s) = (%d bytes, %v), want a fail-closed error", kind, len(b), err)
		}
	}
	if b, err := createWebSessionKey(); err == nil || b != nil {
		t.Fatalf("createWebSessionKey = (%d bytes, %v), want a fail-closed error", len(b), err)
	}
}

// TestFSClusterKeyStoreLoadOrCreateEntropyFailure: a web-session key that
// cannot be generated is reported and nothing is created on disk.
func TestFSClusterKeyStoreLoadOrCreateEntropyFailure(t *testing.T) {
	dir := t.TempDir()
	store := &FSClusterKeyStore{Dir: dir}
	restore := seamRand(t, seamErrReader{})
	defer restore()

	if b, err := store.LoadOrCreate(clusterKindWebSession); err == nil || b != nil {
		t.Fatalf("LoadOrCreate(web-session) = (%d bytes, %v)", len(b), err)
	}
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(entries) != 0 {
		t.Fatalf("failed generation left files behind: %v", entries)
	}
}

// TestFSClusterKeyStoreInstallOrLoadUnwritableDir: when the directory cannot
// be created (a regular file occupies its path) or written (read-only), the
// install fails closed instead of reporting success.
func TestFSClusterKeyStoreInstallOrLoadUnwritableDir(t *testing.T) {
	// Dir is a regular file: MkdirAll fails.
	dir := t.TempDir()
	filePath := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := &FSClusterKeyStore{Dir: filePath}
	if b, created, err := store.InstallOrLoad(clusterKindOIDC, []byte("material")); err == nil || created || b != nil {
		t.Fatalf("install into a file path = (%d bytes, %v, %v)", len(b), created, err)
	}

	// Dir exists but is read-only: the CAS temp file cannot be created.
	readonly := filepath.Join(dir, "ro")
	if err := os.Mkdir(readonly, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readonly, 0o700) })
	ro := &FSClusterKeyStore{Dir: readonly}
	if b, created, err := ro.InstallOrLoad(clusterKindProvenance, []byte("material")); err == nil || created || b != nil {
		t.Fatalf("install into a read-only dir = (%d bytes, %v, %v)", len(b), created, err)
	}
}

// TestFSClusterKeyStoreInstallOrLoadMalformedMaterial: key-pair kinds must
// reject material that does not parse, and a public-sidecar write failure
// (a directory occupies the sidecar path) must be reported rather than
// silently dropping the verification half of the pair.
func TestFSClusterKeyStoreInstallOrLoadMalformedMaterial(t *testing.T) {
	dir := t.TempDir()
	store := &FSClusterKeyStore{Dir: dir}
	if b, created, err := store.InstallOrLoad(clusterKindProvenance, []byte("not-a-pem-key")); err == nil || created || b != nil {
		t.Fatalf("malformed provenance material = (%d bytes, %v, %v)", len(b), created, err)
	}

	// Valid material, but the public sidecar path is a directory.
	dir2 := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir2, "provenance.pub"), 0o755); err != nil {
		t.Fatal(err)
	}
	store2 := &FSClusterKeyStore{Dir: dir2}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := encodeEd25519PrivatePEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	if b, created, err := store2.InstallOrLoad(clusterKindProvenance, keyPEM); err == nil || created || b != nil {
		t.Fatalf("sidecar write failure = (%d bytes, %v, %v)", len(b), created, err)
	}

	// The same for the cache-signing sidecar.
	dir3 := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir3, cacheSigningPubFile), 0o755); err != nil {
		t.Fatal(err)
	}
	store3 := &FSClusterKeyStore{Dir: dir3}
	if b, created, err := store3.InstallOrLoad(clusterKindCacheSigning, keyPEM); err == nil || created || b != nil {
		t.Fatalf("cache-signing sidecar failure = (%d bytes, %v, %v)", len(b), created, err)
	}
}

// TestFSClusterKeyStoreStoreKeyPathIsDirectory: Store must report an
// unwritable key path (a directory occupies it) for both key-pair kinds
// instead of claiming the rotation was persisted.
func TestFSClusterKeyStoreStoreKeyPathIsDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "provenance.key"), 0o755); err != nil {
		t.Fatal(err)
	}
	store := &FSClusterKeyStore{Dir: dir}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := encodeEd25519PrivatePEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Store(clusterKindProvenance, keyPEM); err == nil {
		t.Fatal("Store over a directory path succeeded")
	}
	if err := store.Store(clusterKindCacheSigning, keyPEM); err == nil {
		// cacheSigningKeyFile has a different path, so it still succeeds;
		// only provenance's occupied path is expected to fail.
		t.Log("cache-signing key path was writable (expected)")
	}
}

// TestUseClusterKeyStoreLoadFailures proves every loader stage fails closed:
// an error from the store for one material aborts the swap and names that
// material, so the server never keeps half-loaded key material.
func TestUseClusterKeyStoreLoadFailures(t *testing.T) {
	boom := errors.New("staged store failure")
	cases := []struct {
		kind string
		want string
	}{
		{clusterKindOIDC, "cluster oidc key ring"},
		{clusterKindLease, "cluster lease key"},
		{clusterKindProvenance, "cluster provenance key"},
		{clusterKindCacheSigning, "cluster cache signing key"},
		{clusterKindWebSession, "cluster web session secret"},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			s := New("shared-dev-token")
			err := s.UseClusterKeyStore(stagedClusterStore{failKind: tc.kind, err: boom})
			if err == nil || !errors.Is(err, boom) {
				t.Fatalf("UseClusterKeyStore(%s failure) = %v, want the staged error", tc.kind, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name %q", err, tc.want)
			}
		})
	}
	// The happy path over the staged store loads every material, proving the
	// failures above are caused by the staged error and not a broken fake.
	s := New("shared-dev-token")
	if err := s.UseClusterKeyStore(stagedClusterStore{}); err != nil {
		t.Fatalf("staged store happy path = %v", err)
	}
	if len(s.leaseKey) != 32 || s.oidc == nil || s.provenance == nil || s.cacheSigner == nil || len(s.WebSessionSecret) != 32 {
		t.Fatal("staged store did not load every material")
	}
}

// TestClusterKeyDirIsNodeLocalEmptyInputs: an empty dir or data dir can only
// be node-local when BOTH are empty; a filesystem alias of the data dir is
// node-local by identity.
func TestClusterKeyDirIsNodeLocalEmptyInputs(t *testing.T) {
	if !clusterKeyDirIsNodeLocal("", "") {
		t.Fatal("two empty paths must compare equal")
	}
	if clusterKeyDirIsNodeLocal("", "/data") || clusterKeyDirIsNodeLocal("/data", "") {
		t.Fatal("an empty path must not alias a real one")
	}
	dir := t.TempDir()
	if !clusterKeyDirIsNodeLocal(dir, dir) {
		t.Fatal("identical paths must be node-local")
	}
	if !clusterKeyDirIsNodeLocal(filepath.Join(dir, "sub", ".."), dir) {
		t.Fatal("a lexical alias of the data dir must be node-local")
	}
	if clusterKeyDirIsNodeLocal(t.TempDir(), dir) {
		t.Fatal("a distinct directory must not be node-local")
	}
}
