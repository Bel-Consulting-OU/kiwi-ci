package server

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
)

// TestFSClusterKeyStoreInstallOrLoad proves the install-or-compare primitive
// on the filesystem store: the first install wins (created), a later install
// returns the stored bytes without replacing them, the runner-CA object
// publishes its ca.crt/ca.key sidecars, and empty/unknown input fails closed.
func TestFSClusterKeyStoreInstallOrLoad(t *testing.T) {
	dir := t.TempDir()
	store := &FSClusterKeyStore{Dir: dir}
	caA, err := runnerpki.NewCA("install A", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	objA := runnerCAObjectForTest(t, caA)

	stored, created, err := store.InstallOrLoad(clusterKindRunnerCA, objA)
	if err != nil || !created || !bytes.Equal(stored, objA) {
		t.Fatalf("first runner-ca install = created=%v err=%v", created, err)
	}
	if certPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt")); err != nil || len(certPEM) == 0 {
		t.Fatalf("runner CA install did not publish ca.crt: %v", err)
	}
	if keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key")); err != nil || len(keyPEM) == 0 {
		t.Fatalf("runner CA install did not publish ca.key: %v", err)
	}

	caB, err := runnerpki.NewCA("install B", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	objB := runnerCAObjectForTest(t, caB)
	stored, created, err = store.InstallOrLoad(clusterKindRunnerCA, objB)
	if err != nil || created || !bytes.Equal(stored, objA) {
		t.Fatalf("second runner-ca install replaced the stored CA: created=%v err=%v", created, err)
	}
	onDisk, ok, err := store.Lookup(clusterKindRunnerCA)
	if err != nil || !ok || !bytes.Equal(onDisk, objA) {
		t.Fatalf("stored runner-ca object changed: ok=%v err=%v", ok, err)
	}

	// A raw 32-byte kind round-trips through the store's on-disk encoding.
	key := bytes.Repeat([]byte{3}, 32)
	stored, created, err = store.InstallOrLoad(clusterKindLease, key)
	if err != nil || !created || !bytes.Equal(stored, key) {
		t.Fatalf("lease install = created=%v err=%v", created, err)
	}
	otherKey := bytes.Repeat([]byte{4}, 32)
	stored, created, err = store.InstallOrLoad(clusterKindLease, otherKey)
	if err != nil || created || !bytes.Equal(stored, key) {
		t.Fatalf("lease compare-or-install = created=%v err=%v", created, err)
	}

	// Key-pair kinds publish their public sidecar.
	privPEM, _, _ := testKeyPairPEM(t)
	if _, created, err := store.InstallOrLoad(clusterKindProvenance, privPEM); err != nil || !created {
		t.Fatalf("provenance install = created=%v err=%v", created, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "provenance.pub")); err != nil {
		t.Fatalf("provenance install did not publish provenance.pub: %v", err)
	}

	// Empty material and unknown kinds fail closed.
	if _, _, err := store.InstallOrLoad(clusterKindRunnerCA, nil); err == nil {
		t.Fatal("empty material accepted")
	}
	if _, _, err := store.InstallOrLoad("bogus", []byte("x")); err == nil {
		t.Fatal("unknown kind accepted")
	}
	if _, _, err := (&FSClusterKeyStore{}).InstallOrLoad(clusterKindLease, key); err == nil {
		t.Fatal("install with an empty store directory accepted")
	}
}

// TestFSClusterKeyStoreInstallOrLoadConcurrent proves racing installers
// converge on ONE value and exactly one install reports created.
func TestFSClusterKeyStoreInstallOrLoadConcurrent(t *testing.T) {
	store := &FSClusterKeyStore{Dir: t.TempDir()}
	const n = 8
	objects := make([][]byte, n)
	for i := range objects {
		ca, err := runnerpki.NewCA("racer", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		objects[i] = runnerCAObjectForTest(t, ca)
	}
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		created int
	)
	results := make([][]byte, n)
	for i := range objects {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b, made, err := store.InstallOrLoad(clusterKindRunnerCA, objects[i])
			if err != nil {
				t.Errorf("install %d: %v", i, err)
				return
			}
			mu.Lock()
			if made {
				created++
			}
			mu.Unlock()
			results[i] = b
		}(i)
	}
	wg.Wait()
	for i := range results {
		if results[i] == nil || !bytes.Equal(results[i], results[0]) {
			t.Fatal("concurrent installers diverged on the shared CA")
		}
	}
	if created != 1 {
		t.Fatalf("created count = %d, want exactly one winner", created)
	}
}

// TestStaticClusterKeyStoreInstallOrLoad pins the in-memory store's
// create-if-absent semantics and copy-on-return behavior.
func TestStaticClusterKeyStoreInstallOrLoad(t *testing.T) {
	store := &StaticClusterKeyStore{}
	b, created, err := store.InstallOrLoad(clusterKindLease, []byte("first"))
	if err != nil || !created || string(b) != "first" {
		t.Fatalf("install = created=%v b=%q err=%v", created, b, err)
	}
	b, created, err = store.InstallOrLoad(clusterKindLease, []byte("second"))
	if err != nil || created || string(b) != "first" {
		t.Fatalf("compare-or-install = created=%v b=%q err=%v", created, b, err)
	}
	if _, _, err := store.InstallOrLoad(clusterKindLease, nil); err == nil {
		t.Fatal("empty material accepted")
	}
	// Mutating the returned slice cannot corrupt the stored material.
	b[0] = 'X'
	again, _, err := store.InstallOrLoad(clusterKindLease, []byte("ignored"))
	if err != nil || string(again) != "first" {
		t.Fatalf("stored material mutated through the returned slice: %q err=%v", again, err)
	}
}

// TestDBClusterKeyStoreInstallOrLoad proves the DB-backed store delegates to
// the CAS insert: the first install wins, a later install never overwrites
// the shared row, and nil/empty inputs fail closed.
func TestDBClusterKeyStoreInstallOrLoad(t *testing.T) {
	blobs := newMemClusterKeyBlobs()
	store := &DBClusterKeyStore{Blobs: blobs}
	caA, err := runnerpki.NewCA("db install A", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	objA := runnerCAObjectForTest(t, caA)
	stored, created, err := store.InstallOrLoad(clusterKindRunnerCA, objA)
	if err != nil || !created || !bytes.Equal(stored, objA) {
		t.Fatalf("first DB install = created=%v err=%v", created, err)
	}
	if v := blobs.version(clusterKindRunnerCA); v != 1 {
		t.Fatalf("row version after install = %d, want 1", v)
	}
	caB, err := runnerpki.NewCA("db install B", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	stored, created, err = store.InstallOrLoad(clusterKindRunnerCA, runnerCAObjectForTest(t, caB))
	if err != nil || created || !bytes.Equal(stored, objA) {
		t.Fatalf("second DB install replaced the shared CA: created=%v err=%v", created, err)
	}
	if v := blobs.version(clusterKindRunnerCA); v != 1 {
		t.Fatalf("install-or-load must not overwrite the shared row: version=%d", v)
	}
	if _, _, err := store.InstallOrLoad(clusterKindRunnerCA, nil); err == nil {
		t.Fatal("empty material accepted")
	}
	if _, _, err := (&DBClusterKeyStore{}).InstallOrLoad(clusterKindRunnerCA, objA); err == nil {
		t.Fatal("install without a blob store accepted")
	}
}

// TestClusterKeyInstallOrLoadParity runs the same install-or-compare contract
// against the FS, static and DB-backed stores so the semantics cannot drift
// between the production provider and the test doubles.
func TestClusterKeyInstallOrLoadParity(t *testing.T) {
	stores := map[string]func(t *testing.T) ClusterKeyInstaller{
		"fs":     func(t *testing.T) ClusterKeyInstaller { return &FSClusterKeyStore{Dir: t.TempDir()} },
		"static": func(t *testing.T) ClusterKeyInstaller { return &StaticClusterKeyStore{} },
		"db":     func(t *testing.T) ClusterKeyInstaller { return &DBClusterKeyStore{Blobs: newMemClusterKeyBlobs()} },
	}
	first, err := runnerpki.NewCA("parity first", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := runnerpki.NewCA("parity second", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	objFirst := runnerCAObjectForTest(t, first)
	objSecond := runnerCAObjectForTest(t, second)
	for name, newStore := range stores {
		t.Run(name, func(t *testing.T) {
			store := newStore(t)
			stored, created, err := store.InstallOrLoad(clusterKindRunnerCA, objFirst)
			if err != nil || !created || !bytes.Equal(stored, objFirst) {
				t.Fatalf("first install = created=%v err=%v", created, err)
			}
			stored, created, err = store.InstallOrLoad(clusterKindRunnerCA, objSecond)
			if err != nil || created || !bytes.Equal(stored, objFirst) {
				t.Fatalf("existing material did not win: created=%v err=%v", created, err)
			}
			if _, _, err := store.InstallOrLoad(clusterKindRunnerCA, nil); err == nil {
				t.Fatal("empty material accepted")
			}
		})
	}
}
