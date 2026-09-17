package server

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSqueezeClusterStoreMkdirFailure covers the MkdirAll refusal when the
// store directory cannot be materialized.
func TestSqueezeClusterStoreMkdirFailure(t *testing.T) {
	root := t.TempDir()
	dangling := filepath.Join(root, "dangling")
	if err := os.Symlink(filepath.Join(root, "missing"), dangling); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := (&FSClusterKeyStore{Dir: dangling}).LoadOrCreate(clusterKindLease); err == nil {
		t.Fatal("dangling store directory = nil error")
	}
}

// TestSqueezeClusterStoreStoreRunnerCAOverwrite covers the runner-CA Store
// overwrite path failing when the object path cannot be replaced.
func TestSqueezeClusterStoreStoreRunnerCAOverwrite(t *testing.T) {
	dir := t.TempDir()
	// A directory at the object path makes the CAS link report EEXIST and the
	// atomic overwrite rename fail.
	if err := os.MkdirAll(filepath.Join(dir, runnerCAObjectFile), 0o700); err != nil {
		t.Fatal(err)
	}
	store := &FSClusterKeyStore{Dir: dir}
	created, err := createClusterKey(clusterKindRunnerCA)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Store(clusterKindRunnerCA, created); err == nil {
		t.Fatal("Store over a directory = nil error")
	}
}

// TestSqueezeClusterStoreStoreCreatesSidecars covers the explicit Store
// publication of the runner CA sidecars.
func TestSqueezeClusterStoreStoreCreatesSidecars(t *testing.T) {
	dir := t.TempDir()
	store := &FSClusterKeyStore{Dir: dir}
	created, err := createClusterKey(clusterKindRunnerCA)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Store(clusterKindRunnerCA, created); err != nil {
		t.Fatalf("Store(runner-ca) = %v", err)
	}
	for _, name := range []string{runnerCAObjectFile, "ca.crt", "ca.key"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s missing after Store: %v", name, err)
		}
	}
}

// TestSqueezeStaticClusterStoreKindErrors covers the default creator
// dispatch inside the static store.
func TestSqueezeStaticClusterStoreKindErrors(t *testing.T) {
	store := &StaticClusterKeyStore{}
	if _, err := store.LoadOrCreate("bogus"); err == nil {
		t.Fatal("unknown kind = nil error")
	}
	if _, err := store.LoadOrCreate(clusterKindWebSession); err != nil {
		t.Fatalf("web session kind = %v", err)
	}
}
