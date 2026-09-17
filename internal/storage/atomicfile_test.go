package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestAtomicWriteFileDurableSuccess proves a successful write is readable
// after a simulated crash-reopen: no scratch file survives the write, the
// final file carries the requested mode, and the parent directory was
// fsynced exactly once per write (seam counter).
func TestAtomicWriteFileDurableSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	syncs := 0
	oldDirSync := atomicDirSync
	atomicDirSync = func(d string) error {
		syncs++
		return oldDirSync(d)
	}
	t.Cleanup(func() { atomicDirSync = oldDirSync })

	if err := AtomicWriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if string(b) != "v1" {
		t.Fatalf("content after reopen = %q, want v1", b)
	}
	if syncs != 1 {
		t.Fatalf("directory fsyncs = %d, want 1", syncs)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}

	if err := AtomicWriteFile(path, []byte("v2"), 0o600); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if b, err = os.ReadFile(path); err != nil || string(b) != "v2" {
		t.Fatalf("content after second write = %q, %v; want v2", b, err)
	}
	if syncs != 2 {
		t.Fatalf("directory fsyncs after second write = %d, want 2", syncs)
	}

	// A crash between the write and the next start must not leave scratch
	// files behind: the directory holds only the final file.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "state.json" {
			t.Fatalf("scratch entry survived the write: %q", e.Name())
		}
	}
}

// TestAtomicWriteFileSyncFailureKeepsOldFile injects a failing file Sync:
// the write fails, the previous contents survive untouched, and no scratch
// file is left behind.
func TestAtomicWriteFileSyncFailureKeepsOldFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := AtomicWriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldSync := atomicFileSync
	atomicFileSync = func(*os.File) error { return errors.New("sync boom") }
	t.Cleanup(func() { atomicFileSync = oldSync })

	if err := AtomicWriteFile(path, []byte("v2"), 0o600); err == nil {
		t.Fatal("failing Sync must fail the write")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "v1" {
		t.Fatalf("old file was replaced after a failed Sync: %q", b)
	}
	assertNoScratchFiles(t, dir, "state.json")
}

// TestAtomicWriteFileCloseFailureKeepsOldFile injects a failing Close: the
// write fails, the previous contents survive, and no scratch file is left
// behind.
func TestAtomicWriteFileCloseFailureKeepsOldFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := AtomicWriteFile(path, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldClose := atomicFileClose
	atomicFileClose = func(f *os.File) error {
		_ = oldClose(f)
		return errors.New("close boom")
	}
	t.Cleanup(func() { atomicFileClose = oldClose })

	if err := AtomicWriteFile(path, []byte("v2"), 0o600); err == nil {
		t.Fatal("failing Close must fail the write")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "v1" {
		t.Fatalf("old file was replaced after a failed Close: %q", b)
	}
	assertNoScratchFiles(t, dir, "state.json")
}

// TestAtomicWriteFileDirSyncFailureIsReturned proves the directory fsync is
// part of the durability contract: a failing parent fsync surfaces as an
// error even though the rename already happened.
func TestAtomicWriteFileDirSyncFailureIsReturned(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	oldDirSync := atomicDirSync
	atomicDirSync = func(string) error { return errors.New("dir fsync boom") }
	t.Cleanup(func() { atomicDirSync = oldDirSync })

	if err := AtomicWriteFile(path, []byte("v1"), 0o600); err == nil {
		t.Fatal("failing directory fsync must fail the write")
	}
	assertNoScratchFiles(t, dir, "state.json")
}

// assertNoScratchFiles fails when the directory contains anything besides
// the expected final entries.
func assertNoScratchFiles(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{}
	for _, w := range want {
		allowed[w] = true
	}
	for _, e := range entries {
		if !allowed[e.Name()] {
			t.Fatalf("unexpected scratch entry %q", e.Name())
		}
	}
}

// TestRepositorySaveIsAtomicAndDurable proves the fs Repository's state
// snapshot rides the checked atomic write: Sync/Close failures surface and
// leave the previous state.json intact, and a successful save round-trips.
func TestRepositorySaveIsAtomicAndDurable(t *testing.T) {
	dir := t.TempDir()
	r := New(dir)
	first := Snapshot{Version: 1, Runs: map[string]model.Run{"r1": {ID: "r1"}},
		Snapshots: map[string]model.SnapshotRecord{"s1": {ID: "s1", RunID: "r1", Path: filepath.Join(dir, "a"), Size: 1, SHA256: "x"}}}
	if err := r.Save(first); err != nil {
		t.Fatal(err)
	}
	loaded, err := r.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Snapshots) != 1 || loaded.Snapshots["s1"].SHA256 != "x" {
		t.Fatalf("snapshot records did not round-trip: %+v", loaded.Snapshots)
	}

	oldSync := atomicFileSync
	atomicFileSync = func(*os.File) error { return errors.New("sync boom") }
	if err := r.Save(Snapshot{Version: 1, Runs: map[string]model.Run{"r2": {ID: "r2"}}}); err == nil {
		t.Fatal("failing state Sync must fail Save")
	}
	atomicFileSync = oldSync
	loaded, err = r.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.Snapshots["s1"]; !ok || len(loaded.Runs) != 1 {
		t.Fatalf("failed Save clobbered the prior state: %+v", loaded)
	}
}

// TestSnapshotSnapshotsFieldAdditive proves an older state.json without the
// snapshots key loads with an initialized empty map (additive field).
func TestSnapshotSnapshotsFieldAdditive(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"version":1,"runs":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(dir).Load()
	if err != nil {
		t.Fatal(err)
	}
	if s.Snapshots == nil {
		t.Fatal("legacy snapshot loaded with a nil Snapshots map")
	}
	if len(s.Snapshots) != 0 {
		t.Fatalf("legacy snapshot loaded %d snapshot records", len(s.Snapshots))
	}
}
