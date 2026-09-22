package storage

// Coverage for AtomicWriteFile's remaining failure paths and the directory
// fsync helper: an unwritable parent, a rename that cannot replace its
// target, and a directory that cannot be opened. Every case asserts the
// previous contents survive.
//
// The directory-fsync fault now injects through fsutil.SetHooks (the seam
// moved to the shared primitive); the helper under test is storage.SyncDir,
// which delegates to fsutil.SyncDir.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
)

// TestAtomicWriteFileUnwritableParent: when the parent path cannot be created
// (a regular file occupies it) the write fails before touching anything.
func TestAtomicWriteFileUnwritableParent(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocker, "child", "state.json")
	if err := AtomicWriteFile(path, []byte("v1"), 0o600); err == nil {
		t.Fatal("write under a regular file succeeded")
	}
	if b, err := os.ReadFile(blocker); err != nil || string(b) != "x" {
		t.Fatalf("blocker changed: %q %v", b, err)
	}
}

// TestAtomicWriteFileRenameOntoNonEmptyDirectory: the rename step cannot
// replace a non-empty directory, so the write fails (rather than removing or
// corrupting the target) and leaves no scratch file behind.
func TestAtomicWriteFileRenameOntoNonEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")
	if err := os.MkdirAll(filepath.Join(target, "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteFile(target, []byte("v1"), 0o600); err == nil {
		t.Fatal("write over a non-empty directory succeeded")
	}
	if _, err := os.Stat(filepath.Join(target, "keep")); err != nil {
		t.Fatalf("target directory contents were lost: %v", err)
	}
	assertNoScratchFiles(t, dir, "state.json")
}

// TestAtomicWriteFileParentDirErrorIsReturned: a failing parent-directory
// fsync after the rename surfaces (the bytes are visible but not certified
// durable) and no scratch file remains.
func TestAtomicWriteFileParentDirErrorIsReturned(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	restore := fsutil.SetHooks(fsutil.Hooks{DirSync: func(string) error {
		return errors.New("parent fsync failed")
	}})
	t.Cleanup(restore)
	err := AtomicWriteFile(path, []byte("v1"), 0o600)
	if err == nil {
		t.Fatal("failing parent fsync was ignored")
	}
	if got := err.Error(); !strings.Contains(got, "parent fsync failed") {
		t.Fatalf("error %q does not surface the fsync failure", got)
	}
	// The rename already happened, so the bytes are present; what failed is
	// the durability certificate.
	if b, rerr := os.ReadFile(path); rerr != nil || string(b) != "v1" {
		t.Fatalf("bytes after a failed parent fsync = (%q, %v)", b, rerr)
	}
	assertNoScratchFiles(t, dir, "state.json")
}

// TestSyncDirMissingDirectory: SyncDir reports an unopenable directory
// instead of silently claiming durability.
func TestSyncDirMissingDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	if err := SyncDir(missing); err == nil {
		t.Fatal("SyncDir on a missing directory succeeded")
	}
	// A real directory syncs cleanly.
	if err := SyncDir(t.TempDir()); err != nil {
		t.Fatalf("SyncDir on a real directory = %v", err)
	}
}
