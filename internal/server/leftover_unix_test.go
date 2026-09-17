//go:build !windows

package server

// Long-path repository GC fixtures need relative openat traversal
// (golang.org/x/sys/unix does not build on Windows); the portable GC
// branches are covered in leftover_idcov_test.go.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// longStoreRoot builds a directory chain that pushes the absolute path close
// to the platform limit, then returns a short spelling of it.
func longStoreRoot(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	limit := len(base)
	for {
		next := base + "/d"
		if err := os.Mkdir(next, 0o755); err != nil {
			break
		}
		base = next
		limit = len(base)
	}
	root := base
	for len(root) > limit-10 {
		root = root[:len(root)-2]
	}
	return root
}

// makeLongChild creates name inside a long-path directory through a relative
// openat so the child itself never needs the oversized absolute path.
func makeLongChild(t *testing.T, dir, name string) {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Skipf("cannot open long directory: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	cfd, err := unix.Openat(fd, name, unix.O_CREAT|unix.O_WRONLY, 0o600)
	if err != nil {
		t.Skipf("cannot create long-path child: %v", err)
	}
	_ = unix.Close(cfd)
}

// TestLeftoverGCTempFileInfoFailures covers the sweep's Info-failure
// fallbacks: a child entry whose absolute path exceeds the platform limit
// fails both DirEntry.Info() and the os.Lstat fallback, so the entry is
// skipped in both the top-level and recursive walks.
func TestLeftoverGCTempFileInfoFailures(t *testing.T) {
	root := longStoreRoot(t)
	artifacts := filepath.Join(root, "artifacts")
	if err := os.Mkdir(artifacts, 0o755); err != nil {
		t.Skipf("cannot create long artifacts dir: %v", err)
	}
	makeLongChild(t, artifacts, "orphan.tmp")

	if removed := sweepTempFiles(root, time.Now()); removed != 0 {
		t.Fatalf("top-level sweep removed %d unreadable entries", removed)
	}
	if removed := sweepTempFilesRecursive(artifacts, 0, time.Now()); removed != 0 {
		t.Fatalf("recursive sweep removed %d unreadable entries", removed)
	}
	// The absolute path is unstattable, so existence is checked through a
	// relative openat on the parent.
	fd, err := unix.Open(artifacts, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Skipf("cannot open long directory: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	cfd, err := unix.Openat(fd, "orphan.tmp", unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("orphan was removed despite the Info fallback failure: %v", err)
	}
	_ = unix.Close(cfd)
}
