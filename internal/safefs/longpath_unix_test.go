//go:build !windows

package safefs

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// longCollectWorkspace returns a workspace path whose directory listing is
// readable while lstat of any child exceeds the platform path limit, so
// DirEntry.Info() fails deterministically during a walk.
func longCollectWorkspace(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	for {
		next := base + "/d"
		if err := os.Mkdir(next, 0o755); err != nil {
			break
		}
		base = next
	}
	fd, err := unix.Open(base, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Skipf("cannot open long workspace: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	cfd, err := unix.Openat(fd, "orphan.tmp", unix.O_CREAT|unix.O_WRONLY, 0o600)
	if err != nil {
		t.Skipf("cannot create long-path child: %v", err)
	}
	_ = unix.Close(cfd)
	return base
}

// TestCollectChildInfoFailure covers the walk's DirEntry.Info failure: an
// entry whose absolute path exceeds the platform limit cannot be stat'ed,
// so the capture fails closed instead of archiving a partial tree.
func TestCollectChildInfoFailure(t *testing.T) {
	ws := longCollectWorkspace(t)
	if _, err := collect(ws, []string{"."}, false); err == nil {
		t.Fatal("collect with an unstatable child succeeded")
	}
}
