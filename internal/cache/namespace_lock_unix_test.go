//go:build unix

package cache

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNamespaceLockExternalCloseUnix pins the held-FD branch of the lock
// contract: once the flock's file descriptor is closed OUTSIDE release,
// release must surface the failed unlock instead of reporting success (a
// silent success would leave the kernel lock state and the Go-side
// bookkeeping disagreeing). The non-flock (!unix) namespaceLock has no open
// handle, so this branch is unix-only by construction.
func TestNamespaceLockExternalCloseUnix(t *testing.T) {
	dir := t.TempDir()
	l, err := acquireNamespaceLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.release(); err == nil {
		t.Fatal("release after an externally closed file reported success")
	}
	// The lock file itself must still exist after the failed release: an
	// unlock error must not delete the ownership token it could not release.
	if _, err := os.Stat(filepath.Join(dir, NamespaceLockFileName)); err != nil {
		t.Fatalf("lock file missing after failed release: %v", err)
	}
}
