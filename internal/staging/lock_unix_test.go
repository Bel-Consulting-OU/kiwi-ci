//go:build unix

package staging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDirLockReleaseUnlockFailure proves a release whose underlying
// descriptor was already closed reports the unlock failure instead of
// acknowledging ownership release. The held-FD branch is unix-only: the
// non-flock (!unix) dirLock has no open handle to close (sharing this test
// in the portable file broke the Windows test build on lock.file).
func TestDirLockReleaseUnlockFailure(t *testing.T) {
	dir := t.TempDir()
	lock, err := acquireDirLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.file.Close(); err != nil {
		t.Fatal(err)
	}
	err = lock.release()
	if err == nil || !strings.Contains(err.Error(), "unlock") {
		t.Fatalf("release after close = %v, want the unlock failure", err)
	}
	// The ownership token must survive the failed release: an unlock error
	// must not delete the file it could not actually release.
	if _, serr := os.Stat(filepath.Join(dir, LockFileName)); serr != nil {
		t.Fatalf("lock file missing after failed release: %v", serr)
	}
}
