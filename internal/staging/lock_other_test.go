//go:build !unix

package staging

// Non-Unix coverage for the lock-file release state machine: a transient
// unlink failure must leave ownership set so the release is retryable; only a
// successful (or already-gone) unlink clears it.

import (
	"errors"
	"os"
	"testing"
)

func TestDirLockReleaseRetainsOwnershipOnRemoveFailure(t *testing.T) {
	dir := t.TempDir()
	l, err := acquireDirLock(dir)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	prev := removeDirLockFile
	t.Cleanup(func() { removeDirLockFile = prev })

	removeDirLockFile = func(string) error { return errors.New("EPERM injected") }
	if err := l.release(); err == nil {
		t.Fatal("release with a failing unlink returned nil")
	}
	if !l.owned {
		t.Fatal("transient unlink failure cleared ownership; the release is no longer retryable")
	}
	if _, err := os.Stat(l.path); err != nil {
		t.Fatalf("lock file disappeared despite the failed unlink: %v", err)
	}

	removeDirLockFile = prev
	if err := l.release(); err != nil {
		t.Fatalf("retry release: %v", err)
	}
	if l.owned {
		t.Fatal("ownership retained after a successful release")
	}
	if _, err := os.Stat(l.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock file still present after release: %v", err)
	}
	// Idempotent replay.
	if err := l.release(); err != nil {
		t.Fatalf("replayed release: %v", err)
	}
}
