//go:build unix

package staging

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// dirLock is the held exclusive ownership token of one staging directory.
type dirLock struct {
	file *os.File
}

// acquireDirLock takes a non-blocking exclusive flock on <dir>/kiwi-stage.lock
// and returns the held token. flock is used because the kernel releases it
// automatically when the owning process exits for any reason — including a
// crash or SIGKILL — so the "pre-existing spool files belong to a dead owner"
// proof needs no stale-lock heuristics and no timeout.
//
// A live process that already holds the lock makes this fail with
// ErrStagingDirOwned; startup must then refuse to serve. The lock FILE is left
// in place on release: unlinking a file another opener may already hold a lock
// on is the classic flock race, and the file itself carries no state that must
// disappear (it is re-truncated by the next owner and is invisible to the
// reclaim and to Prune, which only match FilePrefix).
func acquireDirLock(dir string) (*dirLock, error) {
	path := filepath.Join(dir, LockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("staging: open lock file %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("%w: %s is held by another live process", ErrStagingDirOwned, path)
		}
		return nil, fmt.Errorf("staging: lock %s: %w", path, err)
	}
	// Owner identity is diagnostics only; the flock is the lock.
	_ = f.Truncate(0)
	if _, err := f.WriteAt([]byte(lockOwnerIdentity()+"\n"), 0); err != nil {
		// Best effort: a read-only or full filesystem already failed the
		// writability probe that follows, which reports the real error.
		_ = err
	}
	_ = f.Sync()
	return &dirLock{file: f}, nil
}

// release drops the ownership lock. It is nil-safe and idempotent.
func (l *dirLock) release() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return fmt.Errorf("staging: unlock: %w", unlockErr)
	}
	return closeErr
}
