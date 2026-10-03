//go:build unix

package cache

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// NamespaceLockFileName is the ownership lock file inside a runner cache
// namespace. It carries no state that must survive: the flock is the lock,
// and the file name is deliberately outside every temp/reclaim/retention
// pattern (it is not a *.tar.gz and not a recognized *.tmp shape).
const NamespaceLockFileName = "kiwi-cache.lock"

// namespaceLock is the held exclusive ownership token of one cache
// namespace directory.
type namespaceLock struct {
	file *os.File
}

// acquireNamespaceLock takes a non-blocking exclusive flock on
// <dir>/kiwi-cache.lock. flock is used because the kernel releases it when
// the owning process exits for any reason, so "the temp files I can see
// belong to a dead owner" needs no stale-lock heuristics. A live holder makes
// this fail with ErrCacheDirOwned: destructive startup reclamation must never
// run against another live process's writes.
func acquireNamespaceLock(dir string) (*namespaceLock, error) {
	path := filepath.Join(dir, NamespaceLockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cache: open lock file %s: %w", path, err)
	}
	if info, serr := f.Stat(); serr != nil || !info.Mode().IsRegular() || !sameEUID(info) || info.Mode().Perm()&0o022 != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("cache: lock file %s is not a trustworthy regular file owned by this user", path)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("%w: %s is held by another live process", ErrCacheDirOwned, path)
		}
		return nil, fmt.Errorf("cache: lock %s: %w", path, err)
	}
	// Verify the path still resolves to the inode we locked: an
	// unlink/recreate between open and flock would give two processes locks
	// on different inodes and let destructive reclamation run concurrently.
	if onDisk, lerr := os.Lstat(path); lerr != nil || !os.SameFile(mustStat(f), onDisk) {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
		return nil, fmt.Errorf("%w: %s was replaced during lock acquisition", ErrCacheDirOwned, path)
	}
	// Owner identity is diagnostics only; the flock is the lock.
	_ = f.Truncate(0)
	if _, err := f.WriteAt([]byte(cacheOwnerIdentity()+"\n"), 0); err != nil {
		// Best effort: the writability probe after locking reports the real
		// error.
		_ = err
	}
	_ = f.Sync()
	return &namespaceLock{file: f}, nil
}

// sameEUID reports whether the file belongs to this process's effective user.
func sameEUID(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid())
}

// mustStat re-reads the descriptor for the SameFile check.
func mustStat(f *os.File) os.FileInfo {
	info, err := f.Stat()
	if err != nil {
		return nil
	}
	return info
}

// release drops the ownership lock. It is nil-safe and idempotent.
func (l *namespaceLock) release() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return fmt.Errorf("cache: unlock: %w", unlockErr)
	}
	return closeErr
}
