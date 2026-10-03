//go:build unix

package runner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// acquireRunnerIdentityLock takes a non-blocking exclusive flock on
// <IdentityDir>/runner.lock, held for the whole Run. A second process using
// the same stable identity fails fast instead of racing crash reconciliation
// and reaping the first process's live workloads.
func acquireRunnerIdentityLock(dir string) (func(), error) {
	if err := os.MkdirAll(dir, identityDirMode); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "runner.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open runner identity lock: %w", err)
	}
	if info, serr := f.Stat(); serr != nil || !info.Mode().IsRegular() || !fileOwnedByEUID(info) || info.Mode().Perm()&0o022 != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("runner identity lock %s is not a trustworthy regular file owned by this user", path)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("runner identity %s is already active in another process; refusing to start a duplicate", dir)
		}
		return nil, fmt.Errorf("lock runner identity: %w", err)
	}
	if onDisk, lerr := os.Lstat(path); lerr != nil || !os.SameFile(mustStatInfo(f), onDisk) {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
		return nil, fmt.Errorf("runner identity lock %s was replaced during acquisition", path)
	}
	_ = f.Truncate(0)
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// mustStatInfo re-reads the descriptor for the SameFile check.
func mustStatInfo(f *os.File) os.FileInfo {
	info, err := f.Stat()
	if err != nil {
		return nil
	}
	return info
}
