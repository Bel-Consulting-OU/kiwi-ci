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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open runner identity lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("runner identity %s is already active in another process; refusing to start a duplicate", dir)
		}
		return nil, fmt.Errorf("lock runner identity: %w", err)
	}
	_ = f.Truncate(0)
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
