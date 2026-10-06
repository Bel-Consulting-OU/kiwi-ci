//go:build !unix

package runner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// acquireRunnerIdentityLock takes an exclusive <IdentityDir>/runner.lock via
// O_EXCL on platforms without flock. A lock whose recorded PID is no longer
// alive is reclaimed; a live PID refuses the duplicate identity. Stale locks
// from a process the OS cannot prove dead require manual removal (documented).
func acquireRunnerIdentityLock(dir string) (func(), error) {
	if err := os.MkdirAll(dir, identityDirMode); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "runner.lock")
	for attempt := 0; attempt < 3; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			// The PID publication must be CHECKED: a failed write leaves a
			// lock file whose owner cannot be proven, and reporting success
			// on it would be worse than refusing.
			if _, werr := fmt.Fprintf(f, "%d\n", os.Getpid()); werr != nil {
				_ = f.Close()
				_ = os.Remove(path)
				return nil, fmt.Errorf("write runner identity lock: %w", werr)
			}
			if serr := f.Sync(); serr != nil {
				_ = f.Close()
				_ = os.Remove(path)
				return nil, fmt.Errorf("sync runner identity lock: %w", serr)
			}
			return func() {
				_ = f.Close()
				_ = os.Remove(path)
			}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create runner identity lock: %w", err)
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			// Unreadable: cannot prove anyone dead. Doubt is LIVE.
			return nil, fmt.Errorf("runner identity %s has an unreadable lock; refusing to start a duplicate", dir)
		}
		if classifyIdentityLock(b, processAlive) == identityLockLive {
			return nil, fmt.Errorf("runner identity %s is already active; refusing to start a duplicate", dir)
		}
		if rmErr := os.Remove(path); rmErr != nil {
			// Reclaim raced another creator: refuse rather than spin.
			return nil, fmt.Errorf("runner identity %s is already active; refusing to start a duplicate", dir)
		}
	}
	return nil, fmt.Errorf("runner identity lock %s could not be acquired", path)
}
