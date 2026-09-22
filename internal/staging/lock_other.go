//go:build !unix

package staging

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// dirLock is the held exclusive ownership token of one staging directory on
// platforms without flock.
type dirLock struct {
	path  string
	owned bool
}

// acquireDirLock implements the documented non-flock fallback: an O_EXCL lock
// file carrying the owner's pid and identity. Creation is atomic, so exactly
// one process can own the directory; an existing lock file is treated as LIVE
// unless its recorded pid is provably dead.
//
// Stale-lock detection is deliberately conservative on this platform: pid
// liveness is probed best-effort, and any doubt (unparsable content, a pid
// recycled by an unrelated process, a probe the platform does not support) is
// treated as "live" so a stale lock can never admit a second writer. The
// operational cost is that a crashed owner's lock file may need to be removed
// by hand before the directory can be reused; that is strictly safer than two
// live ledgers over one disk bound.
func acquireDirLock(dir string) (*dirLock, error) {
	path := filepath.Join(dir, LockFileName)
	content := lockOwnerIdentity() + "\n"
	// One retry covers reclaiming a lock file whose owner is provably dead.
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, writeErr := f.WriteString(content)
			syncErr := f.Sync()
			closeErr := f.Close()
			if err := firstErr(writeErr, syncErr, closeErr); err != nil {
				_ = os.Remove(path)
				return nil, fmt.Errorf("staging: write lock file %s: %w", path, err)
			}
			return &dirLock{path: path, owned: true}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("staging: create lock file %s: %w", path, err)
		}
		data, readErr := os.ReadFile(path)
		if readErr == nil && !lockOwnerAlive(string(data)) {
			if err := os.Remove(path); err == nil {
				continue
			}
		}
		return nil, fmt.Errorf("%w: %s exists and its owner may still be live", ErrStagingDirOwned, path)
	}
	return nil, fmt.Errorf("%w: %s", ErrStagingDirOwned, path)
}

// release removes the lock file this owner created. It is nil-safe and
// idempotent.
func (l *dirLock) release() error {
	if l == nil || !l.owned {
		return nil
	}
	l.owned = false
	if err := os.Remove(l.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("staging: remove lock file %s: %w", l.path, err)
	}
	return nil
}

// lockOwnerAlive reports whether the lock file's recorded pid looks like a
// live process. Unknown or unparsable content is reported alive (fail
// closed): refusing a directory is recoverable, sharing it is not.
func lockOwnerAlive(content string) bool {
	pid := 0
	found := false
	for _, field := range strings.Fields(content) {
		if !strings.HasPrefix(field, "pid=") {
			continue
		}
		if _, err := fmt.Sscanf(field, "pid=%d", &pid); err != nil {
			return true
		}
		found = true
	}
	if !found || pid <= 0 || pid == os.Getpid() {
		// No usable pid, or a previous owner inside this very process that
		// never released: the directory is still not ours to share.
		return true
	}
	// A pid that cannot be opened no longer exists; a pid that can be opened
	// may be live (the platform's probe cannot tell more, so fail closed).
	if _, err := os.FindProcess(pid); err != nil {
		return false
	}
	return true
}
