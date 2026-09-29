//go:build !unix

package cache

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// NamespaceLockFileName is the ownership lock file inside a runner cache
// namespace (see the unix implementation's documentation).
const NamespaceLockFileName = "kiwi-cache.lock"

// namespaceLock is the held exclusive ownership token on platforms without
// flock.
type namespaceLock struct {
	path  string
	owned bool
}

// acquireNamespaceLock implements the documented non-flock fallback: an
// O_EXCL lock file carrying the owner's pid and identity. Creation is atomic,
// so exactly one process owns the namespace; an existing lock file is LIVE
// unless its recorded pid is provably dead. Doubt is treated as live so a
// stale lock can never admit a second writer (the cost is that a crashed
// owner's lock file may need manual removal, which is strictly safer than two
// live ledgers over one disk bound).
func acquireNamespaceLock(dir string) (*namespaceLock, error) {
	path := filepath.Join(dir, NamespaceLockFileName)
	content := cacheOwnerIdentity() + "\n"
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_, writeErr := f.WriteString(content)
			syncErr := f.Sync()
			closeErr := f.Close()
			if err := firstNonNil(writeErr, syncErr, closeErr); err != nil {
				_ = os.Remove(path)
				return nil, fmt.Errorf("cache: write lock file %s: %w", path, err)
			}
			return &namespaceLock{path: path, owned: true}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("cache: create lock file %s: %w", path, err)
		}
		data, readErr := os.ReadFile(path)
		if readErr == nil && !cacheLockOwnerAlive(string(data)) {
			if err := os.Remove(path); err == nil {
				continue
			}
		}
		return nil, fmt.Errorf("%w: %s exists and its owner may still be live", ErrCacheDirOwned, path)
	}
	return nil, fmt.Errorf("%w: %s", ErrCacheDirOwned, path)
}

// release removes the lock file this owner created. It is nil-safe and
// idempotent.
func (l *namespaceLock) release() error {
	if l == nil || !l.owned {
		return nil
	}
	l.owned = false
	if err := os.Remove(l.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cache: remove lock file %s: %w", l.path, err)
	}
	return nil
}

// cacheLockOwnerAlive reports whether the lock file's recorded pid looks
// live. Unknown or unparsable content is reported alive (fail closed).
func cacheLockOwnerAlive(content string) bool {
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
		return true
	}
	if _, err := os.FindProcess(pid); err != nil {
		return false
	}
	return true
}

func firstNonNil(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
