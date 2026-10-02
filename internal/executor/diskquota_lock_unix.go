//go:build unix

package executor

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// xfsAllocationLockDir is the host-global directory holding per-filesystem
// allocator locks. KIWI_XFS_LOCK_DIR overrides it (tests, unprivileged
// development); /run/lock is the conventional root-owned location.
func xfsAllocationLockDir() string {
	if dir := strings.TrimSpace(os.Getenv("KIWI_XFS_LOCK_DIR")); dir != "" {
		return dir
	}
	return "/run/lock"
}

// lockXFSAllocation takes an exclusive, host-global flock for one filesystem
// identity so the discover/choose/assign/limit sequence is atomic across
// runner PROCESSES, not merely goroutines. It returns the unlock function.
// The lock file content is irrelevant (the flock is the lock); the file is
// left behind, which is harmless.
func lockXFSAllocation(fsKey string) (func(), error) {
	name := "kiwi-xfs-" + sanitizeXFSLockKey(fsKey) + ".lock"
	path := filepath.Join(xfsAllocationLockDir(), name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		// Fall back to the temp dir when /run/lock is not writable (tests,
		// unprivileged dev): the lock is still host-global for processes
		// sharing the temp dir.
		path = filepath.Join(os.TempDir(), name)
		f, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// sanitizeXFSLockKey keeps the lock filename safe for any fsKey rendering.
func sanitizeXFSLockKey(fsKey string) string {
	var b strings.Builder
	for _, r := range fsKey {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}
