//go:build unix

package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// xfsAllocationLockDir is the host-global directory holding per-filesystem
// allocator locks. KIWI_XFS_LOCK_DIR overrides it (tests, unprivileged
// development); /run/lock is the conventional root-owned location. There is
// deliberately NO world-writable temp fallback: an attacker-replaceable
// directory would let two processes lock different inodes and allocate the
// same project ID (quota collisions), so an unusable lock directory fails the
// quota capability closed instead.
func xfsAllocationLockDir() string {
	if dir := strings.TrimSpace(os.Getenv("KIWI_XFS_LOCK_DIR")); dir != "" {
		return dir
	}
	return "/run/lock"
}

// lockFileOwnerOK reports whether the lock file belongs to the effective
// user, so a pre-created file owned by another local principal is refused.
func lockFileOwnerOK(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid())
}

// lockXFSAllocation takes an exclusive, host-global flock for one filesystem
// identity so the discover/choose/assign/limit sequence is atomic across
// runner PROCESSES, not merely goroutines. Hardening:
//
//   - the lock file is opened O_NOFOLLOW and must be a regular file owned by
//     the effective user and not group/other writable;
//   - after acquiring the flock the path is re-checked with SameFile, so an
//     unlink/recreate between open and flock (which would let two processes
//     hold locks on different inodes) is detected and retried;
//   - an unusable lock directory fails closed.
func lockXFSAllocation(fsKey string) (func(), error) {
	name := "kiwi-xfs-" + sanitizeXFSLockKey(fsKey) + ".lock"
	dir := xfsAllocationLockDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create XFS allocator lock directory %s: %w", dir, err)
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("XFS allocator lock directory %s is not a real directory", dir)
	}
	path := filepath.Join(dir, name)
	for attempt := 0; attempt < 5; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open XFS allocator lock %s: %w", path, err)
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || !lockFileOwnerOK(info) || info.Mode().Perm()&0o022 != 0 {
			_ = f.Close()
			return nil, fmt.Errorf("XFS allocator lock %s is not a trustworthy regular file owned by the runner", path)
		}
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("lock XFS allocator %s: %w", path, err)
		}
		onDisk, err := os.Lstat(path)
		if err == nil && os.SameFile(info, onDisk) {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		// The path was replaced while we waited: release and retry on the
		// current inode.
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}
	return nil, fmt.Errorf("XFS allocator lock %s kept being replaced", path)
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
