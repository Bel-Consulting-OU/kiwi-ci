//go:build !windows

package executor

import (
	"os"
	"syscall"
)

// fileOwnedByCurrentUID reports whether info is owned by this process's UID.
func fileOwnedByCurrentUID(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(st.Uid) == os.Getuid()
}

// claimFileTrusted reports whether an OPENED port-claim file is safe to
// truncate and rewrite. Even inside a 0700 directory the file itself must
// be ours: a file pre-planted by another user (before the directory was
// tightened, or via a shared parent) must never be written through.
// Package-level var so tests can force the untrusted outcome without
// fabricating a foreign-owned file (which needs privilege).
var claimFileTrusted = func(info os.FileInfo) bool {
	return fileOwnedByCurrentUID(info)
}

// openPortClaimFileNoFollow opens path O_RDWR|O_CREATE|O_NOFOLLOW so a
// pre-planted symlink is never followed.
func openPortClaimFileNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
}

// openPortClaimFileRead opens an existing claim file for reading without
// following symlinks.
func openPortClaimFileRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
