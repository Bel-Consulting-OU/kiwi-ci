//go:build !unix

package app

import (
	"fmt"
	"os"
)

// The non-unix variants have no euid or POSIX mode bits: ownership and mode
// checks are delegated to the platform ACLs, and only the type of the path is
// provable here. The symlink refusal on the unix side has no direct
// equivalent; O_EXCL still guarantees the exclusive-create property below.

// verifyUpStateDirOwner is a no-op where unix ownership has no analogue.
func verifyUpStateDirOwner(os.FileInfo) error { return nil }

// verifyUpTokenFileOwner is a no-op where unix ownership has no analogue.
func verifyUpTokenFileOwner(os.FileInfo) error { return nil }

// verifyUpTokenFileMode is a no-op: Windows synthesizes mode bits, so a POSIX
// 0600-style check would reject files the ACL already protects.
func verifyUpTokenFileMode(os.FileInfo) error { return nil }

// openUpTokenRead opens the token file after proving the path is not a
// symlink with Lstat (the platform has no O_NOFOLLOW).
func openUpTokenRead(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("token file %s is a symlink (remove it to regenerate)", path)
	}
	return os.Open(path)
}

// createUpTokenExclusive creates the token file exclusively.
func createUpTokenExclusive(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
}
