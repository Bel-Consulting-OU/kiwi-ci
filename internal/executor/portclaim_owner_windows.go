//go:build windows

package executor

import "os"

// fileOwnedByCurrentUID is always true on Windows: the claim directory is
// under the process user's temp tree and the runner refuses non-regular
// paths; NTFS ACLs already scope the directory to the profile.
func fileOwnedByCurrentUID(info os.FileInfo) bool {
	return info.Mode().IsDir()
}

// claimFileTrusted: Windows has no uid; the pre-open Lstat regular-file
// rejection plus the per-user temp tree (NTFS ACLs) are the ownership
// boundary here. Var (not func) so tests can force the untrusted outcome.
var claimFileTrusted = func(info os.FileInfo) bool {
	return info.Mode().IsRegular()
}

// openPortClaimFileNoFollow opens (creating) the claim file. Windows does
// not have O_NOFOLLOW; the caller Lstats first and rejects non-regular
// paths (symlinks/reparse points) before opening.
func openPortClaimFileNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
}

// openPortClaimFileRead opens an existing claim file for reading.
func openPortClaimFileRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY, 0)
}
