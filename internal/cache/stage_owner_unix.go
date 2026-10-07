//go:build unix

package cache

import (
	"os"
	"syscall"
)

// stageOwnedByCurrentUser reports whether a staging directory is owned by the
// effective user, so crash reclaim never removes another user's tree that
// happens to sit in a shared parent directory.
func stageOwnedByCurrentUser(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(st.Uid) == os.Geteuid()
}
