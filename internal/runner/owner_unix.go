//go:build unix

package runner

import (
	"os"
	"syscall"
)

// fileOwnedByEUID reports whether the file belongs to the effective user, so
// a pre-created attacker-owned ledger directory/file is never trusted.
func fileOwnedByEUID(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid())
}
