//go:build !unix

package runner

import "os"

// fileOwnedByEUID is a no-op off Unix (Windows uses the directory DACL
// established by secureIdentityDir for the identity tree; the ledger lives
// under the runner-owned WorkDir).
func fileOwnedByEUID(os.FileInfo) bool { return true }
