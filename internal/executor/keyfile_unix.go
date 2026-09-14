//go:build !windows

package executor

import "os"

// WriteOwnerOnly writes data to path with mode 0600. On Unix the file mode is
// the access-control mechanism: 0600 grants read/write to the owner only, so
// the file is owner-only by construction and no separate ACL handling exists.
func WriteOwnerOnly(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
