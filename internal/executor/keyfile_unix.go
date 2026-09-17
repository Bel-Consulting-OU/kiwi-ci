//go:build !windows

package executor

import (
	"errors"
	"fmt"
	"os"
)

// WriteOwnerOnly writes data to path with mode 0600. On Unix the file mode is
// the access-control mechanism: 0600 grants read/write to the owner only, so
// the file is owner-only by construction and no separate ACL handling exists.
//
// The file is created with O_EXCL so an existing path (possibly world
// readable, or a pre-planted symlink) is never written through: it is
// removed and recreated at 0600 instead of inheriting its previous mode.
func WriteOwnerOnly(path string, data []byte) error {
	const attempts = 3
	for i := 0; i < attempts; i++ {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			if cerr := f.Chmod(0o600); cerr != nil {
				f.Close()
				_ = os.Remove(path)
				return cerr
			}
			_, werr := f.Write(data)
			cerr := f.Close()
			if werr != nil {
				_ = os.Remove(path)
				return werr
			}
			return cerr
		}
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		if rerr := os.Remove(path); rerr != nil {
			return fmt.Errorf("executor: replace existing key file: %w", rerr)
		}
	}
	return fmt.Errorf("executor: key file %s could not be created exclusively", path)
}
