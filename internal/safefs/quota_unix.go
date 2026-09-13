//go:build !windows

package safefs

import (
	"fmt"
	"syscall"
)

// FitsAvailable reports whether the filesystem containing path has enough
// free bytes. With maxBytes <= 0 it only enforces a 5% free-space safety
// threshold.
func FitsAvailable(path string, maxBytes int64) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return err
	}
	avail := int64(st.Bavail) * int64(st.Bsize)
	total := int64(st.Blocks) * int64(st.Bsize)
	if total > 0 && avail < total/20 {
		return fmt.Errorf("safefs: less than 5%% free space")
	}
	if maxBytes > 0 && avail < maxBytes {
		return fmt.Errorf("safefs: %d bytes required, %d available", maxBytes, avail)
	}
	return nil
}
