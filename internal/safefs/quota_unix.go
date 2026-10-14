//go:build !windows

package safefs

import (
	"fmt"
	"syscall"
)

// statfsFn is a test-only seam over syscall.Statfs. Production behavior is
// unchanged; it lets the checked low-free-space branch be exercised without a
// nearly full filesystem.
var statfsFn = syscall.Statfs

// FitsAvailable reports whether the filesystem containing path has enough
// free bytes. The safety floor is 1 GiB absolute; the historical 5% rule only
// applies to small volumes (under 20 GiB), where 5% is also under 1 GiB.
// On a 1 TB volume 5% is 50 GiB — refusing work when 44 GiB is free is wrong
// and made cache saves fail closed on healthy machines.
func FitsAvailable(path string, maxBytes int64) error {
	var st syscall.Statfs_t
	if err := statfsFn(path, &st); err != nil {
		return err
	}
	avail := int64(st.Bavail) * int64(st.Bsize)
	total := int64(st.Blocks) * int64(st.Bsize)
	const absFloor = int64(1) << 30 // 1 GiB
	if total > 0 {
		// 5% only on small volumes (under 20 GiB); large volumes use the
		// absolute 1 GiB floor. A 1 TB disk with 44 GiB free is healthy.
		if total < 20<<30 && avail < total/20 {
			return fmt.Errorf("safefs: less than 5%% free space")
		}
		if avail < absFloor {
			return fmt.Errorf("safefs: less than 1 GiB free space")
		}
	}
	if maxBytes > 0 && avail < maxBytes {
		return fmt.Errorf("safefs: %d bytes required, %d available", maxBytes, avail)
	}
	return nil
}
