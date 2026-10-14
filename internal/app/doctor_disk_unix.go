//go:build !windows

package app

import (
	"fmt"
	"syscall"
)

// diskUsage reports free/total for the filesystem holding path.
func diskUsage(path string) string {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return ""
	}
	free := int64(st.Bavail) * int64(st.Bsize)
	total := int64(st.Blocks) * int64(st.Bsize)
	if total == 0 {
		return ""
	}
	return fmt.Sprintf("%.1f GiB free of %.1f GiB", float64(free)/(1<<30), float64(total)/(1<<30))
}
