//go:build windows

package app

import (
	"fmt"
	"syscall"
	"unsafe"
)

// diskUsage reports free/total for the filesystem holding path using the
// Windows GetDiskFreeSpaceExW API (syscall.Statfs_t is Unix-only).
func diskUsage(path string) string {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetDiskFreeSpaceExW")
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	var free, total, totalFree uint64
	r, _, _ := proc.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&free)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r == 0 || total == 0 {
		return ""
	}
	return fmt.Sprintf("%.1f GiB free of %.1f GiB", float64(free)/(1<<30), float64(total)/(1<<30))
}
