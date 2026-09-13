//go:build windows

package safefs

import (
	"fmt"
	"syscall"
	"unsafe"
)

func FitsAvailable(path string, maxBytes int64) error {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var free, total, totalFree uint64
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetDiskFreeSpaceExW")
	r, _, callErr := proc.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&free)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&totalFree)))
	if r == 0 {
		return callErr
	}
	if total > 0 && free < total/20 {
		return fmt.Errorf("safefs: less than 5%% free space")
	}
	if maxBytes > 0 && int64(free) < maxBytes {
		return fmt.Errorf("safefs: %d bytes required, %d available", maxBytes, free)
	}
	return nil
}
