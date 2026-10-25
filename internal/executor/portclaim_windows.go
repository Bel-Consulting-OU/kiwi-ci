//go:build windows

package executor

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// errPortLocked is returned when another live holder has the lock.
var errPortLocked = fmt.Errorf("port claim locked by another process")

func portClaimLocked(err error) bool { return err == errPortLocked }

// lockPortClaimFile takes an exclusive LockFileEx (fail-immediately) on an
// already-open claim file. The lock is released when the file handle is
// closed or the process exits — no stale-delete ABA.
func lockPortClaimFile(f *os.File, payload []byte) error {
	var ol windows.Overlapped
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY)
	err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, &ol)
	if err != nil {
		if err == windows.ERROR_LOCK_VIOLATION {
			return errPortLocked
		}
		return err
	}
	if err := f.Truncate(0); err != nil {
		_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ol)
		return err
	}
	if _, err := f.WriteAt(payload, 0); err != nil {
		_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ol)
		return err
	}
	// Handle close (release path) releases the lock.
	_ = ol
	return nil
}
