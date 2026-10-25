//go:build windows

package executor

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// lockPortClaimFile takes an exclusive LockFileEx on the port claim file
// (fail-immediately). The lock is released by the kernel when the process
// exits, so a crashed runner's stale lock never blocks reclamation and two
// reclaimers cannot both succeed (no read-delete-create ABA).
func lockPortClaimFile(path string, payload []byte) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	var ol windows.Overlapped
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY)
	err = windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, &ol)
	if err != nil {
		_ = f.Close()
		if err == windows.ERROR_LOCK_VIOLATION {
			return nil, errPortLocked
		}
		return nil, err
	}
	if err := f.Truncate(0); err != nil {
		_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ol)
		_ = f.Close()
		return nil, err
	}
	if _, err := f.WriteAt(payload, 0); err != nil {
		_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ol)
		_ = f.Close()
		return nil, err
	}
	// Closing the handle releases the lock (and process exit would too).
	_ = ol
	return f, nil
}

// errPortLocked is returned when another live process holds the lock.
var errPortLocked = fmt.Errorf("port claim locked by another process")

func portClaimLocked(err error) bool { return err == errPortLocked }
