//go:build !windows

package executor

import (
	"fmt"
	"os"
	"syscall"
)

// lockPortClaimFile takes an exclusive flock on an already-open claim file
// and writes the identity payload. flock is released automatically when the
// file descriptor is closed or the process dies — no stale-delete ABA.
//
// errPortLocked is returned when another live holder has the lock.
var errPortLocked = fmt.Errorf("port claim locked by another process")

func portClaimLocked(err error) bool { return err == errPortLocked }

func lockPortClaimFile(f *os.File, payload []byte) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			return errPortLocked
		}
		return err
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.WriteAt(payload, 0); err != nil {
		return err
	}
	return nil
}
