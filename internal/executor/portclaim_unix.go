//go:build !windows

package executor

import (
	"fmt"
	"os"
	"syscall"
)

// lockPortClaimFile takes an exclusive flock on the port claim file,
// creating it if needed. flock is released automatically when the holding
// process dies, so a stale lock from a crashed runner never blocks the next
// claimant — and two racing reclaimers cannot both hold the lock (no
// read-delete-create ABA).
//
// Returns the open file (lock held) or an error. The caller must Close the
// file to release the lock.
func lockPortClaimFile(path string, payload []byte) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			return nil, errPortLocked
		}
		return nil, err
	}
	// We hold the lock: write (or overwrite) the identity payload.
	if err := f.Truncate(0); err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err := f.WriteAt(payload, 0); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// errPortLocked is returned when another live process holds the flock.
var errPortLocked = fmt.Errorf("port claim locked by another process")

// portClaimLocked reports whether err is the "someone else holds it" case.
func portClaimLocked(err error) bool { return err == errPortLocked }
