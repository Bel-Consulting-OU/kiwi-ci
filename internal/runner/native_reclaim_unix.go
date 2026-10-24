//go:build !windows

package runner

import (
	"fmt"
	"syscall"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
)

// reclaimNativeServices kills leftover native-service process groups from a
// previous runner incarnation.
//
// Safety rules (PID reuse):
//   - never kill without a recorded start stamp;
//   - kill only when the live stamp still matches the recorded stamp;
//   - a dead PID is success (already gone); a live PID that cannot be
//     verified is recovery debt, not a blind kill.
func reclaimNativeServices(svcs []NativeServiceLedger) error {
	var firstErr error
	for _, ns := range svcs {
		if ns.PID <= 0 {
			continue
		}
		if !processAliveUnix(ns.PID) {
			continue
		}
		if ns.Start == "" {
			if firstErr == nil {
				firstErr = fmt.Errorf("native service %s pid %d is live but has no start stamp; refusing to kill an unverified PID", ns.Name, ns.PID)
			}
			continue
		}
		stamp := executor.ProcessStartStamp(ns.PID)
		if stamp == "" {
			if firstErr == nil {
				firstErr = fmt.Errorf("native service %s pid %d is live but start stamp is unreadable; refusing to kill", ns.Name, ns.PID)
			}
			continue
		}
		if stamp != ns.Start {
			// PID recycled; the original process is gone.
			continue
		}
		if ns.PGID > 1 {
			_ = syscall.Kill(-ns.PGID, syscall.SIGKILL)
		}
		if err := syscall.Kill(ns.PID, syscall.SIGKILL); err != nil && err != syscall.ESRCH && firstErr == nil {
			firstErr = fmt.Errorf("kill native service %s pid %d: %w", ns.Name, ns.PID, err)
		}
	}
	return firstErr
}

func processAliveUnix(pid int) bool {
	if pid <= 0 {
		return false
	}
	// Signal 0: existence/permission probe without delivering a signal.
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	if err == syscall.ESRCH {
		return false
	}
	// EPERM means the process exists but is not ours.
	return err == syscall.EPERM
}
