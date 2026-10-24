//go:build !windows

package runner

import (
	"fmt"
	"syscall"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
)

// reclaimNativeServices kills leftover native-service process groups from a
// previous runner incarnation, but ONLY when the recorded start stamp still
// matches (PID-reuse guard). SIGKILL success is not proof of death: poll
// until the leader is gone or a bounded timeout elapses. A still-live tree
// after the timeout is recovery debt (error) so the caller retains the
// ledger entry instead of retiring it.
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
			if err := syscall.Kill(-ns.PGID, syscall.SIGKILL); err != nil && err != syscall.ESRCH && firstErr == nil {
				firstErr = fmt.Errorf("kill group pgid %d (%s): %w", ns.PGID, ns.Name, err)
			}
		}
		if err := syscall.Kill(ns.PID, syscall.SIGKILL); err != nil && err != syscall.ESRCH && firstErr == nil {
			firstErr = fmt.Errorf("kill native service %s pid %d: %w", ns.Name, ns.PID, err)
		}
		// Prove the leader is gone (or keep debt).
		if err := waitForPIDGone(ns.PID, 2*time.Second); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("native service %s pid %d still alive after SIGKILL: %w", ns.Name, ns.PID, err)
			}
		}
	}
	return firstErr
}

func waitForPIDGone(pid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !processAliveUnix(pid) {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !processAliveUnix(pid) {
		return nil
	}
	return fmt.Errorf("pid %d still present", pid)
}

func processAliveUnix(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	if err == syscall.ESRCH {
		return false
	}
	return err == syscall.EPERM
}
