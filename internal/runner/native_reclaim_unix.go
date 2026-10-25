//go:build !windows

package runner

import (
	"fmt"
	"syscall"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
)

// reclaimNativeServices kills leftover native-service process groups from a
// previous runner incarnation. Proof is about the PROCESS GROUP, not only
// the leader: a leader can exit while descendants remain in the PGID, and a
// recycled leader PID with a mismatched start stamp must not be trusted.
//
//   - Live leader + matching start stamp → kill the group and the leader,
//     then prove the leader is gone (and the group is empty).
//   - Dead leader + recorded PGID → still kill(-PGID): descendants may
//     survive the leader. A recycled PGID is the residual risk accepted for
//     crash recovery of our own recorded group (the same class as PID
//     recycling, bounded by the durable ledger identity of this job).
//   - Live leader + missing/mismatched start stamp → refuse to kill (PID
//     reuse guard).
func reclaimNativeServices(svcs []NativeServiceLedger) error {
	var firstErr error
	for _, ns := range svcs {
		if ns.PID <= 0 && ns.PGID <= 1 {
			continue
		}
		leaderAlive := ns.PID > 0 && processAliveUnix(ns.PID)
		if leaderAlive {
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
				// PID recycled; the original leader is gone. Still try the
				// group below: descendants of the original tree may live.
				leaderAlive = false
			}
		}
		if !leaderAlive && (ns.PGID <= 1) {
			continue
		}
		if ns.PGID > 1 {
			if err := syscall.Kill(-ns.PGID, syscall.SIGKILL); err != nil && err != syscall.ESRCH && firstErr == nil {
				firstErr = fmt.Errorf("kill group pgid %d (%s): %w", ns.PGID, ns.Name, err)
			}
		}
		if leaderAlive {
			if err := syscall.Kill(ns.PID, syscall.SIGKILL); err != nil && err != syscall.ESRCH && firstErr == nil {
				firstErr = fmt.Errorf("kill native service %s pid %d: %w", ns.Name, ns.PID, err)
			}
			if err := waitForPIDGone(ns.PID, 2*time.Second); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("native service %s pid %d still alive after SIGKILL: %w", ns.Name, ns.PID, err)
				}
			}
		}
		// Prove the process GROUP is empty when we have a PGID: a dead
		// leader with a live grandchild is recovery debt, not success.
		if ns.PGID > 1 {
			if err := waitForProcessGroupGone(ns.PGID, 2*time.Second); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("native service %s pgid %d still populated after SIGKILL: %w", ns.Name, ns.PGID, err)
				}
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

// waitForProcessGroupGone polls kill(pgid, 0) until the group has no
// remaining members (ESRCH) or the timeout elapses.
func waitForProcessGroupGone(pgid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		err := syscall.Kill(-pgid, 0)
		if err == syscall.ESRCH {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	err := syscall.Kill(-pgid, 0)
	if err == syscall.ESRCH {
		return nil
	}
	return fmt.Errorf("process group %d still present", pgid)
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
