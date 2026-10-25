//go:build !windows

package runner

import (
	"fmt"
	"syscall"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
)

// reclaimNativeServices kills leftover native-service process groups from a
// previous runner incarnation using only OWNERSHIP PROOFS:
//
//   - Live leader + matching start stamp → kill the group and the leader;
//     the start stamp proves the PID (and therefore the group it leads) is
//     still our tree.
//   - Live leader + missing/mismatched start stamp → the PID was recycled.
//     The numerical PGID may now name an UNRELATED group (ABA: our tree
//     exited, the number was reused). Never kill(-PGID) in this state;
//     report recovery debt instead.
//   - Dead leader (PID gone) + recorded PGID → a process group with PGID=N
//     cannot be a newly created group unless some process occupies PID=N as
//     its leader (setpgid(p,p)). With PID=N gone, a non-empty group can only
//     be our orphaned descendants. Re-check PID absence immediately before
//     the kill to narrow the recycle race, then kill the group.
//   - Dead leader + empty group → nothing to do.
//
// When a durable job cgroup exists, reconcileRuntimeLedger reclaims THAT
// first and skips numeric PID/PGID reclamation entirely; cgroup.kill is the
// ownership primitive. This fallback is only for entries with no cgroup.
func reclaimNativeServices(svcs []NativeServiceLedger) error {
	var firstErr error
	for _, ns := range svcs {
		if ns.PID <= 0 && ns.PGID <= 1 {
			continue
		}
		pidAlive := ns.PID > 0 && processAliveUnix(ns.PID)
		if pidAlive {
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
				// PID recycled: the original leader is gone. The PGID number
				// may now name an unrelated process group — never kill it.
				if ns.PGID > 1 && !processGroupGoneUnix(ns.PGID) {
					if firstErr == nil {
						firstErr = fmt.Errorf("native service %s pid %d start stamp mismatch (recycled) and pgid %d is still populated; refusing to kill an unverified process group", ns.Name, ns.PID, ns.PGID)
					}
				}
				continue
			}
			// Proven our live leader.
			if ns.PGID > 1 {
				if err := syscall.Kill(-ns.PGID, syscall.SIGKILL); err != nil && err != syscall.ESRCH && firstErr == nil {
					firstErr = fmt.Errorf("kill group pgid %d (%s): %w", ns.PGID, ns.Name, err)
				}
			}
			if err := syscall.Kill(ns.PID, syscall.SIGKILL); err != nil && err != syscall.ESRCH && firstErr == nil {
				firstErr = fmt.Errorf("kill native service %s pid %d: %w", ns.Name, ns.PID, err)
			}
			if err := waitForPIDGone(ns.PID, 2*time.Second); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("native service %s pid %d still alive after SIGKILL: %w", ns.Name, ns.PID, err)
				}
			}
			if ns.PGID > 1 {
				if err := waitForProcessGroupGone(ns.PGID, 2*time.Second); err != nil {
					if firstErr == nil {
						firstErr = fmt.Errorf("native service %s pgid %d still populated after SIGKILL: %w", ns.Name, ns.PGID, err)
					}
				}
			}
			continue
		}
		// Leader PID is gone (or was never live). Only then is the numeric
		// PGID still attributable to our orphaned tree.
		if ns.PGID <= 1 {
			continue
		}
		if processGroupGoneUnix(ns.PGID) {
			continue
		}
		// Re-check immediately before the kill: if the leader PID reappeared
		// (recycled into a new group), do not kill an unverified group.
		if ns.PID > 0 && processAliveUnix(ns.PID) {
			if firstErr == nil {
				firstErr = fmt.Errorf("native service %s pgid %d: leader pid %d reappeared before kill; refusing to kill an unverified process group", ns.Name, ns.PGID, ns.PID)
			}
			continue
		}
		if err := syscall.Kill(-ns.PGID, syscall.SIGKILL); err != nil && err != syscall.ESRCH && firstErr == nil {
			firstErr = fmt.Errorf("kill orphan group pgid %d (%s): %w", ns.PGID, ns.Name, err)
		}
		if err := waitForProcessGroupGone(ns.PGID, 2*time.Second); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("native service %s pgid %d still populated after SIGKILL: %w", ns.Name, ns.PGID, err)
			}
		}
	}
	return firstErr
}

// processGroupGoneUnix reports whether kill(pgid, 0) sees no group (ESRCH).
func processGroupGoneUnix(pgid int) bool {
	return syscall.Kill(-pgid, 0) == syscall.ESRCH
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
		if processGroupGoneUnix(pgid) {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	if processGroupGoneUnix(pgid) {
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
