//go:build !windows

package runner

import (
	"fmt"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"syscall"
)

// reclaimNativeServices kills leftover native-service process groups from a
// previous runner incarnation, but only when the recorded start stamp still
// matches (PID-reuse guard).
func reclaimNativeServices(svcs []NativeServiceLedger) error {
	var firstErr error
	for _, ns := range svcs {
		if ns.PID <= 0 {
			continue
		}
		if ns.Start != "" {
			if stamp := executor.ProcessStartStamp(ns.PID); stamp != "" && stamp != ns.Start {
				continue
			}
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
