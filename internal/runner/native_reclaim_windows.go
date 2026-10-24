//go:build windows

package runner

import "os"

// Windows native services are supervised by a Job Object with
// KILL_ON_JOB_CLOSE: losing the runner process already kills the tree.
// Ledger reclamation is a no-op beyond a direct PID kill attempt.
func reclaimNativeServices(svcs []NativeServiceLedger) error {
	var firstErr error
	for _, ns := range svcs {
		if ns.PID <= 0 {
			continue
		}
		p, err := os.FindProcess(ns.PID)
		if err != nil {
			continue
		}
		if err := p.Kill(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
