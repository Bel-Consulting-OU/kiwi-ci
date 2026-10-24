//go:build windows

package runner

// reclaimNativeServices on Windows does NOT kill by PID.
//
// Recorded native children were assigned to a Job Object with
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: losing the runner already terminates
// that tree. Killing a raw PID after crash has no start-identity check here
// and can destroy an unrelated process that reused the PID (P0 host-safety).
// Ledger entries are still retired by the caller once workspace/cgroup
// reclaim succeeds; a leftover Job Object dies with the runner handle.
func reclaimNativeServices(svcs []NativeServiceLedger) error {
	_ = svcs
	return nil
}
