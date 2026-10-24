//go:build !linux

package executor

// No unified-hierarchy process migration outside Linux; PID ledger remains.
func writePIDToJobCgroup(parent string, pid int) error {
	_, _ = parent, pid
	return nil
}
