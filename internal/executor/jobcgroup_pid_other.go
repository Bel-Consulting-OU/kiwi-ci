//go:build !linux

package executor

import (
	"os/exec"
)

// writePIDToJobCgroup is a no-op outside Linux: there is no unified
// hierarchy process migration; the PID ledger remains the fallback.
func writePIDToJobCgroup(parent string, pid int) error {
	_, _ = parent, pid
	return nil
}

// configureProcessCgroup is a no-op beyond Setpgid outside Linux: there is
// no clone-into-cgroup. The post-Start addPIDToJobCgroup (also a no-op
// outside Linux) remains the ledger path. The returned closer is always
// non-nil so callers share one code path with Linux.
func configureProcessCgroup(cmd *exec.Cmd, cgroupParent string) (func(), error) {
	configureProcess(cmd)
	_ = cgroupParent
	return func() {}, nil
}

// cgroupFDActive is always false outside Linux (no UseCgroupFD).
func cgroupFDActive(cmd *exec.Cmd) bool {
	_ = cmd
	return false
}
