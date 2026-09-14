//go:build !windows

package executor

import (
	"os/exec"
	"syscall"
)

// setupChildJob is the non-Windows counterpart of the Job Object helper: on
// Unix the process group configured by configureProcess already gives
// killProcess the whole tree, so nothing extra is needed.
func setupChildJob(cmd *exec.Cmd) func() { return func() {} }

func configureProcess(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func terminateProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
}
func killProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
