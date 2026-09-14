//go:build !windows

package executor

import (
	"os/exec"
	"syscall"
)

// superviseChild is the non-Windows counterpart of the Job Object helper: on
// Unix the process group configured by configureProcess already gives
// killProcess the whole tree, so there is nothing to assign. It preserves the
// same post-Start contract as the Windows implementation — called
// synchronously after cmd.Start() and before any supervision goroutine reads
// cmd.Process — so the portable native backend needs no platform branching.
func superviseChild(cmd *exec.Cmd) (func(), error) { return func() {}, nil }

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
