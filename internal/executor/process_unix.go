//go:build !windows

package executor

import (
	"os"
	"os/exec"
	"syscall"
)

// processAlive reports whether pid is a live process (signal 0 probe).
// Used to reclaim stale host-port claim locks left by a dead runner.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	if err == syscall.ESRCH {
		return false
	}
	return err == syscall.EPERM
}

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
