//go:build linux

package executor

import (
	"os/exec"
	"syscall"
	"testing"
)

// TestStartRetryAfterUseCgroupFDFailure pins the stdlib constraint that
// forced the production design: Go's exec.Cmd.Start is SINGLE-SHOT
// (startCalled is set even when the first call fails). A second Start on
// the same Cmd always returns "exec: already started". Production therefore
// FAILS CLOSED when clone-into-cgroup is rejected (see
// TestNativeRunUseCgroupFDFailureFailsClosed) rather than "retrying"
// outside the durable cgroup.
func TestStartRetryAfterUseCgroupFDFailure(t *testing.T) {
	bad := exec.Command("/bin/true")
	bad.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, UseCgroupFD: true, CgroupFD: 99999}
	err := bad.Start()
	if err == nil {
		_ = bad.Wait()
		t.Skip("kernel accepted bogus CgroupFD; cannot exercise the constraint")
	}
	// Same Cmd, second Start: ALWAYS already-started, never a real retry.
	if err2 := bad.Start(); err2 == nil {
		_ = bad.Wait()
		t.Fatal("std: second Start on the same Cmd must not silently succeed")
	} else if err2.Error() != "exec: already started" {
		t.Fatalf("second Start err = %v, want exec: already started", err2)
	}

	// A FRESH command with Setpgid only is how a caller would start if it
	// were not fail-closed — documents that only a new Cmd can Start.
	fresh := exec.Command("/bin/true")
	configureProcess(fresh)
	if startErr := fresh.Start(); startErr != nil {
		t.Fatalf("fresh Setpgid-only start: %v", startErr)
	}
	_ = fresh.Wait()
}
