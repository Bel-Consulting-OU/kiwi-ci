//go:build linux

package executor

import (
	"os/exec"
	"syscall"
	"testing"
)

// TestStartRetryAfterUseCgroupFDFailure is the oracle for a bug we actually
// shipped: Go's exec.Cmd.Start is SINGLE-SHOT (startCalled is set even when
// the first call fails), so a UseCgroupFD failure must rebuild a FRESH
// command. Re-calling Start on the same Cmd yields "exec: already started"
// and every cgroup-attached native step would die on kernels that reject
// clone-into-cgroup.
func TestStartRetryAfterUseCgroupFDFailure(t *testing.T) {
	bad := exec.Command("/bin/true")
	bad.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, UseCgroupFD: true, CgroupFD: 99999}
	err := bad.Start()
	if err == nil {
		_ = bad.Wait()
		t.Skip("kernel accepted bogus CgroupFD; cannot exercise the fallback")
	}
	// Same Cmd, second Start: ALWAYS already-started, never a real retry.
	if err2 := bad.Start(); err2 == nil {
		_ = bad.Wait()
		t.Fatal("std: second Start on the same Cmd must not silently succeed")
	} else if err2.Error() != "exec: already started" {
		t.Fatalf("second Start err = %v, want exec: already started", err2)
	}

	// The production fallback: a FRESH command with Setpgid only must start.
	fresh := exec.Command("/bin/true")
	configureProcess(fresh)
	if startErr := fresh.Start(); startErr != nil {
		fallback := exec.Command("/bin/true")
		configureProcess(fallback)
		if err2 := fallback.Start(); err2 != nil {
			t.Fatalf("fresh Setpgid-only start: %v (after %v)", err2, startErr)
		}
		_ = fallback.Wait()
		return
	}
	_ = fresh.Wait()
}
