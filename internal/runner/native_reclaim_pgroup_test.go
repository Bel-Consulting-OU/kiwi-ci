//go:build !windows

package runner

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestReclaimNativeDeadLeaderRetainsDebt: when the recorded leader PID is
// gone but the numerical PGID is still populated, recovery must NOT
// kill(-PGID). The number can name an unrelated group (unrelated leader
// occupied PID=N, created PGID=N, spawned descendants, exited). Retain
// recovery debt instead — cgroup.kill or an operator is the authority.
func TestReclaimNativeDeadLeaderRetainsDebt(t *testing.T) {
	dir := t.TempDir()
	grandPidFile := dir + "/grand.pid"
	script := "sleep 30 & echo $! > " + grandPidFile + " ; exit 0"
	cmd := exec.Command("sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pgid := cmd.Process.Pid
	_ = cmd.Wait()
	deadline := time.Now().Add(2 * time.Second)
	for processAliveUnix(pgid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if processAliveUnix(pgid) {
		t.Skip("leader pid still live (recycled or wait incomplete)")
	}
	var b []byte
	var err error
	for i := 0; i < 40; i++ {
		b, err = os.ReadFile(grandPidFile)
		if err == nil && len(b) > 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("grand.pid: %v", err)
	}
	grand, perr := strconv.Atoi(strings.TrimSpace(string(b)))
	if perr != nil || grand <= 0 {
		t.Fatalf("bad grand pid %q", b)
	}
	if !processAliveUnix(grand) {
		t.Skip("grandchild already reaped; oracle needs a live descendant")
	}

	// Dead leader + populated PGID → debt, never kill.
	reclaimErr := reclaimNativeServices([]NativeServiceLedger{
		{Name: "svc", PID: pgid, PGID: pgid, Start: "stale"},
	})
	if reclaimErr == nil {
		t.Fatal("dead leader with populated pgid must report debt, not silent success")
	}
	if !strings.Contains(reclaimErr.Error(), "recovery debt") &&
		!strings.Contains(reclaimErr.Error(), "not ownership proof") {
		t.Fatalf("error = %v, want ownership-proof refusal / debt", reclaimErr)
	}
	// The descendant must survive: numerical PGID was not killed.
	if !processAliveUnix(grand) {
		t.Fatal("unverified PGID was killed: ABA host-safety violation")
	}
	if err := syscall.Kill(-pgid, 0); err != nil {
		t.Fatalf("group was killed: %v", err)
	}
	// Cleanup so the test does not leak.
	_ = syscall.Kill(grand, syscall.SIGKILL)
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
}

// TestReclaimNativeMissingPIDAndEmptyGroupIsSuccess: a fully-gone identity
// (PID absent AND group empty) is success, not debt.
func TestReclaimNativeMissingPIDAndEmptyGroupIsSuccess(t *testing.T) {
	if err := reclaimNativeServices([]NativeServiceLedger{{
		Name: "ghost", Port: 1, PID: 1 << 22, PGID: 1 << 22, Start: "x",
	}}); err != nil {
		t.Fatalf("missing pid + empty group = %v, want nil", err)
	}
}
