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

// TestReclaimNativeProcessGroupDeadLeaderLiveDescendant pins the audit
// oracle: a dead group LEADER with a still-live descendant in the recorded
// PGID is recovery debt, not a skip. The leader PID alone is never proof
// the tree is gone.
func TestReclaimNativeProcessGroupDeadLeaderLiveDescendant(t *testing.T) {
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
	// Leader is gone; grandchild remains in the process group.
	deadline := time.Now().Add(2 * time.Second)
	for processAliveUnix(pgid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if processAliveUnix(pgid) {
		t.Skip("leader pid still live (recycled or wait incomplete)")
	}
	// Wait for the grandchild pid file.
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

	// Recovery: dead leader (stamp mismatch is irrelevant once leader is
	// gone) + recorded PGID must still kill the group.
	if err := reclaimNativeServices([]NativeServiceLedger{
		{Name: "svc", PID: pgid, PGID: pgid, Start: "stale"},
	}); err != nil {
		t.Fatalf("reclaim with dead leader must prove group gone: %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for processAliveUnix(grand) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if processAliveUnix(grand) {
		_ = syscall.Kill(grand, syscall.SIGKILL)
		t.Fatal("descendant survived reclaim: process-group proof is missing")
	}
}
