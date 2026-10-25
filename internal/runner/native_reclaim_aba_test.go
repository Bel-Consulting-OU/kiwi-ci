//go:build !windows

package runner

import (
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
)

// TestReclaimNativeRefusesRecycledLeaderPGID is the ABA oracle: a live PID
// whose start stamp does not match means the original leader is gone AND the
// recorded PGID number may now name an UNRELATED process group. Recovery must
// report debt instead of kill(-PGID).
func TestReclaimNativeRefusesRecycledLeaderPGID(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_, _ = cmd.Process.Wait()
	}()
	pgid := cmd.Process.Pid
	err := reclaimNativeServices([]NativeServiceLedger{
		{Name: "aba", PID: pgid, PGID: pgid, Start: "not-the-real-stamp"},
	})
	if err == nil {
		t.Fatal("recycled/mismatched stamp must refuse to kill and report debt")
	}
	if !strings.Contains(err.Error(), "refusing to kill") {
		t.Fatalf("error = %v, want refusal", err)
	}
	if err := syscall.Kill(-pgid, 0); err != nil {
		t.Fatalf("unrelated group was killed: %v", err)
	}
	if !processAliveUnix(pgid) {
		t.Fatal("unrelated leader was killed")
	}
}

// TestReclaimNativeLedgerSkipsNumericWhenCgroupPresent pins the ledger
// reconciliation inversion: a durable job cgroup is reclaimed FIRST and
// numeric PID/PGID reclamation is skipped entirely for that entry — so a
// foreign live group recorded as a "native service" of a cgroup-backed job
// is never touched by the numeric path.
func TestReclaimNativeLedgerSkipsNumericWhenCgroupPresent(t *testing.T) {
	r := &Runner{ID: "runner-cg-first", Cfg: Config{WorkDir: t.TempDir()}}
	// Foreign live group. If numeric reclaim ran, this sleep would die.
	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_, _ = cmd.Process.Wait()
	}()
	// Matching start stamp so numeric reclaim WOULD kill if it ran.
	stamp := executor.ProcessStartStamp(cmd.Process.Pid)
	if stamp == "" {
		t.Skip("cannot read start stamp on this host")
	}
	_, err := r.ledgerAdd(runtimeLedgerEntry{
		JobID: "j", Instance: "old-instance",
		Cgroup:         "/delegated/kiwi-job-x",
		NativeServices: []NativeServiceLedger{{Name: "svc", PID: cmd.Process.Pid, PGID: cmd.Process.Pid, Start: stamp}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var cgroupCalls int
	origCG := reclaimJobCgroup
	reclaimJobCgroup = func(string) error {
		cgroupCalls++
		return nil
	}
	t.Cleanup(func() { reclaimJobCgroup = origCG })

	res, err := r.reconcileRuntimeLedger("new-instance")
	if err != nil {
		t.Fatalf("reconcile: %v (res=%+v)", err, res)
	}
	if cgroupCalls != 1 {
		t.Fatalf("cgroup reclaim calls = %d, want 1", cgroupCalls)
	}
	// Numeric path must not have run: the foreign group is still alive.
	if err := syscall.Kill(-cmd.Process.Pid, 0); err != nil {
		t.Fatalf("group killed despite cgroup-first path: %v", err)
	}
	if !processAliveUnix(cmd.Process.Pid) {
		t.Fatal("leader killed despite cgroup-first path")
	}
	entries, _ := filepath.Glob(filepath.Join(r.runtimeLedgerDir(), "*.json"))
	if len(entries) != 0 {
		t.Fatalf("ledger entries left after successful reclaim: %v", entries)
	}
}
