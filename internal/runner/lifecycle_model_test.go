package runner

import (
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
)

// Lifecycle model: a crashed incarnation's native PID in the ledger must be
// reclaimed by the next incarnation (or left as debt — never a silent leak).
func TestLifecycleCrashNativeReclaim(t *testing.T) {
	workDir := t.TempDir()
	r := newLedgerRunner("lifecycle-crash", workDir)

	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skipf("sleep: %v", err)
	}
	pid := cmd.Process.Pid
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	time.Sleep(80 * time.Millisecond)

	id, err := r.ledgerAdd(runtimeLedgerEntry{
		Instance:  "old-instance",
		JobID:     "job-crash",
		Workspace: filepath.Join(workDir, "not-runner-owned-ws"),
	})
	if err != nil {
		t.Fatal(err)
	}
	stamp := executor.ProcessStartStamp(pid)
	if stamp == "" {
		// Cannot establish identity; reclaim must refuse, not kill blindly.
		stamp = ""
	}
	if err := r.ledgerSetNativeServices(id, []executor.NativeServiceInfo{{
		Name: "sleeper", Port: 1, PID: pid, PGID: pid, Start: stamp,
	}}); err != nil {
		t.Fatal(err)
	}

	// New incarnation reconciles a STALE instance id.
	lres, err := r.reconcileRuntimeLedger("not-the-recording-instance")
	// Workspace path is not runner-owned ("kiwi-run-none" basename is —
	// prefix is kiwi-run- so removeLedgerPath may try). Ensure we don't
	// hang on the workspace path we never created.
	if err != nil {
		t.Logf("reconcile returned: %v (pending=%d)", err, lres.Pending)
	}

	// Oracle: process is dead OR reconcile reported debt (error).
	alive := cmd.Process.Signal(nil) == nil
	if alive && err == nil {
		_ = cmd.Process.Kill()
		t.Fatal("reclaim succeeded but sleep process still alive")
	}
	if !alive {
		return // reaped
	}
	// Still alive with error → debt path is acceptable (unverified stamp).
	if stamp == "" {
		return
	}
	// Alive with a recorded stamp: reclaim should have killed when stamps
	// match. If still alive and no error, that's a miss (handled above).
	_ = lres
}
