package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
)

// writePrewarmedScript writes an executable fake that exits 0 immediately
// when KIWI_TEST_WARM is set, and executes it once so the OS first-exec cost
// of the freshly written file is paid before the bounded call under test.
// Without this, a host that scans first executions can kill a fake before it
// has produced any output, which is unrelated to the bound being tested.
func writePrewarmedScript(t *testing.T, name, body string) string {
	t.Helper()
	p := writeCleanupScript(t, name, body)
	t.Setenv("KIWI_TEST_WARM", "1")
	if err := exec.Command(p).Run(); err != nil {
		t.Fatalf("prewarm %s: %v", name, err)
	}
	t.Setenv("KIWI_TEST_WARM", "")
	return p
}

// TestBoundedToolCommandSuccessKeepsOutput proves the success path is
// unchanged: exit 0 returns the command output and no error. The timeout is
// generous because this test is about the result, not the bound.
func TestBoundedToolCommandSuccessKeepsOutput(t *testing.T) {
	testutil.UnixShell(t)
	fake := writeCleanupScript(t, "tool", "#!/bin/sh\necho \"$@\"\n")
	out, err := boundedToolCommand(context.Background(), 30*time.Second, fake, "delete", "kiwi-1")
	if err != nil {
		t.Fatalf("boundedToolCommand = %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "delete kiwi-1" {
		t.Fatalf("output = %q, want the invoked command line", got)
	}
}

// TestBoundedToolCommandHangingTimesOutTypedBoundedOutput is the shared
// helper contract: a binary that hangs returns within the bound with the typed
// timeout error, context.DeadlineExceeded, and output truncated so a hostile
// binary cannot flood the diagnostic.
func TestBoundedToolCommandHangingTimesOutTypedBoundedOutput(t *testing.T) {
	testutil.UnixShell(t)
	noisyHang := "#!/bin/sh\nif [ -n \"$KIWI_TEST_WARM\" ]; then exit 0; fi\ni=0\nwhile [ \"$i\" -lt 100 ]; do printf 'abcdefghij'; i=$((i+1)); done\nexec sleep 300\n"
	fake := writePrewarmedScript(t, "tool", noisyHang)

	start := time.Now()
	out, err := boundedToolCommand(context.Background(), 500*time.Millisecond, fake, "delete", "kiwi-1")
	elapsed := time.Since(start)
	if !errors.Is(err, ErrExternalCommandTimeout) {
		t.Fatalf("hanging command error = %v, want ErrExternalCommandTimeout", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error does not wrap context.DeadlineExceeded: %v", err)
	}
	if !strings.Contains(err.Error(), "delete kiwi-1") {
		t.Fatalf("timeout error does not name the command: %v", err)
	}
	if !strings.Contains(err.Error(), "[truncated]") {
		t.Fatalf("hostile output was not bounded: %v", err)
	}
	if len(err.Error()) > 1024 {
		t.Fatalf("timeout diagnostic is %d bytes, want a bounded line", len(err.Error()))
	}
	if len(out) == 0 {
		t.Fatal("timeout returned no captured output; the diagnostic lost the binary's output")
	}
	if elapsed > 10*time.Second {
		t.Fatalf("bounded command took %v; the caller was stranded", elapsed)
	}
}

// TestTartCloseJobHangingDeleteBounded is the tart.go delete site: a fake
// tart that hangs on `delete` must return within the bound with the typed
// timeout instead of stranding CloseJob.
func TestTartCloseJobHangingDeleteBounded(t *testing.T) {
	testutil.UnixShell(t)
	orig := tartCleanupTimeout
	tartCleanupTimeout = 150 * time.Millisecond
	t.Cleanup(func() { tartCleanupTimeout = orig })

	fake := writeCleanupScript(t, "tart", "#!/bin/sh\nexec sleep 300\n")
	b := &TartBackend{tart: fake, clone: "kiwi-1-0123456789abcdef"}
	start := time.Now()
	err := b.CloseJob()
	elapsed := time.Since(start)
	if !errors.Is(err, ErrExternalCommandTimeout) {
		t.Fatalf("hanging tart delete error = %v, want ErrExternalCommandTimeout", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error does not wrap context.DeadlineExceeded: %v", err)
	}
	if !strings.Contains(err.Error(), "delete kiwi-1-0123456789abcdef") {
		t.Fatalf("CloseJob error does not name the clone delete: %v", err)
	}
	if b.clone != "" {
		t.Fatalf("CloseJob left clone state %q", b.clone)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("bounded CloseJob took %v; the runner goroutine was stranded", elapsed)
	}
}

// TestTartDeleteCloneBoundedTypedTimeout exercises the helper the run-start
// failure path uses (the deferred delete after `tart run` cannot start) with
// a hanging fake tart.
func TestTartDeleteCloneBoundedTypedTimeout(t *testing.T) {
	testutil.UnixShell(t)
	orig := tartCleanupTimeout
	tartCleanupTimeout = 150 * time.Millisecond
	t.Cleanup(func() { tartCleanupTimeout = orig })

	fake := writeCleanupScript(t, "tart", "#!/bin/sh\nexec sleep 300\n")
	b := &TartBackend{tart: fake, clone: "kiwi-2-fedcba9876543210"}
	start := time.Now()
	err := b.deleteCloneBounded(context.Background())
	elapsed := time.Since(start)
	if !errors.Is(err, ErrExternalCommandTimeout) {
		t.Fatalf("hanging clone delete = %v, want ErrExternalCommandTimeout", err)
	}
	if !strings.Contains(err.Error(), "delete Tart VM") {
		t.Fatalf("delete error does not name the operation: %v", err)
	}
	if b.clone != "" {
		t.Fatalf("failed bounded delete left clone state %q", b.clone)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("bounded clone delete took %v", elapsed)
	}
	// A no-op delete never invokes the tool.
	if err := (&TartBackend{}).deleteCloneBounded(context.Background()); err != nil {
		t.Fatalf("empty deleteCloneBounded = %v", err)
	}
}

// TestTartDeleteCloneBoundedToleratesMissingVM proves the success/missing
// path is unchanged: tart's "does not exist" output is still tolerated.
func TestTartDeleteCloneBoundedToleratesMissingVM(t *testing.T) {
	testutil.UnixShell(t)
	fake := writeCleanupScript(t, "tart", "#!/bin/sh\necho 'VM \"kiwi-1\" does not exist' >&2\nexit 1\n")
	b := &TartBackend{tart: fake, clone: "kiwi-1"}
	if err := b.deleteCloneBounded(context.Background()); err != nil {
		t.Fatalf("missing VM must be tolerated: %v", err)
	}
}

// TestRunSSHKeygenHangingTimesOut is the tart.go keygen site: a hanging
// ssh-keygen returns the typed timeout within the bound.
func TestRunSSHKeygenHangingTimesOut(t *testing.T) {
	testutil.UnixShell(t)
	orig := sshKeygenTimeout
	sshKeygenTimeout = 150 * time.Millisecond
	t.Cleanup(func() { sshKeygenTimeout = orig })

	fake := writeCleanupScript(t, "ssh-keygen", "#!/bin/sh\nexec sleep 300\n")
	start := time.Now()
	err := runSSHKeygen(fake, filepath.Join(t.TempDir(), "id_ed25519"))
	elapsed := time.Since(start)
	if !errors.Is(err, ErrExternalCommandTimeout) {
		t.Fatalf("hanging ssh-keygen = %v, want ErrExternalCommandTimeout", err)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("bounded ssh-keygen took %v", elapsed)
	}
}

// TestGenerateEphemeralSSHKeyHangingKeygenFallsBackBounded proves the keygen
// path still falls back to the in-process generator (success path unchanged)
// within the bound when ssh-keygen hangs.
func TestGenerateEphemeralSSHKeyHangingKeygenFallsBackBounded(t *testing.T) {
	testutil.UnixShell(t)
	orig := sshKeygenTimeout
	sshKeygenTimeout = 150 * time.Millisecond
	t.Cleanup(func() { sshKeygenTimeout = orig })

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssh-keygen"), []byte("#!/bin/sh\nexec sleep 300\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	target := filepath.Join(t.TempDir(), "id_ed25519")
	start := time.Now()
	if err := generateEphemeralSSHKey(target); err != nil {
		t.Fatalf("keygen timeout must fall back to the Go generator: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("hanging keygen stranded job startup for %v", elapsed)
	}
	for _, path := range []string{target, target + ".pub"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("fallback key %s missing: %v", path, err)
		}
	}
}

// TestRunXFSQuotaCommandHangingTimesOutBounded is the diskquota.go site: a
// hanging fake xfs_quota returns within the bound with the typed timeout and
// the bounded output, so quota setup/cleanup can never strand the runner.
func TestRunXFSQuotaCommandHangingTimesOutBounded(t *testing.T) {
	testutil.UnixShell(t)
	orig := xfsQuotaTimeout
	xfsQuotaTimeout = 500 * time.Millisecond
	t.Cleanup(func() { xfsQuotaTimeout = orig })

	noisyHang := "#!/bin/sh\nif [ -n \"$KIWI_TEST_WARM\" ]; then exit 0; fi\ni=0\nwhile [ \"$i\" -lt 100 ]; do printf 'abcdefghij'; i=$((i+1)); done\nexec sleep 300\n"
	fake := writePrewarmedScript(t, "xfs_quota", noisyHang)
	start := time.Now()
	err := runXFSQuotaCommand(fake, "/mnt/xfs", "limit -p bhard=1 42")
	elapsed := time.Since(start)
	if !errors.Is(err, ErrExternalCommandTimeout) {
		t.Fatalf("hanging xfs_quota = %v, want ErrExternalCommandTimeout", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error does not wrap context.DeadlineExceeded: %v", err)
	}
	if !strings.Contains(err.Error(), "limit -p bhard=1 42") {
		t.Fatalf("xfs timeout error does not name the command: %v", err)
	}
	if !strings.Contains(err.Error(), "[truncated]") {
		t.Fatalf("hostile xfs output was not bounded: %v", err)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("bounded xfs_quota took %v", elapsed)
	}
}

// TestRunXFSQuotaCommandSuccessUnchanged proves a clean xfs_quota invocation
// still reports no error.
func TestRunXFSQuotaCommandSuccessUnchanged(t *testing.T) {
	testutil.UnixShell(t)
	fake := writeCleanupScript(t, "xfs_quota", "#!/bin/sh\nexit 0\n")
	if err := runXFSQuotaCommand(fake, "/mnt/xfs", "limit -p bhard=1 42"); err != nil {
		t.Fatalf("successful xfs_quota = %v", err)
	}
}

// TestTartRunHelpHangingBounded proves the capability probe cannot stall job
// startup: a hanging `tart run --help` returns empty help within the probe
// bound instead of blocking StartJob.
func TestTartRunHelpHangingBounded(t *testing.T) {
	testutil.UnixShell(t)
	orig := tartProbeTimeout
	tartProbeTimeout = 150 * time.Millisecond
	t.Cleanup(func() { tartProbeTimeout = orig })

	fake := writeCleanupScript(t, "tart", "#!/bin/sh\nexec sleep 300\n")
	start := time.Now()
	help := tartRunHelp(context.Background(), fake)
	elapsed := time.Since(start)
	if help != "" {
		t.Fatalf("hanging help probe returned %q, want empty", help)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("bounded help probe took %v", elapsed)
	}
}

// TestTartStartJobHangingIPProbeBounded proves a wedged `tart ip` cannot
// defeat the tartIPWait window: StartJob fails with the never-got-an-IP error
// within the bound instead of hanging forever.
func TestTartStartJobHangingIPProbeBounded(t *testing.T) {
	testutil.UnixShell(t)
	origWait := tartIPWait
	tartIPWait = 300 * time.Millisecond
	t.Cleanup(func() { tartIPWait = origWait })

	script := `#!/bin/sh
if [ -n "$KIWI_TEST_WARM" ]; then exit 0; fi
case "$1" in
  clone) exit 0;;
  run) if [ "$2" = "--help" ]; then echo "--cpu"; fi; exit 0;;
  ip) exec sleep 300;;
  get) echo '{"name":"vm","labels":{"kiwi.ssh.bootstrap":"true"}}'; exit 0;;
  delete) exit 0;;
esac
exit 0
`
	fake := writePrewarmedScript(t, "tart", script)
	t.Setenv("PATH", filepath.Dir(fake)+string(os.PathListSeparator)+os.Getenv("PATH"))

	b := &TartBackend{VM: "vm"}
	start := time.Now()
	err := b.StartJob(context.Background(), t.TempDir(), func(string) {})
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "did not obtain an IP") {
		t.Fatalf("hanging tart ip = %v, want the never-got-an-IP error", err)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("hanging tart ip stranded StartJob for %v", elapsed)
	}
}

// TestGCHangingToolsBounded proves a wedged docker/tart cannot strand a GC
// pass: the discovery commands and the removals are all bounded, and the
// hanging tools contribute nothing to the report.
func TestGCHangingToolsBounded(t *testing.T) {
	testutil.UnixShell(t)
	origQuery, origCleanup := gcCommandTimeout, gcCleanupTimeout
	gcCommandTimeout = 150 * time.Millisecond
	gcCleanupTimeout = 150 * time.Millisecond
	t.Cleanup(func() {
		gcCommandTimeout = origQuery
		gcCleanupTimeout = origCleanup
	})

	dir := t.TempDir()
	old := time.Now().Add(-48 * time.Hour).Format("2006-01-02 15:04:05 -0700 MST")
	docker := "#!/bin/sh\ncase \"$1\" in\n  ps) printf '%s\\n' \"cid1 " + old + "\"; exit 0;;\n  network) exit 0;;\nesac\nexec sleep 300\n"
	tart := "#!/bin/sh\nexec sleep 300\n"
	for name, body := range map[string]string{"docker": docker, "tart": tart} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	start := time.Now()
	rep := GC(context.Background(), t.TempDir(), time.Hour)
	elapsed := time.Since(start)
	if rep != (GCReport{}) {
		t.Fatalf("GC with hanging tools = %+v, want a zero report", rep)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("GC with hanging tools took %v; the pass was not bounded", elapsed)
	}
}

// TestWaitKilledCommandBoundedTypedTimeoutAndDrains is the W4-A primitive
// contract: a killed command whose wait cannot complete within the grace must
// return within the bound with a typed ErrExternalCommandTimeout (wrapping
// context.DeadlineExceeded), and the detached reaper must drain the eventual
// wait result once the process is finally reaped (no blocked send, no
// zombie). The wait is injected because a process wedged in an
// uninterruptible kernel wait cannot be fabricated portably.
func TestWaitKilledCommandBoundedTypedTimeoutAndDrains(t *testing.T) {
	testutil.UnixShell(t)
	origReap, origDetach := waitKilledReap, reapDetached
	released := make(chan struct{})
	waitEntered := make(chan struct{})
	waitKilledReap = func(cmd *exec.Cmd) error {
		close(waitEntered)
		<-released
		return cmd.Wait()
	}
	drained := make(chan error, 1)
	reapDetached = func(done <-chan error) {
		go func() { drained <- <-done }()
	}
	t.Cleanup(func() { waitKilledReap, reapDetached = origReap, origDetach })

	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := waitKilledCommand(cmd, 50*time.Millisecond)
	elapsed := time.Since(start)
	if !errors.Is(err, ErrExternalCommandTimeout) {
		t.Fatalf("bounded reap error = %v, want ErrExternalCommandTimeout", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bounded reap error does not wrap context.DeadlineExceeded: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("un-reapable kill/reap took %v; the caller was stranded", elapsed)
	}
	select {
	case <-waitEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("waitKilledCommand never called cmd.Wait")
	}
	// The process is finally reaped: the detached reaper must drain the
	// result, proving the reaper goroutine is not leaked with a blocked send.
	close(released)
	select {
	case werr := <-drained:
		if werr == nil {
			t.Fatal("detached reaper received a nil wait result for a SIGKILLed process")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("detached reaper did not drain the wait result")
	}
}

// TestWaitKilledCommandReapsKillableCommand proves the normal path: a
// killable command is killed and reaped through cmd.Wait (Cmd bookkeeping,
// never Process.Wait) well within the grace, with no error.
func TestWaitKilledCommandReapsKillableCommand(t *testing.T) {
	testutil.UnixShell(t)
	if err := waitKilledCommand(nil, time.Second); err != nil {
		t.Fatalf("nil command = %v", err)
	}
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := waitKilledCommand(cmd, 5*time.Second); err != nil {
		t.Fatalf("killable command reap = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("killable command reap took %v", elapsed)
	}
	if cmd.ProcessState == nil {
		t.Fatal("cmd.Wait bookkeeping missing: the process was not reaped through exec.Cmd")
	}
	if cmd.ProcessState.ExitCode() >= 0 {
		t.Fatalf("SIGKILLed process reported exit code %d, want a signaled exit", cmd.ProcessState.ExitCode())
	}
}

// TestTartCloseJobReapFailureNotMaskedByDeleteSuccess is the W4-A join rule:
// a bounded-reap failure must reach the caller even when the clone delete
// succeeds, and the command handle must not be dropped while the process is
// un-reaped.
func TestTartCloseJobReapFailureNotMaskedByDeleteSuccess(t *testing.T) {
	testutil.UnixShell(t)
	orig := reapKilledCommand
	reapKilledCommand = func(*exec.Cmd, time.Duration) error {
		return fmt.Errorf("%w: injected reap failure", ErrExternalCommandTimeout)
	}
	t.Cleanup(func() { reapKilledCommand = orig })

	fake := writeCleanupScript(t, "tart", "#!/bin/sh\nexit 0\n")
	run := exec.Command("sleep", "300")
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = run.Process.Kill()
		_ = run.Wait()
	})
	sshDir := t.TempDir()
	b := &TartBackend{tart: fake, clone: "kiwi-1-0123456789abcdef", sshDir: sshDir, run: run}
	err := b.CloseJob()
	if !errors.Is(err, ErrExternalCommandTimeout) {
		t.Fatalf("CloseJob with failed reap and successful delete = %v, want ErrExternalCommandTimeout", err)
	}
	if !strings.Contains(err.Error(), "injected reap failure") {
		t.Fatalf("CloseJob error does not name the reap failure: %v", err)
	}
	if b.clone != "" {
		t.Fatalf("CloseJob left clone state %q", b.clone)
	}
	if b.sshDir != "" {
		t.Fatalf("CloseJob left ssh dir state %q", b.sshDir)
	}
	if _, statErr := os.Stat(sshDir); !os.IsNotExist(statErr) {
		t.Fatalf("CloseJob did not remove the ssh dir: %v", statErr)
	}
	if b.run == nil {
		t.Fatal("failed reap dropped the command handle; an un-reaped process was forgotten")
	}
}

// TestTartCloseJobJoinsReapAndDeleteFailures proves both bounded failures are
// joined: neither the wedged reap nor the wedged clone delete can hide the
// other.
func TestTartCloseJobJoinsReapAndDeleteFailures(t *testing.T) {
	testutil.UnixShell(t)
	origReap, origTimeout := reapKilledCommand, tartCleanupTimeout
	tartCleanupTimeout = 150 * time.Millisecond
	reapKilledCommand = func(*exec.Cmd, time.Duration) error {
		return fmt.Errorf("%w: injected reap failure", ErrExternalCommandTimeout)
	}
	t.Cleanup(func() { reapKilledCommand, tartCleanupTimeout = origReap, origTimeout })

	fake := writeCleanupScript(t, "tart", "#!/bin/sh\nexec sleep 300\n")
	b := &TartBackend{tart: fake, clone: "kiwi-2-fedcba9876543210", run: exec.Command("sleep", "300")}
	start := time.Now()
	err := b.CloseJob()
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("reap and delete both failed but CloseJob reported success")
	}
	if !errors.Is(err, ErrExternalCommandTimeout) {
		t.Fatalf("joined CloseJob error = %v, want ErrExternalCommandTimeout", err)
	}
	for _, want := range []string{"injected reap failure", "delete Tart VM"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("joined CloseJob error %q missing %q", err, want)
		}
	}
	if elapsed > 10*time.Second {
		t.Fatalf("double-failure CloseJob took %v; the runner goroutine was stranded", elapsed)
	}
}

// TestTartCloseJobNormalPathUnchanged proves a live `tart run` process is
// still killed, reaped through cmd.Wait, and both ownership fields are
// cleared, with no error when the delete succeeds.
func TestTartCloseJobNormalPathUnchanged(t *testing.T) {
	testutil.UnixShell(t)
	fake := writeCleanupScript(t, "tart", "#!/bin/sh\nexit 0\n")
	run := exec.Command("sleep", "300")
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	sshDir := t.TempDir()
	b := &TartBackend{tart: fake, clone: "kiwi-3", sshDir: sshDir, run: run}
	if err := b.CloseJob(); err != nil {
		t.Fatalf("CloseJob: %v", err)
	}
	if b.run != nil {
		t.Fatal("CloseJob did not clear the reaped command handle")
	}
	if b.clone != "" || b.sshDir != "" {
		t.Fatalf("CloseJob did not clear session state: clone=%q sshDir=%q", b.clone, b.sshDir)
	}
	if run.ProcessState == nil {
		t.Fatal("CloseJob did not reap the process through cmd.Wait")
	}
	if _, statErr := os.Stat(sshDir); !os.IsNotExist(statErr) {
		t.Fatalf("CloseJob did not remove the ssh dir: %v", statErr)
	}
	if err := b.CloseJob(); err != nil {
		t.Fatalf("second CloseJob: %v", err)
	}
}
