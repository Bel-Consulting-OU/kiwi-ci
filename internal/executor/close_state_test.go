package executor

// Teardown state-machine regressions: runtime removal must be PROVEN before
// workspace protections are torn down or runtime identity is dropped, and
// cleanup callbacks must stay retryable until they succeed.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContainerCloseRemoveFailureRetainsContainerIdentity(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_RM_EXIT", "1")
	b := &ContainerBackend{docker: "docker", container: "kiwi-job-1"}
	quotaCalls, restoreCalls := 0, 0
	b.quotaCleanup = func() error { quotaCalls++; return nil }
	b.restoreWorkspace = func() error { restoreCalls++; return nil }

	if err := b.CloseJob(); err == nil {
		t.Fatal("CloseJob with a failing docker rm = nil")
	}
	if b.container != "kiwi-job-1" {
		t.Fatalf("container identity lost after failed removal: %q", b.container)
	}
	if quotaCalls != 0 || restoreCalls != 0 {
		t.Fatalf("workspace teardown ran before the container was proven gone: quota=%d restore=%d", quotaCalls, restoreCalls)
	}
	if b.quotaCleanup == nil || b.restoreWorkspace == nil {
		t.Fatal("workspace callbacks discarded before running")
	}

	// Retry: docker rm succeeds, so the identity clears and the teardown runs
	// exactly once.
	t.Setenv("FAKE_DOCKER_RM_EXIT", "0")
	if err := b.CloseJob(); err != nil {
		t.Fatalf("retry CloseJob: %v", err)
	}
	if b.container != "" || quotaCalls != 1 || restoreCalls != 1 {
		t.Fatalf("retry state = container %q quota=%d restore=%d", b.container, quotaCalls, restoreCalls)
	}
	// Idempotent replay: no double teardown.
	if err := b.CloseJob(); err != nil {
		t.Fatalf("replayed CloseJob: %v", err)
	}
	if quotaCalls != 1 || restoreCalls != 1 {
		t.Fatalf("replayed teardown ran again: quota=%d restore=%d", quotaCalls, restoreCalls)
	}
}

func TestContainerCloseNoSuchContainerAllowsTeardown(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_RM_EXIT", "1")
	t.Setenv("FAKE_DOCKER_RM_MSG", "Error: No such container: kiwi-job-1")
	b := &ContainerBackend{docker: "docker", container: "kiwi-job-1"}
	quotaCalls := 0
	b.quotaCleanup = func() error { quotaCalls++; return nil }
	if err := b.CloseJob(); err != nil {
		t.Fatalf("proven-absent container must allow teardown: %v", err)
	}
	if b.container != "" || quotaCalls != 1 {
		t.Fatalf("container %q quotaCalls=%d, want cleared/1", b.container, quotaCalls)
	}
}

func TestQuotaCleanupFailureRetainsCallback(t *testing.T) {
	b := &ContainerBackend{}
	calls := 0
	boom := errors.New("xfs cleanup failed (id quarantined)")
	b.quotaCleanup = func() error {
		calls++
		if calls == 1 {
			return boom
		}
		return nil
	}
	if err := b.CloseJob(); !errors.Is(err, boom) {
		t.Fatalf("first CloseJob = %v, want the cleanup failure", err)
	}
	if b.quotaCleanup == nil {
		t.Fatal("failed quota cleanup discarded its callback")
	}
	if err := b.CloseJob(); err != nil {
		t.Fatalf("retry CloseJob: %v", err)
	}
	if calls != 2 || b.quotaCleanup != nil {
		t.Fatalf("retry calls=%d callbackSet=%t, want 2/false", calls, b.quotaCleanup != nil)
	}
	// A successful cleanup clears exactly once.
	if err := b.CloseJob(); err != nil || calls != 2 {
		t.Fatalf("replay: err=%v calls=%d, want nil/2", err, calls)
	}
}

func TestWorkspaceRestoreFailureRetainsCallback(t *testing.T) {
	b := &ContainerBackend{}
	calls := 0
	boom := errors.New("chown failed")
	b.restoreWorkspace = func() error {
		calls++
		if calls == 1 {
			return boom
		}
		return nil
	}
	if err := b.CloseJob(); !errors.Is(err, boom) {
		t.Fatalf("first CloseJob = %v, want the restore failure", err)
	}
	if b.restoreWorkspace == nil {
		t.Fatal("failed workspace restore discarded its callback")
	}
	if err := b.CloseJob(); err != nil {
		t.Fatalf("retry CloseJob: %v", err)
	}
	if calls != 2 || b.restoreWorkspace != nil {
		t.Fatalf("retry calls=%d callbackSet=%t, want 2/false", calls, b.restoreWorkspace != nil)
	}
}

func TestTartDeleteFailureRetainsClone(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_TART_DELETE_EXIT", "1")
	sshDir := t.TempDir()
	b := &TartBackend{tart: "tart", clone: "kiwi-vm-1", sshDir: sshDir}
	if err := b.CloseJob(); err == nil {
		t.Fatal("CloseJob with a failing tart delete = nil")
	}
	if b.clone != "kiwi-vm-1" {
		t.Fatalf("clone identity lost after failed delete: %q", b.clone)
	}
	if _, err := os.Stat(sshDir); err != nil {
		t.Fatalf("per-job SSH state removed while the VM may still exist: %v", err)
	}

	// Retry uses the SAME clone and only then clears state.
	t.Setenv("FAKE_TART_DELETE_EXIT", "0")
	if err := b.CloseJob(); err != nil {
		t.Fatalf("retry CloseJob: %v", err)
	}
	if b.clone != "" {
		t.Fatalf("clone not cleared after successful delete: %q", b.clone)
	}
	if _, err := os.Stat(sshDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("SSH state not removed after successful delete: %v", err)
	}
}

func TestTartMissingCloneClearsState(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_TART_DELETE_EXIT", "1")
	t.Setenv("FAKE_TART_DELETE_MSG", "vm does not exist")
	b := &TartBackend{tart: "tart", clone: "kiwi-vm-1", sshDir: filepath.Join(t.TempDir(), "ssh")}
	if err := os.MkdirAll(b.sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := b.CloseJob(); err != nil {
		t.Fatalf("proven-absent clone must not fail: %v", err)
	}
	if b.clone != "" {
		t.Fatalf("clone not cleared after proven absence: %q", b.clone)
	}
}

// TestContainerLabelsOwnedIncludesRunnerIdentity pins the label contract used
// by crash reconciliation.
func TestContainerLabelsOwnedIncludesRunnerIdentity(t *testing.T) {
	got := strings.Join(containerLabelsOwned("run1", "job1", runtimeOwner{RunnerID: "runner-a", InstanceID: "inst-1"}), " ")
	for _, want := range []string{"kiwi.run=run1", "kiwi.job=job1", "kiwi.runner=runner-a", "kiwi.instance=inst-1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("labels %q missing %s", got, want)
		}
	}
	// Legacy (no runner identity) stays unlabelled beyond run/job.
	if got := strings.Join(containerLabelsOwned("run1", "job1", runtimeOwner{}), " "); strings.Contains(got, "kiwi.runner") {
		t.Fatalf("empty owner produced runner labels: %q", got)
	}
}

// TestReconcileRuntimeReapsOnlyOwnPredecessor pins the crash-recovery
// boundary: containers/networks carrying THIS runner's stable ID with a
// previous (or absent) instance label are removed, while the current
// incarnation's resources and (implicitly) other runners' labels are left
// alone.
func TestReconcileRuntimeReapsOnlyOwnPredecessor(t *testing.T) {
	installFakeBins(t)
	current := "inst-current"
	t.Setenv("FAKE_DOCKER_PS", "c-old inst-old\nc-current "+current+"\nc-legacy")
	t.Setenv("FAKE_DOCKER_NET_LS", "net-old inst-old\nnet-current "+current)
	log := filepath.Join(t.TempDir(), "docker.log")
	t.Setenv("FAKE_DOCKER_LOG", log)

	rep, rerr := ReconcileRuntime(context.Background(), t.TempDir(), "runner-a", current)
	if rerr != nil || rep.Containers != 2 || rep.Networks != 1 {
		t.Fatalf("reconcile = %+v err=%v, want 2 containers / 1 network", rep, rerr)
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	logged := string(data)
	for _, want := range []string{"rm -f c-old", "rm -f c-legacy", "network rm net-old"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("reconcile did not issue %q:\n%s", want, logged)
		}
	}
	for _, forbidden := range []string{"rm -f c-current", "network rm net-current"} {
		if strings.Contains(logged, forbidden) {
			t.Fatalf("reconcile touched the CURRENT incarnation's resource: %q", forbidden)
		}
	}

	// No stable identity: nothing is enumerated or removed.
	if rep, err := ReconcileRuntime(context.Background(), t.TempDir(), "", current); err != nil || rep != (GCReport{}) {
		t.Fatalf("empty runner id reconciled %+v err=%v", rep, err)
	}
}

// TestReconcileRuntimeDiscoveryFailureFailsClosed pins the crash-recovery
// contract: docker being unable to enumerate (daemon down, timeout) must be
// an ERROR, never "nothing stale".
func TestReconcileRuntimeDiscoveryFailureFailsClosed(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_PS_EXIT", "1")
	if _, err := ReconcileRuntime(context.Background(), t.TempDir(), "runner-a", "inst"); err == nil {
		t.Fatal("docker ps failure was treated as proven absence")
	}
}

// TestReconcileRuntimeDiscoveryTruncationFailsClosed pins the parser-bound
// case: an over-limit discovery response is an error, not empty output.
func TestReconcileRuntimeDiscoveryTruncationFailsClosed(t *testing.T) {
	installFakeBins(t)
	// The fake ps handler prints the env value; 4 MiB+ exceeds the executor's
	// 4 MiB capture bound.
	t.Setenv("FAKE_DOCKER_PS", strings.Repeat("x", (4<<20)+16))
	if _, err := ReconcileRuntime(context.Background(), t.TempDir(), "runner-a", "inst"); err == nil {
		t.Fatal("truncated discovery output was treated as proven absence")
	}
}

// TestReconcileRuntimeRemovalFailureFailsClosed pins that a failed rm of a
// stale predecessor container refuses reconciliation (the runner must not
// lease while the old runtime may still exist).
func TestReconcileRuntimeRemovalFailureFailsClosed(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_PS", "c-old inst-old")
	t.Setenv("FAKE_DOCKER_PS_EXIT", "0")
	t.Setenv("FAKE_DOCKER_RM_EXIT", "1")
	t.Setenv("FAKE_DOCKER_RM_MSG", "operation not permitted")
	if _, err := ReconcileRuntime(context.Background(), t.TempDir(), "runner-a", "inst-current"); err == nil {
		t.Fatal("failed stale-container removal was tolerated")
	}
}

// TestReconcileRuntimeAbsenceIsDistinctFromDiscoveryFailure: a positively
// absent container (rm reports "No such container") is not an error.
func TestReconcileRuntimeAbsenceIsDistinctFromDiscoveryFailure(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_PS", "c-old inst-old")
	t.Setenv("FAKE_DOCKER_RM_EXIT", "1")
	t.Setenv("FAKE_DOCKER_RM_MSG", "Error: No such container: c-old")
	rep, err := ReconcileRuntime(context.Background(), t.TempDir(), "runner-a", "inst-current")
	if err != nil || rep.Containers != 1 {
		t.Fatalf("proven-absent container = %+v err=%v, want counted success", rep, err)
	}
}
