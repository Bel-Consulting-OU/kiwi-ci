package executor

// Teardown state-machine regressions: runtime removal must be PROVEN before
// workspace protections are torn down or runtime identity is dropped, and
// cleanup callbacks must stay retryable until they succeed.

import (
	"errors"
	"os"
	"path/filepath"
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
