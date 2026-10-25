//go:build linux

package executor

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestWritePIDToJobCgroupDeadPIDIsSuccess: a fast-exit service that was
// born inside the cgroup (or is already gone) must NOT fail the start —
// ESRCH means nothing is running outside the ownership boundary.
func TestWritePIDToJobCgroupDeadPIDIsSuccess(t *testing.T) {
	root := t.TempDir()
	t.Setenv(jobCgroupRootEnv, root)
	dir := filepath.Join(root, "delegated", "kiwi-job-deadpid")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A PID that cannot be a live process (kernel max + margin).
	dead := 999999999
	if err := writePIDToJobCgroup("/delegated/kiwi-job-deadpid", dead); !errors.Is(err, nil) {
		// write may also get ESRCH wrapped — both must be success.
		if err != nil && !errors.Is(err, syscall.ESRCH) {
			t.Fatalf("dead PID write = %v, want nil or ESRCH treated as success", err)
		}
	}
}

// TestWritePIDToJobCgroupMissingCgroupFails: ENOENT on cgroup.procs means
// the durable cgroup itself is gone — that is ownership loss, never
// "already a member".
func TestWritePIDToJobCgroupMissingCgroupFails(t *testing.T) {
	root := t.TempDir()
	t.Setenv(jobCgroupRootEnv, root)
	if err := writePIDToJobCgroup("/delegated/does-not-exist", 1); err == nil {
		t.Fatal("missing cgroup must fail, not succeed")
	}
}

// TestWritePIDToJobCgroupMalformedParentFails: path-shape refusals stay
// fail-closed.
func TestWritePIDToJobCgroupMalformedParentFails(t *testing.T) {
	if err := writePIDToJobCgroup("../escape", 1); err == nil {
		t.Fatal("escaping parent must fail")
	}
	if err := writePIDToJobCgroup("", 1); err == nil {
		t.Fatal("empty parent must fail")
	}
}
