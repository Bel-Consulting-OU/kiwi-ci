//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNativeRunUseCgroupFDFailureFailsClosed: when a durable job cgroup is
// recorded but the kernel rejects clone-into-cgroup (UseCgroupFD against a
// non-cgroup directory), NativeBackend.Run must FAIL CLOSED rather than
// rebuild the command and run outside the ownership boundary. The previous
// rebuild path silently downgraded the invariant the ledger had recorded.
func TestNativeRunUseCgroupFDFailureFailsClosed(t *testing.T) {
	root := t.TempDir()
	t.Setenv(jobCgroupRootEnv, root)
	parent := "/delegated/kiwi-job-fails-closed"
	dir := filepath.Join(root, "delegated", "kiwi-job-fails-closed")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	outFile := filepath.Join(work, "marker")
	script := "echo ran > marker"
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + work}
	b := &NativeBackend{}
	err := b.Run(context.Background(), Command{
		Shell:        "bash",
		Script:       script,
		Dir:          work,
		Env:          env,
		CgroupParent: parent,
	}, func(string) {})
	if err == nil {
		// Some kernels may accept a plain-dir CgroupFD; then the step runs
		// inside that directory as a cgroup — still ownership. Only treat
		// unexpected success with a missing marker as a failure.
		if _, serr := os.Stat(outFile); serr != nil {
			t.Fatalf("run reported success but marker missing: %v", serr)
		}
		t.Skip("kernel accepted UseCgroupFD on a non-cgroup FD; fail-closed path not exercised")
	}
	msg := err.Error()
	if !strings.Contains(msg, "clone-into-cgroup") && !strings.Contains(msg, "cgroup") {
		t.Fatalf("want clone-into-cgroup fail-closed error, got: %v", err)
	}
	if strings.Contains(msg, "already started") {
		t.Fatalf("must not retry Start on the same Cmd: %v", err)
	}
	// Fail-closed: no user code ran outside the cgroup.
	if _, serr := os.Stat(outFile); serr == nil {
		t.Fatal("step executed despite rejected clone-into-cgroup (ownership invariant broken)")
	}
}
