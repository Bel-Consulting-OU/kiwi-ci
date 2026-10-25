//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNativeRunUseCgroupFDFailureFallsBack: a real NativeBackend.Run whose
// clone-into-cgroup is rejected (CgroupFD points at a plain directory, not
// cgroupfs) must rebuild a FRESH command with Setpgid and still execute the
// step. Before the rebuild fix this died with "exec: already started".
func TestNativeRunUseCgroupFDFailureFallsBack(t *testing.T) {
	root := t.TempDir()
	t.Setenv(jobCgroupRootEnv, root)
	parent := "/delegated/kiwi-job-fallback"
	dir := filepath.Join(root, "delegated", "kiwi-job-fallback")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	outFile := filepath.Join(work, "marker")
	script := "echo ran > marker"
	// Force UseCgroupFD: configureProcessCgroup opens the plain dir successfully.
	// The kernel then rejects CLONE_INTO_CGROUP for a non-cgroup FD.
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + work}
	b := &NativeBackend{}
	var lines []string
	err := b.Run(context.Background(), Command{
		Shell:        "bash",
		Script:       script,
		Dir:          work,
		Env:          env,
		CgroupParent: parent,
	}, func(s string) { lines = append(lines, s) })
	if err != nil {
		// Fallback may still fail addPID if the kernel accepted UseCgroupFD
		// on this host (some environments treat open dirs leniently). Only
		// the "already started" class of failure is the regression.
		msg := err.Error()
		if strings.Contains(msg, "already started") {
			t.Fatalf("UseCgroupFD fallback did not rebuild the command: %v", err)
		}
		t.Fatalf("native run with rejected UseCgroupFD: %v", err)
	}
	if _, serr := os.Stat(outFile); serr != nil {
		t.Fatalf("step did not execute after fallback (marker missing): %v\nlines=%v", serr, lines)
	}
}
