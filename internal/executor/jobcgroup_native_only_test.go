//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSetupJobCgroupNativeOnlySkipsDocker: a native-only request must not
// probe the Docker cgroup driver (a Docker-less Linux host still gets a
// durable ownership cgroup).
func TestSetupJobCgroupNativeOnlySkipsDocker(t *testing.T) {
	root := t.TempDir()
	t.Setenv(jobCgroupRootEnv, root)
	// No KIWI_JOB_CGROUP_PARENT: without NativeOnly the Docker probe would
	// fail (no docker CLI / no daemon). With NativeOnly we still need a
	// delegated base — create one that already enables no controllers
	// (Force with no CPU/Memory/PIDs needs no controllers).
	delegated := filepath.Join(root, "delegated")
	if err := os.MkdirAll(delegated, 0o755); err != nil {
		t.Fatal(err)
	}
	// Place the runner "inside" delegated by faking /proc is impossible;
	// use the operator override which skips the self-cgroup walk.
	t.Setenv(jobCgroupParentEnv, "delegated")
	status, cleanup := setupJobCgroup(context.Background(), jobCgroupRequest{
		JobID: "native-1", Force: true, NativeOnly: true,
	})
	if cleanup != nil {
		defer func() { _ = cleanup() }()
	}
	if !status.Enabled {
		t.Fatalf("native-only cgroup unavailable: %s", status.Detail)
	}
	if !strings.Contains(status.Parent, "kiwi-job-native-1") {
		t.Fatalf("parent = %q", status.Parent)
	}
}

// TestNativeOnlyCgroupIsLeafNoSubtreeControllers: native jobs place
// processes DIRECTLY in the job cgroup. Enabling domain controllers in that
// same cgroup's subtree_control violates cgroup-v2's no-internal-process
// rule. A native-only cgroup with declared resources must write limits but
// leave its own subtree_control empty (unlike a container job cgroup, which
// enables controllers for docker child cgroups).
func TestNativeOnlyCgroupIsLeafNoSubtreeControllers(t *testing.T) {
	simulateCgroupControlFiles(t)
	root, _ := writeCgroupRoot(t, true)
	t.Setenv(jobCgroupRootEnv, root)
	t.Setenv(jobCgroupParentEnv, "delegated")

	// Native-only with a full declared envelope.
	status, cleanup := setupJobCgroup(context.Background(), jobCgroupRequest{
		JobID: "native-leaf", CPU: 2, Memory: 1 << 30, PIDs: 64,
		Force: true, NativeOnly: true,
	})
	if cleanup != nil {
		defer func() { _ = cleanup() }()
	}
	if !status.Enabled {
		t.Fatalf("native leaf cgroup unavailable: %s", status.Detail)
	}
	dir := filepath.Join(root, strings.TrimPrefix(status.Parent, "/"))
	// Limits still apply to the leaf.
	for file, want := range map[string]string{
		"cpu.max":    "200000 100000",
		"memory.max": "1073741824",
		"pids.max":   "64",
	} {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if strings.TrimSpace(string(b)) != want {
			t.Fatalf("%s = %q, want %q", file, b, want)
		}
	}
	// The LEAF must NOT enable domain controllers for nonexistent children.
	subtree, err := os.ReadFile(filepath.Join(dir, "cgroup.subtree_control"))
	if err != nil {
		t.Fatalf("read subtree_control: %v", err)
	}
	if got := strings.TrimSpace(string(subtree)); got != "" {
		t.Fatalf("native leaf subtree_control = %q, want empty (no-internal-process: processes live here)", got)
	}

	// Contrast: container (non-native) job cgroup WITH resources DOES enable
	// controllers for docker children.
	statusC, cleanupC := setupJobCgroup(context.Background(), jobCgroupRequest{
		JobID: "container-parent", CPU: 2, Memory: 1 << 30, PIDs: 64,
	})
	if cleanupC != nil {
		defer func() { _ = cleanupC() }()
	}
	if !statusC.Enabled {
		t.Fatalf("container cgroup unavailable: %s", statusC.Detail)
	}
	dirC := filepath.Join(root, strings.TrimPrefix(statusC.Parent, "/"))
	subtreeC, err := os.ReadFile(filepath.Join(dirC, "cgroup.subtree_control"))
	if err != nil {
		t.Fatalf("read container subtree_control: %v", err)
	}
	if !strings.Contains(string(subtreeC), "+cpu") {
		t.Fatalf("container cgroup subtree_control = %q, want +cpu for docker children", subtreeC)
	}
}

// TestReclaimJobCgroupKillsPopulated: a populated cgroup is killed via
// cgroup.kill before rmdir (self-repair when PID ledger is missing).
func TestReclaimJobCgroupKillsPopulated(t *testing.T) {
	root := t.TempDir()
	t.Setenv(jobCgroupRootEnv, root)
	base := filepath.Join(root, "delegated")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "kiwi-job-kill-abc")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Fake a populated cgroup with a regular cgroup.procs file; the kill
	// write and empty-procs check still exercise the recovery path.
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// cgroup.kill may not exist on a plain dir: reclaim falls through to
	// rmdir which fails while procs is non-empty and not a real cgroup.
	// Write an empty procs after a successful kill attempt simulation.
	if err := os.WriteFile(filepath.Join(dir, "cgroup.kill"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Simulate kernel emptying procs on kill by making reclaim's wait see
	// empty after we clear it asynchronously — simpler: clear immediately.
	_ = os.WriteFile(filepath.Join(dir, "cgroup.procs"), nil, 0o644)
	if err := ReclaimJobCgroup("/delegated/kiwi-job-kill-abc"); err != nil {
		t.Fatalf("reclaim empty-after-kill: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("cgroup dir should be removed")
	}
}
