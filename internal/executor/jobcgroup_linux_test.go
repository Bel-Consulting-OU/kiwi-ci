//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// simulateCgroupControlFiles makes a plain temporary directory behave like a
// cgroupfs directory (which materializes its control files on mkdir).
func simulateCgroupControlFiles(t *testing.T) {
	t.Helper()
	orig := materializeCgroupControls
	materializeCgroupControls = func(dir string) error {
		for _, name := range []string{"cpu.max", "memory.max", "memory.swap.max", "pids.max", "cgroup.subtree_control"} {
			if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
				return err
			}
		}
		return nil
	}
	t.Cleanup(func() { materializeCgroupControls = orig })
}

// writeCgroupRoot builds a simulated cgroup-v2 mount root with one delegated
// base directory.
func writeCgroupRoot(t *testing.T, delegated bool) (root, base string) {
	t.Helper()
	root = t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	base = filepath.Join(root, "delegated")
	if err := os.Mkdir(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if delegated {
		if err := os.WriteFile(filepath.Join(base, "cgroup.subtree_control"), []byte("+cpu +memory +pids\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, base
}

// TestSetupJobCgroupWithOperatorParentCreatesLimits proves the Linux path
// end-to-end on a simulated cgroupfs: the job cgroup is created under the
// operator-provided delegated base, the declared envelope is written to the
// kernel limit files, the returned --cgroup-parent value is inside the cgroup
// root, and cleanup removes the directory.
func TestSetupJobCgroupWithOperatorParentCreatesLimits(t *testing.T) {
	simulateCgroupControlFiles(t)
	root, _ := writeCgroupRoot(t, true)
	t.Setenv(jobCgroupRootEnv, root)
	t.Setenv(jobCgroupParentEnv, "delegated")

	status, cleanup := setupJobCgroup(context.Background(), jobCgroupRequest{JobID: "job-1", CPU: 2, Memory: 1 << 30, PIDs: 128})
	if !status.Enabled {
		t.Fatalf("status = %+v, want an enabled job cgroup", status)
	}
	if !strings.HasPrefix(status.Parent, "/delegated/"+jobCgroupNamePrefix+"job-1-") {
		t.Fatalf("docker --cgroup-parent = %q, want it under the delegated base", status.Parent)
	}
	if cleanup == nil {
		t.Fatal("enabled job cgroup without cleanup")
	}
	dir := filepath.Join(root, strings.TrimPrefix(status.Parent, "/"))
	for file, want := range map[string]string{
		"cpu.max":    "200000 100000",
		"memory.max": "1073741824",
		"pids.max":   "128",
	} {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if string(b) != want {
			t.Fatalf("%s = %q, want %q", file, string(b), want)
		}
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("job cgroup survived cleanup: %v", err)
	}
}

// TestSetupJobCgroupWithoutDelegationReportsReason proves the exact reason
// surfaces when the configured base does not delegate the controllers.
func TestSetupJobCgroupWithoutDelegationReportsReason(t *testing.T) {
	root, _ := writeCgroupRoot(t, false)
	t.Setenv(jobCgroupRootEnv, root)
	t.Setenv(jobCgroupParentEnv, "delegated")
	status, cleanup := setupJobCgroup(context.Background(), jobCgroupRequest{JobID: "job-1", CPU: 2})
	if status.Enabled || cleanup != nil {
		t.Fatalf("undelegated base = %+v, cleanup=%v", status, cleanup != nil)
	}
	if !strings.Contains(status.Detail, "subtree_control") && !strings.Contains(status.Detail, "delegate") {
		t.Fatalf("reason does not explain the delegation gap: %q", status.Detail)
	}
}

// TestSetupJobCgroupWithoutCgroupV2ReportsReason proves a host without the
// unified hierarchy reports the cgroup-v2 reason instead of pretending.
func TestSetupJobCgroupWithoutCgroupV2ReportsReason(t *testing.T) {
	t.Setenv(jobCgroupRootEnv, t.TempDir()) // no cgroup.controllers
	t.Setenv(jobCgroupParentEnv, "delegated")
	status, cleanup := setupJobCgroup(context.Background(), jobCgroupRequest{JobID: "job-1", CPU: 2})
	if status.Enabled || cleanup != nil {
		t.Fatalf("cgroup-v1 host = %+v, cleanup=%v", status, cleanup != nil)
	}
	if !strings.Contains(status.Detail, "cgroup v2") {
		t.Fatalf("reason = %q, want it to name cgroup v2", status.Detail)
	}
}

// TestSetupJobCgroupUndeclaredEnvelopeIsNoOp proves an undeclared resource
// envelope (nothing reserved by the scheduler) does not create an empty
// cgroup: there is no bound to enforce.
func TestSetupJobCgroupUndeclaredEnvelopeIsNoOp(t *testing.T) {
	root, _ := writeCgroupRoot(t, true)
	t.Setenv(jobCgroupRootEnv, root)
	t.Setenv(jobCgroupParentEnv, "delegated")
	status, cleanup := setupJobCgroup(context.Background(), jobCgroupRequest{JobID: "job-1"})
	if status.Enabled || cleanup != nil {
		t.Fatalf("undeclared envelope = %+v, cleanup=%v", status, cleanup != nil)
	}
	if !strings.Contains(status.Detail, "declares no resources") {
		t.Fatalf("reason = %q", status.Detail)
	}
}

// TestJobCgroupBaseWalksDelegatedAncestors proves the automatic base
// resolution picks the deepest delegated ancestor and reports the gap when
// none exists.
func TestJobCgroupBaseWalksDelegatedAncestors(t *testing.T) {
	root, base := writeCgroupRoot(t, false)
	child := filepath.Join(base, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := jobCgroupBase(root, []string{"cpu"}, ""); err == nil {
		t.Fatal("base resolution succeeded without any delegation")
	} else if !strings.Contains(err.Error(), "delegates") {
		t.Fatalf("gap error = %v", err)
	}
	// The operator override resolves the delegated ancestor even when it is
	// not the runner's own cgroup.
	if err := os.WriteFile(filepath.Join(base, "cgroup.subtree_control"), []byte("+cpu\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := jobCgroupBase(root, []string{"cpu"}, "delegated")
	if err != nil || got != base {
		t.Fatalf("override base = (%q, %v), want %q", got, err, base)
	}
	// A relative override resolves under the cgroup root.
	got, err = jobCgroupBase(root, []string{"cpu"}, "delegated/child")
	if err == nil || got != "" {
		t.Fatalf("undelegated relative override = (%q, %v), want an error", got, err)
	}
}

// TestRunnerCgroupDirParsesProcSelfCgroup proves the runner's own cgroup is
// read from /proc/self/cgroup and joined under the configured root.
func TestRunnerCgroupDirParsesProcSelfCgroup(t *testing.T) {
	root := t.TempDir()
	dir, ok := runnerCgroupDir(root)
	if !ok {
		t.Skip("/proc/self/cgroup has no unified (0::) entry on this host")
	}
	if !strings.HasPrefix(dir, root) {
		t.Fatalf("runner cgroup %q is not under %q", dir, root)
	}
}

// installFakeDockerOnPath installs a `docker` shell script into a fresh directory and
// puts it first on PATH, returning nothing. The scripts used here never touch
// a real daemon.
func installFakeDockerOnPath(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestDockerAcceptsCgroupPathHangingProbeBounded pins the W5-D residual: the
// job-cgroup `docker info` probe runs under the runtime probe ceiling through
// phaseCommand, so a wedged daemon returns a typed ErrExternalCommandTimeout
// instead of pinning job startup when the job has no timeout. The probe
// timeout is shrunk so the test is deterministic and fast.
func TestDockerAcceptsCgroupPathHangingProbeBounded(t *testing.T) {
	installFakeDockerOnPath(t, "exec sleep 300")
	orig := runtimeProbeTimeout
	runtimeProbeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { runtimeProbeTimeout = orig })

	begin := time.Now()
	err := dockerAcceptsCgroupPath(context.Background())
	elapsed := time.Since(begin)
	if !errors.Is(err, ErrExternalCommandTimeout) {
		t.Fatalf("hanging probe = %v, want ErrExternalCommandTimeout", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("hanging probe took %v, want it bounded near the phase ceiling", elapsed)
	}
}

// TestDockerAcceptsCgroupPathDriverClassification pins the probe's parsing
// and classification: cgroupfs is accepted, systemd reports the delegation
// gap, and an empty driver is refused.
func TestDockerAcceptsCgroupPathDriverClassification(t *testing.T) {
	for _, tc := range []struct {
		name    string
		output  string
		wantErr string
	}{
		{"cgroupfs accepted", "cgroupfs", ""},
		{"systemd refused", "systemd", "systemd"},
		{"empty refused", "", "no cgroup driver"},
		{"unknown refused", "weird", "does not accept"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installFakeDockerOnPath(t, "echo "+tc.output)
			err := dockerAcceptsCgroupPath(context.Background())
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("cgroupfs probe = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("probe(%q) = %v, want %q", tc.output, err, tc.wantErr)
			}
		})
	}
}
