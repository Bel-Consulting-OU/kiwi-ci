package executor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

// TestNativeShellPathQualifiedBindsToWorkDir is the shell-contamination
// oracle: a job that requests a path-qualified custom shell must execute
// only the shell inside ITS workdir. The old resolver fell through to a
// bare stat of the name relative to the runner process CWD, so a decoy
// shell planted beside the runner daemon interpreted (and contaminated)
// every observed byte of the job.
func TestNativeShellPathQualifiedBindsToWorkDir(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	// Decoy shell in the RUNNER's CWD: it drops a marker if it ever runs.
	runnerCWD := t.TempDir()
	marker := filepath.Join(t.TempDir(), "decoy-shell-ran")
	decoy := filepath.Join(runnerCWD, "tools", exeName("sh"))
	if err := os.MkdirAll(filepath.Dir(decoy), 0o755); err != nil {
		t.Fatal(err)
	}
	decoyBody := "#!/bin/sh\n: > '" + marker + "'\nexit 0\n"
	if runtime.GOOS == "windows" {
		// A text file with an .exe name cannot actually execute; the pre-fix
		// escape still RESOLVED it, producing a different failure than the
		// workdir-bound not-found this test asserts.
		decoyBody = "MZ-decoy"
	}
	if err := os.WriteFile(decoy, []byte(decoyBody), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(runnerCWD)

	calls, cleanups := stubJobCgroup(t, JobCgroupStatus{Detail: "test: no cgroup"})
	sink := &covSink{}
	spec := &pipeline.Spec{Version: 1, Jobs: map[string]pipeline.Job{
		"build": {Runtime: "native", Shell: "./tools/" + exeName("sh"), Steps: []pipeline.Step{{Run: "echo hi"}}},
	}}
	j := pipeline.CompiledJob{ID: "build", BaseID: "build", Job: pipeline.Job{
		Runtime: "native",
		Shell:   "./tools/" + exeName("sh"),
		Steps:   []pipeline.Step{{Run: "echo hi"}},
	}}
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", Logs: sink}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), spec, j, "success", nil)
	if res.Status != "failure" {
		t.Fatalf("runJob = %q / %q, want failure: the path-qualified shell does not exist in the workdir", res.Status, res.Error)
	}
	if !strings.Contains(res.Error, "resolve shell") || !strings.Contains(res.Error, "not found relative to workdir") {
		t.Fatalf("runJob error = %q, want resolve-shell workdir-bound not-found", res.Error)
	}
	if runtime.GOOS != "windows" {
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("the runner-CWD decoy shell executed — argv0 escaped the job's workdir authority")
		} else if !os.IsNotExist(err) {
			t.Fatalf("marker stat: %v", err)
		}
	}
	if *calls != 1 || *cleanups != 0 {
		t.Fatalf("job cgroup setup/cleanup = (%d, %d), want (1, 0)", *calls, *cleanups)
	}
}
