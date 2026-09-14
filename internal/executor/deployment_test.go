package executor

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// deploymentSpecYAML wraps the deployment phases; pipeline validation still
// requires a non-empty plain step list, so every fixture carries one dummy
// step that the deployment phases replace at execution time.
func deployGraph(t *testing.T, deployment string) (string, map[string]model.JobResult) {
	t.Helper()
	ws := t.TempDir()
	g := mustCompileFailureSpec(t, `version: 1
jobs:
  j:
    steps:
      - run: exit 0
`+deployment)
	ex := Executor{Opt: Options{Workspace: ws, MaxParallel: 1}}
	res, _ := ex.Run(context.Background(), g)
	return ws, res
}

func TestDeploymentSuccessRunsCanaryAndVerify(t *testing.T) {
	ws, res := deployGraph(t, `
    deployment:
      canary:
        - name: roll
          run: echo canary > canary.txt
      verify:
        - name: check
          run: echo verify > verify.txt
      rollback:
        - name: undo
          run: echo rollback > rollback.txt
`)
	if r := res["j"]; r.Status != model.StatusSuccess {
		t.Fatalf("job status = %q, want success (error: %s)", r.Status, r.Error)
	}
	assertFile(t, filepath.Join(ws, "canary.txt"), "canary marker", true)
	assertFile(t, filepath.Join(ws, "verify.txt"), "verify marker", true)
	assertFile(t, filepath.Join(ws, "rollback.txt"), "rollback marker", false)
}

func TestDeploymentCanaryFailureRunsRollback(t *testing.T) {
	ws, res := deployGraph(t, `
    deployment:
      canary:
        - name: roll
          run: exit 1
      verify:
        - name: check
          run: echo verify > verify.txt
      rollback:
        - name: undo
          run: echo rollback > rollback.txt
`)
	r := res["j"]
	if r.Status != model.StatusFailure {
		t.Fatalf("job status = %q, want failure (error: %s)", r.Status, r.Error)
	}
	if !strings.Contains(r.Error, "exit status 1") {
		t.Fatalf("job error = %q, want the canary failure", r.Error)
	}
	// Verify defaults to success() and must be skipped after the failure.
	assertFile(t, filepath.Join(ws, "verify.txt"), "verify marker", false)
	assertFile(t, filepath.Join(ws, "rollback.txt"), "rollback marker", true)
}

func TestDeploymentVerifyFailureRunsRollback(t *testing.T) {
	ws, res := deployGraph(t, `
    deployment:
      canary:
        - name: roll
          run: echo canary > canary.txt
      verify:
        - name: check
          run: exit 1
      rollback:
        - name: undo
          run: echo rollback > rollback.txt
`)
	r := res["j"]
	if r.Status != model.StatusFailure {
		t.Fatalf("job status = %q, want failure (error: %s)", r.Status, r.Error)
	}
	if !strings.Contains(r.Error, "exit status 1") {
		t.Fatalf("job error = %q, want the verify failure", r.Error)
	}
	assertFile(t, filepath.Join(ws, "canary.txt"), "canary marker", true)
	assertFile(t, filepath.Join(ws, "rollback.txt"), "rollback marker", true)
}

func TestDeploymentRollbackFailureKeepsFailure(t *testing.T) {
	ws, res := deployGraph(t, `
    deployment:
      canary:
        - name: roll
          run: exit 1
      rollback:
        - name: undo-a
          run: exit 2
        - name: undo-b
          run: echo second > second.txt
`)
	r := res["j"]
	if r.Status != model.StatusFailure {
		t.Fatalf("job status = %q, want failure (error: %s)", r.Status, r.Error)
	}
	// The recorded error is the FIRST failure (the canary), not the
	// rollback's.
	if !strings.Contains(r.Error, "exit status 1") || strings.Contains(r.Error, "exit status 2") {
		t.Fatalf("job error = %q, want the first failure only", r.Error)
	}
	// A failing rollback step does not clear the failure status, so the
	// next rollback step (still failure()) keeps running.
	assertFile(t, filepath.Join(ws, "second.txt"), "second rollback marker", true)
}

func TestDeploymentSuccessNeverRunsRollback(t *testing.T) {
	ws, res := deployGraph(t, `
    deployment:
      canary:
        - name: roll
          run: echo ok > ok.txt
      rollback:
        - name: undo
          run: echo bad > bad.txt
`)
	if r := res["j"]; r.Status != model.StatusSuccess {
		t.Fatalf("job status = %q, want success (error: %s)", r.Status, r.Error)
	}
	assertFile(t, filepath.Join(ws, "ok.txt"), "canary marker", true)
	assertFile(t, filepath.Join(ws, "bad.txt"), "rollback marker", false)
}

func TestDeploymentStepNamespacesInLogs(t *testing.T) {
	ws := t.TempDir()
	g := mustCompileFailureSpec(t, `version: 1
jobs:
  j:
    steps:
      - run: exit 0
    deployment:
      canary:
        - name: boom
          run: exit 1
      verify:
        - name: check
          run: echo v > v.txt
      rollback:
        - name: undo
          run: echo undo > undo.txt
`)
	var mu sync.Mutex
	steps := map[string]bool{}
	sink := logging.Func(func(job, step, line string) {
		mu.Lock()
		defer mu.Unlock()
		steps[step] = true
	})
	ex := Executor{Opt: Options{Workspace: ws, MaxParallel: 1, Logs: sink}}
	res, _ := ex.Run(context.Background(), g)
	if r := res["j"]; r.Status != model.StatusFailure {
		t.Fatalf("job status = %q, want failure (error: %s)", r.Status, r.Error)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, want := range []string{"canary.boom", "verify.check", "rollback.undo"} {
		if !steps[want] {
			t.Fatalf("no log lines for namespaced step %q (got %v)", want, steps)
		}
	}
}

func TestDeploymentUnnamedStepNamespace(t *testing.T) {
	ws := t.TempDir()
	g := mustCompileFailureSpec(t, `version: 1
jobs:
  j:
    steps:
      - run: exit 0
    deployment:
      canary:
        - run: echo ok > ok.txt
`)
	var mu sync.Mutex
	steps := map[string]bool{}
	sink := logging.Func(func(job, step, line string) {
		mu.Lock()
		defer mu.Unlock()
		steps[step] = true
	})
	ex := Executor{Opt: Options{Workspace: ws, MaxParallel: 1, Logs: sink}}
	res, _ := ex.Run(context.Background(), g)
	if r := res["j"]; r.Status != model.StatusSuccess {
		t.Fatalf("job status = %q, want success (error: %s)", r.Status, r.Error)
	}
	mu.Lock()
	defer mu.Unlock()
	if !steps["canary.step-1"] {
		t.Fatalf("unnamed canary step not logged under canary.step-1 (got %v)", steps)
	}
}

func TestDeploymentEmptySpecRunsPlainSteps(t *testing.T) {
	ws := t.TempDir()
	g := mustCompileFailureSpec(t, `version: 1
jobs:
  j:
    steps:
      - name: plain
        run: echo plain > plain.txt
`)
	ex := Executor{Opt: Options{Workspace: ws, MaxParallel: 1}}
	res, _ := ex.Run(context.Background(), g)
	if r := res["j"]; r.Status != model.StatusSuccess {
		t.Fatalf("job status = %q, want success (error: %s)", r.Status, r.Error)
	}
	assertFile(t, filepath.Join(ws, "plain.txt"), "plain step marker", true)
}
