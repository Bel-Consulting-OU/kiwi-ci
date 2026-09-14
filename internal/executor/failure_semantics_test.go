package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func runGraph(t *testing.T, ctx context.Context, g *pipeline.Graph, ws string) map[string]model.JobResult {
	t.Helper()
	ex := Executor{Opt: Options{Workspace: ws, MaxParallel: 1}}
	// Run surfaces failed jobs as a joined error; the per-job results are
	// the source of truth for these tests.
	res, _ := ex.Run(ctx, g)
	return res
}

func mustCompileFailureSpec(t *testing.T, yaml string) *pipeline.Graph {
	t.Helper()
	s, err := pipeline.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func assertFile(t *testing.T, path, what string, wantExists bool) {
	t.Helper()
	_, err := os.Stat(path)
	if wantExists && err != nil {
		t.Fatalf("%s missing (%q): %v", what, path, err)
	}
	if !wantExists && err == nil {
		t.Fatalf("%s unexpectedly exists: %q", what, path)
	}
}

func TestFailureRunsAlwaysCleanupStep(t *testing.T) {
	ws := t.TempDir()
	g := mustCompileFailureSpec(t, `version: 1
jobs:
  j:
    steps:
      - name: fail
        run: exit 1
      - name: cleanup
        if: always()
        run: echo done > cleanup.txt
`)
	res := runGraph(t, context.Background(), g, ws)
	if r := res["j"]; r.Status != model.StatusFailure {
		t.Fatalf("job status = %q, want failure (error: %s)", r.Status, r.Error)
	}
	if res["j"].Error == "" {
		t.Fatal("job result carries no error for the hard failure")
	}
	assertFile(t, filepath.Join(ws, "cleanup.txt"), "always() cleanup marker", true)
}

func TestFailureConditionalSteps(t *testing.T) {
	ws := t.TempDir()
	g := mustCompileFailureSpec(t, `version: 1
jobs:
  j:
    steps:
      - name: fail
        run: exit 1
      - name: diagnostics
        if: failure()
        run: echo diag > diag.txt
      - name: never
        if: success()
        run: echo nope > nope.txt
      - name: second-failure
        if: always()
        run: exit 2
`)
	res := runGraph(t, context.Background(), g, ws)
	if r := res["j"]; r.Status != model.StatusFailure {
		t.Fatalf("job status = %q, want failure", r.Status)
	}
	// res.Error must record the FIRST failure, not the later one.
	if res["j"].Error == "" {
		t.Fatal("job result carries no error")
	}
	if !strings.Contains(res["j"].Error, "exit status 1") || strings.Contains(res["j"].Error, "exit status 2") {
		t.Fatalf("job error = %q, want the first failure only", res["j"].Error)
	}
	assertFile(t, filepath.Join(ws, "diag.txt"), "failure() diagnostics marker", true)
	assertFile(t, filepath.Join(ws, "nope.txt"), "success() marker after failure", false)
}

func TestFailureSkipsLaterSuccessStepsOnly(t *testing.T) {
	ws := t.TempDir()
	g := mustCompileFailureSpec(t, `version: 1
jobs:
  j:
    steps:
      - name: fail
        run: exit 1
      - name: unguarded
        run: echo unguarded > unguarded.txt
`)
	// A step with no `if` defaults to success() and must be skipped after
	// a hard failure.
	res := runGraph(t, context.Background(), g, ws)
	if r := res["j"]; r.Status != model.StatusFailure {
		t.Fatalf("job status = %q, want failure", r.Status)
	}
	assertFile(t, filepath.Join(ws, "unguarded.txt"), "unguarded step output", false)
}

func TestCancellationRunsCancelledCleanupStep(t *testing.T) {
	ws := t.TempDir()
	g := mustCompileFailureSpec(t, `version: 1
jobs:
  j:
    steps:
      - name: slow
        run: sleep 30
      - name: cleanup
        if: cancelled()
        run: echo done > cancelled.txt
      - name: never
        if: success()
        run: echo nope > nope.txt
`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	res := runGraph(t, ctx, g, ws)
	if r := res["j"]; r.Status != model.StatusCancelled {
		t.Fatalf("job status = %q, want cancelled (error: %s)", r.Status, r.Error)
	}
	assertFile(t, filepath.Join(ws, "cancelled.txt"), "cancelled() cleanup marker", true)
	assertFile(t, filepath.Join(ws, "nope.txt"), "success() marker after cancellation", false)
}

func TestCancellationSkipsFailureOnlySteps(t *testing.T) {
	ws := t.TempDir()
	g := mustCompileFailureSpec(t, `version: 1
jobs:
  j:
    steps:
      - name: slow
        run: sleep 30
      - name: failure-only
        if: failure()
        run: echo nope > failure_only.txt
      - name: always-cleanup
        if: always()
        run: echo done > always.txt
`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	res := runGraph(t, ctx, g, ws)
	if r := res["j"]; r.Status != model.StatusCancelled {
		t.Fatalf("job status = %q, want cancelled", r.Status)
	}
	assertFile(t, filepath.Join(ws, "failure_only.txt"), "failure() marker after cancellation", false)
	assertFile(t, filepath.Join(ws, "always.txt"), "always() marker after cancellation", true)
}
