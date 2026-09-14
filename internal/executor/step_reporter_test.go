package executor

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

type report struct {
	jobID  string
	stepID string
	d      time.Duration
}

func TestStepReporterReportsEachExecutedStep(t *testing.T) {
	ws := t.TempDir()
	g := mustCompileFailureSpec(t, `version: 1
jobs:
  j:
    steps:
      - id: one
        run: echo one > one.txt
      - id: two
        run: echo two > two.txt
`)
	var mu sync.Mutex
	var reports []report
	ex := Executor{Opt: Options{
		Workspace:   ws,
		MaxParallel: 1,
		StepReporter: func(jobID, stepID string, d time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			reports = append(reports, report{jobID: jobID, stepID: stepID, d: d})
		},
	}}
	res, _ := ex.Run(context.Background(), g)
	if r := res["j"]; r.Status != model.StatusSuccess {
		t.Fatalf("job status = %q, want success (error: %s)", r.Status, r.Error)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 2 {
		t.Fatalf("reporter fired %d times, want 2 (reports: %+v)", len(reports), reports)
	}
	byStep := map[string]time.Duration{}
	for _, r := range reports {
		if r.jobID != "j" {
			t.Fatalf("reporter jobID = %q, want j", r.jobID)
		}
		byStep[r.stepID] = r.d
	}
	for _, id := range []string{"one", "two"} {
		d, ok := byStep[id]
		if !ok {
			t.Fatalf("step %q not reported (reports: %+v)", id, reports)
		}
		if d < 0 {
			t.Fatalf("step %q duration = %v, want >= 0", id, d)
		}
	}
}

func TestStepReporterSkipsNonExecutedSteps(t *testing.T) {
	ws := t.TempDir()
	g := mustCompileFailureSpec(t, `version: 1
jobs:
  j:
    steps:
      - id: fail
        run: exit 1
      - id: skipme
        if: "false"
        run: echo nope > nope.txt
      - id: cleanup
        if: failure()
        run: echo cleanup > cleanup.txt
`)
	var mu sync.Mutex
	var reports []report
	ex := Executor{Opt: Options{
		Workspace:   ws,
		MaxParallel: 1,
		StepReporter: func(jobID, stepID string, d time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			reports = append(reports, report{jobID: jobID, stepID: stepID, d: d})
		},
	}}
	res, _ := ex.Run(context.Background(), g)
	if r := res["j"]; r.Status != model.StatusFailure {
		t.Fatalf("job status = %q, want failure (error: %s)", r.Status, r.Error)
	}
	mu.Lock()
	defer mu.Unlock()
	reported := map[string]bool{}
	for _, r := range reports {
		if r.d < 0 {
			t.Fatalf("step %q duration = %v, want >= 0", r.stepID, r.d)
		}
		reported[r.stepID] = true
	}
	if !reported["fail"] || !reported["cleanup"] {
		t.Fatalf("executed steps missing from reports: %+v", reports)
	}
	if reported["skipme"] {
		t.Fatalf("skipped step was reported: %+v", reports)
	}
	assertFile(t, filepath.Join(ws, "nope.txt"), "skipped step output", false)
	assertFile(t, filepath.Join(ws, "cleanup.txt"), "cleanup marker", true)
}

func TestStepReporterUnnamedStepUsesLogName(t *testing.T) {
	ws := t.TempDir()
	g := mustCompileFailureSpec(t, `version: 1
jobs:
  j:
    steps:
      - run: echo ok > ok.txt
`)
	var mu sync.Mutex
	var reports []report
	ex := Executor{Opt: Options{
		Workspace:   ws,
		MaxParallel: 1,
		StepReporter: func(jobID, stepID string, d time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			reports = append(reports, report{jobID: jobID, stepID: stepID, d: d})
		},
	}}
	res, _ := ex.Run(context.Background(), g)
	if r := res["j"]; r.Status != model.StatusSuccess {
		t.Fatalf("job status = %q, want success (error: %s)", r.Status, r.Error)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reports) != 1 || reports[0].stepID != "step-1" {
		t.Fatalf("reports = %+v, want one entry for step-1", reports)
	}
	if reports[0].d < 0 {
		t.Fatalf("duration = %v, want >= 0", reports[0].d)
	}
}
