package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

// TestCleanupStepsAbortOnLifecycleCancellation is the P2 lifecycle
// regression: a cancelled() cleanup step may survive the JOB deadline, but
// never the runner/process lifecycle. Here both the job context and the
// lifecycle context are already cancelled; the cleanup step must not run at
// all, so runJob returns immediately instead of waiting out the (shrunk)
// cleanup grace.
func TestCleanupStepsAbortOnLifecycleCancellation(t *testing.T) {
	orig := cleanupTimeout
	cleanupTimeout = 3 * time.Second
	t.Cleanup(func() { cleanupTimeout = orig })

	ws := t.TempDir()
	marker := filepath.Join(ws, "cleanup-ran")
	block := nativeScript("sleep 30", "Start-Sleep -Seconds 30")
	cleanup := nativeScript(
		"printf x > "+marker+" && sleep 30",
		"Set-Content -LiteralPath '"+marker+"' -Value x; Start-Sleep -Seconds 30",
	)
	lifecycle, lifecycleCancel := context.WithCancel(context.Background())
	defer lifecycleCancel()
	jobCtx, jobCancel := context.WithCancel(lifecycle)
	jobCancel()
	lifecycleCancel()

	ex := &Executor{Opt: Options{Workspace: ws, LifecycleContext: lifecycle}, Masker: &secrets.Masker{}}
	start := time.Now()
	res := ex.runJob(jobCtx, &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{
			{Run: block},
			{Run: cleanup, If: "cancelled()"},
		}},
	}, model.StatusSuccess, nil)
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("runJob took %v; cleanup ignored the runner lifecycle and waited for the cleanup grace", elapsed)
	}
	if res.Status != model.StatusCancelled {
		t.Fatalf("status = %q, want cancelled", res.Status)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("cleanup step ran after runner shutdown (marker err=%v)", err)
	}
}

// TestCleanupStepRunsAfterJobDeadlineOnly pins the intended half: with the
// lifecycle alive, a job deadline still gives cancelled() cleanup steps their
// bounded chance to run.
func TestCleanupStepRunsAfterJobDeadlineOnly(t *testing.T) {
	ws := t.TempDir()
	marker := filepath.Join(ws, "cleanup-ran")
	block := nativeScript("sleep 30", "Start-Sleep -Seconds 30")
	cleanup := nativeScript(
		"printf x > "+marker,
		"Set-Content -LiteralPath '"+marker+"' -Value x",
	)
	lifecycle, lifecycleCancel := context.WithCancel(context.Background())
	defer lifecycleCancel()
	jobCtx, jobCancel := context.WithTimeout(lifecycle, 200*time.Millisecond)
	defer jobCancel()

	ex := &Executor{Opt: Options{Workspace: ws, LifecycleContext: lifecycle}, Masker: &secrets.Masker{}}
	start := time.Now()
	res := ex.runJob(jobCtx, &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{
			{Run: block},
			{Run: cleanup, If: "cancelled()"},
		}},
	}, model.StatusSuccess, nil)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("runJob took %v; cleanup did not run promptly after the job deadline", elapsed)
	}
	if res.Status != model.StatusCancelled {
		t.Fatalf("status = %q, want cancelled", res.Status)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("cleanup step did not run after the job deadline: %v", err)
	}
}

// TestCancelledBeforePublicationSkipsCacheSave pins the phase gate: once the
// job context has ended, success-only publication (cache key hashing and
// archive creation) must be skipped, not run to completion on a dead
// deadline and discarded afterwards. The step reporter cancels the context
// exactly when the last step finishes, so the job is still Success when the
// gate runs.
func TestCancelledBeforePublicationSkipsCacheSave(t *testing.T) {
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeCaptureFile(t, filepath.Join(ws, "data"), "file.bin", 4096)
	cacheRoot := t.TempDir()
	sink := &covSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ex := &Executor{Opt: Options{
		Workspace: ws, RunID: "run-gate", Cache: &cache.Store{Root: cacheRoot}, Logs: sink,
		StepReporter: func(string, string, time.Duration) { cancel() },
	}, Masker: &secrets.Masker{}}
	res := ex.runJob(ctx, &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{
			Cache: []pipeline.Cache{{Name: "c", Key: "k", Paths: []string{"data"}}},
			Steps: []pipeline.Step{{Run: "true"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusCancelled {
		t.Fatalf("status = %+v, want cancelled", res)
	}
	if left := filesUnder(t, cacheRoot); len(left) != 0 {
		t.Fatalf("cache archive was created after the job context ended: %v", left)
	}
	if sink.has("saved c") {
		t.Fatalf("cache save ran despite the ended job context: %v", sink.lines)
	}
}
