package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

// TestPreJobCheckpointRunsOnceAfterRestoreBeforeSteps is the ordering proof:
// the hook observes the cache-restored workspace and runs before any step has
// mutated it, exactly once per executed job.
func TestPreJobCheckpointRunsOnceAfterRestoreBeforeSteps(t *testing.T) {
	store := cacheStoreAt(t)
	seedWS := canonicalTempDir(t)
	seed := &Executor{Opt: Options{Workspace: seedWS, RunID: "seed", MaxParallel: 1, Cache: store}, Masker: &secrets.Masker{}}
	seedRes := seed.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "seed", Job: pipeline.Job{
			Cache: []pipeline.Cache{{Name: "c", Key: "k", Paths: []string{"data"}}},
			Steps: []pipeline.Step{{Run: "mkdir -p data && echo restored > data/restored.txt"}},
		},
	}, model.StatusSuccess, nil)
	if seedRes.Status != model.StatusSuccess {
		t.Fatalf("seeding cache = %+v", seedRes)
	}

	ws := canonicalTempDir(t)
	calls := 0
	restoredSeen := false
	stepSeenInHook := false
	hook := func(context.Context) error {
		calls++
		if _, err := os.Stat(filepath.Join(ws, "data", "restored.txt")); err == nil {
			restoredSeen = true
		}
		if _, err := os.Stat(filepath.Join(ws, "step.txt")); err == nil {
			stepSeenInHook = true
		}
		return nil
	}
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", MaxParallel: 1, Cache: store, PreJobCheckpoint: hook}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{
			Cache: []pipeline.Cache{{Name: "c", Key: "k", Paths: []string{"data"}}},
			Steps: []pipeline.Step{{Run: "echo step > step.txt"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess {
		t.Fatalf("checkpointed job = %+v", res)
	}
	if calls != 1 {
		t.Fatalf("checkpoint calls = %d, want exactly 1", calls)
	}
	if !restoredSeen {
		t.Fatal("checkpoint ran before the cache restore: restored file was absent")
	}
	if stepSeenInHook {
		t.Fatal("checkpoint observed a step mutation: it ran after the first step")
	}
	if _, err := os.Stat(filepath.Join(ws, "step.txt")); err != nil {
		t.Fatalf("the step did not run after the checkpoint: %v", err)
	}
}

// TestPreJobCheckpointFailureWarnsAndDoesNotFailJob mirrors the post-job
// snapshot capture semantics: a checkpoint failure is a warning only.
func TestPreJobCheckpointFailureWarnsAndDoesNotFailJob(t *testing.T) {
	sink := &covSink{}
	ex := &Executor{Opt: Options{
		Workspace:        canonicalTempDir(t),
		RunID:            "r",
		MaxParallel:      1,
		Logs:             sink,
		PreJobCheckpoint: func(context.Context) error { return errors.New("upload refused") },
	}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{{Run: "echo ok"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess {
		t.Fatalf("checkpoint failure changed the job status: %+v", res)
	}
	if !sink.has("pre-job checkpoint warning: upload refused") {
		t.Fatalf("checkpoint warning missing: %v", sink.lines)
	}
}

// TestPreJobCheckpointNilSkips proves a nil hook is a no-op (local runs and
// debug replay do not set it).
func TestPreJobCheckpointNilSkips(t *testing.T) {
	ex := &Executor{Opt: Options{Workspace: canonicalTempDir(t), RunID: "r", MaxParallel: 1}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{{Run: "echo ok"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess {
		t.Fatalf("nil checkpoint job = %+v", res)
	}
}
