package server

// Direct coverage for applyQueueReasonsLocked, the per-runner explainer the
// fleet-global in-memory path replaced: it must annotate every waiting job
// with exactly the reason the spec models (dependency gating, labels,
// regions, environment capacity, pending approval) and clear a stale reason
// once the job becomes leasable.

import (
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/queue"
)

// TestApplyQueueReasonsLockedTable pins every reason branch and the clearing
// behavior with one server holding all fixture jobs at once.
func TestApplyQueueReasonsLockedTable(t *testing.T) {
	s := New("shared-dev-tok")
	now := time.Now().UTC()
	runner := model.Runner{ID: "runner-1", Labels: []string{"linux"}, Region: "eu", Capacity: 4}

	jobs := map[string]model.Job{
		"approval": {ID: "approval", RunID: "run-1", Status: model.StatusWaitingApproval, CreatedAt: now},
		"dep-wait": {ID: "dep-wait", RunID: "run-1", Status: model.StatusQueued, Needs: []string{"upstream"}, Condition: "success()", CreatedAt: now},
		"label":    {ID: "label", RunID: "run-1", Status: model.StatusQueued, RequiredLabels: []string{"gpu"}, CreatedAt: now},
		"region":   {ID: "region", RunID: "run-1", Status: model.StatusQueued, PlacementRegions: []string{"us"}, CreatedAt: now},
		"ready":    {ID: "ready", RunID: "run-1", Status: model.StatusQueued, CreatedAt: now},
		"running":  {ID: "running", RunID: "run-1", Status: model.StatusRunning, CreatedAt: now},
		"upstream": {ID: "upstream", RunID: "run-1", Status: model.StatusQueued, CreatedAt: now, QueueReason: string(queue.WaitingDependency)},
	}
	// The environment-capacity fixture: one running plus one queued job in
	// the same (repo, environment) with concurrency 1.
	jobs["env-running"] = model.Job{ID: "env-running", RunID: "run-1", Status: model.StatusRunning, Environment: "prod", EnvironmentConcurrency: 1, RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r", CreatedAt: now}
	jobs["env-blocked"] = model.Job{ID: "env-blocked", RunID: "run-1", Status: model.StatusQueued, Environment: "prod", EnvironmentConcurrency: 1, RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r", CreatedAt: now}
	// A stale annotation on a job that is now leasable must be cleared.
	ready := jobs["ready"]
	ready.QueueReason = string(queue.WaitingDependency)
	jobs["ready"] = ready
	s.jobs = jobs

	s.applyQueueReasonsLocked(runner)

	want := map[string]queue.ReasonCode{
		"approval":    queue.WaitingApproval,
		"dep-wait":    queue.WaitingDependency,
		"label":       queue.NoCompatibleRunner,
		"region":      queue.RegionUnavailable,
		"ready":       queue.None,
		"running":     queue.None,
		"upstream":    queue.None,
		"env-running": queue.None,
		"env-blocked": queue.EnvironmentLocked,
	}
	for id, code := range want {
		if got := queue.ReasonCode(s.jobs[id].QueueReason); got != code {
			t.Errorf("job %s reason = %q, want %q", id, got, code)
		}
	}
}

// TestApplyQueueReasonsLockedRuntimeMismatchAndMaterializedLabels proves the
// labels dimension is evaluated like the lease predicate (an exact subset)
// and that a fully-satisfied job is annotated with the empty reason.
func TestApplyQueueReasonsLockedRequiresAllLabels(t *testing.T) {
	s := New("shared-dev-tok")
	s.jobs = map[string]model.Job{
		"both":   {ID: "both", RunID: "run-1", Status: model.StatusQueued, RequiredLabels: []string{"linux", "gpu"}, CreatedAt: time.Now().UTC()},
		"subset": {ID: "subset", RunID: "run-1", Status: model.StatusQueued, RequiredLabels: []string{"linux"}, CreatedAt: time.Now().UTC()},
	}
	s.applyQueueReasonsLocked(model.Runner{ID: "r", Labels: []string{"linux"}, Capacity: 1})
	if got := s.jobs["both"].QueueReason; got != string(queue.NoCompatibleRunner) {
		t.Fatalf("missing label reason = %q", got)
	}
	if got := s.jobs["subset"].QueueReason; got != "" {
		t.Fatalf("satisfied labels reason = %q, want none", got)
	}
}
