package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/queue"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const fcDownstreamPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    downstream:
      repository: o/target
      ref: refs/heads/main
    steps:
      - run: echo hi
`

const fcDownstreamNoRefPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    downstream:
      repository: o/target
    steps:
      - run: echo hi
`

func fcEffectsServerWithRun(t *testing.T) *Server {
	t.Helper()
	s := New("tok")
	s.mu.Lock()
	s.runs["run-1"] = model.Run{ID: "run-1", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Ref: "refs/heads/main", Status: model.StatusRunning}
	s.mu.Unlock()
	return s
}

func TestFlowEffectsReconcileMissingJob(t *testing.T) {
	s := New("tok")
	if err := s.reconcileCompletionEffects(context.Background(), "gone"); err != nil {
		t.Fatalf("missing job reconcile = %v", err)
	}
}

func TestFlowEffectsReconcileStoreError(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	s.DB = &fcStore{dbFakeStore: f, getJobErr: errors.New("job read down")}
	if err := s.reconcileCompletionEffects(context.Background(), "job-a"); err == nil {
		t.Fatal("job read failure must propagate")
	}
}

func TestFlowEffectsReconcilePropagatesDownstreamError(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	now := time.Now().UTC()
	f.mu.Lock()
	f.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-c", Key: "build", Status: model.StatusSuccess, Pipeline: fcDownstreamPipeline, RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", FinishedAt: &now}
	f.mu.Unlock()
	// The downstream ref is declared, so no run lookup is needed until the
	// link check; the link read fails.
	s.DB = &fcStore{dbFakeStore: f, getDownstreamLinkErr: errors.New("link read down")}
	if err := s.reconcileCompletionEffects(context.Background(), "job-a"); err == nil {
		t.Fatal("downstream link failure must propagate")
	}
}

func TestFlowEffectsReconcilePropagatesDeploymentError(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	now := time.Now().UTC()
	f.mu.Lock()
	f.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-c", Key: "build", Status: model.StatusSuccess, Environment: "prod", RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", FinishedAt: &now}
	f.mu.Unlock()
	s.DB = &fcStore{dbFakeStore: f, listDeploymentsErr: errors.New("deployment read down")}
	if err := s.reconcileCompletionEffects(context.Background(), "job-a"); err == nil {
		t.Fatal("deployment lookup failure must propagate")
	}
}

func TestFlowEffectsReconcilePropagatesUsageError(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	started := time.Now().UTC().Add(-time.Minute)
	f.mu.Lock()
	f.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-c", Key: "build", Status: model.StatusSuccess, StartedAt: &started, RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a"}
	f.updateJobErr = errors.New("job write down")
	f.mu.Unlock()
	if err := s.reconcileCompletionEffects(context.Background(), "job-a"); err == nil {
		t.Fatal("usage account failure must propagate")
	}
}

func TestFlowEffectsDownstreamCheckBranches(t *testing.T) {
	ctx := context.Background()
	s := fcEffectsServerWithRun(t)
	// Non-success skip.
	if err := s.effectDownstreamCheck(ctx, model.Job{ID: "j", Status: model.StatusFailure}); err != nil {
		t.Fatalf("non-success downstream check = %v", err)
	}
	// Unparseable pipeline skip.
	if err := s.effectDownstreamCheck(ctx, model.Job{ID: "j", Status: model.StatusSuccess, Pipeline: "jobs: [oops"}); err != nil {
		t.Fatalf("unparseable downstream check = %v", err)
	}
	// Missing run while the ref falls back to it.
	job := model.Job{ID: "j", RunID: "ghost", Key: "build", Status: model.StatusSuccess, Pipeline: fcDownstreamNoRefPipeline}
	if err := s.effectDownstreamCheck(ctx, job); err == nil {
		t.Fatal("missing run must fail the ref fallback")
	}
	// Ref fallback succeeds through the run. The repair path re-reads the
	// job from the authoritative mirror, so seed it (real completions always
	// have their job row present).
	job.RunID = "run-1"
	s.mu.Lock()
	s.jobs[job.ID] = job
	s.mu.Unlock()
	if err := s.effectDownstreamCheck(ctx, job); err != nil {
		t.Fatalf("ref fallback downstream check = %v", err)
	}
	job.Pipeline = fcDownstreamPipeline
	if err := s.effectDownstreamCheck(ctx, job); err != nil {
		t.Fatalf("declared-ref downstream check = %v", err)
	}
	// An existing link is the marker: the recording is skipped.
	s.mu.Lock()
	s.downstreamLinks[downstreamLinkKey("j", "o/target", "refs/heads/main")] = storage.DownstreamLink{ParentJobID: "j", TargetRepo: "o/target", TargetRef: "refs/heads/main"}
	s.mu.Unlock()
	if err := s.effectDownstreamCheck(ctx, job); err != nil {
		t.Fatalf("existing-link downstream check = %v", err)
	}
}

func TestFlowEffectsDownstreamCheckLinkReadFailure(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	f.mu.Lock()
	f.contracts["job-a"] = nil
	f.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-c", Key: "build", Status: model.StatusSuccess, Pipeline: fcDownstreamPipeline, RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a"}
	f.mu.Unlock()
	s.DB = &fcStore{dbFakeStore: f, getDownstreamLinkErr: errors.New("link read down")}
	f.mu.Lock()
	job := f.jobs["job-a"]
	f.mu.Unlock()
	if err := s.effectDownstreamCheck(context.Background(), job); err == nil {
		t.Fatal("link read failure must propagate")
	}
}

func TestFlowEffectsDeploymentFinishBranches(t *testing.T) {
	ctx := context.Background()
	s := fcEffectsServerWithRun(t)
	// No environment: nothing to finish.
	if err := s.effectDeploymentFinish(ctx, model.Job{ID: "j"}); err != nil {
		t.Fatalf("environmentless finish = %v", err)
	}
	// No deployment record.
	if err := s.effectDeploymentFinish(ctx, model.Job{ID: "j", Environment: "prod"}); err != nil {
		t.Fatalf("missing deployment finish = %v", err)
	}
	// Memory finish: the record is stamped with the job's terminal state.
	finished := time.Now().UTC().Add(-time.Minute)
	s.mu.Lock()
	s.deployments["j"] = model.Deployment{ID: "dep-1", JobID: "j", RunID: "run-1", Status: model.StatusRunning}
	s.mu.Unlock()
	job := model.Job{ID: "j", RunID: "run-1", Environment: "prod", Status: model.StatusSuccess, FinishedAt: &finished}
	if err := s.effectDeploymentFinish(ctx, job); err != nil {
		t.Fatalf("memory deployment finish = %v", err)
	}
	s.mu.Lock()
	got := s.deployments["j"]
	s.mu.Unlock()
	if got.Status != model.StatusSuccess || got.FinishedAt == nil || !got.FinishedAt.Equal(finished) {
		t.Fatalf("deployment after finish = %+v", got)
	}
	// Already finished: idempotent no-op.
	if err := s.effectDeploymentFinish(ctx, job); err != nil {
		t.Fatalf("finished deployment replay = %v", err)
	}
}

func TestFlowEffectsDeploymentFinishDB(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	f.mu.Lock()
	f.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-c", Key: "build", Status: model.StatusSuccess, Environment: "prod", RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a"}
	f.deployments["dep-1"] = model.Deployment{ID: "dep-1", JobID: "job-a", RunID: "run-c", Status: model.StatusRunning}
	f.mu.Unlock()
	job, err := s.DB.GetJob(context.Background(), "job-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.effectDeploymentFinish(context.Background(), job); err != nil {
		t.Fatalf("db deployment finish = %v", err)
	}
	f.mu.Lock()
	got := f.deployments["dep-1"]
	f.mu.Unlock()
	if got.Status != model.StatusSuccess || got.FinishedAt == nil {
		t.Fatalf("db deployment after finish = %+v", got)
	}
}

func TestFlowEffectsDeploymentForJobListError(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	s.DB = &fcStore{dbFakeStore: f, listDeploymentsErr: errors.New("deployment read down")}
	if _, found, err := s.deploymentForJob(context.Background(), model.Job{ID: "job-a", RunID: "run-c"}); err == nil || found {
		t.Fatalf("deployment lookup = %v %v", found, err)
	}
}

func TestFlowEffectsUsageAccountBranches(t *testing.T) {
	ctx := context.Background()
	s := fcEffectsServerWithRun(t)
	// Already recorded: marker short-circuits.
	if err := s.effectUsageAccount(ctx, model.Job{ID: "j", UsageRecorded: true}); err != nil {
		t.Fatalf("recorded usage = %v", err)
	}
	// Missing job: nothing to update.
	if err := s.effectUsageAccount(ctx, model.Job{ID: "ghost"}); err != nil {
		t.Fatalf("missing usage job = %v", err)
	}
	// Started job: usage is computed and persisted.
	started := time.Now().UTC().Add(-time.Hour)
	s.mu.Lock()
	s.jobs["j"] = model.Job{ID: "j", RunID: "run-1", Key: "build", StartedAt: &started, CostRate: 1, PowerWatts: 100}
	s.mu.Unlock()
	if err := s.effectUsageAccount(ctx, model.Job{ID: "j", RunID: "run-1", StartedAt: &started, CostRate: 1, PowerWatts: 100}); err != nil {
		t.Fatalf("usage account = %v", err)
	}
	s.mu.Lock()
	got := s.jobs["j"]
	s.mu.Unlock()
	if !got.UsageRecorded || got.Cost <= 0 || got.EnergyWh <= 0 {
		t.Fatalf("persisted usage = %+v", got)
	}
}

func TestFlowEffectsRunAggregateBranches(t *testing.T) {
	ctx := context.Background()
	s := fcEffectsServerWithRun(t)
	// Missing run: no-op.
	if err := s.effectRunAggregate(ctx, model.Job{ID: "j", RunID: "ghost"}); err != nil {
		t.Fatalf("missing run aggregate = %v", err)
	}
	// Present run: re-aggregation runs.
	s.mu.Lock()
	s.jobs["j"] = model.Job{ID: "j", RunID: "run-1", Status: model.StatusSuccess}
	s.mu.Unlock()
	if err := s.effectRunAggregate(ctx, model.Job{ID: "j", RunID: "run-1"}); err != nil {
		t.Fatalf("run aggregate = %v", err)
	}
	s.mu.Lock()
	run := s.runs["run-1"]
	s.mu.Unlock()
	if run.Status != model.StatusSuccess {
		t.Fatalf("aggregated run = %+v", run)
	}
}

func TestFlowEffectsForgeStatusBranches(t *testing.T) {
	ctx := context.Background()
	s := fcEffectsServerWithRun(t)
	if _, err := s.runForJob(ctx, "ghost"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("runForJob memory = %v", err)
	}
	// Missing run: no-op.
	if err := s.effectForgeStatus(ctx, model.Job{ID: "j", RunID: "ghost"}); err != nil {
		t.Fatalf("missing forge status = %v", err)
	}
	// Terminal run: publish path; non-terminal: skip.
	if err := s.effectForgeStatus(ctx, model.Job{ID: "j", RunID: "run-1"}); err != nil {
		t.Fatalf("non-terminal forge status = %v", err)
	}
	s.mu.Lock()
	run := s.runs["run-1"]
	run.Status = model.StatusSuccess
	s.runs["run-1"] = run
	s.mu.Unlock()
	if err := s.effectForgeStatus(ctx, model.Job{ID: "j", RunID: "run-1"}); err != nil {
		t.Fatalf("terminal forge status = %v", err)
	}
}

func TestFlowEffectsForgeStatusRunError(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	s.DB = &fcStore{dbFakeStore: f, getRunErr: errors.New("run read down")}
	if err := s.effectForgeStatus(context.Background(), model.Job{ID: "job-a", RunID: "run-c"}); err == nil {
		t.Fatal("run read failure must propagate")
	}
}

func TestFlowEffectsEnqueueCompletionEffects(t *testing.T) {
	s := New("tok")
	if err := s.enqueueCompletionEffects(model.Job{ID: "j"}, model.Run{ID: "r"}); err != nil {
		t.Fatalf("memory effect enqueue = %v", err)
	}
	// Single-row design: ONE deterministic reconcile intent per completion
	// runs the whole effect chain (the per-kind fan-out amplified one
	// completion into five rows × five chains).
	if got := len(s.outbox.Pending()); got != 1 {
		t.Fatalf("queued effects = %d, want 1 reconcile intent", got)
	}
	if s.outbox.Pending()[0].Kind != storage.OutboxKindCompletionReconcile {
		t.Fatalf("queued kind = %q", s.outbox.Pending()[0].Kind)
	}
	// DB append failure surfaces.
	s2, f, _, _ := cacheFixture(t)
	f.mu.Lock()
	f.outboxAppendErr = errors.New("outbox append down")
	f.mu.Unlock()
	if err := s2.enqueueCompletionEffects(model.Job{ID: "j"}, model.Run{ID: "r"}); err == nil {
		t.Fatal("outbox append failure must propagate")
	}
	f.mu.Lock()
	f.outboxAppendErr = nil
	f.mu.Unlock()
	// Local-only copies dedupe by deterministic effect id.
	s2.enqueueCompletionEffectsLocal("j", "r", 1)
	first := len(s2.outbox.Pending())
	s2.enqueueCompletionEffectsLocal("j", "r", 1)
	if got := len(s2.outbox.Pending()); got != first {
		t.Fatalf("local effect enqueue duplicated: %d -> %d", first, got)
	}
}

func TestFlowEffectsEffectiveCapsOf(t *testing.T) {
	if _, ok := effectiveCapsOf(model.Job{}); ok {
		t.Fatal("nil payload caps must be absent")
	}
	if _, ok := effectiveCapsOf(model.Job{CompiledJobPayload: &model.CompiledJobPayload{}}); ok {
		t.Fatal("nil policy caps must be absent")
	}
	bad := model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectivePolicy: make(chan int)}}
	if _, ok := effectiveCapsOf(bad); ok {
		t.Fatal("unmarshalable policy must be absent")
	}
	str := model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectivePolicy: "not-an-object"}}
	if _, ok := effectiveCapsOf(str); ok {
		t.Fatal("malformed policy must be absent")
	}
	good := model.Job{CompiledJobPayload: &model.CompiledJobPayload{EffectivePolicy: policy.Capabilities{Container: true}}}
	caps, ok := effectiveCapsOf(good)
	if !ok || !caps.Container {
		t.Fatalf("valid caps = %+v %v", caps, ok)
	}
}

func TestFlowEffectsDownstreamChildTrusted(t *testing.T) {
	if downstreamChildTrusted(model.Job{}) {
		t.Fatal("untrusted job must not grant child trust")
	}
	if downstreamChildTrusted(model.Job{Trusted: true}) {
		t.Fatal("trusted job without caps must not grant child trust")
	}
	noGrant := model.Job{Trusted: true, CompiledJobPayload: &model.CompiledJobPayload{EffectivePolicy: policy.Capabilities{CrossRepoTrigger: false}}}
	if downstreamChildTrusted(noGrant) {
		t.Fatal("job without cross_repo_trigger must not grant child trust")
	}
	grant := model.Job{Trusted: true, CompiledJobPayload: &model.CompiledJobPayload{EffectivePolicy: policy.Capabilities{CrossRepoTrigger: true}}}
	if !downstreamChildTrusted(grant) {
		t.Fatal("cross_repo_trigger job must grant child trust")
	}
}

func TestFlowQueueReasonsDBPaths(t *testing.T) {
	ctx := context.Background()
	// Store without the queue-reason extension: no-op.
	s0, f0, _, _ := cacheFixture(t)
	s0.DB = fcPlainStore{f0}
	s0.applyQueueReasonsDB(ctx, model.Runner{ID: "r1"})

	// List error: no-op.
	s1, f1, _, _ := cacheFixture(t)
	s1.DB = &fcStore{dbFakeStore: f1, listQueuedErr: errors.New("queued list down")}
	s1.applyQueueReasonsDB(ctx, model.Runner{ID: "r1"})

	base := model.Job{ID: "job-q", RunID: "run-c", Key: "build", Status: model.StatusQueued, RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", RequiredLabels: []string{"container"}}
	runner := model.Runner{ID: "r1", Labels: []string{"container"}}

	// Non-queued rows are skipped.
	s2, f2, _, _ := cacheFixture(t)
	j := base
	j.ID = "job-done"
	j.Status = model.StatusSuccess
	s2.DB = &fcStore{dbFakeStore: f2, queuedOverride: []model.Job{j}}
	s2.applyQueueReasonsDB(ctx, runner)

	// Missing dependency: read failure resolves to WaitingDependency.
	s3, f3, _, _ := cacheFixture(t)
	j = base
	j.Needs = []string{"absent"}
	s3.DB = &fcStore{dbFakeStore: f3, queuedOverride: []model.Job{j}, getJobErr: errors.New("dependency read down")}
	s3.applyQueueReasonsDB(ctx, runner)
	if got := f3.queueReason("job-q"); got != string(queue.WaitingDependency) {
		t.Fatalf("dependency reason = %q", got)
	}

	// Label mismatch.
	s4, f4, _, _ := cacheFixture(t)
	j = base
	s4.DB = &fcStore{dbFakeStore: f4, queuedOverride: []model.Job{j}}
	s4.applyQueueReasonsDB(ctx, model.Runner{ID: "r1", Labels: []string{"other"}})
	if got := f4.queueReason("job-q"); got != string(queue.NoCompatibleRunner) {
		t.Fatalf("label reason = %q", got)
	}

	// Region mismatch.
	s5, f5, _, _ := cacheFixture(t)
	j = base
	j.PlacementRegions = []string{"eu"}
	s5.DB = &fcStore{dbFakeStore: f5, queuedOverride: []model.Job{j}}
	s5.applyQueueReasonsDB(ctx, model.Runner{ID: "r1", Labels: []string{"container"}, Region: "us"})
	if got := f5.queueReason("job-q"); got != string(queue.RegionUnavailable) {
		t.Fatalf("region reason = %q", got)
	}

	// Environment capacity: the running twin blocks the queued job, and the
	// job itself is skipped in the listing.
	s6, f6, _, _ := cacheFixture(t)
	queued := base
	queued.Environment = "prod"
	queued.EnvironmentConcurrency = 1
	twin := base
	twin.ID = "job-running"
	twin.Status = model.StatusRunning
	twin.Environment = "prod"
	twin.EnvironmentConcurrency = 1
	s6.DB = &fcStore{dbFakeStore: f6, queuedOverride: []model.Job{queued, twin}}
	s6.applyQueueReasonsDB(ctx, runner)
	if got := f6.queueReason("job-q"); got != string(queue.EnvironmentLocked) {
		t.Fatalf("environment reason = %q", got)
	}

	// Persist failure is swallowed.
	s7, f7, _, _ := cacheFixture(t)
	j = base
	s7.DB = &fcStore{dbFakeStore: f7, queuedOverride: []model.Job{j}, setQueueReasonsErr: errors.New("reason write down")}
	s7.applyQueueReasonsDB(ctx, model.Runner{ID: "r1", Labels: []string{"other"}})

	// Environment listing failure: not at capacity.
	s8, f8, _, _ := cacheFixture(t)
	queued = base
	queued.Environment = "prod"
	queued.EnvironmentConcurrency = 1
	s8.DB = &fcStore{dbFakeStore: f8, queuedOverride: []model.Job{queued}, listJobsByEnvErr: errors.New("env list down")}
	s8.applyQueueReasonsDB(ctx, runner)
	if got := f8.queueReason("job-q"); got == string(queue.EnvironmentLocked) {
		t.Fatalf("env list failure must not lock the environment: %q", got)
	}

	// No active twin: the environment is not at capacity.
	s9, f9, _, _ := cacheFixture(t)
	queued = base
	queued.Environment = "prod"
	queued.EnvironmentConcurrency = 1
	idleTwin := twin
	idleTwin.Status = model.StatusQueued
	s9.DB = &fcStore{dbFakeStore: f9, queuedOverride: []model.Job{queued, idleTwin}}
	s9.applyQueueReasonsDB(ctx, runner)
	if got := f9.queueReason("job-q"); got == string(queue.EnvironmentLocked) {
		t.Fatalf("idle twin must not lock the environment: %q", got)
	}
}

func TestFlowQueueReasonsNoopWhenReasonUnchanged(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	job := model.Job{ID: "job-q", RunID: "run-c", Key: "build", Status: model.StatusQueued, RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a"}
	f.mu.Lock()
	f.queueReasons["job-q"] = string(queue.None)
	f.mu.Unlock()
	s.DB = &fcStore{dbFakeStore: f, queuedOverride: []model.Job{job}}
	s.applyQueueReasonsDB(context.Background(), model.Runner{ID: "r1"})
	if got := f.queueReason("job-q"); got != string(queue.None) {
		t.Fatalf("unchanged reason = %q", got)
	}
}

func TestFlowEffectsOutboxKindList(t *testing.T) {
	if len(storage.CompletionEffectKinds()) == 0 {
		t.Fatal("completion effect kinds must not be empty")
	}
	var _ forge.OutboxItem
}
