package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const effectsPipeline = `version: 1
jobs:
  deploy:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    environment:
      name: production
    downstream:
      repository: acme/child
      ref: refs/heads/main
    steps:
      - run: echo deploy
`

// grantEffectsCapabilities enables the deployments and cross-repo
// capabilities for the effects test pipeline.
func grantEffectsCapabilities(s *Server) {
	caps := policy.DefaultTrustedCapabilities()
	caps.Deployments = true
	caps.CrossRepoTrigger = true
	s.AdmissionCapabilities = &caps
}

// effectsFixture builds a DB-mode server with a leased job whose runner
// carries cost rates so usage accounting is observable.
func effectsFixture(t *testing.T, f *dbFakeStore) (*Server, string, Task) {
	t.Helper()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	grantEffectsCapabilities(s)
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: effectsPipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2,"cost_per_hour":10,"power_watts":50}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next: %d %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	// Give the leased job a start time so usage accounting computes a
	// non-zero cost (the DB fake does not set it itself).
	f.mu.Lock()
	j := f.jobs[task.Job.ID]
	st := time.Now().UTC().Add(-30 * time.Second)
	j.StartedAt = &st
	f.jobs[task.Job.ID] = j
	f.mu.Unlock()
	return s, ri.ID, task
}

// deploymentOfJob finds the deployment record bound to a job in the fake
// store.
func deploymentOfJob(t *testing.T, f *dbFakeStore, jobID string) model.Deployment {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, d := range f.deployments {
		if d.JobID == jobID {
			return d
		}
	}
	t.Fatalf("no deployment record for job %s", jobID)
	return model.Deployment{}
}

// crashComplete applies the completion through the store directly (like the
// HTTP path's transaction) WITHOUT running any post-transaction effect: it
// simulates a crash between the durable completion commit and the effect
// pass.
func crashComplete(t *testing.T, s *Server, task Task, runnerID string) {
	t.Helper()
	hash := completionResultHash(model.StatusSuccess, "", nil)
	if err := s.Sched.Complete(context.Background(), task.Job.ID, task.LeaseGeneration, runnerID, model.StatusSuccess, "", nil, hash); err != nil {
		t.Fatalf("store completion: %v", err)
	}
}

// effectKindsQueued reports the effect kinds present in the store's outbox.
func effectKindsQueued(f *dbFakeStore) map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]int{}
	for _, it := range f.outboxItems {
		out[it.Kind]++
	}
	return out
}

func downstreamIntentsQueued(f *dbFakeStore) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, it := range f.outboxItems {
		if it.Kind == forge.OutboxKindDownstream {
			n++
		}
	}
	return n
}

// TestCompletionEffectsReceiptReplayExactlyOnce simulates the crash window:
// the completion commits (receipt + effect intents in the same transaction)
// but the effects never run, then the runner's replayed completion hits the
// receipt fast path and reconciliation applies every effect exactly once.
// A second replay must not double-account.
func TestCompletionEffectsReceiptReplayExactlyOnce(t *testing.T) {
	f := newDBFakeStore()
	s, runnerID, task := effectsFixture(t, f)
	crashComplete(t, s, task, runnerID)

	// The durable completion committed but no effect ran yet.
	f.mu.Lock()
	j := f.jobs[task.Job.ID]
	f.mu.Unlock()
	if j.UsageRecorded {
		t.Fatal("usage recorded before any effect ran")
	}
	f.mu.Lock()
	_, hasLink := f.downstreamLinks[task.Job.ID+"\x00acme/child\x00refs/heads/main"]
	f.mu.Unlock()
	if hasLink {
		t.Fatal("downstream link recorded before any effect ran")
	}
	kinds := effectKindsQueued(f)
	for _, k := range []string{storage.OutboxKindCompletionReconcile, storage.OutboxKindForgeDelivery} {
		if kinds[k] != 1 {
			t.Fatalf("effect kind %q queued %d times, want 1 (in-transaction intents)", k, kinds[k])
		}
	}
	if len(kinds) != storage.CompletionEffectIntentCount {
		t.Fatalf("completion persisted %d intents, want %d", len(kinds), storage.CompletionEffectIntentCount)
	}
	if downstreamIntentsQueued(f) != 0 {
		t.Fatal("downstream dispatch intent must not exist before reconciliation")
	}

	// The replayed completion (same payload) acknowledges through the
	// receipt fast path and reconciles the effects.
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("receipt replay = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	j = f.jobs[task.Job.ID]
	f.mu.Unlock()
	if !j.UsageRecorded || j.Cost <= 0 {
		t.Fatalf("usage not recorded after reconciliation: %+v", j)
	}
	f.mu.Lock()
	_, hasLink = f.downstreamLinks[task.Job.ID+"\x00acme/child\x00refs/heads/main"]
	f.mu.Unlock()
	if !hasLink {
		t.Fatal("downstream link not recorded after reconciliation")
	}
	d := deploymentOfJob(t, f, task.Job.ID)
	if d.FinishedAt == nil {
		t.Fatal("deployment not finished after reconciliation")
	}
	if downstreamIntentsQueued(f) != 1 {
		t.Fatalf("downstream dispatch intents = %d, want exactly 1", downstreamIntentsQueued(f))
	}
	costCounter := s.Metrics.counters["kiwi_usage_cost_total"][""]
	finishedAt := d.FinishedAt

	// A second identical replay must not double-account.
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("second replay = %d: %s", w.Code, w.Body.String())
	}
	if got := s.Metrics.counters["kiwi_usage_cost_total"][""]; got != costCounter {
		t.Fatalf("usage cost counter = %v after second replay, want %v (no double accounting)", got, costCounter)
	}
	if downstreamIntentsQueued(f) != 1 {
		t.Fatalf("downstream dispatch intents after second replay = %d, want 1", downstreamIntentsQueued(f))
	}
	d = deploymentOfJob(t, f, task.Job.ID)
	if d.FinishedAt == nil || !d.FinishedAt.Equal(*finishedAt) {
		t.Fatal("deployment finished_at changed on replay")
	}
}

// TestCompletionEffectsFlushAfterRestart simulates the same crash window
// resolved by the OUTBOX FLUSH after a restart: the replayed effect intents
// run the effects (markers absent), exactly once each.
func TestCompletionEffectsFlushAfterRestart(t *testing.T) {
	f := newDBFakeStore()
	s, runnerID, task := effectsFixture(t, f)
	crashComplete(t, s, task, runnerID)

	// "Restart": a fresh server on the same store replays the pending
	// intents and its flush performs the effects.
	s2 := New("token")
	if err := s2.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s2.DownstreamAllowlist = map[string][]string{"acme/child": {"o/r"}}
	s2.DownstreamPipelineFetcher = func(ctx context.Context, repo, ref string) (string, error) {
		return childPipeline, nil
	}
	s2.flushOutbox(context.Background())

	f.mu.Lock()
	j := f.jobs[task.Job.ID]
	_, hasLink := f.downstreamLinks[task.Job.ID+"\x00acme/child\x00refs/heads/main"]
	pending := len(f.outboxItems)
	f.mu.Unlock()
	if !j.UsageRecorded || j.Cost <= 0 {
		t.Fatalf("flush did not account usage: %+v", j)
	}
	if !hasLink {
		t.Fatal("flush did not record the downstream link")
	}
	if d := deploymentOfJob(t, f, task.Job.ID); d.FinishedAt == nil {
		t.Fatal("flush did not finish the deployment")
	}
	if pending != 0 {
		t.Fatalf("outbox not drained after restart flush: %d items", pending)
	}
	_ = runnerID
}

// TestCompletionEffectsMemoryMarkersPreventDoubleAccounting (memory mode):
// complete() applies the effects inline AND records the effect intents into
// the outbox; the flush re-runs them as marker-guarded no-ops, so the usage
// window holds exactly one entry and the downstream intent is recorded
// exactly once.
func TestCompletionEffectsMemoryMarkersPreventDoubleAccounting(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{"o/r": {CrossRepoTrigger: boolPtr(true)}}}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: downstreamPipeline, Trusted: true,
	}); err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseRunJob(t, s)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	usageLen := len(s.usage)
	j := s.jobs[task.Job.ID]
	s.mu.Unlock()
	if !j.UsageRecorded {
		t.Fatal("memory completion did not set the usage marker")
	}
	// The completion recorded its effect intents plus the downstream intent.
	if got := downstreamPendingItem(t, s).Kind; got != forge.OutboxKindDownstream {
		t.Fatalf("downstream intent missing")
	}
	// Flushing the effect intents must be marker-guarded no-ops.
	s.DownstreamAllowlist = map[string][]string{"acme/child": {"o/r"}}
	s.DownstreamPipelineFetcher = func(ctx context.Context, repo, ref string) (string, error) {
		return childPipeline, nil
	}
	s.flushOutbox(context.Background())
	s.mu.Lock()
	afterFlush := len(s.usage)
	s.mu.Unlock()
	if afterFlush != usageLen {
		t.Fatalf("usage window grew from %d to %d entries on effect flush", usageLen, afterFlush)
	}
	s.mu.Lock()
	_, hasLink := s.downstreamLinks[downstreamLinkKey(task.Job.ID, "acme/child", "refs/heads/main")]
	s.mu.Unlock()
	if !hasLink {
		t.Fatal("downstream link missing after flush")
	}
}
