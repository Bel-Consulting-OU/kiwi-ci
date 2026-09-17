package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// hasDeploymentCompletionAudit reports whether the store recorded the
// deployment.completed audit event.
func hasDeploymentCompletionAudit(f *dbFakeStore) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.audit {
		if e.Action == "deployment.completed" {
			return true
		}
	}
	return false
}

// TestDeploymentFinishEffectRetriesAfterUpdateFailure: a failed durable
// status update leaves the deployment running, emits no completion audit,
// keeps the effect pending, and a restarted instance converges it once the
// store recovers.
func TestDeploymentFinishEffectRetriesAfterUpdateFailure(t *testing.T) {
	f := newDBFakeStore()
	s, runnerID, task := effectsFixture(t, f)
	s.DownstreamAllowlist = map[string][]string{"acme/child": {"o/r"}}
	s.DownstreamPipelineFetcher = func(context.Context, string, string) (string, error) { return childPipeline, nil }
	crashComplete(t, s, task, runnerID)

	f.mu.Lock()
	f.updateDeploymentErr = errors.New("deployment update down")
	f.mu.Unlock()
	s.flushOutbox()

	f.mu.Lock()
	d := f.deployments[task.Job.ID]
	pending := len(f.outboxItems)
	f.mu.Unlock()
	if d.FinishedAt != nil {
		t.Fatalf("failed update reached the store: %+v", d)
	}
	if pending == 0 {
		t.Fatal("failing effect was acked instead of staying pending")
	}
	s.mu.Lock()
	mirror := s.deployments[task.Job.ID]
	s.mu.Unlock()
	if mirror.FinishedAt != nil {
		t.Fatalf("failed update set the in-memory marker: %+v", mirror)
	}
	if hasDeploymentCompletionAudit(f) {
		t.Fatal("failed update emitted the completion audit")
	}

	// Store recovers. The failed flush left its claims on the rows it never
	// reached; simulate the claim TTL passing (a crashed flusher's claims
	// expire after storage.OutboxClaimTTL) so the restart claims them again.
	f.mu.Lock()
	f.updateDeploymentErr = nil
	f.outboxClaims = map[string]fakeOutboxClaim{}
	f.mu.Unlock()
	s2 := New("token")
	if err := s2.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s2.DownstreamAllowlist = map[string][]string{"acme/child": {"o/r"}}
	s2.DownstreamPipelineFetcher = func(context.Context, string, string) (string, error) { return childPipeline, nil }
	s2.flushOutbox()

	d = deploymentOfJob(t, f, task.Job.ID)
	if d.FinishedAt == nil || d.Status != model.StatusSuccess {
		t.Fatalf("deployment not converged after recovery: %+v", d)
	}
	if !hasDeploymentCompletionAudit(f) {
		t.Fatal("recovery did not emit the completion audit")
	}
	f.mu.Lock()
	pendingAfter := len(f.outboxItems)
	f.mu.Unlock()
	if pendingAfter != 0 {
		t.Fatalf("outbox not drained after recovery: %d items", pendingAfter)
	}
}

// TestDeploymentFinishEffectCreatesRecordAfterInsertRecovery: a deployment
// whose lease-time insert never committed is rebuilt by the completion
// effect; a failing insert keeps the effect pending, and a retry after the
// store recovers creates and finishes the record.
func TestDeploymentFinishEffectCreatesRecordAfterInsertRecovery(t *testing.T) {
	f := newDBFakeStore()
	s, runnerID, task := effectsFixture(t, f)
	// Simulate the lease-time create failure: no durable row, no mirror.
	f.mu.Lock()
	delete(f.deployments, task.Job.ID)
	f.mu.Unlock()
	s.mu.Lock()
	delete(s.deployments, task.Job.ID)
	s.mu.Unlock()
	crashComplete(t, s, task, runnerID)

	f.mu.Lock()
	f.deploymentInsertErr = errors.New("deployment insert down")
	f.mu.Unlock()
	s.flushOutbox()

	f.mu.Lock()
	_, created := f.deployments[task.Job.ID]
	pending := len(f.outboxItems)
	f.mu.Unlock()
	if created {
		t.Fatal("failed insert created a durable deployment record")
	}
	if pending == 0 {
		t.Fatal("failing create was acked instead of staying pending")
	}
	if hasDeploymentCompletionAudit(f) {
		t.Fatal("failed create emitted the completion audit")
	}

	f.mu.Lock()
	f.deploymentInsertErr = nil
	f.mu.Unlock()
	s2 := New("token")
	if err := s2.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s2.DownstreamAllowlist = map[string][]string{"acme/child": {"o/r"}}
	s2.DownstreamPipelineFetcher = func(context.Context, string, string) (string, error) { return childPipeline, nil }
	s2.flushOutbox()

	d := deploymentOfJob(t, f, task.Job.ID)
	if d.Status != model.StatusSuccess || d.FinishedAt == nil {
		t.Fatalf("recovered create did not finish the deployment: %+v", d)
	}
	if !hasDeploymentCompletionAudit(f) {
		t.Fatal("recovered create did not emit the completion audit")
	}
}

// TestDeploymentFinishEffectFSPersistFailureRollsBack: in fs mode a failed
// state write rolls the in-memory marker back and leaves the effect in the
// outbox; the retry persists it and converges (with the audit emitted only
// after durability).
func TestDeploymentFinishEffectFSPersistFailureRollsBack(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	j := model.Job{ID: "job-env", RunID: "run-env", Key: "deploy", Status: model.StatusSuccess, Environment: "production", FinishedAt: &now}
	s.mu.Lock()
	s.runs[j.RunID] = model.Run{ID: j.RunID, Repo: "https://github.com/o/r.git", RepoFullName: "o/r", Status: model.StatusSuccess}
	s.jobs[j.ID] = j
	s.deployments[j.ID] = model.Deployment{ID: j.ID, RunID: j.RunID, JobID: j.ID, Environment: "production", Status: model.StatusRunning, CreatedAt: now}
	s.mu.Unlock()
	payload, err := jsonMarshal(storage.CompletionEffectsPayload{JobID: j.ID, RunID: j.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.outbox.Enqueue(forge.OutboxItem{Kind: storage.OutboxKindDeploymentFinish, Payload: payload, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}

	old := persistDeploymentFinishState
	persistDeploymentFinishState = func(*Server) error { return errors.New("state write down") }
	s.flushOutbox()
	persistDeploymentFinishState = old

	s.mu.Lock()
	d := s.deployments[j.ID]
	s.mu.Unlock()
	if d.FinishedAt != nil || d.Status != model.StatusRunning {
		t.Fatalf("failed persist left the in-memory marker: %+v", d)
	}
	if pending := s.outbox.Pending(); len(pending) == 0 {
		t.Fatal("failing effect was acked instead of staying pending")
	}
	audit, err := s.store.ReadAudit(1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range audit {
		if e.Action == "deployment.completed" {
			t.Fatal("failed persist emitted the completion audit")
		}
	}

	// Retry after the state write recovers: the marker commits and the
	// audit follows.
	s.flushOutbox()
	s.mu.Lock()
	d = s.deployments[j.ID]
	s.mu.Unlock()
	if d.FinishedAt == nil || d.Status != model.StatusSuccess {
		t.Fatalf("retry did not finish the deployment: %+v", d)
	}
	if pending := s.outbox.Pending(); len(pending) != 0 {
		t.Fatalf("outbox not drained after retry: %d items", len(pending))
	}
	audit, err = s.store.ReadAudit(1000)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range audit {
		if e.Action == "deployment.completed" {
			found = true
		}
	}
	if !found {
		t.Fatal("retry did not emit the completion audit")
	}
}
