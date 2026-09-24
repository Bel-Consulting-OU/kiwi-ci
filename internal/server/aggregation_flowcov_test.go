package server

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestFlowAggregationDBSkipsMemoryPasses(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(newDBFakeStore()); err != nil {
		t.Fatal(err)
	}
	// All three memory aggregation passes are SQL-owned in DB mode.
	s.mu.Lock()
	s.scheduleStateLocked()
	s.refreshRunLocked("whatever")
	s.recoverLeasesLocked(time.Now().UTC(), false)
	s.mu.Unlock()
}

func TestFlowAggregationScheduleState(t *testing.T) {
	s := New("tok")
	now := time.Now().UTC()
	s.mu.Lock()
	s.runs["run-1"] = model.Run{ID: "run-1", Ref: "refs/heads/dev", Status: model.StatusRunning}
	s.jobs["parent"] = model.Job{ID: "parent", RunID: "run-1", Key: "build", Status: model.StatusFailure, FinishedAt: &now}
	s.jobs["blocked"] = model.Job{ID: "blocked", RunID: "run-1", Key: "after", Status: model.StatusQueued, Needs: []string{"parent"}}
	s.jobs["env"] = model.Job{ID: "env", RunID: "run-1", Key: "deploy", Status: model.StatusQueued, Environment: "prod", EnvironmentBranches: []string{"main"}}
	s.jobs["approved"] = model.Job{ID: "approved", RunID: "run-1", Key: "gate", Status: model.StatusWaitingApproval}
	s.mu.Unlock()
	s.mu.Lock()
	s.scheduleStateLocked()
	blocked := s.jobs["blocked"]
	env := s.jobs["env"]
	approved := s.jobs["approved"]
	s.mu.Unlock()
	if blocked.Status != model.StatusBlocked || blocked.Error != "dependency failed" {
		t.Fatalf("dependency-blocked job = %+v", blocked)
	}
	if env.Status != model.StatusBlocked {
		t.Fatalf("branch-blocked job = %+v", env)
	}
	if approved.Status != model.StatusQueued {
		t.Fatalf("approved job = %+v", approved)
	}
	// An approval-gated job parks in WaitingApproval.
	s2 := New("tok")
	s2.mu.Lock()
	s2.runs["run-1"] = model.Run{ID: "run-1", Ref: "refs/heads/main", Status: model.StatusRunning}
	s2.jobs["gate"] = model.Job{ID: "gate", RunID: "run-1", Key: "gate", Status: model.StatusQueued, ApprovalRequired: true}
	s2.mu.Unlock()
	s2.mu.Lock()
	s2.scheduleStateLocked()
	gate := s2.jobs["gate"]
	s2.mu.Unlock()
	if gate.Status != model.StatusWaitingApproval || gate.WaitingSince == nil {
		t.Fatalf("waiting job = %+v", gate)
	}
}

func TestFlowAggregationRefreshRunMissing(t *testing.T) {
	s := New("tok")
	s.mu.Lock()
	s.refreshRunLocked("ghost")
	s.mu.Unlock()
	// A run with no jobs keeps its status.
	s.mu.Lock()
	s.runs["empty"] = model.Run{ID: "empty", Status: model.StatusRunning}
	s.refreshRunLocked("empty")
	run := s.runs["empty"]
	s.mu.Unlock()
	if run.Status != model.StatusRunning {
		t.Fatalf("empty run = %+v", run)
	}
	// A cancelled run is left alone even with terminal jobs.
	s.mu.Lock()
	s.runs["cancelled"] = model.Run{ID: "cancelled", Status: model.StatusCancelled}
	s.jobs["c1"] = model.Job{ID: "c1", RunID: "cancelled", Status: model.StatusSuccess}
	s.refreshRunLocked("cancelled")
	cancelled := s.runs["cancelled"]
	s.mu.Unlock()
	if cancelled.Status != model.StatusCancelled {
		t.Fatalf("cancelled run = %+v", cancelled)
	}
	// Waiting jobs surface as waiting approval; partial terminal jobs keep
	// the run queued.
	s.mu.Lock()
	s.runs["waiting"] = model.Run{ID: "waiting", Status: model.StatusRunning}
	s.jobs["w1"] = model.Job{ID: "w1", RunID: "waiting", Status: model.StatusWaitingApproval}
	s.refreshRunLocked("waiting")
	waiting := s.runs["waiting"]
	s.mu.Unlock()
	if waiting.Status != model.StatusWaitingApproval {
		t.Fatalf("waiting run = %+v", waiting)
	}
	s.mu.Lock()
	s.runs["queued"] = model.Run{ID: "queued", Status: model.StatusRunning}
	s.jobs["q1"] = model.Job{ID: "q1", RunID: "queued", Status: model.StatusSuccess}
	s.jobs["q2"] = model.Job{ID: "q2", RunID: "queued", Status: model.StatusQueued}
	s.refreshRunLocked("queued")
	queued := s.runs["queued"]
	s.mu.Unlock()
	if queued.Status != model.StatusQueued {
		t.Fatalf("queued run = %+v", queued)
	}
}

func TestFlowAggregationRecoverLeases(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	// Queue timeout cancels a queued job past its deadline.
	s := New("tok")
	s.mu.Lock()
	s.runs["run-1"] = model.Run{ID: "run-1", Status: model.StatusRunning}
	deadline := now.Add(-time.Minute)
	s.jobs["q"] = model.Job{ID: "q", RunID: "run-1", Key: "build", Status: model.StatusQueued, QueueDeadline: &deadline}
	s.mu.Unlock()
	s.mu.Lock()
	s.recoverLeasesLocked(now, true)
	q := s.jobs["q"]
	s.mu.Unlock()
	if q.Status != model.StatusCancelled || q.Error != "queue timeout" {
		t.Fatalf("queue-timeout job = %+v", q)
	}

	// Lost runner: the infra retry budget is exhausted, and releasing the
	// runner promotes its next active job.
	s2 := New("tok")
	s2.mu.Lock()
	s2.runs["run-1"] = model.Run{ID: "run-1", Status: model.StatusRunning}
	s2.jobs["lost"] = model.Job{ID: "lost", RunID: "run-1", Key: "build", Status: model.StatusRunning,
		LeaseRunnerID: "r1", LeaseExpiresAt: &past, Attempts: 5, MaxInfraRetries: 1}
	s2.runners["r1"] = model.Runner{ID: "r1", Capacity: 2, ActiveJobs: []string{"lost", "next"}, CurrentJob: "lost"}
	s2.mu.Unlock()
	s2.mu.Lock()
	s2.recoverLeasesLocked(now, false)
	lost := s2.jobs["lost"]
	runner := s2.runners["r1"]
	s2.mu.Unlock()
	if lost.Status != model.StatusFailure || lost.Error == "" {
		t.Fatalf("lost-runner job = %+v", lost)
	}
	if runner.CurrentJob != "next" || runner.Busy {
		t.Fatalf("runner after release = %+v", runner)
	}

	// Retryable expiry requeues the job.
	s3 := New("tok")
	s3.mu.Lock()
	s3.runs["run-1"] = model.Run{ID: "run-1", Status: model.StatusRunning}
	s3.jobs["retry"] = model.Job{ID: "retry", RunID: "run-1", Key: "build", Status: model.StatusRunning,
		LeaseRunnerID: "r1", LeaseExpiresAt: &past, Attempts: 0, MaxInfraRetries: 1}
	s3.mu.Unlock()
	s3.mu.Lock()
	s3.recoverLeasesLocked(now, false)
	retry := s3.jobs["retry"]
	s3.mu.Unlock()
	if retry.Status != model.StatusQueued {
		t.Fatalf("retryable job = %+v", retry)
	}
}

func TestFlowAggregationAuditStoreFailure(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	s.DB = &fcStore{dbFakeStore: f, appendAuditErr: context.DeadlineExceeded}
	// An audit append failure is best-effort: the server must log it (with
	// the action and the underlying error) instead of silently swallowing it
	// or panicking.
	var buf bytes.Buffer
	s.Logger = logging.NewStructured(&buf)
	s.mu.Lock()
	s.auditLocked("test.action", "actor", "run-c", "job-a", "msg", nil)
	s.mu.Unlock()
	out := buf.String()
	if !strings.Contains(out, "audit: append failed") {
		t.Fatalf("audit failure was not logged: %s", out)
	}
	if !strings.Contains(out, context.DeadlineExceeded.Error()) {
		t.Fatalf("audit failure log is missing the underlying error: %s", out)
	}
}
