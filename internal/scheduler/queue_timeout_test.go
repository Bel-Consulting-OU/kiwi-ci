package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// compiledPayload builds a model.CompiledJobPayload whose EffectiveJob is
// the JSON of a pipeline.CompiledJob declaring the given queue timeout.
func compiledPayload(queueTimeout string) *model.CompiledJobPayload {
	cj := pipeline.CompiledJob{ID: "build", BaseID: "build"}
	if queueTimeout != "" {
		d, err := time.ParseDuration(queueTimeout)
		if err != nil {
			panic(err)
		}
		cj.Job.QueueTimeout.Duration = d
		cj.Job.QueueTimeout.Set = true
	}
	b, err := json.Marshal(cj)
	if err != nil {
		panic(err)
	}
	return &model.CompiledJobPayload{
		SchemaVersion:  1,
		PipelineDigest: "d",
		JobDigest:      "d",
		EffectiveJob:   json.RawMessage(b),
	}
}

func TestLeaseSkipsExpiredQueueDeadline(t *testing.T) {
	f := newFakeStore()
	f.setLeader(true, nil)
	now := time.Now().UTC()
	f.putRunner(model.Runner{ID: "runner", Name: "runner", Capacity: 1})
	f.putRun(model.Run{ID: "run", Status: model.StatusQueued, CreatedAt: now})
	past := now.Add(-time.Minute)
	f.putJob(model.Job{ID: "job", RunID: "run", Key: "build", Status: model.StatusQueued, CreatedAt: now.Add(-time.Hour), QueueDeadline: &past})
	s := NewDB(f, time.Minute, nil, nil)
	if _, _, _, err := s.Lease(context.Background(), "runner", now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("Lease with expired deadline = %v, want ErrNoJobs", err)
	}
	if len(f.acquireCalls) != 0 {
		t.Fatalf("expired job was leased: %+v", f.acquireCalls)
	}
}

func TestLeaseAcceptsFreshQueueDeadline(t *testing.T) {
	f := newFakeStore()
	f.setLeader(true, nil)
	now := time.Now().UTC()
	f.putRunner(model.Runner{ID: "runner", Name: "runner", Capacity: 1})
	f.putRun(model.Run{ID: "run", Status: model.StatusQueued, CreatedAt: now})
	fut := now.Add(time.Hour)
	f.putJob(model.Job{ID: "job", RunID: "run", Key: "build", Status: model.StatusQueued, CreatedAt: now, QueueDeadline: &fut})
	s := NewDB(f, time.Minute, nil, nil)
	j, _, _, err := s.Lease(context.Background(), "runner", now)
	if err != nil {
		t.Fatalf("Lease with fresh deadline: %v", err)
	}
	if j == nil || j.ID != "job" {
		t.Fatalf("leased job = %+v, want job", j)
	}
}

func TestRecoverExpiredCancelsQueueTimedOutJobs(t *testing.T) {
	f := newFakeStore()
	f.setLeader(true, nil)
	now := time.Now().UTC()
	f.putRun(model.Run{ID: "run", Status: model.StatusQueued, CreatedAt: now.Add(-time.Hour)})
	past := now.Add(-time.Minute)
	f.putJob(model.Job{ID: "expired", RunID: "run", Key: "expired", Status: model.StatusQueued, CreatedAt: now.Add(-time.Hour), QueueDeadline: &past})
	f.putJob(model.Job{ID: "down", RunID: "run", Key: "down", Status: model.StatusQueued, Condition: "success()", Needs: []string{"expired"}, CreatedAt: now.Add(-time.Hour)})
	fut := now.Add(time.Hour)
	f.putJob(model.Job{ID: "fresh", RunID: "run", Key: "fresh", Status: model.StatusQueued, CreatedAt: now, QueueDeadline: &fut})
	s := NewDB(f, time.Minute, nil, nil)
	if err := s.RecoverExpired(context.Background(), now); err != nil {
		t.Fatalf("RecoverExpired: %v", err)
	}
	j, _ := f.job("expired")
	if j.Status != model.StatusCancelled {
		t.Errorf("expired job status = %q, want cancelled", j.Status)
	}
	if j.Error != "queue timeout" {
		t.Errorf("expired job error = %q, want queue timeout", j.Error)
	}
	if j.FinishedAt == nil {
		t.Error("expired job FinishedAt not set")
	}
	j, _ = f.job("fresh")
	if j.Status != model.StatusQueued {
		t.Errorf("fresh job status = %q, want queued", j.Status)
	}
	// Dependents of the cancelled job are recomputed and blocked.
	j, _ = f.job("down")
	if j.Status != model.StatusBlocked {
		t.Errorf("dependent status = %q, want blocked", j.Status)
	}
	audits := f.audits()
	found := false
	for _, a := range audits {
		if a.Action == "job.queue_timeout" {
			found = true
		}
	}
	if !found {
		t.Errorf("audit events = %+v, want a job.queue_timeout event", audits)
	}
}

func TestRecoverExpiredQueueTimeoutAttemptsIndependent(t *testing.T) {
	f := newFakeStore()
	f.setLeader(true, nil)
	now := time.Now().UTC()
	f.putRun(model.Run{ID: "run", Status: model.StatusQueued, CreatedAt: now.Add(-time.Hour)})
	past := now.Add(-time.Minute)
	// Attempts 0 with a huge infra budget: the queue timeout still cancels
	// terminally; it never requeues or defers to the retry budget.
	f.putJob(model.Job{ID: "job", RunID: "run", Key: "job", Status: model.StatusQueued, Attempts: 0, MaxInfraRetries: 100, QueueDeadline: &past})
	s := NewDB(f, time.Minute, nil, nil)
	if err := s.RecoverExpired(context.Background(), now); err != nil {
		t.Fatalf("RecoverExpired: %v", err)
	}
	j, _ := f.job("job")
	if j.Status != model.StatusCancelled || j.Attempts != 0 {
		t.Errorf("job = %s (attempts %d), want terminal cancelled with attempts untouched", j.Status, j.Attempts)
	}
	run, _ := f.GetRun(context.Background(), "run")
	if run.Status != model.StatusCancelled {
		t.Errorf("run status = %q, want cancelled", run.Status)
	}
}

func TestQueueDeadlineDerivedFromCompiledPayload(t *testing.T) {
	f := newFakeStore()
	f.setLeader(true, nil)
	now := time.Now().UTC()
	f.putRunner(model.Runner{ID: "runner", Name: "runner", Capacity: 1})
	f.putRun(model.Run{ID: "run", Status: model.StatusQueued, CreatedAt: now.Add(-time.Hour)})
	// QueueDeadline unset, but the compiled payload declares a 5m timeout
	// and the job was created an hour ago: the derived deadline passed.
	f.putJob(model.Job{ID: "job", RunID: "run", Key: "build", Status: model.StatusQueued,
		CreatedAt: now.Add(-time.Hour), CompiledJobPayload: compiledPayload("5m")})
	s := NewDB(f, time.Minute, nil, nil)
	if _, _, _, err := s.Lease(context.Background(), "runner", now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("Lease with payload-derived expired deadline = %v, want ErrNoJobs", err)
	}
	if err := s.RecoverExpired(context.Background(), now); err != nil {
		t.Fatalf("RecoverExpired: %v", err)
	}
	j, _ := f.job("job")
	if j.Status != model.StatusCancelled || j.Error != "queue timeout" {
		t.Errorf("job = %s/%q, want cancelled queue timeout", j.Status, j.Error)
	}
}

func TestEnqueueMaterializesQueueDeadline(t *testing.T) {
	f := newFakeStore()
	now := time.Now().UTC()
	run := model.Run{ID: "run", Status: model.StatusQueued, CreatedAt: now}
	job := model.Job{ID: "job", RunID: "run", Key: "build", Status: model.StatusQueued, CreatedAt: now, CompiledJobPayload: compiledPayload("10m")}
	s := NewDB(f, time.Minute, nil, nil)
	if err := s.Enqueue(context.Background(), run, map[string]model.Job{"job": job}, nil, false); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	stored, _ := f.job("job")
	if stored.QueueDeadline == nil {
		t.Fatal("QueueDeadline not materialized at enqueue")
	}
	if want := now.Add(10 * time.Minute); !stored.QueueDeadline.Equal(want) {
		t.Errorf("QueueDeadline = %v, want %v", stored.QueueDeadline, want)
	}
	// A job without a queue timeout gets no deadline (a fresh run, since the
	// atomic enqueue inserts one run per request and rejects duplicates).
	plain := model.Job{ID: "job2", RunID: "run2", Key: "plain", Status: model.StatusQueued, CreatedAt: now}
	if err := s.Enqueue(context.Background(), model.Run{ID: "run2", Status: model.StatusQueued, CreatedAt: now}, map[string]model.Job{"job2": plain}, nil, false); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if stored, _ := f.job("job2"); stored.QueueDeadline != nil {
		t.Errorf("job without queue_timeout got a deadline: %v", stored.QueueDeadline)
	}
}
