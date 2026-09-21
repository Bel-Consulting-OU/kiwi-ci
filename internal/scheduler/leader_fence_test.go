package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestSchedulerRecoverExpiredStopsOnStaleLeader pins the scheduler half of
// the leadership fence: when the store rejects a recovery mutation with
// storage.ErrStaleLeader (the cached claim outlived the advisory lock), the
// sweep must abort immediately after the FIRST rejected transition — every
// later candidate would be rejected the same way — return the typed error,
// mutate nothing, and demote this instance so the next Maintain tick goes
// through a real acquisition instead of re-running a stale leader's sweep.
func TestSchedulerRecoverExpiredStopsOnStaleLeader(t *testing.T) {
	now := time.Now().UTC()
	f := newAtomicFakeStore()
	f.setLeader(true, nil)
	exp := now.Add(-time.Minute)
	for _, id := range []string{"job-a", "job-b"} {
		j := leaseTestJob(id, "run")
		j.Status = model.StatusRunning
		j.Attempts = 1
		j.MaxInfraRetries = 3
		j.LeaseRunnerID = "runner"
		j.LeaseTokenHash = []byte("hash")
		j.LeaseGeneration = 1
		j.LeaseExpiresAt = &exp
		f.putJob(j)
	}
	f.putRunner(model.Runner{ID: "runner", Name: "runner", Capacity: 2})
	f.recoverErr = storage.ErrStaleLeader

	s := NewDB(f, time.Minute, nil, nil)
	err := s.RecoverExpired(context.Background(), now)
	if !errors.Is(err, storage.ErrStaleLeader) {
		t.Fatalf("RecoverExpired with a stale epoch = %v; want ErrStaleLeader", err)
	}
	if s.leader.Load() {
		t.Fatal("stale-leader rejection did not demote the scheduler")
	}
	if len(f.recoverCalls) != 1 {
		t.Fatalf("recovery appliers after the stale rejection = %d; want 1 (abort the sweep)", len(f.recoverCalls))
	}
	for _, id := range []string{"job-a", "job-b"} {
		j, _ := f.job(id)
		if j.Status != model.StatusRunning || j.LeaseRunnerID != "runner" {
			t.Fatalf("stale sweep mutated %s: %+v", id, j)
		}
	}
}

// TestSchedulerExpireQueuedJobStopsOnStaleLeader is the queue-timeout half of
// the same contract: the first ErrStaleLeader aborts the queue-timeout sweep
// and demotes instead of logging per-candidate rejections for every elapsed
// deadline.
func TestSchedulerExpireQueuedJobStopsOnStaleLeader(t *testing.T) {
	now := time.Now().UTC()
	f := newAtomicFakeStore()
	f.setLeader(true, nil)
	deadline := now.Add(-time.Minute)
	for _, id := range []string{"job-a", "job-b"} {
		j := leaseTestJob(id, "run")
		j.QueueDeadline = &deadline
		f.putJob(j)
	}
	f.expireErr = storage.ErrStaleLeader

	s := NewDB(f, time.Minute, nil, nil)
	err := s.RecoverExpired(context.Background(), now)
	if !errors.Is(err, storage.ErrStaleLeader) {
		t.Fatalf("RecoverExpired with a stale epoch = %v; want ErrStaleLeader", err)
	}
	if s.leader.Load() {
		t.Fatal("stale-leader rejection did not demote the scheduler")
	}
	if len(f.expireCalls) != 1 {
		t.Fatalf("queue-timeout appliers after the stale rejection = %d; want 1 (abort the sweep)", len(f.expireCalls))
	}
	for _, id := range []string{"job-a", "job-b"} {
		j, _ := f.job(id)
		if j.Status != model.StatusQueued {
			t.Fatalf("stale sweep cancelled %s: %+v", id, j)
		}
	}
}
