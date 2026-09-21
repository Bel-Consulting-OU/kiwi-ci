package scheduler

// Real-PostgreSQL regression for the end-to-end scheduler fence: a scheduler
// whose store retains a stale leadership epoch (the cached-claim window a dead
// advisory-lock session leaves behind) must have its recovery sweep rejected
// by the store inside the mutation's transaction, be demoted, and mutate
// nothing. Re-acquisition must then sweep normally — no false stale
// rejections for the current leader. Gated on KIWI_TEST_POSTGRES_URL like the
// other scheduler integration tests.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func TestPostgresIntegrationSchedulerStaleLeaderFenceDemotes(t *testing.T) {
	st := pgITSchedStore(t)
	ctx := context.Background()
	sched := pgITSchedLeader(t, st)
	now := time.Now().UTC()

	runID, jobID, runnerID := pgITSchedID(t), pgITSchedID(t), pgITSchedID(t)
	job := pgITSchedJob(runID, jobID)
	job.MaxInfraRetries = 3
	if err := st.InsertCompiledRun(ctx, storage.InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: pgITSchedRepo, Status: model.StatusRunning, CreatedAt: now},
		Jobs: map[string]model.Job{jobID: job},
	}); err != nil {
		t.Fatalf("enqueue run: %v", err)
	}
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 1}); err != nil {
		t.Fatalf("upsert runner: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, storage.LeaseClaim{
		JobID: jobID, RunnerID: runnerID, TokenHash: []byte("hash"), Generation: 1, ExpiresAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("lease: %v", err)
	}

	// Simulate the cached-claim window: the store's retained epoch goes back
	// to the previous durable value while its session and cached proof still
	// look live. This is observably identical to a throttled cached true
	// whose advisory lock a new leader has already taken.
	current, err := st.ReadLeaderEpoch(ctx)
	if err != nil || current < 2 {
		t.Fatalf("current epoch = %d/%v; want at least 2 after acquisition", current, err)
	}
	st.SetLeaderEpoch(current - 1)

	err = sched.RecoverExpired(ctx, now)
	if !errors.Is(err, storage.ErrStaleLeader) {
		t.Fatalf("stale RecoverExpired = %v; want ErrStaleLeader", err)
	}
	if sched.leader.Load() {
		t.Fatal("stale-leader rejection did not demote the scheduler")
	}
	if j, gerr := st.GetJob(ctx, jobID); gerr != nil || j.Status != model.StatusRunning || j.LeaseRunnerID != runnerID {
		t.Fatalf("stale sweep mutated the job: %+v err=%v", j, gerr)
	}
	if _, ok := st.LeaderEpoch(); ok {
		t.Fatal("stale store still retains an epoch after the rejection")
	}

	// No false stale: the same scheduler re-acquires (publishing a fresh,
	// greater epoch on a new session) and the sweep then recovers the lease.
	if !sched.IsLeader(ctx) {
		t.Fatal("scheduler could not re-acquire after the stale rejection")
	}
	if err := sched.RecoverExpired(ctx, now); err != nil {
		t.Fatalf("recovery after re-acquisition = %v", err)
	}
	if j, gerr := st.GetJob(ctx, jobID); gerr != nil || j.Status != model.StatusQueued || j.LeaseRunnerID != "" {
		t.Fatalf("current leader's recovery did not requeue: %+v err=%v", j, gerr)
	}
}
