package server

// Real-PostgreSQL integration coverage for the leader-gated Maintain tick
// under the leadership-epoch fence (migration 0025): the current leader's
// recovery sweeps must run end-to-end with no false stale rejections, and a
// server whose store retains a stale epoch must be rejected inside the
// mutation's transaction, demoted, and mutate nothing. Gated on
// KIWI_TEST_POSTGRES_URL like the other integration tests in this package.

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func TestPostgresIntegrationServerMaintainLeaderFence(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	ctx := context.Background()
	now := time.Now().UTC()

	seedLeasedJob := func() (jobID string) {
		t.Helper()
		runID := pgITServerRandomHex(t, 32)
		jobID = pgITServerRandomHex(t, 32)
		runnerID := pgITServerRandomHex(t, 32)
		job := model.Job{
			ID: jobID, RunID: runID, Key: "build", RepoURL: "https://example.com/o/r.git",
			RepoFullName: "o/r", Status: model.StatusQueued, CreatedAt: now, MaxInfraRetries: 3,
		}
		if err := st.InsertCompiledRun(ctx, storage.InsertCompiledRunRequest{
			Run:  model.Run{ID: runID, Repo: "https://example.com/o/r.git", Status: model.StatusRunning, CreatedAt: now},
			Jobs: map[string]model.Job{jobID: job},
		}); err != nil {
			t.Fatalf("enqueue run %s: %v", runID, err)
		}
		if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 1}); err != nil {
			t.Fatalf("upsert runner %s: %v", runnerID, err)
		}
		if _, err := st.AcquireLeaseAtomic(ctx, storage.LeaseClaim{
			JobID: jobID, RunnerID: runnerID, TokenHash: []byte("hash"), Generation: 1, ExpiresAt: now.Add(-time.Minute),
		}); err != nil {
			t.Fatalf("lease job %s: %v", jobID, err)
		}
		return jobID
	}

	// Phase 1: the current leader's tick recovers the seeded expired lease
	// AND the queue-timed-out job in full, end-to-end through maintainDB's
	// recovery, downstream-recovery, outbox, GC and CAS GC steps. A false
	// stale rejection anywhere would surface as an error log and an
	// unrecovered job.
	jobID := seedLeasedJob()
	timeoutRun, timeoutJob := pgITServerRandomHex(t, 32), pgITServerRandomHex(t, 32)
	deadline := now.Add(-time.Minute)
	timeoutJobObj := model.Job{
		ID: timeoutJob, RunID: timeoutRun, Key: "build", RepoURL: "https://example.com/o/r.git",
		RepoFullName: "o/r", Status: model.StatusQueued, CreatedAt: now.Add(-time.Hour), QueueDeadline: &deadline,
	}
	if err := st.InsertCompiledRun(ctx, storage.InsertCompiledRunRequest{
		Run:  model.Run{ID: timeoutRun, Repo: "https://example.com/o/r.git", Status: model.StatusQueued, CreatedAt: now.Add(-time.Hour)},
		Jobs: map[string]model.Job{timeoutJob: timeoutJobObj},
	}); err != nil {
		t.Fatalf("enqueue queue-timeout run: %v", err)
	}
	s.mu.Lock()
	s.leader = true // pin the fast gate: the scheduler claim is already held
	s.mu.Unlock()
	s.maintainDB(ctx, now)
	if j, err := st.GetJob(ctx, jobID); err != nil || j.Status != model.StatusQueued || j.LeaseRunnerID != "" {
		t.Fatalf("current leader's recovery of %s = %+v err=%v; want queued with cleared lease", jobID, j, err)
	}
	if j, err := st.GetJob(ctx, timeoutJob); err != nil || j.Status != model.StatusCancelled {
		t.Fatalf("queue-timeout job = %+v err=%v; want cancelled", j, err)
	}
	s.mu.Lock()
	leader := s.leader
	s.mu.Unlock()
	if !leader {
		t.Fatal("current leader was falsely demoted by the epoch fence")
	}

	// Phase 2: a stale retained epoch (the cached-claim window) must be
	// rejected inside the recovery transaction, leave the seeded lease
	// untouched, and demote the server so the rest of the tick's leader-only
	// work is skipped.
	staleJobID := seedLeasedJob()
	current, err := st.ReadLeaderEpoch(ctx)
	if err != nil || current < 2 {
		t.Fatalf("current epoch = %d/%v; want at least 2", current, err)
	}
	st.SetLeaderEpoch(current - 1)
	s.mu.Lock()
	s.leader = true
	s.mu.Unlock()
	s.maintainDB(ctx, now)
	s.mu.Lock()
	leader = s.leader
	s.mu.Unlock()
	if leader {
		t.Fatal("stale leadership epoch did not demote the server")
	}
	if j, err := st.GetJob(ctx, staleJobID); err != nil || j.Status != model.StatusRunning || j.LeaseRunnerID == "" {
		t.Fatalf("stale tick mutated the job: %+v err=%v", j, err)
	}
	if _, ok := st.LeaderEpoch(); ok {
		t.Fatal("stale store still retains an epoch after the rejection")
	}
}
