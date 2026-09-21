package storage

// The focused FAIL-before regression for the leadership-epoch fence: the
// identical file compiled against the pre-fix tree fails (the stale leader's
// RecoverExpiredLease succeeds — the split-brain window), and against the
// fixed tree it must pass (the mutation is rejected and nothing changes).
// Gated on KIWI_TEST_POSTGRES_URL like every *_it_test.go here.

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestPostgresIntegrationLeaderFenceStaleMutationRejected(t *testing.T) {
	env := pgITSetup(t)
	a := env.open(t)
	env.migrate(t, a)
	b := env.open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	key := "kiwi-scratch-leader-fence"

	if got, err := a.TryAcquireLeadership(ctx, key, time.Minute); err != nil || !got {
		t.Fatalf("A acquire = %v, %v", got, err)
	}
	runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	job := pgITJob(runID, jobID, pgITRepo)
	job.MaxInfraRetries = 3
	pgITRecSeedRun(t, a, runID, model.StatusRunning, map[string]model.Job{jobID: job})
	pgITSeedRunner(t, a, runnerID, 1, 0, 0)
	pgITRecLease(t, a, jobID, runnerID, 1, now.Add(-time.Minute))

	// Kill A's dedicated leadership session: the advisory lock dies with it
	// while A's cached claim survives.
	if a.leaderConn == nil {
		t.Fatal("A has no leader session to kill")
	}
	_ = a.leaderConn.Close(ctx)

	// B takes the freed lock: A is now a stale leader.
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := b.TryAcquireLeadership(ctx, key, time.Minute)
		if err != nil {
			t.Fatalf("B acquire = %v, %v", got, err)
		}
		if got {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("B never acquired the lock A's dead session released")
		}
		time.Sleep(25 * time.Millisecond)
	}

	// A's leader-only mutation must be rejected by the fence and mutate
	// nothing. Pre-fix this is exactly the split-brain window: the mutation
	// succeeds.
	if err := a.RecoverExpiredLease(ctx, jobID, 1, now); err == nil {
		t.Fatal("stale leader's RecoverExpiredLease succeeded; every leader-only mutation must be epoch-fenced")
	}
	j, gerr := a.GetJob(ctx, jobID)
	if gerr != nil {
		t.Fatalf("GetJob after stale mutation: %v", gerr)
	}
	if j.Status != model.StatusRunning || j.LeaseRunnerID != runnerID {
		t.Fatalf("stale leader mutated the job: status=%s lease=%q", j.Status, j.LeaseRunnerID)
	}
}
