package scheduler

// Real-PostgreSQL integration coverage for the transactional recovery paths:
// DBScheduler.CancelJobsByRunner, DBScheduler.RecoverExpired (expired lease
// and queue timeout) and their idempotency under two replicas. Gated on
// KIWI_TEST_POSTGRES_URL like the other scheduler integration tests.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestPostgresIntegrationSchedulerKillSwitchTransactional proves the runner
// disable kill switch drives exactly one transactional revocation: every job
// is terminal or requeued with its lease cleared, the runner slot is freed,
// the quota counters move once, and a replayed call changes nothing.
func TestPostgresIntegrationSchedulerKillSwitchTransactional(t *testing.T) {
	st := pgITSchedStore(t)
	ctx := context.Background()
	sched := NewDB(st, time.Minute, nil, nil)
	if err := sched.InitErr(); err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	runnerID := pgITSchedID(t)
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 2, Labels: []string{"container"}}); err != nil {
		t.Fatal(err)
	}
	runID := pgITSchedID(t)
	jobRetry, jobDoomed, depID := pgITSchedID(t), pgITSchedID(t), pgITSchedID(t)
	retry := pgITSchedJob(runID, jobRetry)
	retry.MaxInfraRetries = 2
	doomed := pgITSchedJob(runID, jobDoomed)
	doomed.MaxInfraRetries = 0
	dep := pgITSchedJob(runID, depID)
	dep.Condition = "success()"
	dep.Needs = []string{jobDoomed}
	if err := st.InsertCompiledRun(ctx, storage.InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: pgITSchedRepo, Status: model.StatusRunning, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{jobRetry: retry, jobDoomed: doomed, depID: dep},
		Quota: &storage.QuotaReservation{
			RepoKey:  storage.RepoIDFor("", pgITSchedRepo, "kiwi-it/repo"),
			JobCount: 3,
		},
	}); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	for _, jobID := range []string{jobRetry, jobDoomed} {
		if _, err := st.AcquireLeaseAtomic(ctx, storage.LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: expires}); err != nil {
			t.Fatal(err)
		}
	}
	repoKey := storage.RepoIDFor("", pgITSchedRepo, "kiwi-it/repo")
	beforeRunning, beforeQueued, err := st.QuotaCounts(ctx, repoKey, "")
	if err != nil {
		t.Fatal(err)
	}

	count, err := sched.CancelJobsByRunner(ctx, runnerID, "runner disabled")
	if err != nil {
		t.Fatalf("CancelJobsByRunner: %v", err)
	}
	if count != 2 {
		t.Fatalf("revoked count = %d, want 2", count)
	}
	if j, err := st.GetJob(ctx, jobRetry); err != nil || j.Status != model.StatusQueued || j.LeaseRunnerID != "" {
		t.Fatalf("retryable job = %+v err=%v, want queued with cleared lease", j, err)
	}
	if j, err := st.GetJob(ctx, jobDoomed); err != nil || j.Status != model.StatusCancelled || j.FinishedAt == nil {
		t.Fatalf("exhausted job = %+v err=%v, want cancelled", j, err)
	}
	if j, err := st.GetJob(ctx, depID); err != nil || j.Status != model.StatusBlocked {
		t.Fatalf("dependent = %+v err=%v, want blocked", j, err)
	}
	if ri, err := st.GetRunner(ctx, runnerID); err != nil || len(ri.ActiveJobs) != 0 || ri.Failed != 2 {
		t.Fatalf("runner = %+v err=%v, want empty/2 failures", ri, err)
	}
	if running, queued, _ := st.QuotaCounts(ctx, repoKey, ""); running != beforeRunning-2 || queued != beforeQueued+1 {
		t.Fatalf("quota = %d/%d, want %d/%d", running, queued, beforeRunning-2, beforeQueued+1)
	}

	// A second replica racing the same disable sees nothing to revoke.
	count, err = sched.CancelJobsByRunner(ctx, runnerID, "runner disabled")
	if err != nil || count != 0 {
		t.Fatalf("replayed kill switch = %d/%v, want 0/nil", count, err)
	}
	if running, queued, _ := st.QuotaCounts(ctx, repoKey, ""); running != beforeRunning-2 || queued != beforeQueued+1 {
		t.Fatalf("quota after replay = %d/%d, want unchanged", running, queued)
	}
}

// TestPostgresIntegrationSchedulerRecoverExpiredTransactional proves the
// leader's RecoverExpired applies each transition transactionally:
// queue-timeout jobs release their queued reservation exactly once and
// expired leases requeue with the runner slot freed.
func TestPostgresIntegrationSchedulerRecoverExpiredTransactional(t *testing.T) {
	st := pgITSchedStore(t)
	ctx := context.Background()
	sched := pgITSchedLeader(t, st)
	repoKey := storage.RepoIDFor("", pgITSchedRepo, "kiwi-it/repo")

	// Queue timeout: the queued reservation is released in the same commit.
	toRun, toJob, toDep := pgITSchedID(t), pgITSchedID(t), pgITSchedID(t)
	deadline := time.Now().UTC().Add(-time.Minute)
	queued := pgITSchedJob(toRun, toJob)
	queued.QueueDeadline = &deadline
	dep := pgITSchedJob(toRun, toDep)
	dep.Condition = "success()"
	dep.Needs = []string{toJob}
	if err := st.InsertCompiledRun(ctx, storage.InsertCompiledRunRequest{
		Run:  model.Run{ID: toRun, Repo: pgITSchedRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{toJob: queued, toDep: dep},
		Quota: &storage.QuotaReservation{
			RepoKey:  repoKey,
			JobCount: 2,
		},
	}); err != nil {
		t.Fatal(err)
	}
	_, beforeQueued, err := st.QuotaCounts(ctx, repoKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := sched.RecoverExpired(ctx, time.Now().UTC()); err != nil {
		t.Fatalf("RecoverExpired (queue timeout): %v", err)
	}
	if j, err := st.GetJob(ctx, toJob); err != nil || j.Status != model.StatusCancelled || j.Error != "queue timeout" {
		t.Fatalf("queue-timeout job = %+v err=%v", j, err)
	}
	if d, err := st.GetJob(ctx, toDep); err != nil || d.Status != model.StatusBlocked {
		t.Fatalf("queue-timeout dependent = %+v err=%v, want blocked", d, err)
	}
	// Only the timed-out job's reservation is released; the blocked
	// dependent still owns its queued slot.
	if _, queuedCount, _ := st.QuotaCounts(ctx, repoKey, ""); queuedCount != beforeQueued-1 {
		t.Fatalf("queued reservation after timeout = %d, want %d", queuedCount, beforeQueued-1)
	}
	if err := sched.RecoverExpired(ctx, time.Now().UTC()); err != nil {
		t.Fatalf("replayed RecoverExpired: %v", err)
	}
	if _, queuedCount, _ := st.QuotaCounts(ctx, repoKey, ""); queuedCount != beforeQueued-1 {
		t.Fatalf("queued reservation after replay = %d, want %d (no double release)", queuedCount, beforeQueued-1)
	}

	// Expired lease: requeued with the runner slot freed and the reservation
	// moved from running to queued in one transaction.
	runnerID := pgITSchedID(t)
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 1, Labels: []string{"container"}}); err != nil {
		t.Fatal(err)
	}
	lsRun, lsJob := pgITSchedID(t), pgITSchedID(t)
	ls := pgITSchedJob(lsRun, lsJob)
	ls.MaxInfraRetries = 2
	if err := sched.Enqueue(ctx, model.Run{ID: lsRun, Repo: pgITSchedRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()}, map[string]model.Job{lsJob: ls}, nil, false); err != nil {
		t.Fatal(err)
	}
	leased, _, _, err := sched.Lease(ctx, runnerID, time.Now().UTC())
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}
	if err := st.HeartbeatLease(ctx, lsJob, runnerID, leased.LeaseGeneration, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := sched.RecoverExpired(ctx, time.Now().UTC()); err != nil {
		t.Fatalf("RecoverExpired (lease): %v", err)
	}
	recovered, err := st.GetJob(ctx, lsJob)
	if err != nil || recovered.Status != model.StatusQueued || !strings.Contains(recovered.Error, "retrying") {
		t.Fatalf("recovered job = %+v err=%v", recovered, err)
	}
	if ri, err := st.GetRunner(ctx, runnerID); err != nil || len(ri.ActiveJobs) != 0 {
		t.Fatalf("runner after recovery = %+v err=%v, want released slot", ri, err)
	}
}

// TestPostgresIntegrationSchedulerKillSwitchTwoReplicas races two schedulers
// over the same schema through the kill switch: the leases are revoked once
// in total and the counters move exactly once.
func TestPostgresIntegrationSchedulerKillSwitchTwoReplicas(t *testing.T) {
	env := pgITSchedSetup(t)
	storeA := env.open(t)
	storeB := env.open(t)
	ctx := context.Background()
	runnerID := pgITSchedID(t)
	if err := storeA.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 2, Labels: []string{"container"}}); err != nil {
		t.Fatal(err)
	}
	runID := pgITSchedID(t)
	jobA, jobB := pgITSchedID(t), pgITSchedID(t)
	ja := pgITSchedJob(runID, jobA)
	ja.MaxInfraRetries = 2
	jb := pgITSchedJob(runID, jobB)
	jb.MaxInfraRetries = 2
	if err := storeA.InsertCompiledRun(ctx, storage.InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: pgITSchedRepo, Status: model.StatusRunning, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{jobA: ja, jobB: jb},
		Quota: &storage.QuotaReservation{
			RepoKey:  storage.RepoIDFor("", pgITSchedRepo, "kiwi-it/repo"),
			JobCount: 2,
		},
	}); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	for _, jobID := range []string{jobA, jobB} {
		if _, err := storeA.AcquireLeaseAtomic(ctx, storage.LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: expires}); err != nil {
			t.Fatal(err)
		}
	}

	schedA := NewDB(storeA, time.Minute, nil, nil)
	schedB := NewDB(storeB, time.Minute, nil, nil)
	var wg sync.WaitGroup
	counts := make(chan int, 2)
	for _, sched := range []*DBScheduler{schedA, schedB} {
		wg.Add(1)
		go func(sched *DBScheduler) {
			defer wg.Done()
			n, err := sched.CancelJobsByRunner(ctx, runnerID, "runner disabled")
			if err != nil {
				t.Errorf("concurrent kill switch: %v", err)
				counts <- -1
				return
			}
			counts <- n
		}(sched)
	}
	wg.Wait()
	close(counts)
	total := 0
	for n := range counts {
		if n < 0 {
			t.Fatal("concurrent kill switch failed")
		}
		total += n
	}
	if total != 2 {
		t.Fatalf("total revoked = %d, want 2", total)
	}
	repoKey := storage.RepoIDFor("", pgITSchedRepo, "kiwi-it/repo")
	if ri, err := storeA.GetRunner(ctx, runnerID); err != nil || len(ri.ActiveJobs) != 0 || ri.Failed != 2 {
		t.Fatalf("runner = %+v err=%v, want empty/2", ri, err)
	}
	if running, queued, _ := storeA.QuotaCounts(ctx, repoKey, ""); running != 0 || queued != 2 {
		t.Fatalf("quota = %d/%d, want exactly-once release 0/2", running, queued)
	}
}
