package storage

// Real-PostgreSQL integration tests for the transactional recovery contract
// (RecoveryStore): RevokeRunnerLeases, RecoverExpiredLease and
// ExpireQueuedJob. Gated on KIWI_TEST_POSTGRES_URL like every *_it_test.go
// file; each test owns a throwaway schema.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITRecSeedRun enqueues one run with the given jobs and a queued quota
// reservation for them.
func pgITRecSeedRun(t *testing.T, st *PostgresStore, runID string, status model.Status, jobs map[string]model.Job) {
	t.Helper()
	if err := st.InsertCompiledRun(context.Background(), InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: pgITRepo, Status: status, CreatedAt: time.Now().UTC()},
		Jobs: jobs,
		Quota: &QuotaReservation{
			RepoKey:  pgITRepoID,
			JobCount: len(jobs),
		},
	}); err != nil {
		t.Fatalf("enqueue run %s: %v", runID, err)
	}
}

// pgITRecLease leases one job through the real atomic claim.
func pgITRecLease(t *testing.T, st *PostgresStore, jobID, runnerID string, generation int64, expiresAt time.Time) {
	t.Helper()
	if _, err := st.AcquireLeaseAtomic(context.Background(), LeaseClaim{
		JobID: jobID, RunnerID: runnerID, TokenHash: []byte("hash"), Generation: generation, ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatalf("lease %s on %s: %v", jobID, runnerID, err)
	}
}

func TestPostgresIntegrationRevokeRunnerLeases(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo := pgITRepo
	runID, runnerID := pgITNewID(t), pgITNewID(t)
	jobRetry, jobDoomed, depID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	otherRun, otherJob, otherRunner := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	expires := time.Now().UTC().Add(time.Hour)

	retry := pgITJob(runID, jobRetry, repo)
	retry.MaxInfraRetries = 2
	doomed := pgITJob(runID, jobDoomed, repo)
	doomed.MaxInfraRetries = 0
	dep := pgITJob(runID, depID, repo)
	dep.Condition = "success()"
	dep.Needs = []string{jobDoomed}
	pgITRecSeedRun(t, st, runID, model.StatusRunning, map[string]model.Job{jobRetry: retry, jobDoomed: doomed, depID: dep})
	pgITRecSeedRun(t, st, otherRun, model.StatusRunning, map[string]model.Job{otherJob: pgITJob(otherRun, otherJob, repo)})

	pgITSeedRunner(t, st, runnerID, 2, 0, 0)
	pgITSeedRunner(t, st, otherRunner, 1, 0, 0)
	pgITRecLease(t, st, jobRetry, runnerID, 1, expires)
	pgITRecLease(t, st, jobDoomed, runnerID, 1, expires)
	pgITRecLease(t, st, otherJob, otherRunner, 1, expires)

	beforeRunning, beforeQueued, err := st.QuotaCounts(ctx, pgITRepoID, "")
	if err != nil {
		t.Fatal(err)
	}

	revoked, err := st.RevokeRunnerLeases(ctx, runnerID, "runner disabled")
	if err != nil {
		t.Fatalf("RevokeRunnerLeases: %v", err)
	}
	if len(revoked) != 2 {
		t.Fatalf("revoked = %v, want 2 jobs", revoked)
	}

	rj, err := st.GetJob(ctx, jobRetry)
	if err != nil || rj.Status != model.StatusQueued || rj.Error != "runner disabled; retrying" {
		t.Fatalf("retryable revoked job = %+v err=%v", rj, err)
	}
	if rj.LeaseRunnerID != "" || rj.LeaseTokenHash != nil || rj.LeaseExpiresAt != nil {
		t.Fatalf("retryable revoked job lease not cleared: %+v", rj)
	}
	if rj.Attempts != 1 {
		t.Fatalf("retryable revoked job attempts = %d, want the lease-time increment only", rj.Attempts)
	}
	dj, err := st.GetJob(ctx, jobDoomed)
	if err != nil || dj.Status != model.StatusCancelled || dj.Error != "runner disabled" || dj.FinishedAt == nil {
		t.Fatalf("exhausted revoked job = %+v err=%v", dj, err)
	}
	dp, err := st.GetJob(ctx, depID)
	if err != nil || dp.Status != model.StatusBlocked || dp.DependencyStatus != model.StatusCancelled {
		t.Fatalf("dependent = %+v err=%v, want blocked/cancelled", dp, err)
	}
	ri, err := st.GetRunner(ctx, runnerID)
	if err != nil || len(ri.ActiveJobs) != 0 || ri.Busy || ri.Failed != 2 {
		t.Fatalf("runner after revocation = %+v err=%v, want empty/2 failures", ri, err)
	}
	ori, err := st.GetRunner(ctx, otherRunner)
	if err != nil || len(ori.ActiveJobs) != 1 || ori.ActiveJobs[0] != otherJob || ori.Failed != 0 {
		t.Fatalf("unrelated runner = %+v err=%v, want untouched", ori, err)
	}
	oj, err := st.GetJob(ctx, otherJob)
	if err != nil || oj.Status != model.StatusRunning {
		t.Fatalf("unrelated job = %+v err=%v, want running", oj, err)
	}
	afterRunning, afterQueued, err := st.QuotaCounts(ctx, pgITRepoID, "")
	if err != nil {
		t.Fatal(err)
	}
	if afterRunning != beforeRunning-2 || afterQueued != beforeQueued+1 {
		t.Fatalf("quota after revocation = %d/%d, want %d/%d", afterRunning, afterQueued, beforeRunning-2, beforeQueued+1)
	}
	audit, err := st.ReadAudit(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range audit {
		seen[e.Action] = true
	}
	if !seen["job.runner_disabled_requeued"] || !seen["job.runner_disabled_cancelled"] {
		t.Fatalf("audit missing revocation events: %v", seen)
	}

	// Idempotent replay: a second replica releases nothing again.
	again, err := st.RevokeRunnerLeases(ctx, runnerID, "runner disabled")
	if err != nil || len(again) != 0 {
		t.Fatalf("replayed revocation = %v err=%v, want empty/nil", again, err)
	}
	if ri, _ := st.GetRunner(ctx, runnerID); ri.Failed != 2 {
		t.Fatalf("runner failed after replay = %d, want 2", ri.Failed)
	}
	if running, queued, _ := st.QuotaCounts(ctx, pgITRepoID, ""); running != afterRunning || queued != afterQueued {
		t.Fatalf("quota after replay = %d/%d, want unchanged %d/%d", running, queued, afterRunning, afterQueued)
	}
}

// TestPostgresIntegrationRevokeRunnerLeasesCrashWindow rails the LAST
// statement in the revocation transaction (the run aggregation UPDATE) and
// proves the whole transition rolls back: the jobs stay running+leased, the
// runner keeps its active set and counters, and the quota reservations and
// audit rows are untouched.
func TestPostgresIntegrationRevokeRunnerLeasesCrashWindow(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, runnerID := pgITNewID(t), pgITNewID(t)
	jobID := pgITNewID(t)
	expires := time.Now().UTC().Add(time.Hour)
	job := pgITJob(runID, jobID, pgITRepo)
	job.MaxInfraRetries = 2
	pgITRecSeedRun(t, st, runID, model.StatusRunning, map[string]model.Job{jobID: job})
	pgITSeedRunner(t, st, runnerID, 1, 0, 0)
	pgITRecLease(t, st, jobID, runnerID, 1, expires)
	beforeRunning, beforeQueued, _ := st.QuotaCounts(ctx, pgITRepoID, "")

	pgITBoomOp(t, st, "runs", "UPDATE")
	if _, err := st.RevokeRunnerLeases(ctx, runnerID, "runner disabled"); err == nil {
		t.Fatal("revocation with a failing final aggregation succeeded")
	}
	j, err := st.GetJob(ctx, jobID)
	if err != nil || j.Status != model.StatusRunning || j.LeaseRunnerID != runnerID {
		t.Fatalf("job after rolled-back revocation = %+v err=%v, want running+leased", j, err)
	}
	ri, err := st.GetRunner(ctx, runnerID)
	if err != nil || len(ri.ActiveJobs) != 1 || ri.ActiveJobs[0] != jobID || ri.Failed != 0 {
		t.Fatalf("runner after rolled-back revocation = %+v err=%v, want intact slot and counters", ri, err)
	}
	if running, queued, _ := st.QuotaCounts(ctx, pgITRepoID, ""); running != beforeRunning || queued != beforeQueued {
		t.Fatalf("quota after rolled-back revocation = %d/%d, want %d/%d", running, queued, beforeRunning, beforeQueued)
	}
	if audit, _ := st.ReadAudit(ctx, 50); len(audit) != 0 {
		t.Fatalf("audit rows after rolled-back revocation = %d, want 0", len(audit))
	}
}

// TestPostgresIntegrationRevokeRunnerLeasesTwoReplicas races two stores on
// the same schema through the same revocation: the second caller observes the
// leases already gone, and every counter moves exactly once.
func TestPostgresIntegrationRevokeRunnerLeasesTwoReplicas(t *testing.T) {
	env := pgITSetup(t)
	storeA := env.open(t)
	env.migrate(t, storeA)
	storeB := env.open(t)
	ctx := context.Background()
	runID, runnerID := pgITNewID(t), pgITNewID(t)
	jobA, jobB := pgITNewID(t), pgITNewID(t)
	expires := time.Now().UTC().Add(time.Hour)
	ja := pgITJob(runID, jobA, pgITRepo)
	ja.MaxInfraRetries = 2
	jb := pgITJob(runID, jobB, pgITRepo)
	jb.MaxInfraRetries = 2
	pgITRecSeedRun(t, storeA, runID, model.StatusRunning, map[string]model.Job{jobA: ja, jobB: jb})
	pgITSeedRunner(t, storeA, runnerID, 2, 0, 0)
	pgITRecLease(t, storeA, jobA, runnerID, 1, expires)
	pgITRecLease(t, storeA, jobB, runnerID, 1, expires)

	var wg sync.WaitGroup
	counts := make(chan int, 2)
	for _, st := range []*PostgresStore{storeA, storeB} {
		wg.Add(1)
		go func(st *PostgresStore) {
			defer wg.Done()
			revoked, err := st.RevokeRunnerLeases(ctx, runnerID, "runner disabled")
			if err != nil {
				t.Errorf("concurrent revocation: %v", err)
				counts <- -1
				return
			}
			counts <- len(revoked)
		}(st)
	}
	wg.Wait()
	close(counts)
	total := 0
	for n := range counts {
		if n < 0 {
			t.Fatal("concurrent revocation failed")
		}
		total += n
	}
	if total != 2 {
		t.Fatalf("total revoked across replicas = %d, want 2", total)
	}
	ri, err := storeA.GetRunner(ctx, runnerID)
	if err != nil || len(ri.ActiveJobs) != 0 || ri.Failed != 2 {
		t.Fatalf("runner after two-replica revocation = %+v err=%v", ri, err)
	}
	// Two running slots released, two queued slots re-reserved: exactly once.
	if running, queued, _ := storeA.QuotaCounts(ctx, pgITRepoID, ""); running != 0 || queued != 2 {
		t.Fatalf("quota after two-replica revocation = %d/%d, want 0/2", running, queued)
	}
}

func TestPostgresIntegrationRecoverExpiredLease(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo := pgITRepo
	runID, runnerID := pgITNewID(t), pgITNewID(t)
	jobID, depID := pgITNewID(t), pgITNewID(t)
	expired := time.Now().UTC().Add(-time.Minute)

	job := pgITJob(runID, jobID, repo)
	job.MaxInfraRetries = 2
	dep := pgITJob(runID, depID, repo)
	dep.Condition = "success()"
	dep.Needs = []string{jobID}
	pgITRecSeedRun(t, st, runID, model.StatusRunning, map[string]model.Job{jobID: job, depID: dep})
	pgITSeedRunner(t, st, runnerID, 1, 0, 0)
	pgITRecLease(t, st, jobID, runnerID, 3, expired)

	// A generation mismatch (a concurrent re-lease) is a no-op.
	if err := st.RecoverExpiredLease(ctx, jobID, 2, time.Now().UTC()); err != nil {
		t.Fatalf("mismatched generation: %v", err)
	}
	if j, _ := st.GetJob(ctx, jobID); j.Status != model.StatusRunning || j.LeaseRunnerID != runnerID {
		t.Fatalf("job after mismatched generation = %+v, want running+leased", j)
	}

	if err := st.RecoverExpiredLease(ctx, jobID, 3, time.Now().UTC()); err != nil {
		t.Fatalf("RecoverExpiredLease: %v", err)
	}
	j, err := st.GetJob(ctx, jobID)
	if err != nil || j.Status != model.StatusQueued || j.Error != "runner lease expired; retrying" {
		t.Fatalf("recovered job = %+v err=%v, want queued/retrying", j, err)
	}
	if j.LeaseRunnerID != "" || j.LeaseTokenHash != nil || j.LeaseExpiresAt != nil {
		t.Fatalf("lease not cleared: %+v", j)
	}
	if j.Attempts != 1 {
		t.Fatalf("attempts = %d, want the lease-time increment only", j.Attempts)
	}
	ri, err := st.GetRunner(ctx, runnerID)
	if err != nil || len(ri.ActiveJobs) != 0 || ri.Failed != 1 {
		t.Fatalf("runner after recovery = %+v err=%v, want empty/1 failure", ri, err)
	}
	dp, err := st.GetJob(ctx, depID)
	if err != nil || dp.Status != model.StatusQueued {
		t.Fatalf("dependent of a requeued job = %+v err=%v, want queued", dp, err)
	}
	if running, queued, _ := st.QuotaCounts(ctx, pgITRepoID, ""); running != 0 || queued != 2 {
		t.Fatalf("quota after recovery = %d/%d, want 0/2", running, queued)
	}
	// Exactly once: a replayed recovery changes nothing.
	if err := st.RecoverExpiredLease(ctx, jobID, 3, time.Now().UTC()); err != nil {
		t.Fatalf("replayed recovery: %v", err)
	}
	if ri, _ := st.GetRunner(ctx, runnerID); ri.Failed != 1 {
		t.Fatalf("runner failed after replay = %d, want 1", ri.Failed)
	}
	if running, queued, _ := st.QuotaCounts(ctx, pgITRepoID, ""); running != 0 || queued != 2 {
		t.Fatalf("quota after replayed recovery = %d/%d, want unchanged 0/2", running, queued)
	}

	// Budget exhausted: the same shape fails terminally and blocks the
	// dependent in the same transaction.
	hardRun, hardJob, hardDep := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	hj := pgITJob(hardRun, hardJob, repo)
	hj.MaxInfraRetries = 0
	hd := pgITJob(hardRun, hardDep, repo)
	hd.Condition = "success()"
	hd.Needs = []string{hardJob}
	pgITRecSeedRun(t, st, hardRun, model.StatusRunning, map[string]model.Job{hardJob: hj, hardDep: hd})
	pgITRecLease(t, st, hardJob, runnerID, 1, expired)
	if err := st.RecoverExpiredLease(ctx, hardJob, 1, time.Now().UTC()); err != nil {
		t.Fatalf("RecoverExpiredLease (exhausted): %v", err)
	}
	if fj, err := st.GetJob(ctx, hardJob); err != nil || fj.Status != model.StatusFailure || fj.FinishedAt == nil {
		t.Fatalf("exhausted job = %+v err=%v, want failure", fj, err)
	}
	if fd, err := st.GetJob(ctx, hardDep); err != nil || fd.Status != model.StatusBlocked {
		t.Fatalf("dependent of an exhausted lease = %+v err=%v, want blocked", fd, err)
	}
	if r, err := st.GetRun(ctx, runID); err != nil || r.Status != model.StatusQueued {
		t.Fatalf("run after requeue = %+v err=%v, want queued", r, err)
	}
}

// TestPostgresIntegrationRecoverExpiredLeaseCrashWindow rails the LAST
// statement (run aggregation) and proves the expired lease is untouched by
// the rolled-back transaction.
func TestPostgresIntegrationRecoverExpiredLeaseCrashWindow(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, runnerID, jobID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	expired := time.Now().UTC().Add(-time.Minute)
	job := pgITJob(runID, jobID, pgITRepo)
	job.MaxInfraRetries = 2
	pgITRecSeedRun(t, st, runID, model.StatusRunning, map[string]model.Job{jobID: job})
	pgITSeedRunner(t, st, runnerID, 1, 0, 0)
	pgITRecLease(t, st, jobID, runnerID, 1, expired)
	beforeRunning, beforeQueued, _ := st.QuotaCounts(ctx, pgITRepoID, "")

	pgITBoomOp(t, st, "runs", "UPDATE")
	if err := st.RecoverExpiredLease(ctx, jobID, 1, time.Now().UTC()); err == nil {
		t.Fatal("recovery with a failing final aggregation succeeded")
	}
	j, err := st.GetJob(ctx, jobID)
	if err != nil || j.Status != model.StatusRunning || j.LeaseRunnerID != runnerID || j.LeaseExpiresAt == nil {
		t.Fatalf("job after rolled-back recovery = %+v err=%v, want running+leased", j, err)
	}
	ri, err := st.GetRunner(ctx, runnerID)
	if err != nil || len(ri.ActiveJobs) != 1 || ri.Failed != 0 {
		t.Fatalf("runner after rolled-back recovery = %+v err=%v, want intact", ri, err)
	}
	if running, queued, _ := st.QuotaCounts(ctx, pgITRepoID, ""); running != beforeRunning || queued != beforeQueued {
		t.Fatalf("quota after rolled-back recovery = %d/%d, want %d/%d", running, queued, beforeRunning, beforeQueued)
	}
	if audit, _ := st.ReadAudit(ctx, 50); len(audit) != 0 {
		t.Fatalf("audit rows after rolled-back recovery = %d, want 0", len(audit))
	}
}

func TestPostgresIntegrationExpireQueuedJob(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo := pgITRepo
	runID, jobID, depID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	deadline := time.Now().UTC().Add(-time.Minute)

	job := pgITJob(runID, jobID, repo)
	job.QueueDeadline = &deadline
	dep := pgITJob(runID, depID, repo)
	dep.Condition = "success()"
	dep.Needs = []string{jobID}
	pgITRecSeedRun(t, st, runID, model.StatusRunning, map[string]model.Job{jobID: job, depID: dep})
	beforeRunning, beforeQueued, _ := st.QuotaCounts(ctx, pgITRepoID, "")

	// A future deadline observation never expires the job.
	if err := st.ExpireQueuedJob(ctx, jobID, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("future deadline: %v", err)
	}
	if j, _ := st.GetJob(ctx, jobID); j.Status != model.StatusQueued {
		t.Fatalf("job with a future deadline = %s, want queued", j.Status)
	}

	if err := st.ExpireQueuedJob(ctx, jobID, deadline); err != nil {
		t.Fatalf("ExpireQueuedJob: %v", err)
	}
	j, err := st.GetJob(ctx, jobID)
	if err != nil || j.Status != model.StatusCancelled || j.Error != "queue timeout" || j.FinishedAt == nil {
		t.Fatalf("expired job = %+v err=%v", j, err)
	}
	dp, err := st.GetJob(ctx, depID)
	if err != nil || dp.Status != model.StatusBlocked || dp.DependencyStatus != model.StatusCancelled {
		t.Fatalf("dependent = %+v err=%v, want blocked/cancelled", dp, err)
	}
	if running, queued, _ := st.QuotaCounts(ctx, pgITRepoID, ""); running != beforeRunning || queued != beforeQueued-1 {
		t.Fatalf("quota after expire = %d/%d, want %d/%d", running, queued, beforeRunning, beforeQueued-1)
	}
	audit, _ := st.ReadAudit(ctx, 50)
	found := false
	for _, e := range audit {
		if e.Action == "job.queue_timeout" {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit missing queue timeout event: %+v", audit)
	}
	// Replay releases nothing a second time.
	if err := st.ExpireQueuedJob(ctx, jobID, deadline); err != nil {
		t.Fatalf("replayed expire: %v", err)
	}
	if running, queued, _ := st.QuotaCounts(ctx, pgITRepoID, ""); running != beforeRunning || queued != beforeQueued-1 {
		t.Fatalf("quota after replayed expire = %d/%d, want unchanged", running, queued)
	}
}

// TestPostgresIntegrationExpireQueuedJobCrashWindow rails the run
// aggregation and proves the queue-timeout transaction rolls back whole: the
// job stays queued and its reservation stays reserved.
func TestPostgresIntegrationExpireQueuedJobCrashWindow(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID := pgITNewID(t), pgITNewID(t)
	deadline := time.Now().UTC().Add(-time.Minute)
	job := pgITJob(runID, jobID, pgITRepo)
	job.QueueDeadline = &deadline
	pgITRecSeedRun(t, st, runID, model.StatusRunning, map[string]model.Job{jobID: job})
	beforeRunning, beforeQueued, _ := st.QuotaCounts(ctx, pgITRepoID, "")

	pgITBoomOp(t, st, "runs", "UPDATE")
	if err := st.ExpireQueuedJob(ctx, jobID, deadline); err == nil {
		t.Fatal("expire with a failing final aggregation succeeded")
	}
	j, err := st.GetJob(ctx, jobID)
	if err != nil || j.Status != model.StatusQueued || j.Error != "" {
		t.Fatalf("job after rolled-back expire = %+v err=%v, want queued", j, err)
	}
	if running, queued, _ := st.QuotaCounts(ctx, pgITRepoID, ""); running != beforeRunning || queued != beforeQueued {
		t.Fatalf("quota after rolled-back expire = %d/%d, want %d/%d", running, queued, beforeRunning, beforeQueued)
	}
	if audit, _ := st.ReadAudit(ctx, 50); len(audit) != 0 {
		t.Fatalf("audit rows after rolled-back expire = %d, want 0", len(audit))
	}
}

// TestPostgresIntegrationExpireQueuedJobTwoReplicas races two stores through
// the same queue timeout: exactly one transition commits and the queued
// reservation is released once.
func TestPostgresIntegrationExpireQueuedJobTwoReplicas(t *testing.T) {
	env := pgITSetup(t)
	storeA := env.open(t)
	env.migrate(t, storeA)
	storeB := env.open(t)
	ctx := context.Background()
	runID, jobID := pgITNewID(t), pgITNewID(t)
	deadline := time.Now().UTC().Add(-time.Minute)
	job := pgITJob(runID, jobID, pgITRepo)
	job.QueueDeadline = &deadline
	pgITRecSeedRun(t, storeA, runID, model.StatusRunning, map[string]model.Job{jobID: job})

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, st := range []*PostgresStore{storeA, storeB} {
		wg.Add(1)
		go func(st *PostgresStore) {
			defer wg.Done()
			errs <- st.ExpireQueuedJob(ctx, jobID, deadline)
		}(st)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil && !errors.Is(err, ErrNotFound) {
			t.Fatalf("concurrent expire: %v", err)
		}
	}
	if running, queued, _ := storeA.QuotaCounts(ctx, pgITRepoID, ""); running != 0 || queued != 0 {
		t.Fatalf("quota after two-replica expire = %d/%d, want 0/0 (exactly one release)", running, queued)
	}
	if j, _ := storeA.GetJob(ctx, jobID); j.Status != model.StatusCancelled {
		t.Fatalf("job after two-replica expire = %s, want cancelled", j.Status)
	}
}
