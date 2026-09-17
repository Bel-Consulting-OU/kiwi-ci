package scheduler

// Real-PostgreSQL integration tests for the scheduler package: DBScheduler
// Enqueue/Lease/RecoverExpired against a live database. Gated on
// KIWI_TEST_POSTGRES_URL (skipped when unset, and in -short mode).
//
// Every test opens its own throwaway schema (kiwi_it_<random>) by setting
// search_path on the pool and DROP SCHEMA ... CASCADE on cleanup.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const pgITSchedRepo = "https://github.com/kiwi-it/repo.git"

// pgITSchedDSN returns the integration DSN or skips the test.
func pgITSchedDSN(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("postgres integration tests skipped in -short mode")
	}
	dsn := strings.TrimSpace(os.Getenv("KIWI_TEST_POSTGRES_URL"))
	if dsn == "" {
		t.Skip("KIWI_TEST_POSTGRES_URL not set; skipping PostgreSQL integration tests")
	}
	return dsn
}

func pgITSchedRandomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random bytes: %v", err)
	}
	return hex.EncodeToString(b)[:n]
}

func pgITSchedID(t *testing.T) string { t.Helper(); return pgITSchedRandomHex(t, 32) }

// pgITSchedEnv owns one per-test schema and can open several pools on it.
type pgITSchedEnv struct {
	base   string
	schema string
}

func pgITSchedSetup(t *testing.T) *pgITSchedEnv {
	t.Helper()
	base := pgITSchedDSN(t)
	schema := "kiwi_it_" + pgITSchedRandomHex(t, 12)
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect to KIWI_TEST_POSTGRES_URL: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create schema %s: %v", schema, err)
	}
	if err := admin.Close(ctx); err != nil {
		t.Fatalf("close admin connection: %v", err)
	}
	t.Cleanup(func() {
		cctx := context.Background()
		c, cerr := pgx.Connect(cctx, base)
		if cerr != nil {
			t.Logf("drop schema %s: connect: %v", schema, cerr)
			return
		}
		defer func() { _ = c.Close(cctx) }()
		if _, err := c.Exec(cctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Logf("drop schema %s: %v", schema, err)
		}
	})
	return &pgITSchedEnv{base: base, schema: schema}
}

// open opens one migrated pool bound to the test schema.
func (e *pgITSchedEnv) open(t *testing.T) *storage.PostgresStore {
	t.Helper()
	ctx := context.Background()
	schema := e.schema
	st, err := storage.NewPostgresOpt(ctx, e.base, func(c *pgxpool.Config) {
		if c.ConnConfig.RuntimeParams == nil {
			c.ConnConfig.RuntimeParams = map[string]string{}
		}
		c.ConnConfig.RuntimeParams["search_path"] = schema
	})
	if err != nil {
		t.Fatalf("open store on schema %s: %v", schema, err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}

// pgITSchedStore returns a migrated store on a fresh schema.
func pgITSchedStore(t *testing.T) *storage.PostgresStore {
	t.Helper()
	return pgITSchedSetup(t).open(t)
}

// pgITSchedLeader returns a DBScheduler that holds the leadership claim. The
// claim is database-wide, so another package's integration test can hold it
// briefly; the wait is bounded and explicit.
func pgITSchedLeader(t *testing.T, st *storage.PostgresStore) *DBScheduler {
	t.Helper()
	sched := NewDB(st, time.Minute, nil, nil)
	if err := sched.InitErr(); err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	deadline := time.Now().Add(90 * time.Second)
	for !sched.IsLeader(context.Background()) {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for scheduler leadership")
		}
		time.Sleep(250 * time.Millisecond)
	}
	return sched
}

// pgITSchedJob builds a minimal queued job.
func pgITSchedJob(runID, jobID string) model.Job {
	return model.Job{ID: jobID, RunID: runID, Key: "build", RepoURL: pgITSchedRepo, RepoFullName: "kiwi-it/repo", Status: model.StatusQueued, CreatedAt: time.Now().UTC()}
}

// TestPostgresIntegrationSchedulerEnqueueAtomic proves DBScheduler.Enqueue
// commits the run, its jobs and their dependency edges atomically and leaves
// zero rows when the batch contains an invalid job, and that supersession
// cancels the prior run in the same transaction.
func TestPostgresIntegrationSchedulerEnqueueAtomic(t *testing.T) {
	st := pgITSchedStore(t)
	ctx := context.Background()
	sched := pgITSchedLeader(t, st)

	runID, jobA, jobB := pgITSchedID(t), pgITSchedID(t), pgITSchedID(t)
	jobs := map[string]model.Job{jobA: pgITSchedJob(runID, jobA), jobB: pgITSchedJob(runID, jobB)}
	if err := sched.Enqueue(ctx, model.Run{ID: runID, Repo: pgITSchedRepo, ConcurrencyGroup: "grp", Status: model.StatusQueued, CreatedAt: time.Now().UTC()}, jobs, map[string][]string{jobB: {jobA}}, false); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	run, err := st.GetRun(ctx, runID)
	if err != nil || run.Status != model.StatusQueued {
		t.Fatalf("enqueued run = %+v err=%v", run, err)
	}
	stored, err := st.ListJobsByRun(ctx, runID)
	if err != nil || len(stored) != 2 {
		t.Fatalf("jobs = %d err=%v, want 2", len(stored), err)
	}
	b, err := st.GetJob(ctx, jobB)
	if err != nil || len(b.Needs) != 1 || b.Needs[0] != jobA {
		t.Fatalf("dependency edge = %+v err=%v, want [%s]", b.Needs, err, jobA)
	}

	// Atomic rollback: the run row and the valid job must both disappear when
	// the batch carries an invalid job ID.
	badRun, goodJob := pgITSchedID(t), pgITSchedID(t)
	badErr := sched.Enqueue(ctx, model.Run{ID: badRun, Repo: pgITSchedRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		map[string]model.Job{
			goodJob:              pgITSchedJob(badRun, goodJob),
			"not-a-valid-job-id": {ID: "not-a-valid-job-id", RunID: badRun, Key: "bad", Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		}, nil, false)
	if badErr == nil {
		t.Fatal("Enqueue with an invalid job ID must fail")
	}
	if _, err := st.GetRun(ctx, badRun); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("failed enqueue leaked a run: %v", err)
	}
	if _, err := st.GetJob(ctx, goodJob); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("failed enqueue leaked a job: %v", err)
	}
	if rest, err := st.ListJobsByRun(ctx, badRun); err != nil || len(rest) != 0 {
		t.Fatalf("failed enqueue left %d jobs err=%v, want 0", len(rest), err)
	}

	// Supersession: a second enqueue of the same concurrency group cancels
	// the first run in the same transaction.
	nextRun, nextJob := pgITSchedID(t), pgITSchedID(t)
	if err := sched.Enqueue(ctx, model.Run{ID: nextRun, Repo: pgITSchedRepo, ConcurrencyGroup: "grp", Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		map[string]model.Job{nextJob: pgITSchedJob(nextRun, nextJob)}, nil, true); err != nil {
		t.Fatalf("superseding Enqueue: %v", err)
	}
	if prev, err := st.GetRun(ctx, runID); err != nil || prev.Status != model.StatusCancelled {
		t.Fatalf("superseded run = %+v err=%v, want cancelled", prev, err)
	}
	if j, err := st.GetJob(ctx, jobA); err != nil || j.Status != model.StatusCancelled {
		t.Fatalf("superseded job A = %+v err=%v, want cancelled", j, err)
	}
	if j, err := st.GetJob(ctx, jobB); err != nil || j.Status != model.StatusCancelled {
		t.Fatalf("superseded job B = %+v err=%v, want cancelled", j, err)
	}
}

// TestPostgresIntegrationSchedulerLeaseRecoverExpired proves Lease claims
// through the real predicate, RecoverExpired requeues a lost lease within the
// retry budget, fails it once the budget is spent, and cancels a queued job
// past its queue deadline.
func TestPostgresIntegrationSchedulerLeaseRecoverExpired(t *testing.T) {
	st := pgITSchedStore(t)
	ctx := context.Background()
	sched := pgITSchedLeader(t, st)

	runnerID := pgITSchedID(t)
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 1, Labels: []string{"container"}}); err != nil {
		t.Fatalf("upsert runner: %v", err)
	}
	runID, jobID := pgITSchedID(t), pgITSchedID(t)
	job := pgITSchedJob(runID, jobID)
	job.MaxInfraRetries = 2
	if err := sched.Enqueue(ctx, model.Run{ID: runID, Repo: pgITSchedRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()}, map[string]model.Job{jobID: job}, nil, false); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	leased, raw, expires, err := sched.Lease(ctx, runnerID, time.Now().UTC())
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}
	if leased.ID != jobID || raw == "" || leased.LeaseGeneration == 0 || !expires.After(time.Now()) {
		t.Fatalf("lease = %+v raw=%q expires=%v", leased, raw, expires)
	}
	if leased.Attempts != 1 || leased.LeaseRunnerID != runnerID {
		t.Fatalf("leased job attempts/runner = %d/%q", leased.Attempts, leased.LeaseRunnerID)
	}
	// Capacity 1: a second lease finds nothing.
	if _, _, _, err := sched.Lease(ctx, runnerID, time.Now().UTC()); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("second Lease = %v, want ErrNoJobs", err)
	}

	// Expire the lease and recover: the job requeues (attempt budget left)
	// and the runner slot is released.
	if err := st.HeartbeatLease(ctx, jobID, runnerID, leased.LeaseGeneration, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatalf("expire lease: %v", err)
	}
	if err := sched.RecoverExpired(ctx, time.Now().UTC()); err != nil {
		t.Fatalf("RecoverExpired: %v", err)
	}
	recovered, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Status != model.StatusQueued || !strings.Contains(recovered.Error, "retrying") {
		t.Fatalf("recovered job = %s/%q, want queued/retrying", recovered.Status, recovered.Error)
	}
	if ri, err := st.GetRunner(ctx, runnerID); err != nil || len(ri.ActiveJobs) != 0 {
		t.Fatalf("runner after recovery = %+v err=%v, want released slot", ri, err)
	}

	// Re-lease: attempts increments, then exhaust the retry budget and
	// recover again: the job fails terminally and the run fails with it.
	released, _, _, err := sched.Lease(ctx, runnerID, time.Now().UTC())
	if err != nil {
		t.Fatalf("re-lease: %v", err)
	}
	if released.Attempts != 2 {
		t.Fatalf("attempts after re-lease = %d, want 2", released.Attempts)
	}
	released.MaxInfraRetries = 1
	if err := st.UpdateJob(ctx, *released); err != nil {
		t.Fatalf("shrink retry budget: %v", err)
	}
	if err := st.HeartbeatLease(ctx, jobID, runnerID, released.LeaseGeneration, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatalf("expire second lease: %v", err)
	}
	if err := sched.RecoverExpired(ctx, time.Now().UTC()); err != nil {
		t.Fatalf("RecoverExpired (budget spent): %v", err)
	}
	if failed, err := st.GetJob(ctx, jobID); err != nil || failed.Status != model.StatusFailure {
		t.Fatalf("job after exhausted budget = %+v err=%v, want failure", failed, err)
	}
	if r, err := st.GetRun(ctx, runID); err != nil || r.Status != model.StatusFailure {
		t.Fatalf("run after exhausted budget = %+v err=%v, want failure", r, err)
	}

	// Queue timeout: a queued job past its deadline is cancelled by recovery.
	toRun, toJob := pgITSchedID(t), pgITSchedID(t)
	deadline := time.Now().UTC().Add(-time.Minute)
	queued := pgITSchedJob(toRun, toJob)
	queued.QueueDeadline = &deadline
	if err := sched.Enqueue(ctx, model.Run{ID: toRun, Repo: pgITSchedRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()}, map[string]model.Job{toJob: queued}, nil, false); err != nil {
		t.Fatalf("Enqueue (queue timeout): %v", err)
	}
	if err := sched.RecoverExpired(ctx, time.Now().UTC()); err != nil {
		t.Fatalf("RecoverExpired (queue timeout): %v", err)
	}
	if timedOut, err := st.GetJob(ctx, toJob); err != nil || timedOut.Status != model.StatusCancelled || timedOut.Error != "queue timeout" {
		t.Fatalf("queue-timeout job = %+v err=%v, want cancelled/queue timeout", timedOut, err)
	}
}

// TestPostgresIntegrationSchedulerStandby proves a second scheduler on the
// same database is a standby: Lease and RecoverExpired refuse with
// ErrNotLeader.
func TestPostgresIntegrationSchedulerStandby(t *testing.T) {
	env := pgITSchedSetup(t)
	storeA := env.open(t)
	_ = pgITSchedLeader(t, storeA)

	storeB := env.open(t)
	schedB := NewDB(storeB, time.Minute, nil, nil)
	if err := schedB.InitErr(); err != nil {
		t.Fatalf("NewDB standby: %v", err)
	}
	if schedB.IsLeader(context.Background()) {
		t.Fatal("second scheduler must not hold the claim while the first does")
	}
	runnerID := pgITSchedID(t)
	if _, _, _, err := schedB.Lease(context.Background(), runnerID, time.Now().UTC()); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("standby Lease = %v, want ErrNotLeader", err)
	}
	if err := schedB.RecoverExpired(context.Background(), time.Now().UTC()); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("standby RecoverExpired = %v, want ErrNotLeader", err)
	}
}
