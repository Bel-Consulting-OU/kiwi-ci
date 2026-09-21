package scheduler

// Real-PostgreSQL regression coverage for the bounded recovery discovery
// (S2-A). The sweeper must never enumerate runs: with more than 10,000 newer
// runs, an old run whose job holds an expired lease (or whose queued job is
// past its deadline) was permanently invisible to the ListRuns(10000)-based
// discovery. These tests seed that exact shape and prove the direct, paged
// candidate queries recover the old candidates, exactly once, in bounded
// pages, and keep going past a persistently failing candidate.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// pgITSchedRawPool opens a raw pool bound to the test schema so seeding can
// use bulk generate_series inserts (and rows the canonical write path would
// reject, like a deliberately unvalidatable job ID).
func pgITSchedRawPool(t *testing.T, env *pgITSchedEnv) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(env.base)
	if err != nil {
		t.Fatalf("parse base DSN: %v", err)
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = env.schema
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open raw pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// pgITSchedRawJobStatus reads a job status through the raw pool, bypassing ID
// validation (the deliberately failing candidates have unvalidatable ids and
// the public GetJob refuses them).
func pgITSchedRawJobStatus(t *testing.T, pool *pgxpool.Pool, id string) string {
	t.Helper()
	var status string
	if err := pool.QueryRow(context.Background(), `SELECT status FROM jobs WHERE id=$1`, id).Scan(&status); err != nil {
		t.Fatalf("raw read job %q: %v", id, err)
	}
	return status
}

// pgITSchedAuditCount counts the audit events for one (job, action) pair.
func pgITSchedAuditCount(t *testing.T, st *storage.PostgresStore, jobID, action string) int {
	t.Helper()
	events, err := st.ReadAudit(context.Background(), 10000)
	if err != nil {
		t.Fatalf("ReadAudit: %v", err)
	}
	n := 0
	for _, e := range events {
		if e.JobID == jobID && e.Action == action {
			n++
		}
	}
	return n
}

// TestPostgresIntegrationSchedulerRecoverExpiredBeyondListRunsWindow is the
// S2-A regression: >10,000 NEWER runs exist, and the only candidates live in
// the OLDEST run. The current ListRuns(10000)-based discovery never sees that
// run (it is outside the newest-10k window), so this test fails on the defect
// and passes with direct candidate discovery.
func TestPostgresIntegrationSchedulerRecoverExpiredBeyondListRunsWindow(t *testing.T) {
	env := pgITSchedSetup(t)
	st := env.open(t)
	raw := pgITSchedRawPool(t, env)
	ctx := context.Background()
	sched := pgITSchedLeader(t, st)

	// 10,010 filler runs, all newer than the old run. They need no jobs:
	// the defect is the run window itself.
	if _, err := raw.Exec(ctx, `INSERT INTO runs (id, status, created_at, payload)
		SELECT lpad(to_hex(g), 32, '0'), 'success', now() - (g || ' seconds')::interval, '{}'::jsonb
		FROM generate_series(1, 10010) g`); err != nil {
		t.Fatalf("seed filler runs: %v", err)
	}

	now := time.Now().UTC()
	oldCreated := now.Add(-30 * 24 * time.Hour)
	oldRunID := pgITSchedID(t)
	if err := st.InsertRun(ctx, model.Run{ID: oldRunID, Repo: pgITSchedRepo, RepoFullName: "kiwi-it/repo", Status: model.StatusRunning, CreatedAt: oldCreated}); err != nil {
		t.Fatalf("insert old run: %v", err)
	}
	runnerID := pgITSchedID(t)
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 1}); err != nil {
		t.Fatalf("upsert runner: %v", err)
	}

	// One old running job with an expired lease and no infrastructure retry
	// budget: exactly one terminal recovery transition exists for it.
	expiredLease := now.Add(-time.Hour)
	oldRunningID := pgITSchedID(t)
	oldRunning := model.Job{
		ID: oldRunningID, RunID: oldRunID, Key: "build", RepoURL: pgITSchedRepo, RepoFullName: "kiwi-it/repo",
		Status: model.StatusRunning, CreatedAt: oldCreated,
		Attempts: 1, MaxInfraRetries: 0,
		LeaseRunnerID: runnerID, LeaseGeneration: 1, LeaseExpiresAt: &expiredLease,
	}
	if err := st.InsertJob(ctx, oldRunning); err != nil {
		t.Fatalf("insert old running job: %v", err)
	}
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 1, ActiveJobs: []string{oldRunningID}}); err != nil {
		t.Fatalf("attach runner slot: %v", err)
	}

	// One old queued job past its deadline.
	elapsedDeadline := now.Add(-2 * time.Hour)
	oldQueuedID := pgITSchedID(t)
	oldQueued := model.Job{
		ID: oldQueuedID, RunID: oldRunID, Key: "deploy", RepoURL: pgITSchedRepo, RepoFullName: "kiwi-it/repo",
		Status: model.StatusQueued, CreatedAt: oldCreated, QueueDeadline: &elapsedDeadline,
	}
	if err := st.InsertJob(ctx, oldQueued); err != nil {
		t.Fatalf("insert old queued job: %v", err)
	}

	if err := sched.RecoverExpired(ctx, now); err != nil {
		t.Fatalf("RecoverExpired: %v", err)
	}
	recovered, err := st.GetJob(ctx, oldRunningID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Status != model.StatusFailure || !strings.Contains(recovered.Error, "infrastructure retry budget exhausted") {
		t.Fatalf("old running job = %s/%q, want failure/budget exhausted", recovered.Status, recovered.Error)
	}
	if ri, err := st.GetRunner(ctx, runnerID); err != nil || len(ri.ActiveJobs) != 0 {
		t.Fatalf("runner after recovery = %+v err=%v, want released slot", ri, err)
	}
	timedOut, err := st.GetJob(ctx, oldQueuedID)
	if err != nil {
		t.Fatal(err)
	}
	if timedOut.Status != model.StatusCancelled || timedOut.Error != "queue timeout" {
		t.Fatalf("old queued job = %s/%q, want cancelled/queue timeout", timedOut.Status, timedOut.Error)
	}
	if n := pgITSchedAuditCount(t, st, oldRunningID, "job.lost_runner"); n != 1 {
		t.Fatalf("lost-runner audits = %d, want exactly 1", n)
	}
	if n := pgITSchedAuditCount(t, st, oldQueuedID, "job.queue_timeout"); n != 1 {
		t.Fatalf("queue-timeout audits = %d, want exactly 1", n)
	}

	// Replay: the candidates are terminal, so nothing transitions twice.
	if err := sched.RecoverExpired(ctx, now); err != nil {
		t.Fatalf("replayed RecoverExpired: %v", err)
	}
	if n := pgITSchedAuditCount(t, st, oldRunningID, "job.lost_runner"); n != 1 {
		t.Fatalf("replayed lost-runner audits = %d, want still 1", n)
	}
	if n := pgITSchedAuditCount(t, st, oldQueuedID, "job.queue_timeout"); n != 1 {
		t.Fatalf("replayed queue-timeout audits = %d, want still 1", n)
	}
}

// TestPostgresIntegrationSchedulerRecoverExpiredPagingAndFailureIsolation
// seeds a candidate set larger than the page size (including one candidate
// whose applier fails on every attempt because its id can never validate, and
// one genuinely corrupt-payload row per class that sorts before the healthy
// candidates) and proves: pages are visited deterministically and exactly
// once, every healthy candidate is recovered exactly once, the persistently
// failing candidate neither stalls the sweep nor makes it return an error,
// and a corrupt row is discovered and force-recovered — never skipped out of
// the sweep (which used to strand its lease/quota forever).
func TestPostgresIntegrationSchedulerRecoverExpiredPagingAndFailureIsolation(t *testing.T) {
	env := pgITSchedSetup(t)
	st := env.open(t)
	raw := pgITSchedRawPool(t, env)
	ctx := context.Background()
	sched := pgITSchedLeader(t, st)

	oldPage := recoveryPageSize
	recoveryPageSize = 2
	t.Cleanup(func() { recoveryPageSize = oldPage })

	now := time.Now().UTC()
	expired := now.Add(-time.Minute)
	runID := pgITSchedID(t)
	if err := st.InsertRun(ctx, model.Run{ID: runID, Repo: pgITSchedRepo, Status: model.StatusRunning, CreatedAt: now}); err != nil {
		t.Fatalf("insert run: %v", err)
	}

	// The failing candidate's id is 32 dashes: it sorts before every hex id
	// (so the sweep must advance past it to reach the healthy candidates),
	// and ValidateJobID rejects it inside RecoverExpiredLease/ExpireQueuedJob
	// on every attempt.
	failingRunning := strings.Repeat("-", 32)
	failingQueued := strings.Repeat("-", 31) + "~"
	var runningIDs, queuedIDs []string
	for i := 0; i < 5; i++ {
		runningIDs = append(runningIDs, fmt.Sprintf("%032x", i+1))
		queuedIDs = append(queuedIDs, fmt.Sprintf("%032x", i+100))
	}
	for _, id := range runningIDs {
		if err := st.InsertJob(ctx, model.Job{ID: id, RunID: runID, Key: "build", RepoURL: pgITSchedRepo,
			Status: model.StatusRunning, CreatedAt: now, Attempts: 1, MaxInfraRetries: 0,
			LeaseRunnerID: "runner", LeaseGeneration: 1, LeaseExpiresAt: &expired}); err != nil {
			t.Fatalf("insert running candidate %s: %v", id, err)
		}
	}
	for _, id := range queuedIDs {
		dl := expired
		if err := st.InsertJob(ctx, model.Job{ID: id, RunID: runID, Key: "build", RepoURL: pgITSchedRepo,
			Status: model.StatusQueued, CreatedAt: now, QueueDeadline: &dl}); err != nil {
			t.Fatalf("insert queue candidate %s: %v", id, err)
		}
	}
	// Raw inserts: the canonical path validates ids, this candidate must not.
	for _, row := range []struct {
		id, status string
	}{
		{failingRunning, "running"},
		{failingQueued, "queued"},
	} {
		payload, _ := json.Marshal(model.Job{ID: row.id, RunID: runID, Key: "build", Status: model.Status(row.status), CreatedAt: now})
		if _, err := raw.Exec(ctx, `INSERT INTO jobs (id, run_id, key, status, attempts, lease_runner_id, lease_generation, lease_expires_at, created_at, queue_deadline, payload)
			VALUES ($1, $2, 'build', $3, 1, NULL, 0, $4, $5, $4, $6::jsonb)`, row.id, runID, row.status, expired, now, string(payload)); err != nil {
			t.Fatalf("insert failing candidate %q: %v", row.id, err)
		}
	}
	// Genuinely CORRUPT payloads (valid jsonb, invalid model.Job), with valid
	// ids that sort BEFORE every healthy candidate in their class: discovery
	// must return them from the relational columns (they used to be skipped),
	// and the fenced appliers must force-recover them instead of failing (a
	// failure would previously have left them non-terminal forever).
	corruptRunning := fmt.Sprintf("%032x", 0)
	corruptQueued := fmt.Sprintf("%032x", 99)
	for _, row := range []struct {
		id, status string
		deadline   time.Time
	}{
		{corruptRunning, "running", expired},
		{corruptQueued, "queued", expired},
	} {
		if _, err := raw.Exec(ctx, `INSERT INTO jobs (id, run_id, key, status, attempts, lease_runner_id, lease_generation, lease_expires_at, created_at, queue_deadline, payload)
			VALUES ($1, $2, 'build', $3, 1, 'runner-x', 1, $4, $5, $4, '"scalar"'::jsonb)`, row.id, runID, row.status, row.deadline, now); err != nil {
			t.Fatalf("insert corrupt candidate %q: %v", row.id, err)
		}
	}

	// Deterministic paging smaller than the candidate set: a full page walk
	// yields every candidate exactly once, in strictly increasing id order.
	collect := func(fetch func(afterID string) ([]storage.RecoveryCandidate, error)) []string {
		var got []string
		afterID := ""
		for {
			page, err := fetch(afterID)
			if err != nil {
				t.Fatalf("page after %q: %v", afterID, err)
			}
			for _, c := range page {
				if afterID != "" && c.ID <= afterID {
					t.Fatalf("cursor not strictly increasing: %q after %q", c.ID, afterID)
				}
				got = append(got, c.ID)
				afterID = c.ID
			}
			if len(page) < recoveryPageSize {
				break
			}
		}
		return got
	}
	leasePages := collect(func(afterID string) ([]storage.RecoveryCandidate, error) {
		return st.ListExpiredRunningJobs(ctx, now, afterID, recoveryPageSize)
	})
	if len(leasePages) != len(runningIDs)+2 {
		t.Fatalf("expired-lease page walk = %v, want %d healthy + the failing and corrupt candidates", leasePages, len(runningIDs))
	}
	queuePages := collect(func(afterID string) ([]storage.RecoveryCandidate, error) {
		return st.ListQueueTimedOutJobs(ctx, now, afterID, recoveryPageSize)
	})
	if len(queuePages) != len(queuedIDs)+2 {
		t.Fatalf("queue page walk = %v, want %d healthy + the failing and corrupt candidates", queuePages, len(queuedIDs))
	}

	// A per-candidate applier failure is logged, never returned: the sweep
	// itself must succeed and recover every healthy candidate.
	if err := sched.RecoverExpired(ctx, now); err != nil {
		t.Fatalf("RecoverExpired: %v", err)
	}
	for _, id := range runningIDs {
		j, err := st.GetJob(ctx, id)
		if err != nil || j.Status != model.StatusFailure {
			t.Fatalf("running candidate %s = %+v err=%v, want failure", id, j, err)
		}
		if n := pgITSchedAuditCount(t, st, id, "job.lost_runner"); n != 1 {
			t.Fatalf("running candidate %s audits = %d, want 1", id, n)
		}
	}
	for _, id := range queuedIDs {
		j, err := st.GetJob(ctx, id)
		if err != nil || j.Status != model.StatusCancelled {
			t.Fatalf("queue candidate %s = %+v err=%v, want cancelled", id, j, err)
		}
		if n := pgITSchedAuditCount(t, st, id, "job.queue_timeout"); n != 1 {
			t.Fatalf("queue candidate %s audits = %d, want 1", id, n)
		}
	}
	// The failing candidates are untouched and still non-terminal.
	if got := pgITSchedRawJobStatus(t, raw, failingRunning); got != string(model.StatusRunning) {
		t.Fatalf("failing running candidate status = %q, want running", got)
	}
	if got := pgITSchedRawJobStatus(t, raw, failingQueued); got != string(model.StatusQueued) {
		t.Fatalf("failing queued candidate status = %q, want queued", got)
	}
	// The CORRUPT candidates were discovered (relational columns), did not
	// stall the healthy candidates behind them, and were force-recovered to a
	// terminal state with the explicit corruption reason plus audit evidence.
	// Their payloads stay untouched, so the state is read through the raw
	// pool (GetJob cannot decode them by definition).
	var status, errMsg string
	if err := raw.QueryRow(ctx, `SELECT status, COALESCE(error, '') FROM jobs WHERE id=$1`, corruptRunning).Scan(&status, &errMsg); err != nil {
		t.Fatalf("read corrupt running row: %v", err)
	}
	if status != string(model.StatusFailure) || errMsg != storage.CorruptLeaseRecoveryReason {
		t.Fatalf("corrupt running candidate = %s/%q, want failure/%q", status, errMsg, storage.CorruptLeaseRecoveryReason)
	}
	if n := pgITSchedAuditCount(t, st, corruptRunning, "job.corrupt_payload_recovered"); n != 1 {
		t.Fatalf("corrupt running audits = %d, want exactly 1", n)
	}
	if err := raw.QueryRow(ctx, `SELECT status, COALESCE(error, '') FROM jobs WHERE id=$1`, corruptQueued).Scan(&status, &errMsg); err != nil {
		t.Fatalf("read corrupt queued row: %v", err)
	}
	if status != string(model.StatusCancelled) || errMsg != storage.CorruptQueueExpiryReason {
		t.Fatalf("corrupt queued candidate = %s/%q, want cancelled/%q", status, errMsg, storage.CorruptQueueExpiryReason)
	}
	if n := pgITSchedAuditCount(t, st, corruptQueued, "job.corrupt_payload_expired"); n != 1 {
		t.Fatalf("corrupt queued audits = %d, want exactly 1", n)
	}

	// A replay recovers nothing further: no candidate transitions twice.
	if err := sched.RecoverExpired(ctx, now); err != nil {
		t.Fatalf("replayed RecoverExpired: %v", err)
	}
	for _, id := range append(append([]string{}, runningIDs...), queuedIDs...) {
		j, err := st.GetJob(ctx, id)
		if err != nil {
			t.Fatalf("get %s: %v", id, err)
		}
		if j.Status == model.StatusRunning || j.Status == model.StatusQueued {
			t.Fatalf("candidate %s transitioned more than once: %+v", id, j)
		}
	}
	if n := pgITSchedAuditCount(t, st, corruptRunning, "job.corrupt_payload_recovered"); n != 1 {
		t.Fatalf("replayed corrupt running audits = %d, want still 1", n)
	}
	if n := pgITSchedAuditCount(t, st, corruptQueued, "job.corrupt_payload_expired"); n != 1 {
		t.Fatalf("replayed corrupt queued audits = %d, want still 1", n)
	}
}
