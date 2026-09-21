package storage

// Real-PostgreSQL integration tests for the corrupt-payload emergency
// recovery contract (T4-B): an expired running lease or an elapsed queue
// deadline whose job payload cannot be decoded must be force-recovered in the
// same fenced transaction, releasing the lease, the runner active slot and
// the quota reservation while recording the corruption reason and audit
// evidence. Gated on KIWI_TEST_POSTGRES_URL like every *_it_test.go file.

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITAuditCount counts the audit rows for one (job, action) pair.
func pgITAuditCount(t *testing.T, st *PostgresStore, jobID, action string) int {
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

// TestPostgresIntegrationRecoverCorruptPayloadFreesCapacity is test (a) and
// (d): an expired running job with a corrupt payload is forcibly recovered to
// a terminal failure with the corruption reason, its lease columns are
// cleared, the runner active slot and failure counter move, the running quota
// reservation is released (NOT converted into a queued one), the dependent
// and run aggregation are recomputed, and the audit evidence is written —
// while a normal payload keeps the existing retry-policy behavior.
func TestPostgresIntegrationRecoverCorruptPayloadFreesCapacity(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, runnerID := pgITNewID(t), pgITNewID(t)
	jobID, depID := pgITNewID(t), pgITNewID(t)
	expired := time.Now().UTC().Add(-time.Minute)

	// Retry budget deliberately left (attempts=1, MaxInfraRetries=2): a
	// decodable payload would requeue, the corrupt one must fail terminally.
	job := pgITJob(runID, jobID, pgITRepo)
	job.MaxInfraRetries = 2
	dep := pgITJob(runID, depID, pgITRepo)
	dep.Condition = "success()"
	dep.Needs = []string{jobID}
	pgITRecSeedRun(t, st, runID, model.StatusRunning, map[string]model.Job{jobID: job, depID: dep})
	pgITSeedRunner(t, st, runnerID, 1, 0, 0)
	pgITRecLease(t, st, jobID, runnerID, 1, expired)

	// Corrupt the persisted payload (valid jsonb, invalid model.Job).
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, jobID); err != nil {
		t.Fatalf("corrupt payload: %v", err)
	}
	beforeRunning, beforeQueued, err := st.QuotaCounts(ctx, pgITRepoID, "")
	if err != nil {
		t.Fatal(err)
	}

	if err := st.RecoverExpiredLease(ctx, jobID, 1, time.Now().UTC()); err != nil {
		t.Fatalf("RecoverExpiredLease with a corrupt payload = %v, want the forced recovery to commit", err)
	}

	// The relational columns carry the terminal state; the payload is kept
	// as evidence (never rewritten).
	var (
		status, errMsg, payloadText string
		leaseRunner                 *string
		leaseExpires, finished      *time.Time
	)
	if err := st.pool.QueryRow(ctx, `SELECT status, COALESCE(error, ''), payload::text, lease_runner_id, lease_expires_at, finished_at FROM jobs WHERE id=$1`, jobID).
		Scan(&status, &errMsg, &payloadText, &leaseRunner, &leaseExpires, &finished); err != nil {
		t.Fatalf("read corrupt job: %v", err)
	}
	if status != string(model.StatusFailure) || errMsg != CorruptLeaseRecoveryReason || finished == nil {
		t.Fatalf("corrupt job = %s/%q finished=%v, want failure/%q", status, errMsg, finished, CorruptLeaseRecoveryReason)
	}
	if leaseRunner != nil || leaseExpires != nil {
		t.Fatalf("corrupt job lease columns = runner %v expires %v, want NULL", leaseRunner, leaseExpires)
	}
	if payloadText != `"scalar"` {
		t.Fatalf("corrupt payload was rewritten: %s", payloadText)
	}
	ri, err := st.GetRunner(ctx, runnerID)
	if err != nil || len(ri.ActiveJobs) != 0 || ri.Busy || ri.CurrentJob != "" || ri.Failed != 1 {
		t.Fatalf("runner after corrupt recovery = %+v err=%v, want freed slot and 1 failure", ri, err)
	}
	afterRunning, afterQueued, err := st.QuotaCounts(ctx, pgITRepoID, "")
	if err != nil {
		t.Fatal(err)
	}
	if afterRunning != beforeRunning-1 || afterQueued != beforeQueued {
		t.Fatalf("quota after corrupt recovery = %d/%d, want %d/%d (running released, nothing re-queued)", afterRunning, afterQueued, beforeRunning-1, beforeQueued)
	}
	dp, err := st.GetJob(ctx, depID)
	if err != nil || dp.Status != model.StatusBlocked || dp.DependencyStatus != model.StatusFailure {
		t.Fatalf("dependent after corrupt recovery = %+v err=%v, want blocked/failure", dp, err)
	}
	if run, err := st.GetRun(ctx, runID); err != nil || run.Status != model.StatusFailure {
		t.Fatalf("run after corrupt recovery = %+v err=%v, want failure aggregation", run, err)
	}
	if n := pgITAuditCount(t, st, jobID, "job.corrupt_payload_recovered"); n != 1 {
		t.Fatalf("corruption audits = %d, want exactly 1", n)
	}

	// Replay is a no-op: capacity moves exactly once.
	if err := st.RecoverExpiredLease(ctx, jobID, 1, time.Now().UTC()); err != nil {
		t.Fatalf("replayed corrupt recovery: %v", err)
	}
	if ri, _ := st.GetRunner(ctx, runnerID); ri.Failed != 1 {
		t.Fatalf("runner failed after replay = %d, want 1", ri.Failed)
	}
	if running, queued, _ := st.QuotaCounts(ctx, pgITRepoID, ""); running != afterRunning || queued != afterQueued {
		t.Fatalf("quota after replay = %d/%d, want unchanged %d/%d", running, queued, afterRunning, afterQueued)
	}
	if n := pgITAuditCount(t, st, jobID, "job.corrupt_payload_recovered"); n != 1 {
		t.Fatalf("replayed corruption audits = %d, want still 1", n)
	}

	// (d) A normal payload keeps the existing retry-policy behavior.
	normalRun, normalJob := pgITNewID(t), pgITNewID(t)
	nj := pgITJob(normalRun, normalJob, pgITRepo)
	nj.MaxInfraRetries = 2
	pgITRecSeedRun(t, st, normalRun, model.StatusRunning, map[string]model.Job{normalJob: nj})
	pgITRecLease(t, st, normalJob, runnerID, 1, expired)
	if err := st.RecoverExpiredLease(ctx, normalJob, 1, time.Now().UTC()); err != nil {
		t.Fatalf("normal recovery: %v", err)
	}
	if got, err := st.GetJob(ctx, normalJob); err != nil || got.Status != model.StatusQueued || got.Error != "runner lease expired; retrying" {
		t.Fatalf("normal job after recovery = %+v err=%v, want queued/retrying", got, err)
	}
}

// TestPostgresIntegrationExpireCorruptQueuedPayloadReleasesReservation is
// test (b): a queued job past its persisted queue deadline whose payload
// cannot be decoded is expired terminally with the corruption reason and its
// queued reservation is released; a corrupt row with no provable deadline is
// left alone (the payload cannot invent one), while an intact legacy payload
// still expires through the compiled fallback.
func TestPostgresIntegrationExpireCorruptQueuedPayloadReleasesReservation(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID := pgITNewID(t), pgITNewID(t)
	past := time.Now().UTC().Add(-time.Minute)

	job := pgITJob(runID, jobID, pgITRepo)
	job.QueueDeadline = &past
	pgITRecSeedRun(t, st, runID, model.StatusRunning, map[string]model.Job{jobID: job})
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, jobID); err != nil {
		t.Fatalf("corrupt payload: %v", err)
	}
	beforeRunning, beforeQueued, _ := st.QuotaCounts(ctx, pgITRepoID, "")

	if err := st.ExpireQueuedJob(ctx, jobID, past); err != nil {
		t.Fatalf("ExpireQueuedJob with a corrupt payload = %v, want the forced expiry to commit", err)
	}
	var (
		status, errMsg, payloadText string
		leaseRunner                 *string
		leaseExpires, finished      *time.Time
	)
	if err := st.pool.QueryRow(ctx, `SELECT status, COALESCE(error, ''), payload::text, lease_runner_id, lease_expires_at, finished_at FROM jobs WHERE id=$1`, jobID).
		Scan(&status, &errMsg, &payloadText, &leaseRunner, &leaseExpires, &finished); err != nil {
		t.Fatalf("read corrupt queued job: %v", err)
	}
	if status != string(model.StatusCancelled) || errMsg != CorruptQueueExpiryReason || finished == nil {
		t.Fatalf("corrupt queued job = %s/%q finished=%v, want cancelled/%q", status, errMsg, finished, CorruptQueueExpiryReason)
	}
	if leaseRunner != nil || leaseExpires != nil {
		t.Fatalf("corrupt queued job lease columns = runner %v expires %v, want NULL", leaseRunner, leaseExpires)
	}
	if payloadText != `"scalar"` {
		t.Fatalf("corrupt payload was rewritten: %s", payloadText)
	}
	running, queued, err := st.QuotaCounts(ctx, pgITRepoID, "")
	if err != nil {
		t.Fatal(err)
	}
	if running != beforeRunning || queued != beforeQueued-1 {
		t.Fatalf("quota after corrupt expiry = %d/%d, want %d/%d (queued reservation released)", running, queued, beforeRunning, beforeQueued-1)
	}
	if run, err := st.GetRun(ctx, runID); err != nil || run.Status != model.StatusCancelled {
		t.Fatalf("run after corrupt expiry = %+v err=%v, want cancelled aggregation", run, err)
	}
	if n := pgITAuditCount(t, st, jobID, "job.corrupt_payload_expired"); n != 1 {
		t.Fatalf("corruption expiry audits = %d, want exactly 1", n)
	}
	// Replay releases nothing a second time.
	if err := st.ExpireQueuedJob(ctx, jobID, past); err != nil {
		t.Fatalf("replayed corrupt expiry: %v", err)
	}
	if running, queued, _ := st.QuotaCounts(ctx, pgITRepoID, ""); running != beforeRunning || queued != beforeQueued-1 {
		t.Fatalf("quota after replay = %d/%d, want unchanged", running, queued)
	}

	// A corrupt payload with a NULL column cannot invent a deadline: the
	// deadline-less row stays queued (nothing provable to expire).
	noDeadlineRun, noDeadlineJob := pgITNewID(t), pgITNewID(t)
	nd := pgITJob(noDeadlineRun, noDeadlineJob, pgITRepo)
	nd.QueueDeadline = &past
	pgITRecSeedRun(t, st, noDeadlineRun, model.StatusRunning, map[string]model.Job{noDeadlineJob: nd})
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb, queue_deadline=NULL WHERE id=$1`, noDeadlineJob); err != nil {
		t.Fatalf("corrupt deadline-less row: %v", err)
	}
	if err := st.ExpireQueuedJob(ctx, noDeadlineJob, time.Time{}); err != nil {
		t.Fatalf("ExpireQueuedJob (corrupt, no deadline): %v", err)
	}
	var ndStatus string
	if err := st.pool.QueryRow(ctx, `SELECT status FROM jobs WHERE id=$1`, noDeadlineJob).Scan(&ndStatus); err != nil {
		t.Fatalf("read deadline-less row: %v", err)
	}
	if ndStatus != string(model.StatusQueued) {
		t.Fatalf("deadline-less corrupt job = %s, want queued", ndStatus)
	}

	// An intact legacy payload (NULL column, compiled queue_timeout) still
	// expires through the fallback with the nil observed deadline.
	legacyRun, legacyJob := pgITNewID(t), pgITNewID(t)
	lj := pgITJob(legacyRun, legacyJob, pgITRepo)
	lj.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	pgITRecSeedRun(t, st, legacyRun, model.StatusRunning, map[string]model.Job{legacyJob: lj})
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET queue_deadline=NULL, payload=$2::jsonb WHERE id=$1`, legacyJob,
		`{"id":"`+legacyJob+`","run_id":"`+legacyRun+`","key":"build","repo_url":"`+pgITRepo+`","repo_full_name":"kiwi-it/repo","status":"queued","created_at":"`+lj.CreatedAt.Format(time.RFC3339)+`","compiled_job_payload":{"effective_job":{"job":{"queue_timeout":"5m"}}}}`); err != nil {
		t.Fatalf("seed legacy payload: %v", err)
	}
	if err := st.ExpireQueuedJob(ctx, legacyJob, time.Time{}); err != nil {
		t.Fatalf("ExpireQueuedJob (legacy fallback): %v", err)
	}
	if got, err := st.GetJob(ctx, legacyJob); err != nil || got.Status != model.StatusCancelled || got.Error != "queue timeout" {
		t.Fatalf("legacy fallback job = %+v err=%v, want cancelled/queue timeout", got, err)
	}
}
