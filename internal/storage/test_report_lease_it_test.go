package storage

// Real-PostgreSQL integration tests for the lease-fenced test-report
// delivery (LeaseTestReportStore): the report/delivery/fold transaction is
// gated on the post-lock database clock, and the canonical (created_at,id)
// ordering instant comes from that clock instead of the serving replica.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// testReportLeaseClaim acquires a live TTL lease for the fixture job and
// returns the fresh job row (with its lease generation) and canonical repo.
func testReportLeaseClaim(t *testing.T, st *PostgresStore, jobID, runnerID string, ttl time.Duration) (model.Job, string) {
	t.Helper()
	ctx := context.Background()
	if _, err := st.AcquireLeaseWithTTL(ctx, leaseClockITClaim(jobID, runnerID, ttl)); err != nil {
		t.Fatalf("acquire lease: %v", err)
	}
	job, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	return job, RepoIDForJob(job)
}

// testReportForLease builds one report bound to the leased job.
func testReportForLease(t *testing.T, job model.Job, name string, passed bool, createdAt time.Time) model.TestReport {
	t.Helper()
	return model.TestReport{
		ID:        pgITNewID(t),
		RunID:     job.RunID,
		JobID:     job.ID,
		JobKey:    job.Key,
		CreatedAt: createdAt,
		Cases:     []model.TestResult{{Name: name, Passed: passed, Duration: 1}},
	}
}

func testReportHistoryState(t *testing.T, st *PostgresStore, repoID string) (int64, []byte) {
	t.Helper()
	version, stats, err := st.LoadRepoTestHistory(context.Background(), repoID)
	if err != nil {
		t.Fatalf("load repo test history: %v", err)
	}
	return version, stats
}

// TestIntegrationExpiredTestReportCannotChangeHistory pins the fence: a
// delivery whose lease already expired at the database clock commits nothing
// — no report, no delivery receipt, no history fold/version bump.
func TestIntegrationExpiredTestReportCannotChangeHistory(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, runnerID := leaseClockITSetup(t, st)
	job, repo := testReportLeaseClaim(t, st, jobID, runnerID, 800*time.Millisecond)
	// Expire the lease at the database clock without touching the row's
	// runner/generation/status: only the expiry half changes.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	beforeVersion, beforeStats := testReportHistoryState(t, st, repo)
	rep := testReportForLease(t, job, "late", false, time.Now().UTC().Add(time.Hour))
	delivery := TestReportDelivery{JobID: jobID, LeaseGeneration: job.LeaseGeneration, DeliveryID: "expired-delivery", ContentDigest: "digest-expired"}
	if _, err := st.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runnerID, job.LeaseGeneration, rep, repo, delivery); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expired test report = %v, want ErrLeaseLost", err)
	}
	afterVersion, afterStats := testReportHistoryState(t, st, repo)
	if afterVersion != beforeVersion || !bytes.Equal(afterStats, beforeStats) {
		t.Fatalf("expired report changed history: version %d -> %d", beforeVersion, afterVersion)
	}
	reports, err := st.ListTestReports(ctx, job.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 0 {
		t.Fatalf("expired report persisted %d report row(s)", len(reports))
	}
	var deliveries int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM test_report_deliveries WHERE job_id=$1`, jobID).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if deliveries != 0 {
		t.Fatalf("expired report persisted %d delivery receipt(s)", deliveries)
	}
}

// TestIntegrationTestReportLeaseExpiresWhileWaitingForLock pins the TOCTOU
// rule at commit: a delivery that starts under a live lease and then waits
// on another transaction's job row lock past the lease expiry is refused
// with ErrLeaseLost and commits nothing.
func TestIntegrationTestReportLeaseExpiresWhileWaitingForLock(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, runnerID := leaseClockITSetup(t, st)
	job, repo := testReportLeaseClaim(t, st, jobID, runnerID, 800*time.Millisecond)

	tx, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT 1 FROM jobs WHERE id=$1 FOR UPDATE`, jobID); err != nil {
		t.Fatalf("lock job row: %v", err)
	}
	rep := testReportForLease(t, job, "blocked", true, time.Now().UTC())
	delivery := TestReportDelivery{JobID: jobID, LeaseGeneration: job.LeaseGeneration, DeliveryID: "blocked-delivery", ContentDigest: "digest-blocked"}
	done := make(chan error, 1)
	go func() {
		_, err := st.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runnerID, job.LeaseGeneration, rep, repo, delivery)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("delivery returned before the row lock was released: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	// Wait past the lease expiry, then release the unchanged row.
	time.Sleep(900 * time.Millisecond)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit unchanged row: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("delivery after the lease expired while blocked = %v, want ErrLeaseLost", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("delivery did not finish")
	}
	if reports, err := st.ListTestReports(ctx, job.RunID); err != nil {
		t.Fatal(err)
	} else if len(reports) != 0 {
		t.Fatalf("expired-while-blocked delivery persisted %d report row(s)", len(reports))
	}
	version, stats := testReportHistoryState(t, st, repo)
	if version != 0 || len(stats) != 0 {
		t.Fatalf("expired-while-blocked delivery changed history: version=%d stats=%d bytes", version, len(stats))
	}
}

// TestIntegrationTestReportUsesDatabaseCreatedAt pins the canonical ordering
// instant: the stored report's CreatedAt is the database clock sampled inside
// the fenced transaction, never the caller's application instant.
func TestIntegrationTestReportUsesDatabaseCreatedAt(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, runnerID := leaseClockITSetup(t, st)
	job, repo := testReportLeaseClaim(t, st, jobID, runnerID, time.Minute)

	appLie := time.Now().UTC().Add(2 * time.Hour)
	rep := testReportForLease(t, job, "stamped", true, appLie)
	delivery := TestReportDelivery{JobID: jobID, LeaseGeneration: job.LeaseGeneration, DeliveryID: "stamped-delivery", ContentDigest: "digest-stamped"}
	before := leaseClockITDBNow(t, st)
	if _, err := st.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runnerID, job.LeaseGeneration, rep, repo, delivery); err != nil {
		t.Fatalf("fenced delivery: %v", err)
	}
	after := leaseClockITDBNow(t, st)
	reports, err := st.ListTestReports(ctx, job.RunID)
	if err != nil || len(reports) != 1 {
		t.Fatalf("reports = %d err=%v, want 1", len(reports), err)
	}
	got := reports[0].CreatedAt.UTC()
	if got.Before(before.Add(-time.Second)) || got.After(after.Add(time.Second)) {
		t.Fatalf("report CreatedAt %s outside the database window [%s, %s]: application clock was used", got, before, after)
	}
	if !got.Before(appLie.Add(-time.Minute)) {
		t.Fatalf("report CreatedAt %s kept the application lie %s", got, appLie)
	}
}

// TestIntegrationReplicaClockSkewCannotReorderTestHistory pins the ordering
// consequence: two deliveries whose application clocks are inverted commit in
// database order, and the durable (created_at,id) fold order follows the
// database clock — so replica skew cannot make an earlier-committed outcome
// the newest history entry (or change the derived shard window).
func TestIntegrationReplicaClockSkewCannotReorderTestHistory(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	// Two independent jobs on the same repository, in DIFFERENT runs: the
	// unique (run_id, key) identity (migration 0048) permits the deliberately
	// shared logical suite key across runs, so their reports still fold into
	// ONE repository history suite (the same key inside one run would be a
	// duplicate logical node and is rejected at admission).
	const skewSuite = "shared"
	_, jobAID, runnerA := leaseClockITSetupKeyed(t, st, skewSuite)
	_, jobBID, runnerB := leaseClockITSetupKeyed(t, st, skewSuite)
	jobA, repoA := testReportLeaseClaim(t, st, jobAID, runnerA, time.Minute)
	jobB, repoB := testReportLeaseClaim(t, st, jobBID, runnerB, time.Minute)
	if repoA != repoB {
		t.Fatalf("fixture repositories differ: %s vs %s", repoA, repoB)
	}
	if jobA.Key != skewSuite || jobB.Key != skewSuite {
		t.Fatalf("fixture suite keys = %q/%q, want the shared %q", jobA.Key, jobB.Key, skewSuite)
	}

	// Report A is committed FIRST but carries a future application instant;
	// report B is committed SECOND with a past application instant. Both
	// observe the SAME test name, so the durable 16-outcome window exposes
	// the fold order directly: database order gives [fail, pass].
	repA := testReportForLease(t, jobA, "shared", false, time.Now().UTC().Add(time.Hour))
	repB := testReportForLease(t, jobB, "shared", true, time.Now().UTC().Add(-time.Hour))
	if _, err := st.InsertTestReportWithHistoryDeliveryForLease(ctx, jobA.ID, runnerA, jobA.LeaseGeneration, repA, repoA, TestReportDelivery{JobID: jobA.ID, LeaseGeneration: jobA.LeaseGeneration, DeliveryID: "skew-a", ContentDigest: "digest-a"}); err != nil {
		t.Fatalf("delivery A: %v", err)
	}
	if _, err := st.InsertTestReportWithHistoryDeliveryForLease(ctx, jobB.ID, runnerB, jobB.LeaseGeneration, repB, repoB, TestReportDelivery{JobID: jobB.ID, LeaseGeneration: jobB.LeaseGeneration, DeliveryID: "skew-b", ContentDigest: "digest-b"}); err != nil {
		t.Fatalf("delivery B: %v", err)
	}

	reportsA, err := st.ListTestReports(ctx, jobA.RunID)
	if err != nil || len(reportsA) != 1 {
		t.Fatalf("reports A = %d err=%v, want 1", len(reportsA), err)
	}
	reportsB, err := st.ListTestReports(ctx, jobB.RunID)
	if err != nil || len(reportsB) != 1 {
		t.Fatalf("reports B = %d err=%v, want 1", len(reportsB), err)
	}
	storedA, storedB := reportsA[0].CreatedAt.UTC(), reportsB[0].CreatedAt.UTC()
	if storedB.Before(storedA) {
		t.Fatalf("application-clock skew reordered history: A committed first at %s but B sorts earlier at %s", storedA, storedB)
	}
	var raw []byte
	if err := st.pool.QueryRow(ctx, `SELECT outcomes FROM test_history_aggregates WHERE repo_id=$1 AND suite=$2 AND test_class='' AND test_name='shared'`, repoA, skewSuite).Scan(&raw); err != nil {
		t.Fatalf("read folded outcomes: %v", err)
	}
	var outcomes []bool
	if err := json.Unmarshal(raw, &outcomes); err != nil {
		t.Fatalf("decode folded outcomes %s: %v", raw, err)
	}
	if len(outcomes) != 2 || outcomes[0] != false || outcomes[1] != true {
		t.Fatalf("folded outcomes = %v, want [false true] in database-commit order", outcomes)
	}
}

// TestIntegrationCommittedTestReportReplayAfterLeaseExpiry pins the chosen
// replay contract: an identical delivery replay is idempotent while the lease
// is live (returning the original canonical report identity and instant), and
// once the lease has ended the retry is refused with ErrLeaseLost — the first
// commit stays durable and folded exactly once.
func TestIntegrationCommittedTestReportReplayAfterLeaseExpiry(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, runnerID := leaseClockITSetup(t, st)
	job, repo := testReportLeaseClaim(t, st, jobID, runnerID, time.Minute)

	rep := testReportForLease(t, job, "replayed", true, time.Now().UTC())
	delivery := TestReportDelivery{JobID: jobID, LeaseGeneration: job.LeaseGeneration, DeliveryID: "replay-delivery", ContentDigest: "digest-replay"}
	first, err := st.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runnerID, job.LeaseGeneration, rep, repo, delivery)
	if err != nil || first.Replay || first.CreatedAt.IsZero() {
		t.Fatalf("first delivery = %+v err=%v", first, err)
	}
	// Live replay: the ORIGINAL canonical identity and instant, nothing new.
	live, err := st.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runnerID, job.LeaseGeneration, rep, repo, delivery)
	if err != nil || !live.Replay || live.ReportID != first.ReportID || !live.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("live replay = %+v err=%v, want replay of %s at %v", live, err, first.ReportID, first.CreatedAt)
	}
	versionBefore, statsBefore := testReportHistoryState(t, st, repo)
	reportCount := func() int {
		t.Helper()
		reports, err := st.ListTestReports(ctx, job.RunID)
		if err != nil {
			t.Fatal(err)
		}
		return len(reports)
	}
	if reportCount() != 1 {
		t.Fatalf("reports after live replay = %d, want 1", reportCount())
	}
	// End the lease and retry the identical delivery: refused, state intact.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runnerID, job.LeaseGeneration, rep, repo, delivery); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("post-lease replay = %v, want ErrLeaseLost", err)
	}
	if got := reportCount(); got != 1 {
		t.Fatalf("reports after refused replay = %d, want 1", got)
	}
	versionAfter, statsAfter := testReportHistoryState(t, st, repo)
	if versionAfter != versionBefore || !bytes.Equal(statsBefore, statsAfter) {
		t.Fatalf("refused replay changed history: version %d -> %d", versionBefore, versionAfter)
	}
	var deliveries int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM test_report_deliveries WHERE job_id=$1`, jobID).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if deliveries != 1 {
		t.Fatalf("delivery receipts = %d, want 1", deliveries)
	}
}

// TestIntegrationDifferentRunnerCannotReplayReportReceipt proves the receipt
// never becomes a cross-runner acknowledgment channel: another runner cannot
// invoke the fenced commit on a lease it does not hold, even with the exact
// delivery identifiers, so it can neither replay nor duplicate the receipt.
func TestIntegrationDifferentRunnerCannotReplayReportReceipt(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, runnerA := leaseClockITSetup(t, st)
	job, repo := testReportLeaseClaim(t, st, jobID, runnerA, time.Minute)

	rep := testReportForLease(t, job, "owned", true, time.Now().UTC())
	delivery := TestReportDelivery{JobID: jobID, LeaseGeneration: job.LeaseGeneration, DeliveryID: "owned-delivery", ContentDigest: "digest-owned"}
	if _, err := st.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runnerA, job.LeaseGeneration, rep, repo, delivery); err != nil {
		t.Fatalf("owner delivery: %v", err)
	}

	runnerB := pgITNewID(t)
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerB, Name: runnerB, Capacity: 2}); err != nil {
		t.Fatalf("register runner B: %v", err)
	}
	repB := testReportForLease(t, job, "forged", true, time.Now().UTC())
	deliveryB := TestReportDelivery{JobID: jobID, LeaseGeneration: job.LeaseGeneration, DeliveryID: "owned-delivery", ContentDigest: "digest-owned"}
	// Runner B presents the EXACT identifiers of runner A's receipt.
	if _, err := st.InsertTestReportWithHistoryDeliveryForLease(ctx, jobID, runnerB, job.LeaseGeneration, repB, repo, deliveryB); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("cross-runner replay = %v, want ErrLeaseLost", err)
	}
	reports, err := st.ListTestReports(ctx, job.RunID)
	if err != nil || len(reports) != 1 || reports[0].ID != rep.ID {
		t.Fatalf("reports after cross-runner attempt = %+v err=%v, want only %s", reports, err, rep.ID)
	}
}
