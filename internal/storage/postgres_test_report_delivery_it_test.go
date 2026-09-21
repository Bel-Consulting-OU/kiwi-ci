package storage

// Real-PostgreSQL integration tests for the durable report-delivery identity
// (migration 0029): replay idempotence, digest conflicts, concurrent
// duplicates and transactional rollback. Gated on KIWI_TEST_POSTGRES_URL via
// the shared pgIT helpers.

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func pgITDeliveryReport(runID, id, jobKey string, at time.Time, cases ...model.TestResult) model.TestReport {
	failures := 0
	for _, c := range cases {
		if !c.Passed && !c.Skipped {
			failures++
		}
	}
	return model.TestReport{ID: id, RunID: runID, JobKey: jobKey, Tests: len(cases), Failures: failures, Cases: cases, CreatedAt: at}
}

func pgITDeliveryRowCount(t *testing.T, st *PostgresStore, jobID string, generation int64, deliveryID string) int {
	t.Helper()
	var n int
	if err := st.pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM test_report_deliveries WHERE job_id=$1 AND lease_generation=$2 AND delivery_id=$3`, jobID, generation, deliveryID).Scan(&n); err != nil {
		t.Fatalf("count delivery row: %v", err)
	}
	return n
}

// TestPostgresIntegrationReportDeliveryReplayAndConflict is the real-PG
// dropped-response proof: the first delivery inserts the report and folds its
// case once; the identical replay returns the ORIGINAL report ID without
// inserting or folding again; a reused delivery ID with a different digest is
// an explicit conflict that leaves the report count, the aggregate and the
// version untouched.
func TestPostgresIntegrationReportDeliveryReplayAndConflict(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo, full := "github.com/kiwi-it/delivery", "kiwi-it/delivery"
	base := time.Now().UTC().Truncate(time.Second)
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITHistoryRun(t, st, runID, jobID, repo, full, base)
	const generation = 3
	delivery := TestReportDelivery{JobID: jobID, LeaseGeneration: generation, DeliveryID: "delivery-1", ContentDigest: "digest-a"}

	rep := pgITDeliveryReport(runID, pgITNewID(t), "build", base, model.TestResult{Name: "t", Duration: 1, Passed: true})
	first, err := st.InsertTestReportWithHistoryDelivery(ctx, rep, repo, delivery)
	if err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if first.Replay || first.Version != 1 || first.ReportID != rep.ID {
		t.Fatalf("first outcome = %+v, want fresh version 1", first)
	}
	if n := pgITHistoryReportCount(t, st, rep.ID); n != 1 {
		t.Fatalf("report rows after first delivery = %d, want 1", n)
	}

	// The classic lost-response retry: identical bytes, identical identity.
	replay, err := st.InsertTestReportWithHistoryDelivery(ctx, rep, repo, delivery)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !replay.Replay || replay.ReportID != rep.ID {
		t.Fatalf("replay outcome = %+v, want the original report ID", replay)
	}
	if n := pgITHistoryReportCount(t, st, rep.ID); n != 1 {
		t.Fatalf("report rows after replay = %d, want 1 (pre-fix the retry double-inserted)", n)
	}
	if n := pgITDeliveryRowCount(t, st, jobID, generation, "delivery-1"); n != 1 {
		t.Fatalf("delivery rows = %d, want 1", n)
	}
	stats := pgITHistoryStats(t, st, repo)
	if len(stats) != 1 {
		t.Fatalf("history after replay = %v, want exactly one key", stats)
	}
	for _, stat := range stats {
		if stat.Runs != 1 || stat.Passes != 1 {
			t.Fatalf("history after replay = %+v, want the fold to have happened exactly once", stat)
		}
	}
	if v := pgITHistoryVersion(t, st, repo); v != 1 {
		t.Fatalf("history version after replay = %d, want 1", v)
	}

	// Same delivery identity, different payload: explicit conflict, history
	// untouched. The report ID also differs (the server mints a fresh one per
	// request), which is exactly why the conflict must be keyed by identity.
	conflictRep := pgITDeliveryReport(runID, pgITNewID(t), "build", base.Add(time.Second), model.TestResult{Name: "t", Passed: false})
	conflict := delivery
	conflict.ContentDigest = "digest-b"
	if _, err := st.InsertTestReportWithHistoryDelivery(ctx, conflictRep, repo, conflict); !errors.Is(err, ErrTestReportDeliveryConflict) {
		t.Fatalf("conflict err = %v, want ErrTestReportDeliveryConflict", err)
	}
	if n := pgITHistoryReportCount(t, st, conflictRep.ID); n != 0 {
		t.Fatalf("conflict inserted %d report rows", n)
	}
	if n := pgITHistoryReportCount(t, st, rep.ID); n != 1 {
		t.Fatalf("conflict disturbed the original report (%d rows)", n)
	}
	stats = pgITHistoryStats(t, st, repo)
	for _, stat := range stats {
		if stat.Runs != 1 || stat.Fails != 0 {
			t.Fatalf("conflict moved history: %+v", stat)
		}
	}
	if v := pgITHistoryVersion(t, st, repo); v != 1 {
		t.Fatalf("conflict moved the version: %d", v)
	}
}

// TestPostgresIntegrationReportDeliveryConcurrentDuplicates runs the same
// delivery concurrently over one pool (the realistic duplicate: a retry
// racing its own first attempt): the unique key serializes the claims, exactly
// one inserts, the rest replay, and one report/fold/version exists.
func TestPostgresIntegrationReportDeliveryConcurrentDuplicates(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo, full := "github.com/kiwi-it/delivery-race", "kiwi-it/delivery-race"
	base := time.Now().UTC().Truncate(time.Second)
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITHistoryRun(t, st, runID, jobID, repo, full, base)
	rep := pgITDeliveryReport(runID, pgITNewID(t), "build", base,
		model.TestResult{Name: "dup", Duration: 1, Passed: true},
		model.TestResult{Name: "dup", Duration: 2, Passed: false},
	)
	delivery := TestReportDelivery{JobID: jobID, LeaseGeneration: 1, DeliveryID: "delivery-race", ContentDigest: "digest-race"}

	const workers = 8
	var wg sync.WaitGroup
	outcomes := make([]TestReportInsertOutcome, workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outcomes[i], errs[i] = st.InsertTestReportWithHistoryDelivery(ctx, rep, repo, delivery)
		}(i)
	}
	wg.Wait()
	fresh, replays := 0, 0
	for i := range outcomes {
		if errs[i] != nil {
			t.Fatalf("worker %d: %v", i, errs[i])
		}
		if outcomes[i].Replay {
			replays++
		} else {
			fresh++
			if outcomes[i].ReportID != rep.ID {
				t.Fatalf("fresh worker %d returned report %q", i, outcomes[i].ReportID)
			}
		}
	}
	if fresh != 1 || replays != workers-1 {
		t.Fatalf("concurrent deliveries: %d fresh / %d replay, want exactly 1 fresh", fresh, replays)
	}
	if n := pgITHistoryReportCount(t, st, rep.ID); n != 1 {
		t.Fatalf("concurrent deliveries inserted %d reports, want 1", n)
	}
	if n := pgITDeliveryRowCount(t, st, jobID, 1, "delivery-race"); n != 1 {
		t.Fatalf("delivery rows = %d, want 1", n)
	}
	stats := pgITHistoryStats(t, st, repo)
	for _, stat := range stats {
		if stat.Runs != 2 {
			t.Fatalf("concurrent deliveries folded %d outcomes, want 2 (one report's two cases)", stat.Runs)
		}
	}
	if v := pgITHistoryVersion(t, st, repo); v != 1 {
		t.Fatalf("history version = %d, want 1", v)
	}
}

// TestPostgresIntegrationReportDeliveryAtomicRollback proves the receipt, the
// report rows and the fold are ONE transaction: an injected aggregate-write
// failure leaves neither the report nor the delivery receipt behind, and the
// healed retry succeeds exactly once.
func TestPostgresIntegrationReportDeliveryAtomicRollback(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo, full := "github.com/kiwi-it/delivery-atomic", "kiwi-it/delivery-atomic"
	base := time.Now().UTC().Truncate(time.Second)
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITHistoryRun(t, st, runID, jobID, repo, full, base)
	rep := pgITDeliveryReport(runID, pgITNewID(t), "build", base, model.TestResult{Name: "atomic", Passed: true})
	delivery := TestReportDelivery{JobID: jobID, LeaseGeneration: 1, DeliveryID: "delivery-atomic", ContentDigest: "digest-atomic"}

	pgITBoom(t, st, "test_history_aggregates")
	if _, err := st.InsertTestReportWithHistoryDelivery(ctx, rep, repo, delivery); err == nil {
		t.Fatal("injected aggregate failure must fail the delivery")
	}
	if n := pgITHistoryReportCount(t, st, rep.ID); n != 0 {
		t.Fatalf("failed delivery left %d report rows", n)
	}
	if n := pgITDeliveryRowCount(t, st, jobID, 1, "delivery-atomic"); n != 0 {
		t.Fatalf("failed delivery left %d delivery receipts (the retry would be answered as a replay)", n)
	}
	pgITHealBoom(t, st, "test_history_aggregates")

	outcome, err := st.InsertTestReportWithHistoryDelivery(ctx, rep, repo, delivery)
	if err != nil || outcome.Replay {
		t.Fatalf("healed delivery = %+v, %v", outcome, err)
	}
	if n := pgITHistoryReportCount(t, st, rep.ID); n != 1 {
		t.Fatalf("healed delivery stored %d reports, want 1", n)
	}
	if n := pgITDeliveryRowCount(t, st, jobID, 1, "delivery-atomic"); n != 1 {
		t.Fatalf("healed delivery receipts = %d, want 1", n)
	}
	// A replay after healing is served from the receipt.
	replay, err := st.InsertTestReportWithHistoryDelivery(ctx, rep, repo, delivery)
	if err != nil || !replay.Replay {
		t.Fatalf("healed replay = %+v, %v", replay, err)
	}
}

// TestPostgresIntegrationTestHistoryFlakyNamesDedupBeforeLimit is the SQL
// half of the rendered-identity contract: the same class.name flaky in two
// suites yields ONE rendered name, and the LIMIT applies after DISTINCT, so a
// duplicate can never crowd out a later unique name.
func TestPostgresIntegrationTestHistoryFlakyNamesDedupBeforeLimit(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo, full := "github.com/kiwi-it/flaky-dedup", "kiwi-it/flaky-dedup"
	base := time.Now().UTC().Truncate(time.Second)
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITHistoryRun(t, st, runID, jobID, repo, full, base)
	// Two suites share class.name C.dup and are both flaky; one unique later
	// name sorts after them.
	for _, suite := range []string{"alpha", "beta"} {
		for i, passed := range []bool{false, true} {
			rep := pgITDeliveryReport(runID, pgITNewID(t), suite, base.Add(time.Duration(i)*time.Second),
				model.TestResult{Name: "dup", Class: "C", Passed: passed})
			if _, err := st.InsertTestReportWithHistory(ctx, rep, repo); err != nil {
				t.Fatalf("seed %s: %v", suite, err)
			}
		}
	}
	for i, passed := range []bool{false, true} {
		rep := pgITDeliveryReport(runID, pgITNewID(t), "build", base.Add(time.Duration(10+i)*time.Second),
			model.TestResult{Name: "later", Passed: passed})
		if _, err := st.InsertTestReportWithHistory(ctx, rep, repo); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.FlakyTestNames(ctx, []string{repo}, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"C.dup", "later"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("flaky names = %v, want %v (the pre-fix LIMIT-before-dedup returned only [C.dup])", got, want)
	}
}
