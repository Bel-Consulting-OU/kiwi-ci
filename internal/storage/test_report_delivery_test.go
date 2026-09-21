package storage

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// TestMigration0029TestReportDeliveries pins the delivery-receipt migration:
// the (job_id, lease_generation, delivery_id) primary key, the stored digest
// and report ID, the created_at prune index, and its position after 0028.
func TestMigration0029TestReportDeliveries(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0029_test_report_deliveries.sql")
	if err != nil {
		t.Fatalf("read 0029: %v", err)
	}
	sql := string(raw)
	for _, want := range []string{
		`CREATE TABLE IF NOT EXISTS test_report_deliveries`,
		`job_id TEXT NOT NULL`,
		`lease_generation BIGINT NOT NULL`,
		`delivery_id TEXT NOT NULL`,
		`content_digest TEXT NOT NULL`,
		`report_id TEXT NOT NULL`,
		`created_at TIMESTAMPTZ NOT NULL DEFAULT now()`,
		`PRIMARY KEY (job_id, lease_generation, delivery_id)`,
		`CREATE INDEX IF NOT EXISTS test_report_deliveries_created_at_idx`,
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("0029_test_report_deliveries.sql is missing %q", want)
		}
	}
	if stmts := migrations.SplitStatements(sql); len(stmts) != 2 {
		t.Fatalf("0029 has %d statements, want 2 (CREATE TABLE + CREATE INDEX)", len(stmts))
	}
	all, err := migrations.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	var seen29, seen28 bool
	for i, m := range all {
		switch m.Version {
		case 28:
			seen28 = true
		case 29:
			seen29 = true
			if !seen28 {
				t.Fatalf("0029 appears at index %d before 0028", i)
			}
		}
	}
	if !seen29 {
		t.Fatal("0029 is not embedded")
	}
}

// newDeliveryHistoryStore returns a memStore with one run/report repository
// seeded and a helper that folds a report through the delivery API.
func newDeliveryHistoryStore(t *testing.T, repo string) (*memStore, func(rep model.TestReport, d TestReportDelivery) (TestReportInsertOutcome, error)) {
	t.Helper()
	m := newMemStore()
	runID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	m.runs[runID] = model.Run{ID: runID, RepoID: repo, RepoFullName: "o/delivery"}
	insert := func(rep model.TestReport, d TestReportDelivery) (TestReportInsertOutcome, error) {
		rep.RunID = runID
		return m.InsertTestReportWithHistoryDelivery(ctx(), rep, repo, d)
	}
	return m, insert
}

func deliveryReport(id string, at time.Time, cases ...model.TestResult) model.TestReport {
	failures := 0
	for _, c := range cases {
		if !c.Passed && !c.Skipped {
			failures++
		}
	}
	return model.TestReport{ID: id, JobKey: "build", Tests: len(cases), Failures: failures, Cases: cases, CreatedAt: at}
}

// TestMemStoreReportDeliveryReplayFoldsOnce is the in-memory half of the
// dropped-response contract: the first delivery inserts the report and folds
// its case once; an identical replay (same delivery ID and digest) is
// acknowledged with the original report ID and changes NOTHING — no second
// report, no second fold, no version bump.
func TestMemStoreReportDeliveryReplayFoldsOnce(t *testing.T) {
	repo := "github.com/o/delivery"
	m, insert := newDeliveryHistoryStore(t, repo)
	base := time.Now().UTC()
	rep := deliveryReport("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01", base, model.TestResult{Name: "t", Passed: true})
	d := TestReportDelivery{JobID: testJob.ID, LeaseGeneration: 3, DeliveryID: "delivery-1", ContentDigest: "digest-a"}

	first, err := insert(rep, d)
	if err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if first.Replay || first.Version != 1 || first.ReportID != rep.ID {
		t.Fatalf("first delivery outcome = %+v, want fresh version 1 with the report ID", first)
	}
	if len(m.reports) != 1 {
		t.Fatalf("reports after first delivery = %d, want 1", len(m.reports))
	}
	row := m.historyAggregates[repo][memHistoryKey("build", "", "t")]
	if row.Runs != 1 || row.Passes != 1 {
		t.Fatalf("aggregate after first delivery = %+v, want one pass", row)
	}

	replay, err := insert(rep, d)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !replay.Replay || replay.ReportID != rep.ID {
		t.Fatalf("replay outcome = %+v, want a replay of the original report", replay)
	}
	if len(m.reports) != 1 {
		t.Fatalf("reports after replay = %d, want still 1 (the pre-fix double insert)", len(m.reports))
	}
	row = m.historyAggregates[repo][memHistoryKey("build", "", "t")]
	if row.Runs != 1 || row.Passes != 1 {
		t.Fatalf("aggregate after replay = %+v, want the fold to have happened exactly once", row)
	}
	if v := memHistoryVersion(m, repo); v != 1 {
		t.Fatalf("history version after replay = %d, want 1", v)
	}

	// The delivery identity is scoped to the lease generation: the same ID
	// under a new generation is a NEW delivery and inserts its own report.
	d2 := d
	d2.LeaseGeneration = 4
	fresh, err := insert(deliveryReport("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02", base.Add(time.Second), model.TestResult{Name: "t", Passed: false}), d2)
	if err != nil {
		t.Fatalf("next generation delivery: %v", err)
	}
	if fresh.Replay {
		t.Fatal("the same delivery ID under a new lease generation was treated as a replay")
	}
	if len(m.reports) != 2 {
		t.Fatalf("reports after generation change = %d, want 2", len(m.reports))
	}

	// An empty delivery ID is the legacy path: every call inserts.
	if _, err := insert(deliveryReport("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa03", base.Add(2*time.Second), model.TestResult{Name: "plain", Passed: true}), TestReportDelivery{}); err != nil {
		t.Fatal(err)
	}
	if len(m.reports) != 3 {
		t.Fatalf("reports after legacy delivery = %d, want 3", len(m.reports))
	}
}

// memHistoryVersion reads the in-memory version without the pgIT helper.
func memHistoryVersion(m *memStore, repo string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.historyVersions[repo]
}

// TestMemStoreReportDeliveryConflictLeavesHistoryUntouched proves a reused
// delivery ID with a different payload digest is refused and commits
// nothing: no report, no fold, no version move.
func TestMemStoreReportDeliveryConflictLeavesHistoryUntouched(t *testing.T) {
	repo := "github.com/o/delivery"
	m, insert := newDeliveryHistoryStore(t, repo)
	base := time.Now().UTC()
	d := TestReportDelivery{JobID: testJob.ID, LeaseGeneration: 1, DeliveryID: "delivery-x", ContentDigest: "digest-a"}
	if _, err := insert(deliveryReport("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa11", base, model.TestResult{Name: "t", Passed: false}), d); err != nil {
		t.Fatal(err)
	}
	before := m.historyAggregates[repo][memHistoryKey("build", "", "t")]

	conflict := d
	conflict.ContentDigest = "digest-b"
	_, err := insert(deliveryReport("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa12", base.Add(time.Second), model.TestResult{Name: "t", Passed: true}), conflict)
	if !errors.Is(err, ErrTestReportDeliveryConflict) {
		t.Fatalf("err = %v, want ErrTestReportDeliveryConflict", err)
	}
	if len(m.reports) != 1 {
		t.Fatalf("conflict inserted a report: %d reports", len(m.reports))
	}
	if got := m.historyAggregates[repo][memHistoryKey("build", "", "t")]; !reflect.DeepEqual(got, before) {
		t.Fatalf("conflict moved history: %+v -> %+v", before, got)
	}
	if v := memHistoryVersion(m, repo); v != 1 {
		t.Fatalf("conflict moved the version: %d", v)
	}
}

// TestMemStoreReportDeliveryConcurrentDuplicatesInsertOnce runs many
// simultaneous deliveries of the identical identity against the in-memory
// store: exactly one is fresh, the rest replay, and one report/fold/version
// exists afterwards.
func TestMemStoreReportDeliveryConcurrentDuplicatesInsertOnce(t *testing.T) {
	repo := "github.com/o/delivery"
	m, insert := newDeliveryHistoryStore(t, repo)
	rep := deliveryReport("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa21", time.Now().UTC(), model.TestResult{Name: "t", Passed: true})
	d := TestReportDelivery{JobID: testJob.ID, LeaseGeneration: 2, DeliveryID: "delivery-race", ContentDigest: "digest-race"}

	const workers = 16
	var wg sync.WaitGroup
	results := make([]TestReportInsertOutcome, workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = insert(rep, d)
		}(i)
	}
	wg.Wait()
	fresh, replays := 0, 0
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("worker %d: %v", i, errs[i])
		}
		if results[i].Replay {
			replays++
		} else {
			fresh++
			if results[i].ReportID != rep.ID {
				t.Fatalf("fresh worker %d returned report ID %q", i, results[i].ReportID)
			}
		}
	}
	if fresh != 1 || replays != workers-1 {
		t.Fatalf("concurrent duplicates: %d fresh / %d replay, want exactly 1 fresh", fresh, replays)
	}
	if len(m.reports) != 1 {
		t.Fatalf("concurrent duplicates inserted %d reports, want 1", len(m.reports))
	}
	if row := m.historyAggregates[repo][memHistoryKey("build", "", "t")]; row.Runs != 1 {
		t.Fatalf("concurrent duplicates folded %d times, want 1", row.Runs)
	}
}

// TestFaultyStoreReportDeliveryParity proves the wrapper is transparent for
// the delivery API: replay and conflict semantics survive the wrapper, and an
// armed fault surfaces before anything is written.
func TestFaultyStoreReportDeliveryParity(t *testing.T) {
	repo := "github.com/o/delivery"
	inner := newMemStore()
	inner.runs["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] = model.Run{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RepoID: repo, RepoFullName: "o/delivery"}
	f := &FaultyStore{Inner: inner}
	rep := deliveryReport("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa31", time.Now().UTC(), model.TestResult{Name: "t", Passed: true})
	rep.RunID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	d := TestReportDelivery{JobID: testJob.ID, LeaseGeneration: 1, DeliveryID: "delivery-faulty", ContentDigest: "digest-faulty"}

	first, err := f.InsertTestReportWithHistoryDelivery(ctx(), rep, repo, d)
	if err != nil || first.Replay {
		t.Fatalf("wrapper first delivery = %+v, %v", first, err)
	}
	replay, err := f.InsertTestReportWithHistoryDelivery(ctx(), rep, repo, d)
	if err != nil || !replay.Replay {
		t.Fatalf("wrapper replay = %+v, %v", replay, err)
	}
	conflict := d
	conflict.ContentDigest = "other"
	if _, err := f.InsertTestReportWithHistoryDelivery(ctx(), rep, repo, conflict); !errors.Is(err, ErrTestReportDeliveryConflict) {
		t.Fatalf("wrapper conflict err = %v", err)
	}

	armed := &FaultyStore{Inner: inner, FailAfter: 1, Err: errBoom}
	if _, err := armed.InsertTestReportWithHistoryDelivery(ctx(), rep, repo, TestReportDelivery{JobID: testJob.ID, LeaseGeneration: 5, DeliveryID: "delivery-armed", ContentDigest: "d"}); !errors.Is(err, errBoom) {
		t.Fatalf("armed wrapper err = %v, want the injected fault", err)
	}
	// The missing-inner-interface path fails closed too.
	if _, err := (&FaultyStore{Inner: storeOnlyInner{}}).InsertTestReportWithHistoryDelivery(ctx(), rep, repo, d); err == nil {
		t.Fatal("wrapper with a delivery-less inner must fail closed")
	}
}

// TestMemStoreFlakyNamesDedupBeforeLimit pins the rendered-identity contract
// on the in-memory store: the same class.name flaky in two suites renders to
// ONE name, and the limit applies AFTER deduplication, so the duplicate
// cannot crowd out the later unique name.
func TestMemStoreFlakyNamesDedupBeforeLimit(t *testing.T) {
	repo := "github.com/o/delivery"
	m, insert := newDeliveryHistoryStore(t, repo)
	base := time.Now().UTC()
	// Suite "alpha" and "beta": same class.name "C.dup", both flaky.
	for _, suite := range []string{"alpha", "beta"} {
		for i := 0; i < 2; i++ {
			rep := deliveryReport("aaaaaaaaaaaaaaaaaaaaaaaaaaaa4"+suite[:1]+string(rune('0'+i)), base.Add(time.Duration(i)*time.Second),
				model.TestResult{Name: "dup", Class: "C", Passed: i == 1})
			rep.JobKey = suite
			if _, err := insert(rep, TestReportDelivery{}); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A later unique flaky name sorts after the duplicate.
	for i := 0; i < 2; i++ {
		rep := deliveryReport("aaaaaaaaaaaaaaaaaaaaaaaaaaaa5"+string(rune('0'+i)), base.Add(time.Duration(10+i)*time.Second),
			model.TestResult{Name: "later", Passed: i == 1})
		if _, err := insert(rep, TestReportDelivery{}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := m.FlakyTestNames(ctx(), []string{repo}, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"C.dup", "later"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("flaky names = %v, want %v (dedup must precede the limit)", got, want)
	}
}
