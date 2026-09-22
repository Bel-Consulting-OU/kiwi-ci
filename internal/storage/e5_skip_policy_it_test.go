package storage

// E5-A real-PostgreSQL parity: the SQL incremental fold and the SQL rebuild
// both exclude skipped cases, agree with each other byte-for-byte, and match
// the in-memory store's derivation of the same report. Gated on
// KIWI_TEST_POSTGRES_URL like every *_it_test.go here.

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

func e5SkipITCases() []model.TestResult {
	return []model.TestResult{
		{Name: "mix", Passed: true, Duration: 1},
		{Name: "mix", Passed: false, Duration: 2},
		{Name: "skip-me", Passed: false, Skipped: true, Duration: 3},
		{Name: "skip-me", Passed: false, Skipped: true, Duration: 4},
	}
}

// TestPostgresIntegrationTestHistorySkipPolicyParity proves skipped cases
// create no SQL aggregate row, never surface as failures or flakiness, and
// that a repository rebuilt from the same durable reports is identical to the
// incrementally folded one (the incremental/rebuild parity the whole design
// rests on). The in-memory store derives the identical stats JSON from the
// same fixture.
func TestPostgresIntegrationTestHistorySkipPolicyParity(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repoID, full := "github.com/kiwi-it/skip-policy", "kiwi-it/skip-policy"
	base := time.Now().UTC().Truncate(time.Second)
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITHistoryRun(t, st, runID, jobID, repoID, full, base)

	rep := pgITHistoryReport(runID, pgITNewID(t), base, e5SkipITCases()...)
	if _, err := st.InsertTestReportWithHistory(ctx, rep, repoID); err != nil {
		t.Fatalf("incremental insert: %v", err)
	}
	stats := pgITHistoryStats(t, st, repoID)
	mixKey := testintel.EncodeHistoryKey(repoID, "build", "", "mix")
	skipKey := testintel.EncodeHistoryKey(repoID, "build", "", "skip-me")
	mix, ok := stats[mixKey]
	if !ok {
		t.Fatalf("observed test missing from the aggregates: %v", stats)
	}
	if mix.Runs != 2 || mix.Passes != 1 || mix.Fails != 1 {
		t.Fatalf("mix aggregate = runs %d/passes %d/fails %d, want 2/1/1", mix.Runs, mix.Passes, mix.Fails)
	}
	if _, ok := stats[skipKey]; ok {
		t.Fatalf("skipped test has an aggregate row: %v", stats)
	}
	flaky, err := st.FlakyTestNames(ctx, []string{repoID}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(flaky, []string{"mix"}) {
		t.Fatalf("flaky = %v, want [mix] (a skipped test is never flaky)", flaky)
	}

	if _, err := st.RebuildRepoTestHistory(ctx, repoID); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	rebuilt := pgITHistoryStats(t, st, repoID)
	if !reflect.DeepEqual(stats, rebuilt) {
		t.Fatalf("SQL rebuild diverged from the incremental fold under skips:\nincremental %v\nrebuilt     %v", stats, rebuilt)
	}

	// In-memory parity: the same report through memStore produces the same
	// stats for the same repository key.
	m := newMemStore()
	m.runs[runID] = model.Run{ID: runID, RepoID: repoID, RepoFullName: full}
	if _, err := m.InsertTestReportWithHistory(ctx, rep, repoID); err != nil {
		t.Fatal(err)
	}
	_, memStats, err := m.LoadRepoTestHistory(ctx, repoID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stats, e5DecodeStats(t, memStats)) {
		t.Fatalf("memStore diverged from PostgreSQL under skips:\nsql %v\nmem %v", stats, e5DecodeStats(t, memStats))
	}
	// And the memStore rebuild agrees too.
	if _, err := m.RebuildRepoTestHistory(ctx, repoID); err != nil {
		t.Fatal(err)
	}
	_, memRebuilt, err := m.LoadRepoTestHistory(ctx, repoID)
	if err != nil {
		t.Fatal(err)
	}
	if string(memStats) != string(memRebuilt) {
		t.Fatalf("memStore rebuild diverged:\nincremental %s\nrebuilt     %s", memStats, memRebuilt)
	}
}

// TestPostgresIntegrationTestHistorySkipOnlyReport proves a skip-only report
// is a valid upload that leaves the repository's aggregates empty (version
// bumped, zero rows): skipping is not failing.
func TestPostgresIntegrationTestHistorySkipOnlyReport(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repoID, full := "github.com/kiwi-it/skip-only", "kiwi-it/skip-only"
	base := time.Now().UTC().Truncate(time.Second)
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITHistoryRun(t, st, runID, jobID, repoID, full, base)
	rep := pgITHistoryReport(runID, pgITNewID(t), base,
		model.TestResult{Name: "only", Passed: false, Skipped: true},
		model.TestResult{Name: "also", Passed: false, Skipped: true},
	)
	if _, err := st.InsertTestReportWithHistory(ctx, rep, repoID); err != nil {
		t.Fatalf("skip-only insert: %v", err)
	}
	if stats := pgITHistoryStats(t, st, repoID); len(stats) != 0 {
		t.Fatalf("skip-only report produced aggregate rows: %v", stats)
	}
	if v := pgITHistoryVersion(t, st, repoID); v != 1 {
		t.Fatalf("skip-only repository version = %d, want 1", v)
	}
	flaky, err := st.FlakyTestNames(ctx, []string{repoID}, 100)
	if err != nil || len(flaky) != 0 {
		t.Fatalf("skip-only flaky = %v, %v; want none", flaky, err)
	}
}
