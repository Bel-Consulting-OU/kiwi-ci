package storage

// E5-A: skipped tests are not historical pass/fail observations. These tests
// pin the skip policy on the in-memory store (the parity reference for the
// SQL store) across the incremental and rebuild fold paths, and prove the
// fold only ever observes pass/fail outcomes.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

func e5DecodeStats(t *testing.T, stats []byte) map[string]testintel.TestStat {
	t.Helper()
	out := map[string]testintel.TestStat{}
	if len(stats) == 0 {
		return out
	}
	if err := json.Unmarshal(stats, &out); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	return out
}

// TestE5MemStoreSkipPolicyExcludesSkippedOutcomes proves a skipped case
// creates no aggregate row at all: it is neither a failure (the JUnit
// conversion sets Passed=false) nor a pass, and it never enters the
// FlakyTestNames predicate.
func TestE5MemStoreSkipPolicyExcludesSkippedOutcomes(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	repo := "github.com/o/skip"
	m.runs["run-a"] = model.Run{ID: "run-a", RepoID: repo, RepoFullName: "o/skip"}
	base := time.Now().UTC()
	rep := model.TestReport{
		ID: "r1", RunID: "run-a", JobKey: "build", CreatedAt: base,
		Cases: []model.TestResult{
			{Name: "passes", Passed: true},
			{Name: "fails", Passed: false},
			{Name: "skipped", Passed: false, Skipped: true},
		},
	}
	if _, err := m.InsertTestReportWithHistory(ctx, rep, repo); err != nil {
		t.Fatal(err)
	}
	_, stats, err := m.LoadRepoTestHistory(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	got := e5DecodeStats(t, stats)
	if len(got) != 2 {
		t.Fatalf("aggregate rows = %d, want 2 (the skipped case must not create one): %s", len(got), stats)
	}
	for _, name := range []string{"passes", "fails"} {
		if _, ok := got[testintel.EncodeHistoryKey(repo, "build", "", name)]; !ok {
			t.Fatalf("missing aggregate row for %q: %s", name, stats)
		}
	}
	if _, ok := got[testintel.EncodeHistoryKey(repo, "build", "", "skipped")]; ok {
		t.Fatalf("skipped case created an aggregate row: %s", stats)
	}
	// A single skip-only report is a legitimate repository state with zero
	// observed outcomes.
	m2 := newMemStore()
	m2.runs["run-b"] = model.Run{ID: "run-b", RepoID: "github.com/o/skips-only", RepoFullName: "o/skips-only"}
	if _, err := m2.InsertTestReportWithHistory(ctx, model.TestReport{ID: "r2", RunID: "run-b", JobKey: "build", CreatedAt: base,
		Cases: []model.TestResult{{Name: "only", Passed: false, Skipped: true}}}, "github.com/o/skips-only"); err != nil {
		t.Fatal(err)
	}
	_, stats2, err := m2.LoadRepoTestHistory(ctx, "github.com/o/skips-only")
	if err != nil {
		t.Fatal(err)
	}
	if decoded := e5DecodeStats(t, stats2); len(decoded) != 0 {
		t.Fatalf("skip-only report produced aggregate rows: %s", stats2)
	}
}

// TestE5MemStoreSkipPolicyFoldsOnlyPassFail is the "mix of pass/fail/skip
// folds only pass/fail" pin: folding a pass/fail/skip sequence through the
// store must be byte-identical to folding the SAME pass/fail subsequence
// through testintel.History.Record, including the 16-outcome window, the EWMA
// and the flake probability.
func TestE5MemStoreSkipPolicyFoldsOnlyPassFail(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	repo := "github.com/o/mixed"
	m.runs["run-m"] = model.Run{ID: "run-m", RepoID: repo, RepoFullName: "o/mixed"}
	base := time.Now().UTC().Truncate(time.Second)

	// 24 observations: every third one is skipped. The store must record
	// exactly the 16 pass/fail outcomes that would result from the same
	// sequence with the skips removed entirely.
	expected := testintel.NewHistory()
	var cases []model.TestResult
	tests, failures := 0, 0
	for i := 0; i < 24; i++ {
		c := model.TestResult{Name: "t", Duration: float64(i) + 1, Passed: i%2 == 0}
		if i%3 == 0 {
			c.Passed, c.Skipped = false, true
		}
		cases = append(cases, c)
		tests++
		if !c.Passed && !c.Skipped {
			failures++
		}
		if c.Skipped {
			continue
		}
		// The store folds every case at the REPORT's CreatedAt.
		expected.Record(repo, "build", "", "t", c.Duration, c.Passed, base)
	}
	if _, err := m.InsertTestReportWithHistory(ctx, model.TestReport{ID: "r-mix", RunID: "run-m", JobKey: "build", Tests: tests, Failures: failures, CreatedAt: base, Cases: cases}, repo); err != nil {
		t.Fatal(err)
	}
	_, stats, err := m.LoadRepoTestHistory(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	key := testintel.EncodeHistoryKey(repo, "build", "", "t")
	got := e5DecodeStats(t, stats)[key]
	want := e5HistoryStat(t, expected)[key]
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("skip-contaminated fold diverged from the pass/fail-only fold:\ngot  %+v\nwant %+v", got, want)
	}
	if got.Runs != 16 {
		t.Fatalf("observed runs = %d, want the 16 non-skipped outcomes", got.Runs)
	}
}

// TestE5MemStoreSkipPolicyRebuildParity proves the rebuilt aggregates agree
// with the incremental fold when the reports carry skips: the rebuild applies
// the same skip policy, so before/after are byte-identical.
func TestE5MemStoreSkipPolicyRebuildParity(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	repo := "github.com/o/rebuild"
	m.runs["run-r"] = model.Run{ID: "run-r", RepoID: repo, RepoFullName: "o/rebuild"}
	base := time.Now().UTC().Truncate(time.Second)
	for i, c := range []model.TestResult{
		{Name: "t", Passed: false, Skipped: true},
		{Name: "t", Passed: true},
		{Name: "t", Passed: false},
		{Name: "t", Passed: false, Skipped: true},
		{Name: "u", Passed: true},
	} {
		rep := model.TestReport{
			ID: "rr" + itoa64(int64(i)), RunID: "run-r", JobKey: "build",
			CreatedAt: base.Add(time.Duration(i) * time.Second), Cases: []model.TestResult{c},
		}
		if _, err := m.InsertTestReportWithHistory(ctx, rep, repo); err != nil {
			t.Fatal(err)
		}
	}
	_, before, err := m.LoadRepoTestHistory(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.RebuildRepoTestHistory(ctx, repo); err != nil {
		t.Fatal(err)
	}
	_, after, err := m.LoadRepoTestHistory(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("rebuild diverged from the incremental fold under skips:\nbefore %s\nafter  %s", before, after)
	}
	stats := e5DecodeStats(t, after)
	tStat := stats[testintel.EncodeHistoryKey(repo, "build", "", "t")]
	if tStat.Runs != 2 || tStat.Fails != 1 || tStat.Passes != 1 {
		t.Fatalf("t aggregate = %+v, want 2 runs / 1 pass / 1 fail (skips excluded)", tStat)
	}
	if len(stats) != 2 {
		t.Fatalf("aggregate rows = %d, want 2 (t and u; skips add none): %v", len(stats), stats)
	}
}

// e5HistoryStat renders an expected testintel.History through its own Save and
// returns the decoded stats, so comparisons are against the legacy persisted
// shape.
func e5HistoryStat(t *testing.T, h *testintel.History) map[string]testintel.TestStat {
	t.Helper()
	path := filepath.Join(t.TempDir(), "history.json")
	if err := h.Save(path); err != nil {
		t.Fatalf("save expected history: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return e5DecodeStats(t, raw)
}
