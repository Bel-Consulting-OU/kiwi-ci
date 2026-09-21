package storage

// Unit tests for the incremental test-history fold and serialization. The
// real-PostgreSQL integration tests live in test_history_it_test.go; these
// tests pin the fold's equivalence with internal/testintel (the legacy
// history implementation) without a database.

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

// historyFoldFixture exercises duplicate names, classes, mixed outcomes,
// re-runs and more than one outcome window (16) so the EWMA/outcome-window/
// flake-probability derivation is fully exercised.
func historyFoldFixture() []TestHistoryEntry {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	out := []TestHistoryEntry{}
	add := func(suite, class, name string, dur float64, passed bool, at time.Duration) {
		out = append(out, TestHistoryEntry{Suite: suite, Class: class, Name: name, Duration: dur, Passed: passed, When: base.Add(at)})
	}
	for i := 0; i < 20; i++ {
		add("build", "C", "flaky", float64(i)+1, i%2 == 0, time.Duration(i)*time.Minute)
	}
	add("build", "", "plain", 2, true, 21*time.Minute)
	add("build", "", "plain", 4, false, 22*time.Minute)
	add("build", "D", "flaky", 0.5, false, 23*time.Minute)
	add("other-suite", "C", "flaky", 9, true, 24*time.Minute)
	return out
}

// TestTestHistoryFoldMatchesTestintel is the fold-equivalence pin: folding
// the same fixture through the storage fold and through
// testintel.History.Record must produce the same persisted stats JSON, so an
// incrementally updated repository aggregate is byte-identical to the legacy
// full rebuild.
func TestTestHistoryFoldMatchesTestintel(t *testing.T) {
	entries := historyFoldFixture()
	h := testintel.NewHistory()
	aggregates := map[string]TestHistoryAggregate{}
	for _, e := range entries {
		h.Record("github.com/o/r", e.Suite, e.Class, e.Name, e.Duration, e.Passed, e.When)
		key := testHistoryAggregateKey(e.Suite, e.Class, e.Name)
		row := aggregates[key]
		row.RepoID, row.Suite, row.Class, row.Name = "github.com/o/r", e.Suite, e.Class, e.Name
		aggregates[key] = FoldTestHistoryAggregate(row, e)
	}

	path := filepath.Join(t.TempDir(), "history.json")
	if err := h.Save(path); err != nil {
		t.Fatal(err)
	}
	wantBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	list := make([]TestHistoryAggregate, 0, len(aggregates))
	for _, row := range aggregates {
		list = append(list, row)
	}
	gotBytes, err := EncodeTestHistoryStats(list)
	if err != nil {
		t.Fatal(err)
	}

	var want, got map[string]testintel.TestStat
	if err := json.Unmarshal(wantBytes, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(gotBytes, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("storage fold diverged from testintel:\nwant %s\ngot  %s", wantBytes, gotBytes)
	}
}

func TestEncodeTestHistoryStatsEmpty(t *testing.T) {
	stats, err := EncodeTestHistoryStats(nil)
	if err != nil || stats != nil {
		t.Fatalf("empty encode = %q, %v; want nil/nil", stats, err)
	}
}

// TestMemStoreIncrementalHistoryScoped mirrors the SQL semantics in memory:
// only the uploaded repository's aggregate rows change, the version moves
// per repository, reads are repository-scoped and a rebuild is equivalent to
// the incremental fold.
func TestMemStoreIncrementalHistoryScoped(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	m.runs["run-a"] = model.Run{ID: "run-a", RepoID: "github.com/o/a", RepoFullName: "o/a"}
	m.runs["run-b"] = model.Run{ID: "run-b", RepoID: "gitlab.com/o/b", RepoFullName: "o/b"}
	repoA, repoB := "github.com/o/a", "gitlab.com/o/b"

	if _, err := m.InsertTestReportWithHistory(ctx, model.TestReport{ID: "r1", RunID: "run-a", JobKey: "build", CreatedAt: time.Now().UTC(),
		Cases: []model.TestResult{{Name: "t", Passed: true}, {Name: "t", Passed: false}}}, repoA); err != nil {
		t.Fatal(err)
	}
	if _, err := m.InsertTestReportWithHistory(ctx, model.TestReport{ID: "r2", RunID: "run-b", JobKey: "build", CreatedAt: time.Now().UTC(),
		Cases: []model.TestResult{{Name: "other", Passed: true}}}, repoB); err != nil {
		t.Fatal(err)
	}
	// Scoped flaky: only repo A's both-outcome test is returned.
	flaky, err := m.FlakyTestNames(ctx, []string{repoA}, 100)
	if err != nil || len(flaky) != 1 || flaky[0] != "t" {
		t.Fatalf("scoped flaky = %v, %v; want [t]", flaky, err)
	}
	// Totals for repo A only.
	reports, tests, failures, err := m.TestReportTotals(ctx, []string{repoA}, "o/a")
	if err != nil || reports != 1 || tests != 0 || failures != 0 {
		t.Fatalf("totals = %d/%d/%d, %v; want 1/0/0", reports, tests, failures, err)
	}
	// Resolution accepts the human name and the canonical id.
	for _, q := range []string{"o/a", repoA} {
		ids, err := m.ResolveTestHistoryRepoIDs(ctx, q, 10)
		if err != nil || len(ids) != 1 || ids[0] != repoA {
			t.Fatalf("resolve %q = %v, %v; want [%s]", q, ids, err, repoA)
		}
	}
	// Rebuild is equivalent to the incremental fold.
	_, before, err := m.LoadRepoTestHistory(ctx, repoA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.RebuildRepoTestHistory(ctx, repoA); err != nil {
		t.Fatal(err)
	}
	_, after, err := m.LoadRepoTestHistory(ctx, repoA)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("mem rebuild diverged:\nbefore %s\nafter  %s", before, after)
	}
	// A missing repository is version 0 with no stats (the SQL lazy-repair
	// trigger).
	if v, stats, err := m.LoadRepoTestHistory(ctx, "github.com/o/missing"); err != nil || v != 0 || stats != nil {
		t.Fatalf("missing repo history = %d/%v/%v; want 0/nil/nil", v, stats, err)
	}
}
