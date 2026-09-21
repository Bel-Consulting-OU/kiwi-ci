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
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
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

// TestCanonicalIdentitySQLMatchesMigration0027 pins the Go identity helpers
// and the migration-0027 DDL together: the IMMUTABLE function body and both
// expression-index definitions must be byte-identical to what
// canonicalRepoIDFunctionBody / canonicalPolicyRepoIDSQLExpr render, so the
// planner can match the scoped reads and the rebuild to the index and the Go
// derivation can never drift from the database derivation.
func TestCanonicalIdentitySQLMatchesMigration0027(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0027_test_history_canonical_identity_index.sql")
	if err != nil {
		t.Fatalf("read 0027: %v", err)
	}
	sql := string(raw)
	wantFunction := "AS $$SELECT " + canonicalRepoIDFunctionBody() + "$$;"
	if !strings.Contains(sql, wantFunction) {
		t.Fatal("migration 0027 does not create kiwi_canonical_repo_id with the canonicalRepoIDFunctionBody body (Go and SQL derivations would drift)")
	}
	if want := "ON runs ((" + canonicalPolicyRepoIDSQLExpr("repo") + "));"; !strings.Contains(sql, want) {
		t.Fatalf("migration 0027 identity index does not match canonicalPolicyRepoIDSQLExpr(\"repo\") (%s)", want)
	}
	if want := "ON runs ((payload->>'repo_full_name'));"; !strings.Contains(sql, want) {
		t.Fatalf("migration 0027 full-name index does not match the read expression (%s)", want)
	}
	for _, drop := range []string{"DROP INDEX IF EXISTS runs_repo_identity_idx;", "DROP INDEX IF EXISTS runs_repo_full_name_idx;"} {
		if !strings.Contains(sql, drop) {
			t.Fatalf("migration 0027 does not replace the 0026 definition: missing %q", drop)
		}
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

// TestEncodeTestHistoryStatsV2KeysUnambiguous is the aggregate-side key
// round-trip: every part may contain "|", unicode, be empty or whitespace-only
// without another identity's key colliding, because the encoder writes the
// structured v2 key. The encoded stats must load through the legacy history
// reader (testintel.LoadHistory) and answer Manifest/Flaky correctly.
func TestEncodeTestHistoryStatsV2KeysUnambiguous(t *testing.T) {
	rows := []TestHistoryAggregate{
		{RepoID: "github.com/o/r|x", Suite: "suite|part", Class: "cl|ass", Name: "na|me",
			Runs: 2, Passes: 1, Fails: 1, EWMA: 1, FlakeProb: 0.5, Outcomes: []bool{false, true}},
		{RepoID: "github.com/o/r", Suite: "suite", Class: "cl", Name: "ass|na|me",
			Runs: 2, Passes: 2, EWMA: 2, FlakeProb: 0},
		{RepoID: "github.com/o/r", Suite: "suite", Class: "", Name: " ",
			Runs: 1, Passes: 1, EWMA: 3, FlakeProb: 0},
		{RepoID: "github.com/уни/код", Suite: "тест", Class: "класс", Name: "имя🚀",
			Runs: 1, Passes: 0, Fails: 1, EWMA: 4, FlakeProb: 0},
	}
	stats, err := EncodeTestHistoryStats(rows)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]testintel.TestStat
	if err := json.Unmarshal(stats, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(rows) {
		t.Fatalf("encoded %d keys from %d rows (collision): %s", len(decoded), len(rows), stats)
	}
	for key := range decoded {
		if !strings.HasPrefix(key, "v2:") {
			t.Fatalf("aggregate key %q is not the v2 encoding", key)
		}
	}
	// The structured key survives the history-file reader: load the encoded
	// stats as a file and read the exact identities back.
	path := filepath.Join(t.TempDir(), "history.json")
	if err := os.WriteFile(path, stats, 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := testintel.LoadHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := h.Manifest("github.com/o/r|x", "suite|part"); !reflect.DeepEqual(got, []string{"cl|ass.na|me"}) {
		t.Fatalf("manifest through the aggregate encoder = %v", got)
	}
	if got := h.Manifest("github.com/o/r", "suite"); !reflect.DeepEqual(got, []string{" ", "cl.ass|na|me"}) {
		t.Fatalf("second repo manifest = %v", got)
	}
	if got := h.Flaky("github.com/o/r|x"); !reflect.DeepEqual(got, []string{"cl|ass.na|me"}) {
		t.Fatalf("flaky through the aggregate encoder = %v", got)
	}
	if got := h.Flaky("github.com/o/r"); len(got) != 0 {
		t.Fatalf("unrelated repo flaky = %v", got)
	}
	// The pre-v2 join would have collided these two identities; assert they
	// are distinct keys now.
	if testintel.EncodeHistoryKey("a|b", "s", "c", "n") == testintel.EncodeHistoryKey("a", "b|s", "c", "n") {
		t.Fatal("structured keys collided across part boundaries")
	}
}

// TestTestHistoryAggregateKeyStructured pins the rebuild map key against
// in-band-separator collisions.
func TestTestHistoryAggregateKeyStructured(t *testing.T) {
	if testHistoryAggregateKey("a|b", "c", "d") == testHistoryAggregateKey("a", "b|c", "d") {
		t.Fatal("rebuild map key collided across part boundaries")
	}
	if !strings.HasPrefix(testHistoryAggregateKey("s", "c", "n"), "v2:") {
		t.Fatal("rebuild map key is not structured")
	}
}

// TestMemStoreFlakyWindowAndRepoPaging mirrors the SQL defects in memory: the
// flaky predicate is the window-derived flake probability (not lifetime
// counters), and ListTestHistoryRepoIDs returns the complete enumeration for
// any page size (the SQL store loops its keyset pages to the same result).
func TestMemStoreFlakyWindowAndRepoPaging(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	base := time.Now().UTC()
	repo := "github.com/o/a"
	m.runs["run-a"] = model.Run{ID: "run-a", RepoID: repo, RepoFullName: "o/a"}
	// One failure, then a clean 16-outcome window.
	if _, err := m.InsertTestReportWithHistory(ctx, model.TestReport{ID: "r0", RunID: "run-a", JobKey: "build",
		CreatedAt: base, Cases: []model.TestResult{{Name: "t", Passed: false}}}, repo); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < testintel.OutcomeWindow; i++ {
		if _, err := m.InsertTestReportWithHistory(ctx, model.TestReport{ID: "rp" + itoa64(int64(i)), RunID: "run-a", JobKey: "build",
			CreatedAt: base.Add(time.Duration(i+1) * time.Second), Cases: []model.TestResult{{Name: "t", Passed: true}}}, repo); err != nil {
			t.Fatal(err)
		}
	}
	flaky, err := m.FlakyTestNames(ctx, []string{repo}, 100)
	if err != nil || len(flaky) != 0 {
		t.Fatalf("memStore flaky after clean window = %v, %v; want none", flaky, err)
	}
	// A fresh failure restores it.
	if _, err := m.InsertTestReportWithHistory(ctx, model.TestReport{ID: "rf", RunID: "run-a", JobKey: "build",
		CreatedAt: base.Add(time.Minute), Cases: []model.TestResult{{Name: "t", Passed: false}}}, repo); err != nil {
		t.Fatal(err)
	}
	flaky, err = m.FlakyTestNames(ctx, []string{repo}, 100)
	if err != nil || !reflect.DeepEqual(flaky, []string{"t"}) {
		t.Fatalf("memStore flaky after fresh failure = %v, %v; want [t]", flaky, err)
	}

	// Pagination contract: every repository is enumerated regardless of the
	// page size (the SQL store pages internally; the result is identical).
	for i := 0; i < 5; i++ {
		id := "github.com/o/p" + itoa64(int64(i))
		runID := "run-p" + itoa64(int64(i))
		m.runs[runID] = model.Run{ID: runID, RepoID: id, RepoFullName: "o/p" + itoa64(int64(i))}
		if _, err := m.InsertTestReportWithHistory(ctx, model.TestReport{ID: "rep-" + runID, RunID: runID, JobKey: "build",
			CreatedAt: base, Cases: []model.TestResult{{Name: "x", Passed: true}}}, id); err != nil {
			t.Fatal(err)
		}
	}
	full, err := m.ListTestHistoryRepoIDs(ctx, 0)
	if err != nil || len(full) != 6 {
		t.Fatalf("full enumeration = %v, %v; want 6 repositories", full, err)
	}
	small, err := m.ListTestHistoryRepoIDs(ctx, 2)
	if err != nil || !reflect.DeepEqual(small, full) {
		t.Fatalf("small-page enumeration = %v, %v; want the identical complete list %v", small, err, full)
	}
	sorted := append([]string(nil), full...)
	sort.Strings(sorted)
	if !reflect.DeepEqual(full, sorted) {
		t.Fatalf("enumeration is not ascending: %v", full)
	}
}
