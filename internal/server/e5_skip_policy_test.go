package server

// E5-A server-side: skipped cases are never historical pass/fail observations
// in the memory/fs history, the legacy whole-cache rebuild or the
// report-derived test-intelligence summary.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

// e5SkipFixture is a report that mixes observed outcomes with skips. The
// "skip-me" test is skipped twice (the JUnit conversion records Passed=false
// plus Skipped=true); folding it would make it a two-failure test with a
// lifetime failure record, and a later pass would make it look flaky.
func e5SkipFixture() []model.TestResult {
	return []model.TestResult{
		{Name: "mix", Passed: true, Duration: 1},
		{Name: "mix", Passed: false, Duration: 2},
		{Name: "skip-me", Passed: false, Skipped: true, Duration: 3},
		{Name: "skip-me", Passed: false, Skipped: true, Duration: 4},
	}
}

// TestE5UploadSkippedCasesAreNotFailuresOrFlakiness drives the real /tests
// endpoint in fs mode: the skipped test must not appear in the history at all,
// must not be flaky, and must not be counted as a failure anywhere.
func TestE5UploadSkippedCasesAreNotFailuresOrFlakiness(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
	cases := e5SkipFixture()
	body := e5UploadBody("job-a", "delivery-skips", cases)
	if w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", body, hdrs); w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	repo := "github.com/o/repo-a"
	if runs, passes, fails := e5HistoryStat(t, s, repo, "skip-me"); runs != 0 || passes != 0 || fails != 0 {
		t.Fatalf("skipped test created history: runs %d/passes %d/fails %d", runs, passes, fails)
	}
	if runs, passes, fails := e5HistoryStat(t, s, repo, "mix"); runs != 2 || passes != 1 || fails != 1 {
		t.Fatalf("observed test history = runs %d/passes %d/fails %d, want 2/1/1", runs, passes, fails)
	}
	if flaky := s.flakyFromHistory(repo); len(flaky) != 1 || flaky[0] != "mix" {
		t.Fatalf("flaky = %v, want only the genuinely mixed test", flaky)
	}
	// The manifest (shard input) contains only observed tests too.
	if manifest := s.derivedHistory().Manifest(repo, "build"); len(manifest) != 1 || manifest[0] != "mix" {
		t.Fatalf("manifest = %v, want [mix]", manifest)
	}
}

// TestE5SummarizeTestIntelligenceExcludesSkippedCases pins the report-derived
// (legacy-store and memory) flaky summary: skipped cases never enter the
// outcome window, so a skip followed by a pass is ONE clean outcome (not a
// pass/fail mix that would be reported flaky). The discriminating fixture
// matters: a skip-only test looks consistently "failed" and is not flaky
// either way, but a skip-then-pass sequence is flaky exactly when the skip is
// folded as a failure.
func TestE5SummarizeTestIntelligenceExcludesSkippedCases(t *testing.T) {
	now := time.Now().UTC()
	reports := []model.TestReport{
		{ID: "r1", JobKey: "build", Tests: 4, Failures: 1, CreatedAt: now,
			Cases: e5SkipFixture()},
		{ID: "r2", JobKey: "build", Tests: 1, CreatedAt: now.Add(time.Second),
			Cases: []model.TestResult{{Name: "sometimes", Passed: false, Skipped: true}}},
		{ID: "r3", JobKey: "build", Tests: 1, CreatedAt: now.Add(2 * time.Second),
			Cases: []model.TestResult{{Name: "sometimes", Passed: true}}},
	}
	out := summarizeTestIntelligence(reports)
	flaky, _ := out["flaky_tests"].([]string)
	if len(flaky) != 1 || flaky[0] != "mix" {
		t.Fatalf("report-derived flaky = %v, want [mix] (the skip-then-pass test must not be flaky)", flaky)
	}
	if out["total_tests"] != 6 || out["failures"] != 1 {
		t.Fatalf("declared totals changed: %v", out)
	}
}

// TestE5LegacyRebuildExcludesSkippedCases pins the legacy whole-cache rebuild
// (a TestHistoryStore without the aggregate contract): the recomputed stats
// exclude skips exactly like the incremental and aggregate paths.
func TestE5LegacyRebuildExcludesSkippedCases(t *testing.T) {
	ctx := context.Background()
	f := newDBFakeStore()
	f.mu.Lock()
	f.runs["run-c"] = model.Run{ID: "run-c", RepoID: "github.com/o/repo-a", RepoFullName: "o/repo-a"}
	f.reports = []model.TestReport{{
		ID: "rep-skips", RunID: "run-c", JobKey: "build", CreatedAt: time.Now().UTC(),
		Tests: 4, Failures: 1, Cases: e5SkipFixture(),
	}}
	f.mu.Unlock()
	legacy := &legacyHistoryStore{Store: f}
	s := New("tok")
	s.DB = legacy
	s.rebuildTestHistoryDB(ctx)
	if legacy.version == 0 {
		t.Fatal("legacy rebuild did not run")
	}
	h, err := historyFromStats(legacy.stats)
	if err != nil {
		t.Fatalf("decode legacy stats: %v", err)
	}
	if got := h.Manifest("github.com/o/repo-a", "build"); len(got) != 1 || got[0] != "mix" {
		t.Fatalf("legacy rebuilt manifest = %v, want [mix]", got)
	}
	if got := h.Flaky("github.com/o/repo-a"); len(got) != 1 || got[0] != "mix" {
		t.Fatalf("legacy rebuilt flaky = %v, want [mix]", got)
	}
}

// TestE5DBStoreSkipsExcludedFromAggregates pins the DB-mode aggregate fold:
// the SQL/fake aggregate rows contain only observed pass/fail outcomes and
// the skipped test has no row and no flaky entry.
func TestE5DBStoreSkipsExcludedFromAggregates(t *testing.T) {
	ctx := context.Background()
	f := newDBFakeStore()
	s := New("tok")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	repo := "github.com/o/repo-a"
	f.mu.Lock()
	f.runs["run-c"] = model.Run{ID: "run-c", RepoID: repo, RepoFullName: "o/repo-a"}
	f.mu.Unlock()
	rep := model.TestReport{
		ID: "rep-db-skips", RunID: "run-c", JobKey: "build", CreatedAt: time.Now().UTC(),
		Tests: 4, Failures: 1, Cases: e5SkipFixture(),
	}
	if _, err := f.InsertTestReportWithHistory(ctx, rep, repo); err != nil {
		t.Fatal(err)
	}
	_, stats, err := f.LoadRepoTestHistory(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	h, err := historyFromStats(stats)
	if err != nil {
		t.Fatal(err)
	}
	if got := h.Manifest(repo, "build"); len(got) != 1 || got[0] != "mix" {
		t.Fatalf("DB aggregate manifest = %v, want [mix]", got)
	}
	if got := h.Flaky(repo); len(got) != 1 || got[0] != "mix" {
		t.Fatalf("DB aggregate flaky = %v, want [mix]", got)
	}
	var decoded map[string]testintel.TestStat
	if err := json.Unmarshal(stats, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded[testintel.EncodeHistoryKey(repo, "build", "", "skip-me")]; ok {
		t.Fatalf("skipped test has an aggregate row: %s", stats)
	}
	if _, err := f.RebuildRepoTestHistory(ctx, repo); err != nil {
		t.Fatal(err)
	}
	_, rebuilt, err := f.LoadRepoTestHistory(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if string(stats) != string(rebuilt) {
		t.Fatalf("DB rebuild diverged under skips:\nincremental %s\nrebuilt     %s", stats, rebuilt)
	}
}
