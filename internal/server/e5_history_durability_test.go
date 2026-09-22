package server

// E5-D: in fs/memory mode the DURABLE reports (state.json) are the source of
// truth for test history; test-history.json is only a cache. A failed history
// write, a crash between the report commit and the fold, and an identical
// replay must all converge on exactly the durable report's outcomes.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

// e5UploadBody renders a /tests request with a stable delivery identity.
func e5UploadBody(jobID, deliveryID string, cases []model.TestResult) string {
	failures, skipped := 0, 0
	for _, c := range cases {
		if c.Skipped {
			skipped++
			continue
		}
		if !c.Passed {
			failures++
		}
	}
	rep := model.TestReport{Tests: len(cases), Failures: failures, Skipped: skipped, Cases: cases}
	raw, _ := json.Marshal(rep)
	body := map[string]any{
		"runner_id": "runner-a", "lease_token": "cache-lease-token", "lease_generation": 5,
		"delivery_id": deliveryID, "report": json.RawMessage(raw),
	}
	b, _ := json.Marshal(body)
	return string(b)
}

// e5FlakyReport is the report fixture: one test that passes and fails in the
// same report, so it is flaky if and only if BOTH outcomes were folded.
func e5FlakyReport() []model.TestResult {
	now := time.Now().UTC()
	_ = now
	return []model.TestResult{
		{Name: "TestA", Passed: true, Duration: 1},
		{Name: "TestA", Passed: false, Duration: 2},
	}
}

// TestE5FsHistoryWriteFailureThenRestartRebuildsFromReports is the E5-D
// divergence regression: the upload succeeds (the report commits to
// state.json) while the history cache write fails, and after a restart the
// history still includes the durable report because it is re-derived from the
// reports rather than loaded from the stale/absent cache file.
func TestE5FsHistoryWriteFailureThenRestartRebuildsFromReports(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
	// The history cache path is unusable from now on: every save/commit
	// fails, exactly like a full disk or a permission problem.
	s.historyFile = filepath.Join(dir, "blocked-by-missing-parent", testHistoryFile)

	body := e5UploadBody("job-a", "delivery-1", e5FlakyReport())
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", body, hdrs)
	if w.Code != http.StatusCreated {
		t.Fatalf("upload with a failing history cache = %d, want 201: %s", w.Code, w.Body.String())
	}
	reportID := testintel.DeliveryReportID("delivery-1")
	s.mu.Lock()
	_, durable := s.reports[reportID]
	s.mu.Unlock()
	if !durable {
		t.Fatalf("report %s is not durable after a 201", reportID)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err != nil {
		t.Fatalf("state snapshot missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, testHistoryFile)); err == nil {
		t.Fatal("the cache file exists even though every cache write was supposed to fail")
	}

	// Restart: the durable report must answer, not the (absent) cache file.
	s2, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	flaky := s2.flakyFromHistory("github.com/o/repo-a")
	if len(flaky) != 1 || flaky[0] != "TestA" {
		t.Fatalf("flaky after restart = %v, want [TestA] re-derived from the durable report", flaky)
	}
	// The rebuild also repairs the cache so the next restart is cheap.
	if _, err := os.Stat(filepath.Join(dir, testHistoryFile)); err != nil {
		t.Fatalf("the derived rebuild did not repair the history cache: %v", err)
	}
}

// TestE5FsReplayAfterLostFoldFoldsExactlyOnce simulates the crash window the
// defect describes: the report committed to state.json but the process died
// before folding it into the history. An identical delivery replay must
// converge (the report is folded) and must fold EXACTLY once, no matter how
// many times it is replayed.
func TestE5FsReplayAfterLostFoldFoldsExactlyOnce(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)

	cases := e5FlakyReport()
	reportID := testintel.DeliveryReportID("delivery-crash")
	// The durable report a crashed upload would have left behind: server
	// fields stamped, no history fold yet.
	crashed := model.TestReport{
		ID: reportID, RunID: "run-c", JobID: "job-a", JobKey: "build", CreatedAt: time.Now().UTC(),
		Tests: len(cases), Failures: 1, Cases: cases,
	}
	s.mu.Lock()
	s.reports[reportID] = crashed
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()

	body := e5UploadBody("job-a", "delivery-crash", cases)
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", body, hdrs)
	if w.Code != http.StatusOK {
		t.Fatalf("replay = %d, want 200 (idempotent replay of a durable report): %s", w.Code, w.Body.String())
	}
	// The report contributes its TWO observations (one pass, one fail). A
	// lost fold would show 0; folding it twice would show 4.
	if runs, passes, fails := e5HistoryStat(t, s, "github.com/o/repo-a", "TestA"); runs != 2 || passes != 1 || fails != 1 {
		t.Fatalf("TestA after the replay = runs %d/passes %d/fails %d, want 2/1/1", runs, passes, fails)
	}
	// A second replay still folds nothing new.
	w = doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", body, hdrs)
	if w.Code != http.StatusOK {
		t.Fatalf("second replay = %d, want 200: %s", w.Code, w.Body.String())
	}
	if runs, passes, fails := e5HistoryStat(t, s, "github.com/o/repo-a", "TestA"); runs != 2 || passes != 1 || fails != 1 {
		t.Fatalf("TestA after the second replay = runs %d/passes %d/fails %d, want 2/1/1", runs, passes, fails)
	}
	s.mu.Lock()
	reportCount := len(s.reports)
	s.mu.Unlock()
	if reportCount != 1 {
		t.Fatalf("stored reports = %d, want exactly the one durable report", reportCount)
	}
	if flaky := s.flakyFromHistory("github.com/o/repo-a"); len(flaky) != 1 || flaky[0] != "TestA" {
		t.Fatalf("flaky after the replay = %v, want [TestA]", flaky)
	}
}

// e5HistoryStat reads one test's observed counters out of the server's
// derived memory/fs history.
func e5HistoryStat(t *testing.T, s *Server, repo, name string) (runs, passes, fails int) {
	t.Helper()
	h := s.derivedHistory()
	stats, err := historyStats(h)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]testintel.TestStat
	if err := json.Unmarshal(stats, &decoded); err != nil {
		t.Fatal(err)
	}
	stat, ok := decoded[testintel.EncodeHistoryKey(repo, "build", "", name)]
	if !ok {
		return 0, 0, 0
	}
	return stat.Runs, stat.Passes, stat.Fails
}

// TestE5FsHistoryCacheRoundTripCompatibility pins that the cache file keeps
// the legacy history JSON shape: the server's own cache write loads through
// testintel.LoadHistory, and a legacy file (hand-written, old key form) still
// loads and is superseded by the durable reports.
func TestE5FsHistoryCacheRoundTripCompatibility(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
	body := e5UploadBody("job-a", "delivery-rt", e5FlakyReport())
	if w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", body, hdrs); w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	cachePath := filepath.Join(dir, testHistoryFile)
	loaded, err := testintel.LoadHistory(cachePath)
	if err != nil {
		t.Fatalf("cache file does not load through the legacy reader: %v", err)
	}
	if got := loaded.Flaky("github.com/o/repo-a"); len(got) != 1 || got[0] != "TestA" {
		t.Fatalf("round-tripped cache flaky = %v, want [TestA]", got)
	}

	// A legacy (pre-v2) cache file is loaded as a cache and, because the
	// durable reports are the truth, the derived read ignores its content.
	legacy := map[string]testintel.TestStat{
		"github.com/o/repo-a|build||LegacyOnly": {Runs: 2, Passes: 1, Fails: 1, Outcomes: []bool{true, false}},
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s2, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.flakyFromHistory("github.com/o/repo-a"); len(got) != 1 || got[0] != "TestA" {
		t.Fatalf("derived flaky with a legacy cache file = %v, want the durable [TestA]", got)
	}
}
