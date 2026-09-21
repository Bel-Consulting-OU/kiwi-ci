package server

// Scoped-read and bounded-write proofs for the S6-A test-history path, using
// a counting store wrapper: a test-report upload and a test-intelligence
// read must never enumerate all reports and never resolve unrelated runs
// (the old full-rebuild path called ListTestReportsAll + GetRun per report).

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// historyCountingStore counts the full-history calls the fixed path must
// avoid: ListTestReportsAll (whole-table materialization) and GetRun (per-run
// resolution in Go), plus the incremental writes it should perform instead.
type historyCountingStore struct {
	*dbFakeStore
	listAllCalls   atomic.Int64
	getRunCalls    atomic.Int64
	incrementalOps atomic.Int64
}

func (c *historyCountingStore) ListTestReportsAll(ctx context.Context) ([]model.TestReport, error) {
	c.listAllCalls.Add(1)
	return c.dbFakeStore.ListTestReportsAll(ctx)
}

func (c *historyCountingStore) GetRun(ctx context.Context, id string) (model.Run, error) {
	c.getRunCalls.Add(1)
	return c.dbFakeStore.GetRun(ctx, id)
}

func (c *historyCountingStore) InsertTestReportWithHistory(ctx context.Context, rep model.TestReport, repoID string) (int64, error) {
	c.incrementalOps.Add(1)
	return c.dbFakeStore.InsertTestReportWithHistory(ctx, rep, repoID)
}

// InsertTestReportWithHistoryDelivery is the path the handler actually uses;
// it counts as exactly the same single incremental aggregate transaction.
func (c *historyCountingStore) InsertTestReportWithHistoryDelivery(ctx context.Context, rep model.TestReport, repoID string, delivery storage.TestReportDelivery) (storage.TestReportInsertOutcome, error) {
	c.incrementalOps.Add(1)
	return c.dbFakeStore.InsertTestReportWithHistoryDelivery(ctx, rep, repoID, delivery)
}

func (c *historyCountingStore) TestReportTotals(ctx context.Context, repoIDs []string, repoQuery string) (int, int, int, error) {
	if len(repoIDs) == 0 {
		return 0, 0, 0, nil
	}
	return c.dbFakeStore.TestReportTotals(ctx, repoIDs, repoQuery)
}

func historyScopeFixture(t *testing.T) (*Server, *historyCountingStore, *dbFakeStore) {
	t.Helper()
	f := newDBFakeStore()
	cs := &historyCountingStore{dbFakeStore: f}
	s := New("admin")
	if err := s.SwitchToDB(cs); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.runs["run-a"] = model.Run{ID: "run-a", RepoID: "github.com/o/a", RepoFullName: "o/a", Status: model.StatusSuccess}
	f.runs["run-b"] = model.Run{ID: "run-b", RepoID: "github.com/o/b", RepoFullName: "o/b", Status: model.StatusSuccess}
	f.mu.Unlock()
	return s, cs, f
}

// TestTestHistoryUploadDoesNotEnumerateAllReports pins the bounded per-upload
// write THROUGH THE HANDLER: uploading a report for repo A performs exactly
// one incremental aggregate transaction and never the legacy full-table
// rebuild (ListTestReportsAll + a GetRun per report) — no matter how much
// unrelated history exists.
func TestTestHistoryUploadDoesNotEnumerateAllReports(t *testing.T) {
	f := newDBFakeStore()
	cs := &historyCountingStore{dbFakeStore: f}
	s := New("token")
	if err := s.SwitchToDB(cs); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Seed unrelated history for repo B (the old rebuild read every one of
	// these reports on every upload, hence the quadratic work).
	f.mu.Lock()
	f.runs["run-b"] = model.Run{ID: "run-b", RepoID: "github.com/o/b", RepoFullName: "o/b", Status: model.StatusSuccess}
	f.mu.Unlock()
	for i := 0; i < 25; i++ {
		if _, err := cs.InsertTestReportWithHistory(ctx, model.TestReport{
			ID: "seed-" + string(rune('a'+i)), RunID: "run-b", JobKey: "build", CreatedAt: time.Now().UTC(),
			Cases: []model.TestResult{{Name: "unrelated", Passed: true}},
		}, "github.com/o/b"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.enqueue(ctx, SubmitRun{
		RepoURL: "https://github.com/o/a.git", RepoFullName: "o/a",
		Ref: "refs/heads/main", SHA: "abc", Event: "push", Pipeline: smokePipeline, Trusted: true,
	}); err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseRunJob(t, s)

	cs.listAllCalls.Store(0)
	cs.getRunCalls.Store(0)
	cs.incrementalOps.Store(0)
	body := uploadReportBody(task, runnerID, []map[string]any{
		{"name": "fresh", "duration": 1.0, "passed": true},
	})
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/tests", "token", body); w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	if n := cs.incrementalOps.Load(); n != 1 {
		t.Fatalf("incremental writes = %d, want exactly 1", n)
	}
	if n := cs.listAllCalls.Load(); n != 0 {
		t.Fatalf("upload enumerated all reports %d time(s); want 0", n)
	}
	// The handler resolves the REQUEST's own run identity exactly once
	// (requireRunIdentity); anything more means it walked the history's
	// reports and resolved THEIR runs (the old quadratic behavior).
	if n := cs.getRunCalls.Load(); n > 1 {
		t.Fatalf("upload resolved %d runs; want at most the request's own run (1)", n)
	}
	f.mu.Lock()
	_, okA := f.historyAggregates["github.com/o/a"]
	versionA, versionB := f.historyVersions["github.com/o/a"], f.historyVersions["github.com/o/b"]
	f.mu.Unlock()
	if !okA || versionA != 1 {
		t.Fatalf("repo A aggregates missing or version %d, want 1", versionA)
	}
	if versionB != 25 {
		t.Fatalf("repo B version = %d, want 25 (untouched by A's upload)", versionB)
	}
}

// TestTestIntelligenceScopedReadNeverResolvesUnrelatedRuns pins test (c) at
// the handler level: the response contains ONLY repo A's data and the read
// makes no GetRun / ListTestReportsAll call, so an unrelated report (even an
// undecodable one) can never break it.
func TestTestIntelligenceScopedReadNeverResolvesUnrelatedRuns(t *testing.T) {
	s, cs, f := historyScopeFixture(t)
	ctx := context.Background()
	// Repo A: two reports, one flaky test. Repo B: one report that would
	// poison a full-table decode.
	for _, passed := range []bool{false, true} {
		if _, err := cs.InsertTestReportWithHistory(ctx, model.TestReport{
			ID: "a-" + map[bool]string{false: "fail", true: "pass"}[passed], RunID: "run-a", JobKey: "build",
			Tests: 1, Failures: map[bool]int{false: 1, true: 0}[passed], CreatedAt: time.Now().UTC(),
			Cases: []model.TestResult{{Name: "flaky", Passed: passed}},
		}, "github.com/o/a"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cs.InsertTestReportWithHistory(ctx, model.TestReport{
		ID: "b-1", RunID: "run-b", JobKey: "build", Tests: 9, Failures: 9, CreatedAt: time.Now().UTC(),
		Cases: []model.TestResult{{Name: "b-only", Passed: false}},
	}, "github.com/o/b"); err != nil {
		t.Fatal(err)
	}
	cs.listAllCalls.Store(0)
	cs.getRunCalls.Store(0)

	w := doJSON(t, s, http.MethodGet, "/api/v1/test-intelligence?repo=o/a", "admin", "")
	if w.Code != http.StatusOK {
		t.Fatalf("scoped intelligence = %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		Repo       string   `json:"repo"`
		Reports    int      `json:"reports"`
		TotalTests int      `json:"total_tests"`
		Failures   int      `json:"failures"`
		Flaky      []string `json:"flaky_tests"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Repo != "o/a" || out.Reports != 2 || out.TotalTests != 2 || out.Failures != 1 {
		t.Fatalf("scoped intelligence = %+v, want repo o/a 2 reports / 2 tests / 1 failure", out)
	}
	if len(out.Flaky) != 1 || out.Flaky[0] != "flaky" {
		t.Fatalf("flaky = %v, want [flaky]", out.Flaky)
	}
	if n := cs.listAllCalls.Load(); n != 0 {
		t.Fatalf("intelligence enumerated all reports %d time(s); want 0", n)
	}
	if n := cs.getRunCalls.Load(); n != 0 {
		t.Fatalf("intelligence resolved runs individually %d time(s); want 0", n)
	}
	// Repo B's rows were never materialized: the fake still holds them intact.
	f.mu.Lock()
	bRows := len(f.historyAggregates["github.com/o/b"])
	f.mu.Unlock()
	if bRows != 1 {
		t.Fatalf("repo B aggregates = %d, want 1 untouched row", bRows)
	}
}
