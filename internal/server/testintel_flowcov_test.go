package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

func fcLeaseReportHeaders(t *testing.T, s *Server) (string, map[string]string) {
	t.Helper()
	hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
	return "job-a", hdrs
}

func fcReportBody(jobID string, cases ...model.TestResult) string {
	rep := model.TestReport{RunID: "run-c", JobID: jobID, JobKey: "build", Tests: len(cases), Cases: cases}
	raw, _ := json.Marshal(rep)
	return `{"runner_id":"runner-a","lease_token":"cache-lease-token","lease_generation":5,"report":` + string(raw) + `}`
}

func TestFlowTestintelHistoryLifecycle(t *testing.T) {
	// loadTestintelHistory: no data dir, missing file, corrupt file, valid file.
	s := New("tok")
	if err := s.loadTestintelHistory(""); err != nil || s.history.path != "" {
		t.Fatalf("empty dir load = %v %q", err, s.history.path)
	}
	dir := t.TempDir()
	if err := s.loadTestintelHistory(dir); err != nil {
		t.Fatalf("missing history file = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, testHistoryFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.loadTestintelHistory(dir); err == nil {
		t.Fatal("corrupt history file must fail")
	}
	// Valid file round-trip.
	h := testintel.NewHistory()
	h.Record("github.com/o/repo-a", "build", "C", "t1", 1, false, time.Now().UTC())
	h.Record("github.com/o/repo-a", "build", "C", "t1", 1, true, time.Now().UTC())
	if err := h.Save(filepath.Join(dir, testHistoryFile)); err != nil {
		t.Fatal(err)
	}
	if err := s.loadTestintelHistory(dir); err != nil {
		t.Fatal(err)
	}
	if got := s.flakyFromHistory("github.com/o/repo-a"); len(got) == 0 {
		t.Fatal("loaded history missing flaky entry")
	}
}

func TestFlowTestintelHistorySaveCommit(t *testing.T) {
	// Nil history and empty path are no-ops.
	s := New("tok")
	if err := s.saveTestintelHistoryLocked(); err != nil {
		t.Fatalf("nil history save = %v", err)
	}
	if err := s.commitTestintelHistoryLocked(); err != nil {
		t.Fatalf("nil history commit = %v", err)
	}
	s.history = newTestintelHistory("")
	if err := s.saveTestintelHistoryLocked(); err != nil {
		t.Fatalf("pathless save = %v", err)
	}
	if err := s.commitTestintelHistoryLocked(); err != nil {
		t.Fatalf("pathless commit = %v", err)
	}
	// Save failure surfaces.
	block := filepath.Join(t.TempDir(), "block")
	if err := os.WriteFile(block, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.history = newTestintelHistory(block + "/sub/history.json")
	if err := s.saveTestintelHistoryLocked(); err == nil {
		t.Fatal("unwritable history path must fail")
	}
	// Commit failure when the staged file is missing.
	s.history = newTestintelHistory(filepath.Join(t.TempDir(), "missing.json"))
	if err := s.commitTestintelHistoryLocked(); err == nil {
		t.Fatal("missing staged history must fail the commit")
	}
}

func TestFlowTestintelRecordReportHistoryMemory(t *testing.T) {
	s := New("tok")
	// Nil history: no-op.
	s.history = nil
	s.recordTestReportHistory("github.com/o/repo-a", model.TestReport{})
	// Memory: fold, save, commit.
	dir := t.TempDir()
	if err := s.loadTestintelHistory(dir); err != nil {
		t.Fatal(err)
	}
	rep := model.TestReport{Cases: []model.TestResult{{Name: "t1", Passed: true, Duration: 1}}, CreatedAt: time.Now().UTC()}
	s.recordTestReportHistory("github.com/o/repo-a", rep)
	if _, err := os.Stat(filepath.Join(dir, testHistoryFile)); err != nil {
		t.Fatalf("history file not committed: %v", err)
	}
	if got := s.flakyFromHistory("github.com/o/repo-a"); len(got) != 0 {
		t.Fatalf("single-pass case must not be flaky: %v", got)
	}
	// Save failure is logged, not fatal.
	block := filepath.Join(t.TempDir(), "block")
	if err := os.WriteFile(block, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.history.path = block + "/sub/history.json"
	s.recordTestReportHistory("github.com/o/repo-a", rep)

	// Commit failure (save succeeds, rename onto a directory fails) is
	// logged, not fatal.
	blockDir := filepath.Join(t.TempDir(), "hist")
	if err := os.MkdirAll(blockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blockDir, "occupied"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.history.path = blockDir
	s.recordTestReportHistory("github.com/o/repo-a", rep)
}

func TestFlowTestintelRebuildHistoryDB(t *testing.T) {
	ctx := context.Background()
	// Store without the history extension.
	s := New("tok")
	s.DB = fcPlainStore{newDBFakeStore()}
	s.rebuildTestHistoryDB(ctx)

	// Report listing failure.
	f := newDBFakeStore()
	s2 := New("tok")
	if err := s2.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s2.DB = &fcStore{dbFakeStore: f, listReportsAllErr: errors.New("reports down")}
	s2.rebuildTestHistoryDB(ctx)

	// Save failure.
	f2 := newDBFakeStore()
	s3 := New("tok")
	if err := s3.SwitchToDB(f2); err != nil {
		t.Fatal(err)
	}
	f2.mu.Lock()
	f2.testHistorySaveErr = errors.New("history save down")
	f2.reports = []model.TestReport{{ID: "r1", RunID: "run-c", JobKey: "build", CreatedAt: time.Now().UTC(), Cases: []model.TestResult{{Name: "t", Passed: true}}}}
	f2.mu.Unlock()
	s3.rebuildTestHistoryDB(ctx)

	// Success: reports fold into the cached history and its run lookup
	// failure path is exercised through a missing run.
	f3 := newDBFakeStore()
	s4 := New("tok")
	if err := s4.SwitchToDB(f3); err != nil {
		t.Fatal(err)
	}
	f3.mu.Lock()
	f3.reports = []model.TestReport{
		{ID: "r1", RunID: "run-missing", JobKey: "build", CreatedAt: time.Now().UTC(), Cases: []model.TestResult{{Name: "t", Passed: false}}},
		{ID: "r2", RunID: "run-missing", JobKey: "build", CreatedAt: time.Now().UTC(), Cases: []model.TestResult{{Name: "t", Passed: true}}},
	}
	f3.mu.Unlock()
	s4.rebuildTestHistoryDB(ctx)
	f3.mu.Lock()
	version := f3.testHistoryVersion
	f3.mu.Unlock()
	if version == 0 {
		t.Fatal("rebuild did not bump the history version")
	}
	// Serialization failure (unwritable TMPDIR) is logged only.
	f4 := newDBFakeStore()
	s5 := New("tok")
	if err := s5.SwitchToDB(f4); err != nil {
		t.Fatal(err)
	}
	f4.mu.Lock()
	f4.reports = []model.TestReport{{ID: "r1", RunID: "run-c", JobKey: "build", CreatedAt: time.Now().UTC(), Cases: []model.TestResult{{Name: "t", Passed: true}}}}
	f4.mu.Unlock()
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	s5.rebuildTestHistoryDB(ctx)
}

func TestFlowTestintelSyncHistoryDB(t *testing.T) {
	ctx := context.Background()
	s := New("tok")
	s.DB = fcPlainStore{newDBFakeStore()}
	s.syncTestHistoryDB(ctx)

	// Load failure.
	f := newDBFakeStore()
	s2 := New("tok")
	if err := s2.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s2.DB = &fcStore{dbFakeStore: f, loadHistoryErr: errors.New("history load down")}
	s2.syncTestHistoryDB(ctx)

	// Older version: no-op.
	f.mu.Lock()
	f.testHistoryVersion = 1
	f.mu.Unlock()
	s2.DB = f
	s2.historyDBVersion = 5
	s2.syncTestHistoryDB(ctx)

	// Newer empty stats: version recorded without replacing the history.
	f.mu.Lock()
	f.testHistoryVersion = 9
	f.testHistoryStats = nil
	f.mu.Unlock()
	s2.syncTestHistoryDB(ctx)
	if s2.historyDBVersion != 9 {
		t.Fatalf("empty stats version = %d, want 9", s2.historyDBVersion)
	}

	// Newer corrupt stats: decode error keeps the current history.
	f.mu.Lock()
	f.testHistoryVersion = 10
	f.testHistoryStats = []byte("{")
	f.mu.Unlock()
	before := s2.history.h
	s2.syncTestHistoryDB(ctx)
	if s2.history.h != before || s2.historyDBVersion != 9 {
		t.Fatal("corrupt stats must not replace the history")
	}

	// Newer valid stats: history replaced.
	stats, err := historyStats(before)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.testHistoryVersion = 11
	f.testHistoryStats = stats
	f.mu.Unlock()
	s2.syncTestHistoryDB(ctx)
	if s2.historyDBVersion != 11 {
		t.Fatalf("valid stats version = %d, want 11", s2.historyDBVersion)
	}
}

func TestFlowTestintelHistoryStatsTempFailures(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	if _, err := historyStats(testintel.NewHistory()); err == nil {
		t.Fatal("historyStats with unwritable TMPDIR must fail")
	}
	if _, err := historyFromStats([]byte("{}")); err == nil {
		t.Fatal("historyFromStats with unwritable TMPDIR must fail")
	}
	// Decode failure with a usable TMPDIR.
	if _, err := historyFromStats([]byte("{")); err == nil {
		t.Fatal("invalid stats must fail to load")
	}
}

func TestFlowTestintelUploadReportBranches(t *testing.T) {
	ctx := context.Background()
	// Decode failure.
	s, _ := fcMemoryBlobServer(t)
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/j/tests", "runner-tok", "{"); w.Code != http.StatusBadRequest {
		t.Fatalf("decode failure = %d", w.Code)
	}
	jobID, hdrs := fcLeaseReportHeaders(t, s)
	body := fcReportBody(jobID, model.TestResult{Name: "t1", Passed: true})
	path := "/api/v1/jobs/" + jobID + "/tests"
	// Lease failure: the report carries the lease credentials in its body.
	badBody := strings.Replace(body, `"lease_token":"cache-lease-token"`, `"lease_token":"wrong"`, 1)
	if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", badBody, hdrs); w.Code != http.StatusConflict {
		t.Fatalf("bad lease report = %d, want 409", w.Code)
	}
	// Memory success.
	if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", body, hdrs); w.Code != http.StatusCreated {
		t.Fatalf("memory report = %d: %s", w.Code, w.Body.String())
	}
	// Memory persist failure.
	block := filepath.Join(t.TempDir(), "block")
	if err := os.WriteFile(block, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.store.Root = block
	if w := doJSONHeaders(t, s, http.MethodPost, path, "runner-tok", body, hdrs); w.Code != http.StatusInternalServerError {
		t.Fatalf("persist failure report = %d, want 500", w.Code)
	}
	_ = ctx

	// DB insert failure and success.
	s2, f, _, hdrs2 := cacheFixture(t)
	f.mu.Lock()
	f.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-c", Key: "build", Status: model.StatusRunning, RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a",
		LeaseRunnerID: "runner-a", LeaseTokenHash: hashLeaseToken(s2.leaseKey, "cache-lease-token"), LeaseGeneration: 5, LeaseExpiresAt: timePtr(time.Now().UTC().Add(time.Hour))}
	f.mu.Unlock()
	s2.DB = &fcStore{dbFakeStore: f, insertReportErr: errors.New("report insert down")}
	if w := doJSONHeaders(t, s2, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", fcReportBody("job-a", model.TestResult{Name: "t1", Passed: true}), hdrs2); w.Code != http.StatusInternalServerError {
		t.Fatalf("db insert failure = %d, want 500", w.Code)
	}
	s2.DB = f
	if w := doJSONHeaders(t, s2, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", fcReportBody("job-a", model.TestResult{Name: "t1", Passed: true}), hdrs2); w.Code != http.StatusCreated {
		t.Fatalf("db report = %d: %s", w.Code, w.Body.String())
	}
}

func TestFlowTestintelListReports(t *testing.T) {
	// Memory: missing run, scoped denial, success with ordering.
	s, _ := fcMemoryBlobServer(t)
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/nope/tests", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("memory missing run = %d, want 404", w.Code)
	}
	s.mu.Lock()
	s.reports["r-new"] = model.TestReport{ID: "r-new", RunID: "run-c", CreatedAt: time.Now().UTC()}
	s.reports["r-old"] = model.TestReport{ID: "r-old", RunID: "run-c", CreatedAt: time.Now().UTC().Add(-time.Hour)}
	s.mu.Unlock()
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/tests", "admin-tok", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "r-old") {
		t.Fatalf("memory report list = %d %s", w.Code, w.Body.String())
	}
	// Scoped denial.
	if err := s.AuthStore.AddToken("outsider", auth.Principal{Subject: "outsider", Roles: []auth.Role{auth.RoleRead},
		Repositories: map[string]auth.RepositoryPermission{"github.com/o/repo-b": {Read: true}}}); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/tests", "outsider", ""); w.Code != http.StatusForbidden {
		t.Fatalf("scoped report list = %d, want 403", w.Code)
	}

	// DB: scoped denial, missing run, read failure, list failure, success.
	s2, f, _, _ := cacheFixture(t)
	if err := s2.AuthStore.AddToken("outsider", auth.Principal{Subject: "outsider", Roles: []auth.Role{auth.RoleRead},
		Repositories: map[string]auth.RepositoryPermission{"github.com/o/repo-b": {Read: true}}}); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s2, http.MethodGet, "/api/v1/runs/run-c/tests", "outsider", ""); w.Code != http.StatusForbidden {
		t.Fatalf("scoped db report list = %d, want 403", w.Code)
	}
	if w := doJSON(t, s2, http.MethodGet, "/api/v1/runs/missing/tests", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("db missing run = %d, want 404", w.Code)
	}
	s2.DB = &fcStore{dbFakeStore: f, getRunErr: errors.New("run read down")}
	if w := doJSON(t, s2, http.MethodGet, "/api/v1/runs/run-c/tests", "admin-tok", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("db run read failure = %d, want 500", w.Code)
	}
	s2.DB = &fcStore{dbFakeStore: f, listReportsErr: errors.New("report list down")}
	if w := doJSON(t, s2, http.MethodGet, "/api/v1/runs/run-c/tests", "admin-tok", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("db report list failure = %d, want 500", w.Code)
	}
	s2.DB = f
	f.mu.Lock()
	f.reports = append(f.reports, model.TestReport{ID: "db-report", RunID: "run-c", CreatedAt: time.Now().UTC()})
	f.mu.Unlock()
	if w := doJSON(t, s2, http.MethodGet, "/api/v1/runs/run-c/tests", "admin-tok", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "db-report") {
		t.Fatalf("db report list = %d %s", w.Code, w.Body.String())
	}
}

func TestFlowTestintelIntelligence(t *testing.T) {
	// Missing repo parameter.
	s, _ := fcMemoryBlobServer(t)
	if w := doJSON(t, s, http.MethodGet, "/api/v1/test-intelligence", "admin-tok", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("missing repo = %d, want 400", w.Code)
	}
	// A principal without read at all is denied before visibility.
	if err := s.AuthStore.AddToken("manager", auth.Principal{Subject: "manager", Roles: []auth.Role{auth.RolePolicyManage}}); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/test-intelligence?repo=o/repo-a", "manager", ""); w.Code != http.StatusForbidden {
		t.Fatalf("rbac intelligence = %d, want 403", w.Code)
	}
	// Scoped denial through repo visibility.
	if err := s.AuthStore.AddToken("outsider", auth.Principal{Subject: "outsider", Roles: []auth.Role{auth.RoleRead},
		Repositories: map[string]auth.RepositoryPermission{"github.com/o/repo-b": {Read: true}}}); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/test-intelligence?repo=o/repo-a", "outsider", ""); w.Code != http.StatusForbidden {
		t.Fatalf("scoped intelligence = %d, want 403", w.Code)
	}
	// Memory success with a matching run and a flaky case.
	s.mu.Lock()
	s.runs["run-c"] = model.Run{ID: "run-c", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a"}
	s.reports["r1"] = model.TestReport{ID: "r1", RunID: "run-c", JobKey: "build", Cases: []model.TestResult{{Class: "C", Name: "flaky", Passed: false}}, CreatedAt: time.Now().UTC()}
	s.mu.Unlock()
	if err := s.AuthStore.AddToken("reader", auth.Principal{Subject: "reader", Roles: []auth.Role{auth.RoleRead},
		Repositories: map[string]auth.RepositoryPermission{"o/repo-a": {Read: true}}}); err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodGet, "/api/v1/test-intelligence?repo=o/repo-a", "reader", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "flaky") {
		t.Fatalf("memory intelligence = %d %s", w.Code, w.Body.String())
	}

	// DB: report listing failure.
	s2, f, _, _ := cacheFixture(t)
	s2.DB = &fcStore{dbFakeStore: f, listReportsAllErr: errors.New("reports down")}
	if w := doJSON(t, s2, http.MethodGet, "/api/v1/test-intelligence?repo=o/repo-a", "admin-tok", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("db intelligence list failure = %d, want 500", w.Code)
	}
	// DB success: matching reports fold; unmatchable runs are skipped.
	s2.DB = f
	f.mu.Lock()
	f.reports = append(f.reports,
		model.TestReport{ID: "m1", RunID: "run-c", JobKey: "build", Tests: 2, Failures: 1, Cases: []model.TestResult{{Name: "case", Passed: false}}, CreatedAt: time.Now().UTC()},
		model.TestReport{ID: "m2", RunID: "run-unknown", JobKey: "build", CreatedAt: time.Now().UTC()})
	f.mu.Unlock()
	if w := doJSON(t, s2, http.MethodGet, "/api/v1/test-intelligence?repo=github.com/o/repo-a", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("db intelligence = %d: %s", w.Code, w.Body.String())
	}
}

func TestFlowTestintelRunMatchesRepoQuery(t *testing.T) {
	run := model.Run{RepoID: "github.com/o/repo-a", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a"}
	if runMatchesRepoQuery(run, "") {
		t.Fatal("empty query must not match")
	}
	if !runMatchesRepoQuery(run, "o/repo-a") {
		t.Fatal("full name must match")
	}
	if !runMatchesRepoQuery(run, "github.com/o/repo-a") {
		t.Fatal("canonical id must match")
	}
	if !runMatchesRepoQuery(run, "o/repo-a") {
		t.Fatal("legacy canonical form must match")
	}
	if runMatchesRepoQuery(run, "other/repo") {
		t.Fatal("unrelated query must not match")
	}
}

func TestFlowTestintelMergeHistoryFlaky(t *testing.T) {
	s := New("tok")
	s.history = nil
	out := map[string]any{"flaky_tests": []string{"b"}}
	s.mergeHistoryFlaky("github.com/o/repo-a", out)
	if got, _ := out["flaky_tests"].([]string); len(got) != 1 || got[0] != "b" {
		t.Fatalf("nil-history merge = %v", out)
	}
	// Merge dedupes and sorts persisted entries.
	s.history = newTestintelHistory("")
	s.history.h.Record("github.com/o/repo-a", "build", "C", "a", 1, false, time.Now().UTC())
	s.history.h.Record("github.com/o/repo-a", "build", "C", "a", 1, true, time.Now().UTC())
	s.history.h.Record("github.com/o/repo-a", "build", "C", "b", 1, false, time.Now().UTC())
	s.history.h.Record("github.com/o/repo-a", "build", "C", "b", 1, true, time.Now().UTC())
	out = map[string]any{"flaky_tests": []string{"b"}}
	s.mergeHistoryFlaky("github.com/o/repo-a", out)
	got, _ := out["flaky_tests"].([]string)
	if len(got) != 3 || got[0] != "C.a" || got[1] != "C.b" || got[2] != "b" {
		t.Fatalf("merged flaky = %v", got)
	}
}
