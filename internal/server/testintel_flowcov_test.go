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
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
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
	s.recordTestReportHistory(context.Background(), "github.com/o/repo-a", model.TestReport{})
	// Memory: fold, save, commit.
	dir := t.TempDir()
	if err := s.loadTestintelHistory(dir); err != nil {
		t.Fatal(err)
	}
	rep := model.TestReport{Cases: []model.TestResult{{Name: "t1", Passed: true, Duration: 1}}, CreatedAt: time.Now().UTC()}
	s.recordTestReportHistory(context.Background(), "github.com/o/repo-a", rep)
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
	s.recordTestReportHistory(context.Background(), "github.com/o/repo-a", rep)

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
	s.recordTestReportHistory(context.Background(), "github.com/o/repo-a", rep)
}

// legacyHistoryStore exposes only Store + TestHistoryStore (hiding the
// embedded aggregate contract), so tests can drive the legacy whole-cache
// maintenance/sync path that production stores no longer use.
type legacyHistoryStore struct {
	storage.Store
	version int64
	stats   []byte
	saveErr error
}

func (l *legacyHistoryStore) LoadTestHistory(context.Context) (int64, []byte, error) {
	return l.version, append([]byte(nil), l.stats...), nil
}

func (l *legacyHistoryStore) SaveTestHistory(_ context.Context, stats []byte) (int64, error) {
	if l.saveErr != nil {
		return 0, l.saveErr
	}
	l.version++
	l.stats = append([]byte(nil), stats...)
	return l.version, nil
}

// corruptRepoHistoryStore returns corrupt aggregate stats for one repository.
type corruptRepoHistoryStore struct {
	*dbFakeStore
	stats []byte
}

func (c corruptRepoHistoryStore) LoadRepoTestHistory(context.Context, string) (int64, []byte, error) {
	return 10, c.stats, nil
}

func TestFlowTestintelRebuildHistoryDB(t *testing.T) {
	ctx := context.Background()
	// Store without any history extension.
	s := New("tok")
	s.DB = fcPlainStore{newDBFakeStore()}
	s.rebuildTestHistoryDB(ctx)

	// Incremental store: repository enumeration failure.
	f0 := newDBFakeStore()
	s0 := New("tok")
	if err := s0.SwitchToDB(f0); err != nil {
		t.Fatal(err)
	}
	s0.DB = &fcStore{dbFakeStore: f0, listHistoryRepoIDsErr: errors.New("repos down")}
	s0.rebuildTestHistoryDB(ctx)

	// Incremental store: per-repository repair failure is logged, not fatal.
	s1 := New("tok")
	f1 := newDBFakeStore()
	if err := s1.SwitchToDB(f1); err != nil {
		t.Fatal(err)
	}
	f1.mu.Lock()
	f1.runs["run-c"] = model.Run{ID: "run-c", RepoID: "github.com/o/repo-a", RepoFullName: "o/repo-a"}
	f1.reports = []model.TestReport{{ID: "r1", RunID: "run-c", JobKey: "build", CreatedAt: time.Now().UTC(), Cases: []model.TestResult{{Name: "t", Passed: true}}}}
	f1.mu.Unlock()
	s1.DB = &fcStore{dbFakeStore: f1, rebuildRepoHistoryErr: errors.New("rebuild down")}
	s1.rebuildTestHistoryDB(ctx)

	// Incremental store success: the repository aggregates are repaired from
	// the durable reports and the version advances.
	f2 := newDBFakeStore()
	s2 := New("tok")
	if err := s2.SwitchToDB(f2); err != nil {
		t.Fatal(err)
	}
	f2.mu.Lock()
	f2.runs["run-c"] = model.Run{ID: "run-c", RepoID: "github.com/o/repo-a", RepoFullName: "o/repo-a"}
	f2.reports = []model.TestReport{
		{ID: "r1", RunID: "run-c", JobKey: "build", Tests: 1, Failures: 1, CreatedAt: time.Now().UTC(), Cases: []model.TestResult{{Name: "t", Passed: false}}},
		{ID: "r2", RunID: "run-c", JobKey: "build", Tests: 1, CreatedAt: time.Now().UTC(), Cases: []model.TestResult{{Name: "t", Passed: true}}},
	}
	f2.mu.Unlock()
	s2.rebuildTestHistoryDB(ctx)
	f2.mu.Lock()
	version := f2.historyVersions["github.com/o/repo-a"]
	f2.mu.Unlock()
	if version == 0 {
		t.Fatal("repair did not bump the repository history version")
	}
	if got := s2.flakyFromHistory("github.com/o/repo-a"); len(got) != 0 {
		t.Fatalf("in-memory history must only reload on the next sync: %v", got)
	}

	// Legacy store: report listing failure, save failure, success (with a
	// missing run exercising the identity fallback) and serialization failure.
	f3 := newDBFakeStore()
	s3 := New("tok")
	s3.DB = &legacyHistoryStore{Store: &fcStore{dbFakeStore: f3, listReportsAllErr: errors.New("reports down")}}
	s3.rebuildTestHistoryDB(ctx)

	f4 := newDBFakeStore()
	s4 := New("tok")
	s4.DB = &legacyHistoryStore{Store: f4, saveErr: errors.New("history save down")}
	f4.mu.Lock()
	f4.reports = []model.TestReport{{ID: "r1", RunID: "run-c", JobKey: "build", CreatedAt: time.Now().UTC(), Cases: []model.TestResult{{Name: "t", Passed: true}}}}
	f4.mu.Unlock()
	s4.rebuildTestHistoryDB(ctx)

	legacy := &legacyHistoryStore{Store: f4}
	s5 := New("tok")
	s5.DB = legacy
	f4.mu.Lock()
	f4.reports = []model.TestReport{
		{ID: "r1", RunID: "run-missing", JobKey: "build", CreatedAt: time.Now().UTC(), Cases: []model.TestResult{{Name: "t", Passed: false}}},
		{ID: "r2", RunID: "run-missing", JobKey: "build", CreatedAt: time.Now().UTC(), Cases: []model.TestResult{{Name: "t", Passed: true}}},
	}
	f4.mu.Unlock()
	s5.rebuildTestHistoryDB(ctx)
	if legacy.version == 0 {
		t.Fatal("legacy rebuild did not bump the cache version")
	}

	legacyTmp := &legacyHistoryStore{Store: f4}
	s6 := New("tok")
	s6.DB = legacyTmp
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	s6.rebuildTestHistoryDB(ctx)
}

func TestFlowTestintelSyncHistoryDB(t *testing.T) {
	ctx := context.Background()
	// Neither history extension: no-op.
	s := New("tok")
	s.DB = fcPlainStore{newDBFakeStore()}
	s.syncTestHistoryDB(ctx, "github.com/o/repo-a")

	// Aggregate load failure keeps the current history.
	f := newDBFakeStore()
	s2 := New("tok")
	if err := s2.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s2.DB = &fcStore{dbFakeStore: f, loadRepoHistoryErr: errors.New("history load down")}
	s2.syncTestHistoryDB(ctx, "github.com/o/repo-a")

	// Empty repository: the observation is recorded without replacing the
	// in-memory history.
	f.mu.Lock()
	f.historyVersions["github.com/o/repo-a"] = 9
	f.mu.Unlock()
	s2.DB = f
	s2.syncTestHistoryDB(ctx, "github.com/o/repo-a")
	if s2.historyDBVersion != 9 || s2.historyDBRepo != "github.com/o/repo-a" {
		t.Fatalf("empty stats observation = %d/%q, want 9/github.com/o/repo-a", s2.historyDBVersion, s2.historyDBRepo)
	}

	// Corrupt stats for a NEWER version: decode error keeps the current
	// history (and the recorded version).
	s2.DB = corruptRepoHistoryStore{dbFakeStore: f, stats: []byte("{")}
	before := s2.history.h
	s2.syncTestHistoryDB(ctx, "github.com/o/repo-a")
	if s2.history.h != before || s2.historyDBVersion != 9 {
		t.Fatal("corrupt stats must not replace the history")
	}

	// Valid stats from a real commit: the history is replaced and a flaky
	// test is visible.
	if _, err := f.InsertTestReportWithHistory(ctx, model.TestReport{
		ID: "rep-1", RunID: "run-c", JobKey: "build", CreatedAt: time.Now().UTC(),
		Cases: []model.TestResult{{Class: "C", Name: "flaky", Passed: false}},
	}, "github.com/o/repo-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.InsertTestReportWithHistory(ctx, model.TestReport{
		ID: "rep-2", RunID: "run-c", JobKey: "build", CreatedAt: time.Now().UTC(),
		Cases: []model.TestResult{{Class: "C", Name: "flaky", Passed: true}},
	}, "github.com/o/repo-a"); err != nil {
		t.Fatal(err)
	}
	s2.DB = f
	s2.syncTestHistoryDB(ctx, "github.com/o/repo-a")
	if s2.historyDBVersion != 11 {
		t.Fatalf("valid stats version = %d, want 11", s2.historyDBVersion)
	}
	if got := s2.flakyFromHistory("github.com/o/repo-a"); len(got) != 1 || got[0] != "C.flaky" {
		t.Fatalf("flaky after sync = %v, want [C.flaky]", got)
	}

	// Legacy fallback store: load failure, older version no-op, empty stats
	// and corrupt stats keep the history, valid stats replace it.
	legacy := &legacyHistoryStore{Store: f, version: 7, stats: []byte("{")}
	s3 := New("tok")
	s3.DB = legacy
	s3.historyDBVersion = 5
	s3.syncTestHistoryDB(ctx, "github.com/o/repo-a")
	legacyBefore := s3.history.h
	if s3.historyDBVersion != 5 {
		t.Fatalf("corrupt legacy stats version = %d, want 5", s3.historyDBVersion)
	}
	legacy.version = 3
	s3.syncTestHistoryDB(ctx, "github.com/o/repo-a")
	if s3.history.h != legacyBefore || s3.historyDBVersion != 5 {
		t.Fatal("older legacy version must be ignored")
	}
	stats, err := historyStats(legacyBefore)
	if err != nil {
		t.Fatal(err)
	}
	legacy.version = 8
	legacy.stats = stats
	s3.syncTestHistoryDB(ctx, "github.com/o/repo-a")
	if s3.historyDBVersion != 8 {
		t.Fatalf("valid legacy stats version = %d, want 8", s3.historyDBVersion)
	}
	legacy.stats = nil
	legacy.version = 10
	s3.syncTestHistoryDB(ctx, "github.com/o/repo-a")
	if s3.historyDBVersion != 10 {
		t.Fatalf("empty legacy stats version = %d, want 10", s3.historyDBVersion)
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
	s2.DB = &fcStore{dbFakeStore: f, insertReportHistErr: errors.New("report insert down")}
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

	// DB: repository resolution failure (the scoped read never lists every
	// report, so the injected failure is on the set-based identity query).
	s2, f, _, _ := cacheFixture(t)
	s2.DB = &fcStore{dbFakeStore: f, resolveRepoIDsErr: errors.New("repos down")}
	if w := doJSON(t, s2, http.MethodGet, "/api/v1/test-intelligence?repo=o/repo-a", "admin-tok", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("db intelligence resolve failure = %d, want 500", w.Code)
	}
	// Totals and flaky failures surface as 500 too.
	s2.DB = &fcStore{dbFakeStore: f, reportTotalsErr: errors.New("totals down")}
	if w := doJSON(t, s2, http.MethodGet, "/api/v1/test-intelligence?repo=o/repo-a", "admin-tok", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("db intelligence totals failure = %d, want 500", w.Code)
	}
	s2.DB = &fcStore{dbFakeStore: f, flakyNamesErr: errors.New("flaky down")}
	if w := doJSON(t, s2, http.MethodGet, "/api/v1/test-intelligence?repo=o/repo-a", "admin-tok", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("db intelligence flaky failure = %d, want 500", w.Code)
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
