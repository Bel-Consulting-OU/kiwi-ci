package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func seedMemoryRun(t *testing.T, s *Server, repo string, cases ...model.TestResult) (runID, reportID string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	runID = "run-" + repo
	s.runs[runID] = model.Run{ID: runID, RepoFullName: repo, Status: model.StatusSuccess, CreatedAt: time.Now().UTC()}
	reportID = "rep-" + repo
	s.reports[reportID] = model.TestReport{ID: reportID, RunID: runID, Tests: len(cases), Cases: cases, CreatedAt: time.Now().UTC()}
	return runID, reportID
}

func TestTestIntelligenceRequiresRepo(t *testing.T) {
	s := New("token")
	w := doJSON(t, s, http.MethodGet, "/api/v1/test-intelligence", "token", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 without repo, got %d", w.Code)
	}
	f := newDBFakeStore()
	sdb := New("token")
	if err := sdb.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, sdb, http.MethodGet, "/api/v1/test-intelligence", "token", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("db: want 400 without repo, got %d", w.Code)
	}
}

func TestTestIntelligenceRepoScoping(t *testing.T) {
	s := New("token")
	seedMemoryRun(t, s, "org/alpha", model.TestResult{Name: "a", Passed: true}, model.TestResult{Name: "a", Passed: false})
	seedMemoryRun(t, s, "org/beta", model.TestResult{Name: "b", Passed: false})

	w := doJSON(t, s, http.MethodGet, "/api/v1/test-intelligence?repo=org/alpha", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("alpha: %d %s", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["reports"].(float64) != 1 || out["total_tests"].(float64) != 2 {
		t.Fatalf("alpha scope: %v", out)
	}
	flaky, _ := out["flaky_tests"].([]any)
	if len(flaky) != 1 || flaky[0] != "a" {
		t.Fatalf("alpha flaky: %v", flaky)
	}

	w = doJSON(t, s, http.MethodGet, "/api/v1/test-intelligence?repo=org/beta", "token", "")
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["reports"].(float64) != 1 || out["total_tests"].(float64) != 1 {
		t.Fatalf("beta scope: %v", out)
	}
	flaky, _ = out["flaky_tests"].([]any)
	if len(flaky) != 0 {
		t.Fatalf("beta flaky: %v", flaky)
	}

	w = doJSON(t, s, http.MethodGet, "/api/v1/test-intelligence?repo=org/gamma", "token", "")
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["reports"].(float64) != 0 {
		t.Fatalf("gamma scope: %v", out)
	}
	if out["repo"] != "org/gamma" {
		t.Fatalf("repo echo: %v", out)
	}
}

func TestTestIntelligenceRepoScopingDB(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.runs["r1"] = model.Run{ID: "r1", RepoFullName: "org/alpha", Status: model.StatusSuccess}
	f.runs["r2"] = model.Run{ID: "r2", RepoFullName: "org/beta", Status: model.StatusSuccess}
	f.reports = []model.TestReport{
		{ID: "t1", RunID: "r1", Tests: 1, Cases: []model.TestResult{{Name: "x", Passed: true}}},
		{ID: "t2", RunID: "r2", Tests: 1, Cases: []model.TestResult{{Name: "y", Passed: false}}},
	}
	f.mu.Unlock()

	w := doJSON(t, s, http.MethodGet, "/api/v1/test-intelligence?repo=org/alpha", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("db alpha: %d %s", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["reports"].(float64) != 1 || out["total_tests"].(float64) != 1 {
		t.Fatalf("db alpha scope: %v", out)
	}
}

func TestGCExpiredArtifactsAndTempFiles(t *testing.T) {
	root := t.TempDir()
	s := New("token")
	s.store = storage.New(root)
	expired := time.Now().UTC().Add(-time.Hour)
	kept := time.Now().UTC().Add(time.Hour)
	s.mu.Lock()
	s.artifacts["a1"] = model.ArtifactRecord{ID: "a1", RunID: "r", ExpiresAt: &expired, Path: filepath.Join(root, "artifacts", "r", "j", "a1.tar.gz")}
	s.artifacts["a2"] = model.ArtifactRecord{ID: "a2", RunID: "r", ExpiresAt: &kept, Path: filepath.Join(root, "artifacts", "r", "j", "a2.tar.gz")}
	s.runs["r"] = model.Run{ID: "r", CreatedAt: time.Now().UTC().Add(-48 * time.Hour)}
	s.deliveries["stale-delivery"] = "r"
	s.mu.Unlock()

	// Artifact files on disk.
	for _, id := range []string{"a1", "a2"} {
		dir := filepath.Join(root, "artifacts", "r", "j")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, id+".tar.gz"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Orphaned temp files: one old (removed), one fresh (kept).
	oldTmp := filepath.Join(root, "cache", "old.tmp")
	if err := os.MkdirAll(filepath.Dir(oldTmp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldTmp, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(oldTmp, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	freshTmp := filepath.Join(root, "artifacts", "r", "j", ".upload.tmp")
	if err := os.WriteFile(freshTmp, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	stats := s.GC(context.Background(), time.Now().UTC())
	if stats.ArtifactsRemoved != 1 {
		t.Fatalf("artifacts removed: %+v", stats)
	}
	if stats.TempFilesRemoved < 1 {
		t.Fatalf("temp files removed: %+v", stats)
	}
	if _, err := os.Stat(oldTmp); !os.IsNotExist(err) {
		t.Fatalf("old tmp should be gone: %v", err)
	}
	if _, err := os.Stat(freshTmp); err != nil {
		t.Fatalf("fresh tmp should survive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "artifacts", "r", "j", "a2.tar.gz")); err != nil {
		t.Fatalf("unexpired artifact should survive: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.artifacts["a1"]; ok {
		t.Fatal("expired artifact record not removed")
	}
	if _, ok := s.artifacts["a2"]; !ok {
		t.Fatal("unexpired artifact record removed")
	}
	if _, ok := s.deliveries["stale-delivery"]; ok {
		t.Fatal("stale delivery not pruned")
	}
}

func TestGCWithoutStoreIsSafe(t *testing.T) {
	s := New("token")
	stats := s.GC(context.Background(), time.Now().UTC())
	if stats.ArtifactsRemoved != 0 || stats.TempFilesRemoved != 0 {
		t.Fatalf("stats: %+v", stats)
	}
}

const queuePipeline = `version: 1
jobs:
  first:
    runtime: container
    steps:
      - run: echo first
  second:
    runtime: container
    needs:
      - first
    steps:
      - run: echo second
  third:
    runtime: container
    runner:
      - gigantic
    steps:
      - run: echo third
`

func registerMemoryRunner(t *testing.T, s *Server) string {
	t.Helper()
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container","native"],"capacity":2}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var r model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r.ID
}

func TestNextSetsQueueReasons(t *testing.T) {
	s := New("token")
	runnerID := registerMemoryRunner(t, s)
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", `{"repo_url":"https://example.com/o/r.git","repo_full_name":"o/r","ref":"refs/heads/main","sha":"abc","event":"push","pipeline":`+jsonString(queuePipeline)+`}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	// The runner (labels: native) can lease "first"; "second" waits on its
	// dependency and "third" needs the "gigantic" label.
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next: %d %s", w.Code, w.Body.String())
	}
	// A second next() finds no candidates and annotates the queue.
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("next: %d %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reasons := map[string]string{}
	for _, j := range s.jobs {
		reasons[j.Key] = j.QueueReason
	}
	if reasons["second"] != "WAITING_DEPENDENCY" {
		t.Fatalf("second reason: %q", reasons["second"])
	}
	if reasons["third"] != "NO_COMPATIBLE_RUNNER" {
		t.Fatalf("third reason: %q", reasons["third"])
	}
	if reasons["first"] != "" {
		t.Fatalf("first reason should be cleared: %q", reasons["first"])
	}
}

func TestNextSetsWaitingApprovalReason(t *testing.T) {
	s := New("token")
	runnerID := registerMemoryRunner(t, s)
	now := time.Now().UTC()
	s.mu.Lock()
	s.runs["r"] = model.Run{ID: "r", Status: model.StatusQueued, CreatedAt: now}
	s.jobs["deploy"] = model.Job{ID: "deploy", RunID: "r", Key: "deploy", Status: model.StatusWaitingApproval, ApprovalRequired: true, CreatedAt: now}
	s.mu.Unlock()
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("next: %d %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if j.QueueReason != "WAITING_APPROVAL" {
			t.Fatalf("deploy reason: %q (status %s)", j.QueueReason, j.Status)
		}
	}
}

func TestMetricsIncludeQueueReasons(t *testing.T) {
	s := New("token")
	s.mu.Lock()
	s.jobs["j1"] = model.Job{ID: "j1", Status: model.StatusQueued, QueueReason: "WAITING_DEPENDENCY"}
	s.mu.Unlock()
	w := doJSON(t, s, http.MethodGet, "/metrics", "token", "")
	body := w.Body.String()
	if !strings.Contains(body, "kiwi_jobs_queue_reason{reason=\"WAITING_DEPENDENCY\"} 1") {
		t.Fatalf("metrics missing queue reason: %s", body)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
