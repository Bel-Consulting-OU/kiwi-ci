package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// uploadReportBody renders the POST /tests body for a leased job.
func uploadReportBody(task Task, runnerID string, cases []map[string]any) string {
	rep := map[string]any{
		"id": "", "tests": len(cases), "failures": 0, "cases": cases,
	}
	b, _ := json.Marshal(map[string]any{
		"runner_id": runnerID, "lease_token": task.LeaseToken, "lease_generation": task.LeaseGeneration,
		"report": rep,
	})
	return string(b)
}

// TestTestHistoryDBReplicasShareShardDecisions proves the SQL-backed test
// history converges replicas: one replica uploads a report, the other
// derives the SAME shard assignment from the durable cache.
func TestTestHistoryDBReplicasShareShardDecisions(t *testing.T) {
	f := newDBFakeStore()
	s1, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: smokePipeline, Trusted: true,
	}); err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseRunJob(t, s1)
	cases := []map[string]any{
		{"name": "alpha", "duration": 30.0, "passed": true},
		{"name": "beta", "duration": 10.0, "passed": false},
		{"name": "gamma", "duration": 20.0, "passed": true},
	}
	body := uploadReportBody(task, runnerID, cases)
	if w := doJSON(t, s1, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/tests", "token", body); w.Code != http.StatusCreated {
		t.Fatalf("upload report = %d: %s", w.Code, w.Body.String())
	}
	// The upload bumped the durable cache version.
	f.mu.Lock()
	version := f.testHistoryVersion
	f.mu.Unlock()
	if version != 1 {
		t.Fatalf("test history cache version = %d, want 1", version)
	}

	// A second replica on the same store (same dataDir, so it shares the
	// lease verification key) derives the identical assignment.
	s2, err := NewPersistent("token", "token", s1.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	get := func(s *Server) map[string]any {
		t.Helper()
		w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/"+task.Job.ID+"/test-shards?shards=2", "token", "", leaseHeaders(task, runnerID))
		if w.Code != http.StatusOK {
			t.Fatalf("test-shards = %d: %s", w.Code, w.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	first := get(s1)
	second := get(s2)
	a1, _ := json.Marshal(first["assignment"])
	a2, _ := json.Marshal(second["assignment"])
	if string(a1) != string(a2) {
		t.Fatalf("replicas disagree: %s vs %s", a1, a2)
	}
	// The assignment is history-derived, not empty: the suite knows the
	// uploaded tests.
	var shards [][]string
	if err := json.Unmarshal(a1, &shards); err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, shard := range shards {
		total += len(shard)
	}
	if total != 3 {
		t.Fatalf("shard assignment covers %d tests, want 3", total)
	}
	// Both replicas report the same flaky set.
	f1, _ := json.Marshal(first["flaky_tests"])
	f2, _ := json.Marshal(second["flaky_tests"])
	if string(f1) != string(f2) {
		t.Fatalf("replicas disagree on flaky set: %s vs %s", f1, f2)
	}
}

// TestTestHistoryUpdateFailureFailsUploadClosed is the ADAPTED former
// TestTestHistoryUpdateFailureKeepsReport (S6-A behavior change, documented).
//
// Before the fix the history cache write was best-effort: a failing
// SaveTestHistory still acknowledged the upload and kept the durable report,
// and the whole aggregation was silently rebuilt from every report on the
// next upload (the quadratic defect). The fix commits the report and its
// per-repository aggregates in ONE transaction, so an aggregate write
// failure must fail the upload closed: 503 with the raw store error hidden,
// NO report and NO history row durable. Healing and retrying stores exactly
// one report and its history.
func TestTestHistoryUpdateFailureFailsUploadClosed(t *testing.T) {
	f := newDBFakeStore()
	f.mu.Lock()
	f.insertReportHistoryErr = fmt.Errorf("history store down")
	f.mu.Unlock()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: smokePipeline, Trusted: true,
	}); err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseRunJob(t, s)
	body := uploadReportBody(task, runnerID, []map[string]any{
		{"name": "solo", "duration": 5.0, "passed": true},
	})
	w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/tests", "token", body)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("upload with failing history = %d, want 500: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "history store down") {
		t.Fatalf("response leaked the raw store error: %q", w.Body.String())
	}
	f.mu.Lock()
	reports, version := len(f.reports), f.historyVersions["github.com/o/r"]
	f.mu.Unlock()
	if reports != 0 || version != 0 {
		t.Fatalf("failed upload persisted reports=%d history_version=%d, want none", reports, version)
	}

	// Heal: the retry stores exactly one report and exactly its history.
	f.mu.Lock()
	f.insertReportHistoryErr = nil
	f.mu.Unlock()
	body2 := uploadReportBody(task, runnerID, []map[string]any{
		{"name": "second", "duration": 8.0, "passed": false},
	})
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/tests", "token", body2); w.Code != http.StatusCreated {
		t.Fatalf("second upload = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	reports, version = len(f.reports), f.historyVersions["github.com/o/r"]
	f.mu.Unlock()
	if reports != 1 || version != 1 {
		t.Fatalf("healed retry = reports %d, version %d; want exactly 1/1", reports, version)
	}
	_, stats, err := f.LoadRepoTestHistory(context.Background(), "github.com/o/r")
	if err != nil {
		t.Fatal(err)
	}
	// The failed upload left no phantom history: only the acknowledged
	// report's case is present.
	if strings.Contains(string(stats), "solo") || !strings.Contains(string(stats), "second") {
		t.Fatalf("history after healed retry = %s", stats)
	}
}
