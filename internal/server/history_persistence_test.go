package server

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

func TestHistoryPersistenceAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	rep := model.TestReport{
		JobKey:    "tests",
		CreatedAt: time.Now().UTC(),
		Cases: []model.TestResult{
			{Name: "TestA", Passed: true, Duration: 1.0},
			{Name: "TestA", Passed: false, Duration: 1.5},
			{Name: "TestB", Passed: true, Duration: 0.5},
		},
	}
	s.recordTestReportHistory("o/r", rep)
	if _, err := os.Stat(filepath.Join(dir, testHistoryFile)); err != nil {
		t.Fatalf("history file not persisted: %v", err)
	}
	flaky := s.flakyFromHistory("o/r")
	if len(flaky) != 1 || flaky[0] != "TestA" {
		t.Fatalf("flaky = %v, want [TestA]", flaky)
	}

	// A restarted control plane reloads the history from disk.
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	flaky2 := s2.flakyFromHistory("o/r")
	if len(flaky2) != 1 || flaky2[0] != "TestA" {
		t.Fatalf("flaky after restart = %v, want [TestA]", flaky2)
	}
	manifest := s2.history.h.Manifest("o/r", "tests")
	if len(manifest) != 2 {
		t.Fatalf("manifest after restart = %v", manifest)
	}
}

func TestTestShardsEndpointDeterministic(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	// Record history for repo o/r, suite build (the leased job's key).
	rep := model.TestReport{
		JobKey:    "build",
		CreatedAt: time.Now().UTC(),
		Cases: []model.TestResult{
			{Name: "SlowA", Passed: true, Duration: 10},
			{Name: "QuickB", Passed: true, Duration: 1},
			{Name: "QuickC", Passed: true, Duration: 2},
		},
	}
	s.recordTestReportHistory("o/r", rep)

	runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
	hdrs := leaseHeaders(task, runnerID)
	path := "/api/v1/jobs/" + task.Job.ID + "/test-shards?shards=2"

	fetch := func() map[string]any {
		t.Helper()
		w := doJSONHeaders(t, s, http.MethodGet, path, "token", "", hdrs)
		if w.Code != http.StatusOK {
			t.Fatalf("test-shards = %d: %s", w.Code, w.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	out := fetch()
	if out["shards"].(float64) != 2 {
		t.Fatalf("shards = %v", out["shards"])
	}
	assignment, ok := out["assignment"].([]any)
	if !ok || len(assignment) != 2 {
		t.Fatalf("assignment = %v", out["assignment"])
	}
	envContract, ok := out["env_contract"].(map[string]any)
	if !ok || envContract["KIWI_TEST_SHARD_TOTAL"] != "2" {
		t.Fatalf("env contract = %v", out["env_contract"])
	}
	// Deterministic: a second fetch returns the same assignment.
	out2 := fetch()
	b1, _ := json.Marshal(out["assignment"])
	b2, _ := json.Marshal(out2["assignment"])
	if string(b1) != string(b2) {
		t.Fatalf("shard assignment not deterministic: %s vs %s", b1, b2)
	}
	// The single-shard view narrows to the selected list.
	w := doJSONHeaders(t, s, http.MethodGet, path+"&shard=0", "token", "", hdrs)
	if w.Code != http.StatusOK {
		t.Fatalf("shard view = %d: %s", w.Code, w.Body.String())
	}
	var narrow map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &narrow); err != nil {
		t.Fatal(err)
	}
	if narrow["shard"].(float64) != 0 {
		t.Fatalf("shard index = %v", narrow["shard"])
	}
	if _, ok := narrow["tests"]; !ok {
		t.Fatal("narrowed view missing tests")
	}
}

func TestTestShardsCoversManifest(t *testing.T) {
	h := testintel.NewHistory()
	now := time.Now().UTC()
	h.Record("o/r", "build", "", "A", 100, true, now)
	h.Record("o/r", "build", "", "B", 1, true, now)
	h.Record("o/r", "build", "", "C", 1, true, now)
	shards := h.Shard("o/r", "build", 2)
	seen := map[string]int{}
	for _, shard := range shards {
		for _, name := range shard {
			seen[name]++
		}
	}
	for _, name := range []string{"A", "B", "C"} {
		if seen[name] != 1 {
			t.Fatalf("test %q appears %d times across shards", name, seen[name])
		}
	}
	// Deterministic: repeated calls produce identical assignments.
	again := h.Shard("o/r", "build", 2)
	a1, _ := json.Marshal(shards)
	a2, _ := json.Marshal(again)
	if string(a1) != string(a2) {
		t.Fatalf("shards not deterministic: %s vs %s", a1, a2)
	}
}

func TestTestShardsRequiresActiveLease(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, task := leaseArtifactJob(t, s, artifactsPipeline)
	hdrs := leaseHeaders(task, "ghost-runner")
	hdrs["X-Kiwi-Lease-Token"] = "wrong-token"
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/"+task.Job.ID+"/test-shards", "token", "", hdrs)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale lease on test-shards = %d, want 409", w.Code)
	}
}
