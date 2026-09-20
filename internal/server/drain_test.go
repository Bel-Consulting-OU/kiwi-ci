package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestDrainBlocksLeasesAndReadiness(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d", w.Code)
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	s.BeginDrain("maintenance")
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("next while draining = %d, want 503", w.Code)
	}
	if w.Header().Get("X-Kiwi-Draining") != "true" {
		t.Fatalf("next draining header = %q", w.Header().Get("X-Kiwi-Draining"))
	}
	if w = doJSON(t, s, http.MethodGet, "/readiness", "", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness while draining = %d, want 503", w.Code)
	}
	if w.Header().Get("X-Kiwi-Draining") != "true" {
		t.Fatalf("readiness draining header = %q", w.Header().Get("X-Kiwi-Draining"))
	}
	if w = doJSON(t, s, http.MethodGet, "/liveness", "", ""); w.Code != http.StatusOK {
		t.Fatalf("liveness while draining = %d, want 200", w.Code)
	}
}

func TestDrainKeepsHeartbeatAndComplete(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, smokePipeline)
	s.BeginDrain("maintenance")
	hb := fmt.Sprintf(`{"runner_id":%q,"lease_token":%q,"lease_generation":%d}`, runnerID, task.LeaseToken, task.LeaseGeneration)
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/heartbeat", "token", hb); w.Code != http.StatusOK {
		t.Fatalf("heartbeat while draining = %d: %s", w.Code, w.Body.String())
	}
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete while draining = %d: %s", w.Code, w.Body.String())
	}
	if got := s.ActiveJobs(); got != 0 {
		t.Fatalf("ActiveJobs after drain completion = %d, want 0", got)
	}
}

func TestDrainActiveJobsCount(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := s.ActiveJobs(); got != 0 {
		t.Fatalf("ActiveJobs on empty server = %d", got)
	}
	runnerID, task := leaseArtifactJob(t, s, smokePipeline)
	if got := s.ActiveJobs(); got != 1 {
		t.Fatalf("ActiveJobs with one leased job = %d, want 1", got)
	}
	s.BeginDrain("maintenance")
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	if got := s.ActiveJobs(); got != 0 {
		t.Fatalf("ActiveJobs after completion = %d, want 0", got)
	}
}

func TestDrainFlagPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s.BeginDrain("operator maintenance")
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.isDraining() {
		t.Fatal("restarted server must stay draining")
	}
	if s2.drainReasonOf() != "operator maintenance" {
		t.Fatalf("restarted drain reason = %q", s2.drainReasonOf())
	}
	if w := doJSON(t, s2, http.MethodGet, "/readiness", "", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("restarted readiness = %d, want 503", w.Code)
	}
}

func TestDrainEndpoints(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodGet, "/api/v1/drain", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET drain = %d", w.Code)
	}
	var st drainStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Draining {
		t.Fatal("fresh server must not be draining")
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/drain", "token", `{"reason":"rolling update"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("POST drain = %d: %s", w.Code, w.Body.String())
	}
	w = doJSON(t, s, http.MethodGet, "/api/v1/drain", "token", "")
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Draining || st.Reason != "rolling update" {
		t.Fatalf("drain status = %+v", st)
	}
	// The drain endpoint is admin tier: a bare request is rejected when a
	// token is configured.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/drain", "", `{"reason":"x"}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated drain = %d, want 401", w.Code)
	}
}

func TestDrainBlocksLeasesDBMode(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d", w.Code)
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	s.BeginDrain("db drain")
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("db next while draining = %d, want 503", w.Code)
	}
	if w.Header().Get("X-Kiwi-Draining") != "true" {
		t.Fatalf("db next draining header = %q", w.Header().Get("X-Kiwi-Draining"))
	}
}

// waitDrainedForTest mirrors internal/app.waitForDrain: poll ActiveJobs()
// until zero or the timeout elapses. The server package cannot import
// internal/app (cycle), so this keeps the same contract honest against a
// small, test-only timeout.
func waitDrainedForTest(s *Server, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if s.ActiveJobs() == 0 {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestDrainDBUnknownRunningCountKeepsWaiting is the S1B regression: an
// errored CountRunningJobs is UNKNOWN, never zero. The drain wait keeps
// polling (bounded by its timeout, so shutdown cannot hang) and only
// completes once the store proves zero.
func TestDrainDBUnknownRunningCountKeepsWaiting(t *testing.T) {
	s := New("secret")
	f := newDBFakeStore()
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.InsertRun(ctx, model.Run{ID: "run-1", Status: model.StatusRunning}); err != nil {
		t.Fatal(err)
	}
	if err := f.InsertJob(ctx, model.Job{ID: "job-1", RunID: "run-1", Status: model.StatusRunning}); err != nil {
		t.Fatal(err)
	}
	s.BeginDrain("db drain")
	f.countRunningErr = errors.New("count unavailable")

	start := time.Now()
	if waitDrainedForTest(s, 250*time.Millisecond) {
		t.Fatal("drain reported success while the running count was unknown")
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Fatalf("drain wait returned after %s; want it to keep waiting until the timeout", elapsed)
	}
	if got := s.ActiveJobs(); got == 0 {
		t.Fatal("ActiveJobs must never be zero while the store count is unknown")
	}
	// Even completing the only job cannot prove a drain while the count is
	// unknown: the aggregate is the proof, not the job rows we can see.
	f.mu.Lock()
	j := f.jobs["job-1"]
	j.Status = model.StatusSuccess
	f.jobs["job-1"] = j
	f.mu.Unlock()
	if waitDrainedForTest(s, 250*time.Millisecond) {
		t.Fatal("drain reported success from an unknown count after the job completed")
	}
	// Recovery: a readable zero completes the bounded wait.
	f.countRunningErr = nil
	if !waitDrainedForTest(s, 2*time.Second) {
		t.Fatal("drain did not complete after the store count recovered")
	}
	if n, known := s.activeJobCount(); n != 0 || !known {
		t.Fatalf("activeJobCount after recovery = %d,%v; want 0,true", n, known)
	}
}

// TestDrainDBAggregateCountIndependentOfRunScans proves the DB drain count
// no longer walks ListRuns (previously capped at 10000) or ListJobsByRun
// (previously skipped on error): with many runs and both list paths broken,
// the aggregate still reports the running job.
func TestDrainDBAggregateCountIndependentOfRunScans(t *testing.T) {
	s := New("secret")
	f := newDBFakeStore()
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < 150; i++ {
		status := model.StatusSuccess
		if i == 0 {
			status = model.StatusRunning
		}
		if err := f.InsertRun(ctx, model.Run{ID: fmt.Sprintf("run-%03d", i), Status: status, CreatedAt: time.Unix(int64(i), 0).UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.InsertJob(ctx, model.Job{ID: "job-1", RunID: "run-000", Status: model.StatusRunning}); err != nil {
		t.Fatal(err)
	}
	f.listRunsErr = errors.New("runs read down")
	f.listJobsByRunErr = errors.New("jobs read down")
	if got := s.ActiveJobs(); got != 1 {
		t.Fatalf("ActiveJobs with broken run/job lists = %d; want 1 from the aggregate", got)
	}
	if n, known := s.activeJobCount(); !known || n != 1 {
		t.Fatalf("activeJobCount = %d,%v; want 1,true", n, known)
	}
}

// TestDrainStatusReportsActiveJobsKnown pins the ActiveJobsKnown field of the
// drain-status response for BOTH values: false while the store cannot produce
// the in-flight count (ActiveJobs is then the fail-closed unknownActiveJobs
// value, never zero, so the drain keeps waiting), and true with the
// authoritative count once the store recovers.
func TestDrainStatusReportsActiveJobsKnown(t *testing.T) {
	s := New("secret")
	f := newDBFakeStore()
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := f.InsertRun(ctx, model.Run{ID: "run-1", Status: model.StatusRunning}); err != nil {
		t.Fatal(err)
	}
	if err := f.InsertJob(ctx, model.Job{ID: "job-1", RunID: "run-1", Status: model.StatusRunning}); err != nil {
		t.Fatal(err)
	}
	s.BeginDrain("db drain")
	f.countRunningErr = errors.New("count unavailable")

	w := doJSON(t, s, http.MethodGet, "/api/v1/drain", "secret", "")
	if w.Code != http.StatusOK {
		t.Fatalf("drain status with an unavailable count = %d: %s", w.Code, w.Body.String())
	}
	var st drainStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.ActiveJobsKnown {
		t.Fatalf("ActiveJobsKnown with an unavailable store count = true; status = %+v", st)
	}
	if st.ActiveJobs != unknownActiveJobs || st.ActiveJobs == 0 {
		t.Fatalf("ActiveJobs with an unavailable count = %d; want the fail-closed %d", st.ActiveJobs, unknownActiveJobs)
	}
	if !st.Draining {
		t.Fatalf("drain status while the count is unavailable must report draining: %+v", st)
	}

	// Recovery: an authoritative aggregate count is reported with known=true.
	f.countRunningErr = nil
	w = doJSON(t, s, http.MethodGet, "/api/v1/drain", "secret", "")
	if w.Code != http.StatusOK {
		t.Fatalf("drain status after recovery = %d: %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.ActiveJobsKnown || st.ActiveJobs != 1 {
		t.Fatalf("ActiveJobsKnown/ActiveJobs after recovery = %v/%d; want true/1", st.ActiveJobsKnown, st.ActiveJobs)
	}
}

// TestDrainMemoryModeCountKnown pins the memory-mode behavior: the
// in-memory maps are authoritative, so the count is always known and never
// consults the store.
func TestDrainMemoryModeCountKnown(t *testing.T) {
	s := New("secret")
	s.mu.Lock()
	s.jobs["mem-1"] = model.Job{ID: "mem-1", Status: model.StatusRunning}
	s.mu.Unlock()
	if got := s.ActiveJobs(); got != 1 {
		t.Fatalf("memory ActiveJobs = %d; want 1", got)
	}
	if n, known := s.activeJobCount(); n != 1 || !known {
		t.Fatalf("memory activeJobCount = %d,%v; want 1,true", n, known)
	}
}

// TestDrainPersistFailureFailsClosed is the S1C regression: when
// drain.flag cannot be written the POST /api/v1/drain handler answers 503
// with the degraded-state pattern instead of acknowledging a drain that a
// restart would forget, while the in-memory state still fails closed to
// draining. A retry after the seam clears persists and acknowledges.
func TestDrainPersistFailureFailsClosed(t *testing.T) {
	s := New("secret")
	// A data dir whose parent does not exist makes writeFileAtomic fail, the
	// same failure class as a full or read-only state directory.
	s.dataDir = filepath.Join(t.TempDir(), "missing")
	w := doJSON(t, s, http.MethodPost, "/api/v1/drain", "secret", `{"reason":"rolling update"}`)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("drain with unwritable data dir = %d: %s; want 503", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Kiwi-State") != "degraded" {
		t.Fatalf("drain persist failure state header = %q; want degraded", w.Header().Get("X-Kiwi-State"))
	}
	if !strings.Contains(w.Body.String(), statePersistenceDegradedBody) {
		t.Fatalf("drain persist failure body = %q; want %q", w.Body.String(), statePersistenceDegradedBody)
	}
	// Fail closed to DRAINING, not to serving, and never claim the flag was
	// written.
	if !s.isDraining() {
		t.Fatal("in-memory drain state must stay set after a persistence failure")
	}
	if w := doJSON(t, s, http.MethodGet, "/readiness", "", ""); w.Code != http.StatusServiceUnavailable || w.Header().Get("X-Kiwi-Draining") != "true" {
		t.Fatalf("readiness after failed persist = %d header=%q; want 503 draining", w.Code, w.Header().Get("X-Kiwi-Draining"))
	}
	if b, err := readFileIfExists(s.dataDir, drainFlagFile); err == nil && len(b) > 0 {
		t.Fatalf("drain flag exists despite the reported failure: %q", b)
	}

	// Retry after the seam clears: the endpoint persists and acknowledges,
	// and the flag survives a restart.
	if err := os.MkdirAll(s.dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/drain", "secret", `{"reason":"rolling update"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("drain retry after recovery = %d: %s; want 200", w.Code, w.Body.String())
	}
	restarted, err := NewPersistent("secret", "secret", s.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if !restarted.isDraining() || restarted.drainReasonOf() != "rolling update" {
		t.Fatalf("restarted drain state = %v %q; want draining with the retried reason",
			restarted.isDraining(), restarted.drainReasonOf())
	}
}
