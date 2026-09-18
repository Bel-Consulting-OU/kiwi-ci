package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const smokePipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo hi
`

func doJSON(t *testing.T, s *Server, method, path, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewBufferString(body))
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestHealthEndpointsMemoryMode(t *testing.T) {
	s := New("token")
	if w := doJSON(t, s, http.MethodGet, "/liveness", "", ""); w.Code != http.StatusOK {
		t.Errorf("liveness = %d, want 200", w.Code)
	}
	if w := doJSON(t, s, http.MethodGet, "/readiness", "", ""); w.Code != http.StatusOK {
		t.Errorf("readiness (memory) = %d, want 200", w.Code)
	}
}

func TestHealthEndpointsDBMode(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatalf("SwitchToDB: %v", err)
	}
	if w := doJSON(t, s, http.MethodGet, "/liveness", "", ""); w.Code != http.StatusOK {
		t.Errorf("liveness = %d, want 200", w.Code)
	}
	if w := doJSON(t, s, http.MethodGet, "/readiness", "", ""); w.Code != http.StatusOK {
		t.Errorf("readiness (live pool) = %d, want 200", w.Code)
	}
	f.mu.Lock()
	f.schemaErr = errors.New("down")
	f.mu.Unlock()
	if w := doJSON(t, s, http.MethodGet, "/readiness", "", ""); w.Code != http.StatusServiceUnavailable {
		t.Errorf("readiness (dead pool) = %d, want 503", w.Code)
	}
	if w := doJSON(t, s, http.MethodGet, "/liveness", "", ""); w.Code != http.StatusOK {
		t.Errorf("liveness (dead pool) = %d, want 200", w.Code)
	}
}

func TestDBModeSmoke(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatalf("SwitchToDB: %v", err)
	}
	if s.Sched == nil || s.DB == nil {
		t.Fatal("DB mode not wired")
	}

	// Submit a run through the HTTP API; the fake store must receive the
	// run and its job.
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token",
		`{"repo_url":"https://example.com/r","ref":"refs/heads/main","sha":"abc","pipeline":`+jsonStr(smokePipeline)+`}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit = %d: %s", w.Code, w.Body.String())
	}
	var run model.Run
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatalf("decode run: %v", err)
	}
	f.mu.Lock()
	inserted := len(f.insertRunCalls)
	compiled := len(f.compiledCalls)
	jobCount := len(f.jobs)
	f.mu.Unlock()
	if inserted != 1 {
		t.Fatalf("run inserts = %d, want 1", inserted)
	}
	if compiled != 1 {
		t.Fatalf("InsertCompiledRun calls = %d, want 1 (atomic enqueue)", compiled)
	}
	if jobCount != 1 {
		t.Fatalf("jobs stored = %d, want 1", jobCount)
	}

	// Register a runner, then lease through next().
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"runner1","labels":["container"],"protocol_min":3,"protocol_max":3}`); w.Code != http.StatusOK {
		t.Fatalf("register = %d: %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runners", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("list runners = %d", w.Code)
	} else if err := json.Unmarshal(w.Body.Bytes(), &[]any{}); err != nil {
		t.Fatalf("decode runners: %v", err)
	}
	_ = ri

	f.mu.Lock()
	runnerID := ""
	for id := range f.runners {
		runnerID = id
	}
	f.mu.Unlock()
	if runnerID == "" {
		t.Fatal("no runner registered in store")
	}

	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next = %d: %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatalf("decode task: %v", err)
	}
	if task.LeaseToken == "" || task.Job.ID == "" || task.LeaseGeneration == 0 {
		t.Fatalf("incomplete task: %+v", task)
	}
	f.mu.Lock()
	acquires := len(f.acquireCalls)
	f.mu.Unlock()
	if acquires != 1 {
		t.Fatalf("AcquireLease calls = %d, want 1", acquires)
	}

	// Heartbeat extends the lease.
	hb := `{"runner_id":` + jsonStr(runnerID) + `,"lease_token":` + jsonStr(task.LeaseToken) + `,"lease_generation":` + itoa(task.LeaseGeneration) + `}`
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/heartbeat", "token", hb); w.Code != http.StatusOK {
		t.Fatalf("heartbeat = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	heartbeats := len(f.heartbeatCalls)
	f.mu.Unlock()
	if heartbeats != 1 {
		t.Fatalf("HeartbeatLease calls = %d, want 1", heartbeats)
	}

	// Log line appends through the store.
	log := `{"runner_id":` + jsonStr(runnerID) + `,"lease_token":` + jsonStr(task.LeaseToken) + `,"lease_generation":` + itoa(task.LeaseGeneration) + `,"job_key":"build","step":"run","line":"hi"}`
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/log", "token", log); w.Code != http.StatusNoContent {
		t.Fatalf("log = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	logLines := len(f.logs)
	f.mu.Unlock()
	if logLines != 1 {
		t.Fatalf("AppendLog calls = %d, want 1", logLines)
	}

	// Completion is idempotent: the same payload twice is acknowledged.
	complete := `{"runner_id":` + jsonStr(runnerID) + `,"lease_token":` + jsonStr(task.LeaseToken) + `,"lease_generation":` + itoa(task.LeaseGeneration) + `,"status":"success","outputs":{"out":"1"}}`
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", complete); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "token", complete); w.Code != http.StatusNoContent {
		t.Fatalf("replayed complete = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	completions := len(f.completeCalls)
	var receipt model.CompletionReceipt
	for _, c := range f.completeCalls {
		receipt = c.Receipt
	}
	job := f.jobs[task.Job.ID]
	f.mu.Unlock()
	if completions != 1 {
		t.Fatalf("CompleteJob calls = %d, want 1 (the replay is acknowledged from the durable receipt without re-delegating)", completions)
	}
	if receipt.JobID != task.Job.ID || receipt.Generation != task.LeaseGeneration || receipt.RunnerID != runnerID || receipt.ResultHash == "" {
		t.Fatalf("receipt = %+v, want canonical fields", receipt)
	}
	if job.Status != model.StatusSuccess {
		t.Errorf("job status = %q, want success", job.Status)
	}
	if job.LeaseRunnerID != "" {
		t.Errorf("lease not cleared after completion: %+v", job)
	}

	// Cancel a second run through the scheduler path.
	w = doJSON(t, s, http.MethodPost, "/api/v1/runs", "token",
		`{"repo_url":"https://example.com/r2","ref":"refs/heads/main","sha":"def","pipeline":`+jsonStr(smokePipeline)+`}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("second submit = %d: %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatalf("decode second run: %v", err)
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs/"+run.ID+"/cancel", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("cancel = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	cancels := len(f.cancelRunCalls)
	auditCount := len(f.audit)
	f.mu.Unlock()
	if cancels != 1 {
		t.Fatalf("CancelRunJobs calls = %d, want 1", cancels)
	}
	if auditCount == 0 {
		t.Fatal("no audit events recorded in DB mode")
	}

	// Reads are served from the store.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("list runs = %d", w.Code)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/audit", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("list audit = %d", w.Code)
	}
}

func TestDBModeStandbyAndPromotion(t *testing.T) {
	f := newDBFakeStore()
	f.setLeader(false)
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatalf("SwitchToDB: %v", err)
	}
	if s.leader {
		t.Fatal("expected standby after SwitchToDB")
	}
	f.mu.Lock()
	f.runners["runner1"] = model.Runner{ID: "runner1", Name: "runner1", Capacity: 1}
	f.mu.Unlock()
	// Standby refuses to lease.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner1/next", "token", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("standby next = %d, want 503", w.Code)
	}
	// Promotion: the claim is won and the next lease proceeds.
	f.setLeader(true)
	f.mu.Lock()
	f.jobs["job1"] = model.Job{ID: "job1", RunID: "run1", Key: "build", Status: model.StatusQueued}
	f.runs["run1"] = model.Run{ID: "run1", Status: model.StatusQueued}
	f.mu.Unlock()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/runner1/next", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("promoted next = %d: %s", w.Code, w.Body.String())
	}
}

func TestDBModeRejectsStaleLease(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatalf("SwitchToDB: %v", err)
	}
	f.mu.Lock()
	f.jobs["job1"] = model.Job{ID: "job1", RunID: "run1", Status: model.StatusRunning, LeaseRunnerID: "runner1", LeaseGeneration: 3}
	f.mu.Unlock()
	// The fake row has no token hash: any presented token fails validation.
	hb := `{"runner_id":"runner1","lease_token":"bogus","lease_generation":3}`
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/job1/heartbeat", "token", hb); w.Code != http.StatusConflict {
		t.Fatalf("stale heartbeat = %d, want 409", w.Code)
	}
}

func jsonStr(v string) string {
	b, _ := json.Marshal(v)
	return string(b)
}

var _ = storage.ErrNotFound

// TestDBFakeLogBatchConflictMatchesDurableStores is FA-5: the DB-mode test
// fake must compare payload digests exactly like Postgres, the memStore and
// the fs journal, or DB-mode server tests cannot catch a handler that ACKs a
// conflicting batch reuse as a replay.
func TestDBFakeLogBatchConflictMatchesDurableStores(t *testing.T) {
	ctx := context.Background()
	f := newDBFakeStore()
	r := storage.LogBatchReceipt{JobID: "j1", Generation: 1, BatchID: "b1"}
	entries := []model.LogEntry{{RunID: "r1", JobID: "j1", JobKey: "build", Step: "run", Line: "one", CreatedAt: time.Now().UTC()}}
	inserted, err := f.AppendLogBatch(ctx, entries, r)
	if err != nil || !inserted {
		t.Fatalf("first batch = inserted %v err %v, want true/nil", inserted, err)
	}
	// An identical ordered payload with fresh per-delivery metadata (Seq,
	// CreatedAt) is the idempotent duplicate, not a conflict.
	replay := []model.LogEntry{{RunID: "r1", JobID: "j1", JobKey: "build", Step: "run", Line: "one", CreatedAt: time.Now().UTC(), Seq: 99}}
	if inserted, err = f.AppendLogBatch(ctx, replay, r); err != nil || inserted {
		t.Fatalf("identical replay = inserted %v err %v, want false/nil", inserted, err)
	}
	// A reused identity with different lines is the same conflict the
	// durable stores report.
	conflict := []model.LogEntry{{RunID: "r1", JobID: "j1", JobKey: "build", Step: "run", Line: "changed"}}
	if _, err = f.AppendLogBatch(ctx, conflict, r); !errors.Is(err, storage.ErrLogBatchConflict) {
		t.Fatalf("conflicting batch = %v, want storage.ErrLogBatchConflict", err)
	}
	f.mu.Lock()
	stored := len(f.logs)
	f.mu.Unlock()
	if stored != 1 {
		t.Fatalf("stored lines = %d, want exactly the first batch's 1", stored)
	}
}

// TestDBLogBatchHandlerConflictNotAcked is the handler-level half of FA-5:
// a conflicting reuse of a batch identity must get the fixed failure
// response, never the 204 replay ack a digest-blind fake used to produce.
func TestDBLogBatchHandlerConflictNotAcked(t *testing.T) {
	f := newDBFakeStore()
	s, runnerID, task := effectsFixture(t, f)
	path := "/api/v1/jobs/" + task.Job.ID + "/log/batch"

	body := fsLogBatchBody(t, runnerID, task, "conflict-batch", 1, fsLogBatchLine(task.Job.Key, "run", "one"))
	if w := doJSON(t, s, http.MethodPost, path, "token", body); w.Code != http.StatusNoContent {
		t.Fatalf("first batch = %d, want 204: %s", w.Code, w.Body.String())
	}
	conflict := fsLogBatchBody(t, runnerID, task, "conflict-batch", 1, fsLogBatchLine(task.Job.Key, "run", "changed"))
	w := doJSON(t, s, http.MethodPost, path, "token", conflict)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("conflicting batch = %d, want 500 (conflict must not be ACKed as a replay): %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "log batch append failed\n" {
		t.Fatalf("conflicting batch body = %q", got)
	}
	// The original payload is still the idempotent 204 replay.
	if w := doJSON(t, s, http.MethodPost, path, "token", body); w.Code != http.StatusNoContent {
		t.Fatalf("duplicate delivery = %d, want 204: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	stored := len(f.logs)
	f.mu.Unlock()
	if stored != 1 {
		t.Fatalf("stored lines = %d, want exactly 1", stored)
	}
}
