package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

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
	job, _ := f.jobs[task.Job.ID]
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
