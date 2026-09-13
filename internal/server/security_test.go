package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: ubuntu@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo hi
`

type testClient struct {
	t     *testing.T
	h     http.Handler
	token string
}

func newTestClient(t *testing.T, h http.Handler, token string) *testClient {
	return &testClient{t: t, h: h, token: token}
}

func (c *testClient) do(method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	c.t.Helper()
	var rd *bytes.Reader
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			c.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rd)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, req)
	return w
}

// leaseJob submits a run, registers a runner, and leases the job.
func leaseJob(t *testing.T, c *testClient) (runID, jobID, runnerID, leaseToken string, generation int64) {
	t.Helper()
	w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: testPipeline}, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	var run struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	runID = run.ID
	w = c.do(http.MethodPost, "/api/v1/runners/register", map[string]any{"name": "r1", "capacity": 1, "labels": []string{"container"}, "protocol_min": 3, "protocol_max": 3}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var reg struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reg); err != nil {
		t.Fatal(err)
	}
	runnerID = reg.ID
	w = c.do(http.MethodPost, "/api/v1/runners/"+runnerID+"/next", map[string]any{}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("next: %d %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	return runID, task.Job.ID, runnerID, task.LeaseToken, task.LeaseGeneration
}

func TestCancelledJobLeaseRejected(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "secret")
	runID, jobID, runnerID, token, gen := leaseJob(t, c)

	// Sanity: a running lease authorizes log uploads.
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/log", LogLine{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, JobKey: "build", Step: "s", Line: "hello"}, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("log while running: %d %s", w.Code, w.Body.String())
	}

	// Cancel the run; the lease is voided.
	w = c.do(http.MethodPost, "/api/v1/runs/"+runID+"/cancel", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("cancel: %d %s", w.Code, w.Body.String())
	}

	// Cancelled jobs reject log lines.
	w = c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/log", LogLine{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, JobKey: "build", Step: "s", Line: "late"}, nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("log after cancel: want 409 got %d: %s", w.Code, w.Body.String())
	}

	// Cancelled jobs reject test reports.
	w = c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/tests", map[string]any{"runner_id": runnerID, "lease_token": token, "lease_generation": gen, "report": map[string]any{"path": "x", "tests": 1}}, nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("tests after cancel: want 409 got %d: %s", w.Code, w.Body.String())
	}

	// Cancelled jobs reject artifact uploads.
	headers := map[string]string{"X-Kiwi-Runner-ID": runnerID, "X-Kiwi-Lease-Token": token, "X-Kiwi-Lease-Generation": fmt.Sprint(gen)}
	w = c.do(http.MethodPut, "/api/v1/jobs/"+jobID+"/artifacts/pkg", []byte("garbage"), headers)
	if w.Code != http.StatusConflict {
		t.Fatalf("artifact after cancel: want 409 got %d: %s", w.Code, w.Body.String())
	}

	// Heartbeat on a cancelled job still reports cancellation (the runner
	// must learn to stop).
	w = c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/heartbeat", Heartbeat{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen}, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"cancel":true`) {
		t.Fatalf("heartbeat after cancel: want cancel=true got %d: %s", w.Code, w.Body.String())
	}
}

func TestCompletionReceiptIdempotency(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	_, jobID, runnerID, token, gen := leaseJob(t, c)

	payload := Complete{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Status: "success"}
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", payload, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("first complete: %d %s", w.Code, w.Body.String())
	}
	// The lease fields are cleared server-side.
	s.mu.Lock()
	j := s.jobs[jobID]
	s.mu.Unlock()
	if j.Status != "success" || j.LeaseRunnerID != "" || j.LeaseTokenHash != nil || j.LeaseExpiresAt != nil {
		t.Fatalf("lease not cleared after completion: %+v", j)
	}

	// An identical retry is acknowledged idempotently from the receipt.
	w = c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", payload, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("idempotent retry: %d %s", w.Code, w.Body.String())
	}

	// A different payload for the same generation is not idempotent.
	alt := payload
	alt.Error = "different outcome"
	w = c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", alt, nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("divergent retry: want 409 got %d: %s", w.Code, w.Body.String())
	}
}

func TestStaleGenerationRejected(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	_, jobID, runnerID, token, gen := leaseJob(t, c)

	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/heartbeat", Heartbeat{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen + 1}, nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale generation heartbeat: want 409 got %d", w.Code)
	}
	// Wrong token for the right generation is rejected too.
	w = c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/heartbeat", Heartbeat{RunnerID: runnerID, LeaseToken: token + "x", LeaseGeneration: gen}, nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("wrong token heartbeat: want 409 got %d", w.Code)
	}
}

func TestLeaseSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s1.Handler(), "secret")
	_, jobID, runnerID, token, gen := leaseJob(t, c)
	// Sanity: the task response never carries the persisted hash.
	s1.mu.Lock()
	stored := s1.jobs[jobID]
	s1.mu.Unlock()
	if stored.LeaseTokenHash == nil {
		t.Fatal("job must persist a lease token hash")
	}

	// Reload from the same data dir while the lease still has ~30s+ left.
	s2, err := NewPersistent("secret", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	s2.mu.Lock()
	j := s2.jobs[jobID]
	r := s2.runners[runnerID]
	s2.mu.Unlock()
	if j.Status != "running" || j.LeaseRunnerID != runnerID {
		t.Fatalf("lease lost across restart: %+v", j)
	}
	if j.LeaseExpiresAt == nil || !j.LeaseExpiresAt.After(time.Now()) {
		t.Fatalf("lease expiry lost across restart: %+v", j.LeaseExpiresAt)
	}
	if j.LeaseTokenHash == nil {
		t.Fatal("lease token hash lost across restart")
	}
	found := false
	for _, id := range r.ActiveJobs {
		if id == jobID {
			found = true
		}
	}
	if !found || !r.Busy {
		t.Fatalf("runner active jobs not rebuilt after restart: %+v", r)
	}

	// The reloaded server still authorizes the lease (key was persisted).
	c2 := newTestClient(t, s2.Handler(), "secret")
	w := c2.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/heartbeat", Heartbeat{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("heartbeat after restart: %d %s", w.Code, w.Body.String())
	}
}

func TestExpiredLeaseRequeued(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	_, jobID, _, _, _ := leaseJob(t, c)
	s.mu.Lock()
	j := s.jobs[jobID]
	expired := time.Now().Add(-time.Minute)
	j.LeaseExpiresAt = &expired
	s.jobs[jobID] = j
	s.mu.Unlock()
	s.mu.Lock()
	s.recoverLeasesLocked(time.Now(), false)
	s.mu.Unlock()
	s.mu.Lock()
	j = s.jobs[jobID]
	s.mu.Unlock()
	if j.Status != "queued" {
		t.Fatalf("expired lease job should be requeued, got %s", j.Status)
	}
	if j.LeaseRunnerID != "" || j.LeaseTokenHash != nil || j.LeaseExpiresAt != nil {
		t.Fatalf("lease fields not cleared on expiry: %+v", j)
	}
}

func TestDecodeRejectsTrailingData(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	body := `{"repo_url":"https://github.com/kiwi/repo.git","ref":"main","pipeline":"` + testPipeline + `"}{"extra":true}`
	w := c.do(http.MethodPost, "/api/v1/runs", []byte(body), nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("trailing data: want 400 got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogBodyLimits(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	_, jobID, runnerID, token, gen := leaseJob(t, c)
	// Oversized line is rejected before any lease work.
	huge := strings.Repeat("x", 1<<20+1)
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/log", LogLine{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, JobKey: "build", Step: "s", Line: huge}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized line: want 400 got %d", w.Code)
	}
	// Oversized step name.
	w = c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/log", LogLine{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, JobKey: "build", Step: strings.Repeat("s", 129), Line: "x"}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized step: want 400 got %d", w.Code)
	}
}

func TestCompleteErrorLimit(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	_, jobID, runnerID, token, gen := leaseJob(t, c)
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", Complete{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Status: "failure", Error: strings.Repeat("e", 64<<10+1)}, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized error: want 400 got %d", w.Code)
	}
}

func TestRequestIDMiddleware(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	w := c.do(http.MethodGet, "/api/v1/runs", nil, map[string]string{"X-Kiwi-Request-ID": "abc-123_XYZ.9"})
	if got := w.Header().Get("X-Kiwi-Request-ID"); got != "abc-123_XYZ.9" {
		t.Fatalf("valid request id not echoed: %q", got)
	}
	w = c.do(http.MethodGet, "/api/v1/runs", nil, map[string]string{"X-Kiwi-Request-ID": "bad id!"})
	if got := w.Header().Get("X-Kiwi-Request-ID"); got == "" || got == "bad id!" {
		t.Fatalf("invalid request id must be replaced: %q", got)
	}
	long := strings.Repeat("a", 129)
	w = c.do(http.MethodGet, "/api/v1/runs", nil, map[string]string{"X-Kiwi-Request-ID": long})
	if got := w.Header().Get("X-Kiwi-Request-ID"); got == long || len(got) > 128 {
		t.Fatalf("oversized request id must be replaced: len=%d", len(got))
	}
}

func TestRecovererOpaque(t *testing.T) {
	panicky := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("secret stack internals") })
	h := requestID(recoverer(panicky))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "secret stack internals") {
		t.Fatalf("panic text leaked to client: %s", w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "internal server error" {
		t.Fatalf("unexpected error body: %s", w.Body.String())
	}
	if body["request_id"] == "" || w.Header().Get("X-Kiwi-Request-ID") != body["request_id"] {
		t.Fatalf("request_id missing or mismatched: %+v header=%q", body, w.Header().Get("X-Kiwi-Request-ID"))
	}
}

func TestNoRedirectClient(t *testing.T) {
	var got int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got++
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := NoRedirectClient(&http.Client{})
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/start", nil)
	req.Header.Set("Authorization", "Bearer super-secret")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got != 1 {
		t.Fatalf("redirect was followed: %d requests", got)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("want raw 302 got %d", resp.StatusCode)
	}
}
