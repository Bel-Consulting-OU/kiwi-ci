package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// doJSONHeaders serves one request with extra headers (e.g. X-Kiwi-* lease
// headers) set.
func doJSONHeaders(t *testing.T, s *Server, method, path, bearer, body string, headers map[string]string) *httptest.ResponseRecorder {
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
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

const artifactsPipeline = `version: 1
jobs:
  build:
    runtime: container
    artifacts:
      - name: bin
        paths:
          - out/
        retention: 1h
    steps:
      - run: echo hi
`

// leaseArtifactJob registers a runner, submits a run and leases its first
// job, returning the runner ID and the task (with the raw lease token).
func leaseArtifactJob(t *testing.T, s *Server, pipelineText string) (string, Task) {
	t.Helper()
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	submit := `{"repo_url":"https://example.com/o/r.git","repo_full_name":"o/r","ref":"refs/heads/main","sha":"abc","event":"push","pipeline":` + jsonString(pipelineText) + `}`
	if w = doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", submit); w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next: %d %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	return ri.ID, task
}

func leaseHeaders(task Task, runnerID string) map[string]string {
	return map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      task.LeaseToken,
		"X-Kiwi-Lease-Generation": fmt.Sprint(task.LeaseGeneration),
	}
}

func TestArtifactContractRejectsUndeclaredName(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/not-declared", "token", "data", leaseHeaders(task, runnerID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("undeclared name = %d, want 403: %s", w.Code, w.Body.String())
	}
}

func TestArtifactUploadIdempotentSameDigest(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
	hdrs := leaseHeaders(task, runnerID)
	path := "/api/v1/jobs/" + task.Job.ID + "/artifacts/bin"

	w := doJSONHeaders(t, s, http.MethodPut, path, "token", "payload-bytes", hdrs)
	if w.Code != http.StatusCreated {
		t.Fatalf("first upload = %d: %s", w.Code, w.Body.String())
	}
	var first model.ArtifactRecord
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	w = doJSONHeaders(t, s, http.MethodPut, path, "token", "payload-bytes", hdrs)
	if w.Code != http.StatusOK {
		t.Fatalf("idempotent replay = %d, want 200: %s", w.Code, w.Body.String())
	}
	var second model.ArtifactRecord
	if err := json.Unmarshal(w.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID || second.SHA256 != first.SHA256 {
		t.Fatalf("replay returned a different record: %+v vs %+v", first, second)
	}
	if first.ExpiresAt == nil {
		t.Fatal("contract retention (1h) not applied to expiry")
	}
}

func TestArtifactUploadDifferentDigestConflicts(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
	hdrs := leaseHeaders(task, runnerID)
	path := "/api/v1/jobs/" + task.Job.ID + "/artifacts/bin"

	if w := doJSONHeaders(t, s, http.MethodPut, path, "token", "first-payload", hdrs); w.Code != http.StatusCreated {
		t.Fatalf("first upload = %d: %s", w.Code, w.Body.String())
	}
	w := doJSONHeaders(t, s, http.MethodPut, path, "token", "different-payload", hdrs)
	if w.Code != http.StatusConflict {
		t.Fatalf("conflicting digest = %d, want 409: %s", w.Code, w.Body.String())
	}
}

func TestArtifactContractEnforcedInDBMode(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	// Register a runner, submit, and lease through the scheduler.
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	var runnerID string
	for id := range f.runners {
		runnerID = id
	}
	f.mu.Unlock()
	submit := `{"repo_url":"https://example.com/o/r.git","repo_full_name":"o/r","ref":"refs/heads/main","sha":"abc","event":"push","pipeline":` + jsonString(artifactsPipeline) + `}`
	if w = doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", submit); w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next: %d %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	hdrs := leaseHeaders(task, runnerID)
	w = doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/undeclared", "token", "data", hdrs)
	if w.Code != http.StatusForbidden {
		t.Fatalf("db undeclared name = %d, want 403: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	_, found := f.contracts[task.Job.ID]
	f.mu.Unlock()
	if !found {
		t.Fatal("contracts were not persisted through ArtifactContractStore")
	}
}

func TestArtifactContractEnforcesMaxSize(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
	// Seed a MaxSize on the persisted contract (the pipeline schema has no
	// size field yet; the enforcement path is contract-driven).
	s.mu.Lock()
	c := s.contracts[task.Job.ID]
	bin := c["bin"]
	bin.MaxSize = 4
	c["bin"] = bin
	s.contracts[task.Job.ID] = c
	s.mu.Unlock()
	hdrs := leaseHeaders(task, runnerID)
	path := "/api/v1/jobs/" + task.Job.ID + "/artifacts/bin"
	w := doJSONHeaders(t, s, http.MethodPut, path, "token", "toolarge", hdrs)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized upload = %d, want 413: %s", w.Code, w.Body.String())
	}
	// A payload within the limit succeeds.
	if w := doJSONHeaders(t, s, http.MethodPut, path, "token", "ok12", hdrs); w.Code != http.StatusCreated {
		t.Fatalf("within-limit upload = %d: %s", w.Code, w.Body.String())
	}
}

var _ = time.Now
