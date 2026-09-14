package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const producerPipeline = `version: 1
jobs:
  build:
    runtime: container
    artifacts:
      - name: bin
        paths:
          - out/
    steps:
      - run: echo build
  consume:
    runtime: container
    needs:
      - build
    downloads:
      - from: build
        name: bin
        path: bin/
    steps:
      - run: echo consume
`

// seedRunningJob forces jobKey into a running state with a valid lease,
// returning the job ID and lease headers.
func seedRunningJob(t *testing.T, s *Server, jobKey, runnerID, rawToken string) (string, map[string]string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var jobID string
	for id, j := range s.jobs {
		if j.Key == jobKey {
			j.Status = model.StatusRunning
			j.LeaseRunnerID = runnerID
			j.LeaseTokenHash = hashLeaseToken(s.leaseKey, rawToken)
			j.LeaseGeneration = 1
			exp := time.Now().UTC().Add(time.Hour)
			j.LeaseExpiresAt = &exp
			s.jobs[id] = j
			jobID = id
		}
	}
	if jobID == "" {
		t.Fatalf("no job with key %q", jobKey)
	}
	if _, ok := s.runners[runnerID]; !ok {
		s.runners[runnerID] = model.Runner{ID: runnerID, Name: runnerID, Capacity: 1, Labels: []string{"container"}}
	}
	return jobID, map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      rawToken,
		"X-Kiwi-Lease-Generation": "1",
	}
}

func TestDependencyDownloadHappyPath(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnerID, _ := leaseArtifactJob(t, s, producerPipeline)
	// The first lease is the producer (build): consume waits on it.
	s.mu.Lock()
	var build model.Job
	for _, j := range s.jobs {
		if j.Status == model.StatusRunning && j.Key == "build" {
			build = j
		}
	}
	s.mu.Unlock()
	if build.ID == "" {
		t.Fatal("build job was not leased")
	}
	// Recover the raw lease token through a fresh in-memory lease binding.
	buildID, buildHdrs := seedRunningJob(t, s, "build", runnerID, "build-token")
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+buildID+"/artifacts/bin", "token", "the-binary", buildHdrs); w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	// Complete the producer so the consumer becomes leasable.
	complete := `{"runner_id":` + jsonString(runnerID) + `,"lease_token":` + jsonString("build-token") + `,"lease_generation":1,"status":"success"}`
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+buildID+"/complete", "token", complete); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	// Lease the consumer.
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("consumer lease = %d: %s", w.Code, w.Body.String())
	}
	var consumerTask Task
	if err := json.Unmarshal(w.Body.Bytes(), &consumerTask); err != nil {
		t.Fatal(err)
	}
	if consumerTask.Job.Key != "consume" {
		t.Fatalf("leased %q, want consume", consumerTask.Job.Key)
	}
	chdrs := leaseHeaders(consumerTask, runnerID)
	dl := "/api/v1/jobs/" + consumerTask.Job.ID + "/dependencies/build/bin"
	w = doJSONHeaders(t, s, http.MethodGet, dl, "token", "", chdrs)
	if w.Code != http.StatusOK {
		t.Fatalf("download = %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "the-binary" {
		t.Fatalf("downloaded bytes = %q", w.Body.String())
	}
	if w.Header().Get("X-Kiwi-Content-SHA256") == "" {
		t.Fatal("missing digest header")
	}
	if w.Header().Get("X-Kiwi-Producer-Job") != "build" {
		t.Fatal("missing producer job header")
	}
}

func TestDependencyDownloadWrongProducer(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaseArtifactJob(t, s, producerPipeline)
	jobID, hdrs := seedRunningJob(t, s, "consume", "runner-wrong", "consume-token")
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/"+jobID+"/dependencies/other/bin", "token", "", hdrs)
	if w.Code != http.StatusForbidden {
		t.Fatalf("wrong producer = %d, want 403: %s", w.Code, w.Body.String())
	}
}

func TestDependencyDownloadMissingArtifact(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaseArtifactJob(t, s, producerPipeline)
	jobID, hdrs := seedRunningJob(t, s, "consume", "runner-missing", "consume-token")
	// The producer never uploaded "bin": declared but absent → 404.
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/"+jobID+"/dependencies/build/bin", "token", "", hdrs)
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing artifact = %d, want 404: %s", w.Code, w.Body.String())
	}
}

func TestDependencyDownloadStaleLease(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaseArtifactJob(t, s, producerPipeline)
	jobID, hdrs := seedRunningJob(t, s, "consume", "runner-ghost", "consume-token")
	hdrs["X-Kiwi-Lease-Token"] = "bogus-token"
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/"+jobID+"/dependencies/build/bin", "token", "", hdrs)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale lease = %d, want 409: %s", w.Code, w.Body.String())
	}
}
