package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const producerPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    artifacts:
      - name: bin
        paths:
          - out/
    steps:
      - run: echo build
  consume:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
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

// downloadDependencyFixture drives the producer/consumer flow to the point
// where the consumer may download the producer's artifact, returning the
// server, the consumer job ID, its lease headers, and the on-disk artifact
// path whose bytes a test can corrupt.
func downloadDependencyFixture(t *testing.T) (*Server, string, map[string]string, string) {
	t.Helper()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnerID, _ := leaseArtifactJob(t, s, producerPipeline)
	buildID, buildHdrs := seedRunningJob(t, s, "build", runnerID, "build-token")
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+buildID+"/artifacts/bin", "token", "the-binary", buildHdrs); w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	complete := `{"runner_id":` + jsonString(runnerID) + `,"lease_token":` + jsonString("build-token") + `,"lease_generation":1,"status":"success"}`
	if w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+buildID+"/complete", "token", complete); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("consumer lease = %d: %s", w.Code, w.Body.String())
	}
	var consumerTask Task
	if err := json.Unmarshal(w.Body.Bytes(), &consumerTask); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	runID := s.jobs[buildID].RunID
	s.mu.Unlock()
	dir := filepath.Join(s.store.Root, "artifacts", runID, buildID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read artifact dir: %v", err)
	}
	artifactPath := ""
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tar.gz") {
			artifactPath = filepath.Join(dir, e.Name())
		}
	}
	if artifactPath == "" {
		t.Fatal("artifact file not found on disk")
	}
	return s, consumerTask.Job.ID, leaseHeaders(consumerTask, runnerID), artifactPath
}

// integrityFailureCount sums the download-integrity counter across labels.
func integrityFailureCount(s *Server) float64 {
	s.Metrics.mu.Lock()
	defer s.Metrics.mu.Unlock()
	var got float64
	for _, v := range s.Metrics.counters[metricDownloadIntegrityFailures] {
		got += v
	}
	return got
}

// TestDependencyDownloadValidByteIdentical proves the integrity path does not
// alter a valid dependency download.
func TestDependencyDownloadValidByteIdentical(t *testing.T) {
	s, jobID, hdrs, _ := downloadDependencyFixture(t)
	before := integrityFailureCount(s)
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/"+jobID+"/dependencies/build/bin", "token", "", hdrs)
	if w.Code != http.StatusOK {
		t.Fatalf("valid download = %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "the-binary" {
		t.Fatalf("download body = %q, want the-binary", w.Body.String())
	}
	if got := integrityFailureCount(s); got != before {
		t.Fatalf("valid download incremented the integrity metric: %v != %v", got, before)
	}
}

// TestDependencyDownloadShortBodyAborts is the regression: a backend that
// returns FEWER bytes than the record advertises must not be served as a
// successful download. The preverify path serves nothing and meters it.
func TestDependencyDownloadShortBodyAborts(t *testing.T) {
	s, jobID, hdrs, path := downloadDependencyFixture(t)
	if err := os.WriteFile(path, []byte("the-"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := integrityFailureCount(s)
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/"+jobID+"/dependencies/build/bin", "token", "", hdrs)
	if w.Code == http.StatusOK {
		t.Fatalf("short dependency body served a 200 with %d bytes", w.Body.Len())
	}
	if got := integrityFailureCount(s); got != before+1 {
		t.Fatalf("integrity metric = %v, want %v", got, before+1)
	}
	if bytes.Contains(w.Body.Bytes(), []byte("the-")) {
		t.Fatal("response body contains the truncated dependency bytes")
	}
}

// TestDependencyDownloadOversizedBodyAborts proves a body LONGER than the
// record advertises is refused and metered rather than streamed.
func TestDependencyDownloadOversizedBodyAborts(t *testing.T) {
	s, jobID, hdrs, path := downloadDependencyFixture(t)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("EXTRA"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	before := integrityFailureCount(s)
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/"+jobID+"/dependencies/build/bin", "token", "", hdrs)
	if w.Code == http.StatusOK {
		t.Fatalf("oversized dependency body served a 200 with %d bytes", w.Body.Len())
	}
	if got := integrityFailureCount(s); got != before+1 {
		t.Fatalf("integrity metric = %v, want %v", got, before+1)
	}
}

// TestDependencyDownloadDigestMismatchAborts proves a same-length but
// different-content body is refused and metered rather than served.
func TestDependencyDownloadDigestMismatchAborts(t *testing.T) {
	s, jobID, hdrs, path := downloadDependencyFixture(t)
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wrong := append([]byte(nil), orig...)
	for i := range wrong {
		if i < len(wrong)-1 {
			wrong[i] = 'Z'
		}
	}
	if err := os.WriteFile(path, wrong, 0o600); err != nil {
		t.Fatal(err)
	}
	before := integrityFailureCount(s)
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/"+jobID+"/dependencies/build/bin", "token", "", hdrs)
	if w.Code == http.StatusOK {
		t.Fatalf("corrupt dependency body served a 200 with %d bytes", w.Body.Len())
	}
	if got := integrityFailureCount(s); got != before+1 {
		t.Fatalf("integrity metric = %v, want %v", got, before+1)
	}
	if bytes.Contains(w.Body.Bytes(), wrong) {
		t.Fatal("response body contains the corrupt dependency bytes")
	}
}
