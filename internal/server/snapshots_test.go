package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
)

// leaseNativeJob submits a native-runtime pipeline, registers a native
// runner, and leases the job.
func leaseNativeJob(t *testing.T, c *testClient, pipelineText string) (runID, jobID, runnerID, token string, generation int64) {
	t.Helper()
	w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: pipelineText}, nil)
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
	w = c.do(http.MethodPost, "/api/v1/runners/register", map[string]any{"name": "r-native", "capacity": 1, "labels": []string{"native", "container"}, "protocol_min": 3, "protocol_max": 3}, nil)
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

func TestSnapshotUploadAndList(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "secret")
	runID, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)

	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "out.txt"), []byte("snapshot data"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	m, err := snapshot.Create(ws, &buf)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      token,
		"X-Kiwi-Lease-Generation": fmt.Sprint(gen),
		"Content-Type":            "application/gzip",
	}
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", buf.Bytes(), headers)
	if w.Code != http.StatusCreated {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
	var rec struct {
		ID         string `json:"id"`
		JobID      string `json:"job_id"`
		RootSHA256 string `json:"root_sha256"`
		Entries    []struct {
			Path string `json:"path"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.JobID != jobID {
		t.Fatalf("record job = %q, want %q", rec.JobID, jobID)
	}
	if rec.RootSHA256 != m.RootSHA256 {
		t.Fatalf("root sha = %q, want %q", rec.RootSHA256, m.RootSHA256)
	}
	if len(rec.Entries) == 0 || rec.Entries[0].Path != "out.txt" {
		t.Fatalf("entries wrong: %+v", rec.Entries)
	}
	// The archive and manifest sidecar are stored under the data dir.
	s.mu.Lock()
	path := s.snapshots[rec.ID].Path
	s.mu.Unlock()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("archive missing: %v", err)
	}
	if _, err := os.Stat(path + ".manifest.json"); err != nil {
		t.Fatalf("manifest sidecar missing: %v", err)
	}

	// List by run.
	w = c.do(http.MethodGet, "/api/v1/runs/"+runID+"/snapshots", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var out []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("snapshots listed = %d, want 1", len(out))
	}
	if p, _ := out[0]["path"].(string); p != "" {
		t.Fatal("server-local path leaked in list response")
	}

	// Unknown run 404.
	w = c.do(http.MethodGet, "/api/v1/runs/nope/snapshots", nil, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown run: %d", w.Code)
	}
}

func TestSnapshotUploadRequiresLease(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "secret")
	_, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)

	// Wrong token.
	headers := map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      token + "x",
		"X-Kiwi-Lease-Generation": fmt.Sprint(gen),
	}
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", []byte("junk"), headers)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale lease upload: %d %s", w.Code, w.Body.String())
	}
	// Garbage archive under a valid lease is rejected.
	headers["X-Kiwi-Lease-Token"] = token
	w = c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", []byte("not a tar.gz"), headers)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("garbage archive: %d %s", w.Code, w.Body.String())
	}
}
