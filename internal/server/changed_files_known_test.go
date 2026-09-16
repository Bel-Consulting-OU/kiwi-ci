package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestChangedFilesKnownPersistedAtEnqueue (P1-23): the enqueue persists the
// forge completeness flag on every job — a known-empty list stays empty
// (no runner-side git fallback), an unknown list keeps the fallback.
func TestChangedFilesKnownPersistedAtEnqueue(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.enqueue(SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "main", Pipeline: bareContainerPipeline,
		ChangedFiles: nil, ChangedFilesKnown: true,
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	s.mu.Lock()
	known := s.jobs
	knownRun := run.ID
	s.mu.Unlock()
	for _, j := range known {
		if j.RunID != knownRun {
			continue
		}
		if !j.ChangedFilesKnown {
			t.Fatal("job did not persist ChangedFilesKnown=true")
		}
		if len(j.ChangedFiles) != 0 {
			t.Fatalf("known-empty job has files %v", j.ChangedFiles)
		}
	}
	// Unknown completeness: the flag stays false so the runner keeps the
	// git fallback.
	run2, err := s.enqueue(SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "main", Pipeline: bareContainerPipeline,
	})
	if err != nil {
		t.Fatalf("enqueue 2: %v", err)
	}
	s.mu.Lock()
	for _, j := range s.jobs {
		if j.RunID == run2.ID && j.ChangedFilesKnown {
			t.Fatal("job without the completeness flag must persist ChangedFilesKnown=false")
		}
	}
	s.mu.Unlock()
}

// TestChangedFilesKnownViaWebhookCompleteFetch (P1-23): a GitHub webhook
// whose include-path trigger fetch is COMPLETE enqueues jobs marked
// ChangedFilesKnown with the fetched list.
func TestChangedFilesKnownViaWebhookCompleteFetch(t *testing.T) {
	const filtered = `version: 1
on:
  push:
    paths: ["svc/**"]
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    steps:
      - run: echo hi
`
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/contents/.kiwi/pipeline.yaml"):
			_ = json.NewEncoder(w).Encode(map[string]string{
				"content":  base64.StdEncoding.EncodeToString([]byte(filtered)),
				"encoding": "base64",
			})
		case strings.Contains(r.URL.Path, "/compare/"):
			// One file: a complete diff (the GitHub adapter pages at 100).
			_ = json.NewEncoder(w).Encode(map[string]any{"files": []map[string]string{{"filename": "svc/main.go"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	s := New("runner-secret")
	s.GitHubWebhookSecret = "hunter2"
	s.gitHubAPIBase = api.URL
	s.PipelinePath = ".kiwi/pipeline.yaml"
	w := postWebhook(t, s, "hunter2", "push", "complete-diff", pushPayload("9049f1265b7d61be4a8904a9a27120d2064dab3b"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("webhook = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	var job model.Job
	for _, j := range s.jobs {
		job = j
	}
	s.mu.Unlock()
	if job.ID == "" {
		t.Fatal("no job enqueued")
	}
	if !job.ChangedFilesKnown {
		t.Fatal("complete fetch must mark the changed-files list as known")
	}
	if len(job.ChangedFiles) == 0 {
		t.Fatal("complete fetch must populate the changed files")
	}
}
