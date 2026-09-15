package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

type fakeForgeFiles struct {
	files    []string
	complete bool
	err      error
	calls    int
}

func (f *fakeForgeFiles) VerifyWebhook([]byte, string, http.Header) error { return nil }
func (f *fakeForgeFiles) ParseEvent([]byte) (forge.EventContext, error) {
	return forge.EventContext{}, nil
}
func (f *fakeForgeFiles) FetchFile(context.Context, string, string, string) (string, error) {
	return "", nil
}
func (f *fakeForgeFiles) ChangedFiles(context.Context, forge.EventContext) (forge.ChangedFilesResult, error) {
	f.calls++
	return forge.ChangedFilesResult{Files: f.files, Complete: f.complete}, f.err
}
func (f *fakeForgeFiles) PublishCheck(context.Context, string, string, string, string, string, string, string, []forge.CheckAnnotation) error {
	return nil
}
func (f *fakeForgeFiles) CloneCredentialFor(string) (string, bool) { return "", false }

func TestTriggerFilesFetchFailsClosedOnIncludePaths(t *testing.T) {
	s := New("x")
	fg := &fakeForgeFiles{err: context.DeadlineExceeded}
	spec, err := pipeline.Parse([]byte("version: 1\non:\n  push:\n    paths: [\"svc/**\"]\njobs:\n  b:\n    runtime: container\n    image: alpine\n    steps: [{run: echo}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	ec := forge.EventContext{Event: "push", Repository: forge.Repository{FullName: "o/r"}}
	if _, err := s.triggerFilesFetch(context.Background(), fg, spec, &ec); err == nil {
		t.Fatal("include-path trigger with unavailable changed files must fail closed")
	}
	if fg.calls == 0 {
		t.Fatal("changed files must be fetched before evaluation")
	}
}

func TestTriggerFilesFetchIncompleteIncludePathsFailsClosed(t *testing.T) {
	s := New("x")
	fg := &fakeForgeFiles{files: []string{"svc/main.go"}, complete: false}
	spec, err := pipeline.Parse([]byte("version: 1\non:\n  push:\n    paths: [\"svc/**\"]\njobs:\n  b:\n    runtime: container\n    image: alpine\n    steps: [{run: echo}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	ec := forge.EventContext{Event: "push", Repository: forge.Repository{FullName: "o/r"}}
	if _, err := s.triggerFilesFetch(context.Background(), fg, spec, &ec); err == nil {
		t.Fatal("include-path trigger with an incomplete diff must fail closed")
	}
}

func TestTriggerFilesFetchIncompleteIgnoreOnlyProceeds(t *testing.T) {
	s := New("x")
	fg := &fakeForgeFiles{files: []string{"svc/main.go"}, complete: false}
	spec, err := pipeline.Parse([]byte("version: 1\non:\n  push:\n    paths_ignore: [\"docs/**\"]\njobs:\n  b:\n    runtime: container\n    image: alpine\n    steps: [{run: echo}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	ec := forge.EventContext{Event: "push", Repository: forge.Repository{FullName: "o/r"}}
	files, err := s.triggerFilesFetch(context.Background(), fg, spec, &ec)
	if err != nil || files != nil {
		t.Fatalf("ignore-only trigger with an incomplete diff must degrade to nil, got %v %v", files, err)
	}
}

func TestTriggerFilesFetchBestEffortWithoutIncludePaths(t *testing.T) {
	s := New("x")
	fg := &fakeForgeFiles{err: context.DeadlineExceeded}
	spec, err := pipeline.Parse([]byte("version: 1\non:\n  push:\n    paths_ignore: [\"docs/**\"]\njobs:\n  b:\n    runtime: container\n    image: alpine\n    steps: [{run: echo}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	ec := forge.EventContext{Event: "push", Repository: forge.Repository{FullName: "o/r"}}
	files, err := s.triggerFilesFetch(context.Background(), fg, spec, &ec)
	if err != nil || files != nil {
		t.Fatalf("ignore-only trigger must degrade gracefully, got %v %v", files, err)
	}
}

func TestEvalTriggerMatchesPopulatesChangedFiles(t *testing.T) {
	s := New("x")
	fg := &fakeForgeFiles{files: []string{"svc/main.go"}, complete: true}
	spec, err := pipeline.Parse([]byte("version: 1\non:\n  push:\n    paths: [\"svc/**\"]\njobs:\n  b:\n    runtime: container\n    image: alpine\n    steps: [{run: echo}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	ec := forge.EventContext{Event: "push", Ref: "refs/heads/main", Repository: forge.Repository{FullName: "o/r"}}
	ok, _, err := s.evalTriggerMatches(context.Background(), fg, spec, &ec)
	if err != nil || !ok {
		t.Fatalf("matching push must pass: %v %v", ok, err)
	}
	if len(ec.ChangedFiles) != 1 || ec.ChangedFiles[0] != "svc/main.go" {
		t.Fatalf("changed files not populated: %v", ec.ChangedFiles)
	}
	ec2 := forge.EventContext{Event: "push", Ref: "refs/heads/main", Repository: forge.Repository{FullName: "o/r"}}
	fg.files = []string{"docs/readme.md"}
	ok, _, err = s.evalTriggerMatches(context.Background(), fg, spec, &ec2)
	if err != nil || ok {
		t.Fatalf("non-matching paths must not pass: %v %v", ok, err)
	}
}

// TestWebhookPathFilterIncompleteDiffFailsClosed exercises the full
// GitHub webhook handler against a forge API whose compare endpoint can
// never produce a complete diff (three full pages), so an include-path
// pipeline must fail the webhook closed with 502.
func TestWebhookPathFilterIncompleteDiffFailsClosed(t *testing.T) {
	const filtered = `version: 1
on:
  push:
    paths: ["svc/**"]
jobs:
  build:
    runtime: native
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
			files := make([]map[string]string, 100)
			for i := range files {
				files[i] = map[string]string{"filename": fmt.Sprintf("src/f%03d.go", i)}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"files": files})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	s := New("runner-secret")
	s.GitHubWebhookSecret = "hunter2"
	s.gitHubAPIBase = api.URL
	s.PipelinePath = ".kiwi/pipeline.yaml"
	w := postWebhook(t, s, "hunter2", "push", "incomplete-diff", pushPayload("9049f1265b7d61be4a8904a9a27120d2064dab3b"))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("include-path trigger with an incomplete diff must fail closed (502), got %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	n := len(s.runs)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("incomplete diff enqueued %d runs", n)
	}
}
