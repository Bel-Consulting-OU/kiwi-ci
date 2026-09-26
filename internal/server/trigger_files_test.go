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

func TestTriggerFilesFetchFetchErrorLeavesDiffUnknown(t *testing.T) {
	s := New("x")
	fg := &fakeForgeFiles{err: context.DeadlineExceeded}
	ec := forge.EventContext{Event: "push", Repository: forge.Repository{FullName: "o/r"}}
	res, err := s.triggerFilesFetch(context.Background(), fg, &ec)
	if err == nil {
		t.Fatal("fetch failure must be reported")
	}
	if res.Complete || res.Files != nil || ec.ChangedFiles.Complete || ec.ChangedFiles.Files != nil {
		t.Fatalf("fetch failure must leave the diff unknown: %+v / %+v", res, ec.ChangedFiles)
	}
	if fg.calls == 0 {
		t.Fatal("changed files must be fetched before evaluation")
	}
}

func TestTriggerFilesFetchIncompleteDiffIsNotPropagated(t *testing.T) {
	s := New("x")
	fg := &fakeForgeFiles{files: []string{"svc/main.go"}, complete: false}
	ec := forge.EventContext{Event: "push", Repository: forge.Repository{FullName: "o/r"}}
	res, err := s.triggerFilesFetch(context.Background(), fg, &ec)
	if err != nil {
		t.Fatalf("an incomplete diff is not a fetch failure: %v", err)
	}
	if res.Complete || len(res.Files) != 1 {
		t.Fatalf("result must report the incomplete diff: %+v", res)
	}
	if ec.ChangedFiles.Complete || ec.ChangedFiles.Files != nil {
		t.Fatalf("partial diffs must not be propagated to the event context: %+v", ec.ChangedFiles)
	}
}

func TestEvalTriggerMatchesIncompleteIncludePathsFailsClosed(t *testing.T) {
	s := New("x")
	fg := &fakeForgeFiles{files: []string{"svc/main.go"}, complete: false}
	spec, err := pipeline.Parse([]byte("version: 1\non:\n  push:\n    paths: [\"svc/**\"]\njobs:\n  b:\n    runtime: container\n    image: alpine\n    steps: [{run: echo}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	ec := forge.EventContext{Event: "push", Ref: "refs/heads/main", Repository: forge.Repository{FullName: "o/r"}}
	ok, _, known, err := s.evalTriggerMatches(context.Background(), fg, spec, &ec)
	if err == nil || ok || known {
		t.Fatalf("include-path trigger with an incomplete diff must fail closed: ok=%v known=%v err=%v", ok, known, err)
	}
}

func TestEvalTriggerMatchesUnavailableIncludePathsFailsClosed(t *testing.T) {
	s := New("x")
	fg := &fakeForgeFiles{err: context.DeadlineExceeded}
	spec, err := pipeline.Parse([]byte("version: 1\non:\n  push:\n    paths: [\"svc/**\"]\njobs:\n  b:\n    runtime: container\n    image: alpine\n    steps: [{run: echo}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	ec := forge.EventContext{Event: "push", Ref: "refs/heads/main", Repository: forge.Repository{FullName: "o/r"}}
	ok, _, known, err := s.evalTriggerMatches(context.Background(), fg, spec, &ec)
	if err == nil || ok || known {
		t.Fatalf("include-path trigger with an unfetchable diff must fail closed: ok=%v known=%v err=%v", ok, known, err)
	}
}

func TestEvalTriggerMatchesIncompleteIgnoreOnlyProceeds(t *testing.T) {
	s := New("x")
	fg := &fakeForgeFiles{files: []string{"svc/main.go"}, complete: false}
	spec, err := pipeline.Parse([]byte("version: 1\non:\n  push:\n    paths_ignore: [\"docs/**\"]\njobs:\n  b:\n    runtime: container\n    image: alpine\n    steps: [{run: echo}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	ec := forge.EventContext{Event: "push", Ref: "refs/heads/main", Repository: forge.Repository{FullName: "o/r"}}
	ok, key, known, err := s.evalTriggerMatches(context.Background(), fg, spec, &ec)
	if err != nil || !ok || key != "push" || known {
		t.Fatalf("ignore-only trigger with an incomplete diff must admit best-effort: ok=%v key=%q known=%v err=%v", ok, key, known, err)
	}
	if ec.ChangedFiles.Files != nil {
		t.Fatalf("best-effort admit must not propagate the partial diff: %v", ec.ChangedFiles.Files)
	}
}

func TestEvalTriggerMatchesBestEffortWithoutIncludePaths(t *testing.T) {
	s := New("x")
	fg := &fakeForgeFiles{err: context.DeadlineExceeded}
	spec, err := pipeline.Parse([]byte("version: 1\non:\n  push:\n    paths_ignore: [\"docs/**\"]\njobs:\n  b:\n    runtime: container\n    image: alpine\n    steps: [{run: echo}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	ec := forge.EventContext{Event: "push", Ref: "refs/heads/main", Repository: forge.Repository{FullName: "o/r"}}
	ok, _, known, err := s.evalTriggerMatches(context.Background(), fg, spec, &ec)
	if err != nil || !ok || known {
		t.Fatalf("ignore-only trigger must degrade gracefully on fetch failure: ok=%v known=%v err=%v", ok, known, err)
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
	ok, _, known, err := s.evalTriggerMatches(context.Background(), fg, spec, &ec)
	if err != nil || !ok {
		t.Fatalf("matching push must pass: %v %v", ok, err)
	}
	if !known {
		t.Fatal("a complete fetch must report the changed-files list as known")
	}
	if len(ec.ChangedFiles.Files) != 1 || ec.ChangedFiles.Files[0] != "svc/main.go" {
		t.Fatalf("changed files not populated: %v", ec.ChangedFiles.Files)
	}
	ec2 := forge.EventContext{Event: "push", Ref: "refs/heads/main", Repository: forge.Repository{FullName: "o/r"}}
	fg.files = []string{"docs/readme.md"}
	ok, _, _, err = s.evalTriggerMatches(context.Background(), fg, spec, &ec2)
	if err != nil || ok {
		t.Fatalf("non-matching paths must not pass: %v %v", ok, err)
	}
}

// TestWebhookPathFilterIncompleteDiffFailsClosed exercises the full
// GitHub webhook handler against a forge API whose compare endpoint can
// never produce a complete diff (three full pages): the matcher fails the
// include-path trigger closed and the webhook answers 502 without queueing.
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

// TestWebhookPathFilterUnfetchableDiffFailsClosed is the fetch-failure
// sibling: the compare API errors, the matcher still sees an unknown diff,
// refuses the include-path trigger, and the webhook answers 502 without
// queueing the job.
func TestWebhookPathFilterUnfetchableDiffFailsClosed(t *testing.T) {
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
			http.Error(w, "compare unavailable", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	s := New("runner-secret")
	s.GitHubWebhookSecret = "hunter2"
	s.gitHubAPIBase = api.URL
	s.PipelinePath = ".kiwi/pipeline.yaml"
	w := postWebhook(t, s, "hunter2", "push", "unfetchable-diff", pushPayload("9049f1265b7d61be4a8904a9a27120d2064dab3b"))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("include-path trigger with an unfetchable diff must fail closed (502), got %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	n := len(s.runs)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("unfetchable diff enqueued %d runs", n)
	}
}
