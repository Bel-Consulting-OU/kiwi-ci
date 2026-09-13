package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const webhookPipeline = `version: 1
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`

func signGitHubPayload(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// newGitHubHookServer wires a Server against a fake GitHub API serving the
// pipeline contents (and a compare response).
func newGitHubHookServer(t *testing.T, secret string) (*Server, *httptest.Server) {
	t.Helper()
	var contentsCalls int
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/contents/.kiwi/pipeline.yaml"):
			contentsCalls++
			_ = json.NewEncoder(w).Encode(map[string]string{
				"content":  base64.StdEncoding.EncodeToString([]byte(webhookPipeline)),
				"encoding": "base64",
			})
		case strings.Contains(r.URL.Path, "/compare/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"files": []map[string]string{{"filename": "src/main.go"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(api.Close)
	s := New("runner-secret")
	s.GitHubWebhookSecret = secret
	s.gitHubAPIBase = api.URL
	s.PipelinePath = ".kiwi/pipeline.yaml"
	return s, api
}

func pushPayload(sha string) string {
	return `{
  "ref": "refs/heads/main",
  "before": "6113728f27ae82c7b1a177c8d03f9e96e0adf246",
  "after": "` + sha + `",
  "repository": {
    "id": 42,
    "full_name": "octocat/hello-world",
    "clone_url": "https://github.com/octocat/hello-world.git",
    "default_branch": "main"
  }
}`
}

func postWebhook(t *testing.T, s *Server, secret, event, delivery, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/hooks/github", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-Hub-Signature-256", signGitHubPayload(secret, []byte(body)))
	if delivery != "" {
		req.Header.Set("X-GitHub-Delivery", delivery)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func decodeRun(t *testing.T, w *httptest.ResponseRecorder) (string, int) {
	t.Helper()
	var run struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatalf("decode run: %v (body %s)", err, w.Body.String())
	}
	return run.ID, w.Code
}

func TestGitHubWebhookEnqueuesRun(t *testing.T) {
	s, _ := newGitHubHookServer(t, "hunter2")
	w := postWebhook(t, s, "hunter2", "push", "delivery-1", pushPayload("9049f1265b7d61be4a8904a9a27120d2064dab3b"))
	if w.Code != http.StatusAccepted {
		t.Fatalf("want 202 got %d: %s", w.Code, w.Body.String())
	}
	runID, _ := decodeRun(t, w)
	if runID == "" {
		t.Fatal("no run id")
	}
	s.mu.Lock()
	run := s.runs[runID]
	s.mu.Unlock()
	if run.RepoFullName != "octocat/hello-world" || run.SHA != "9049f1265b7d61be4a8904a9a27120d2064dab3b" || run.Event != "push" || !run.Trusted {
		t.Fatalf("bad run: %+v", run)
	}
	if run.Metadata["github_delivery"] != "delivery-1" {
		t.Fatalf("delivery not recorded: %+v", run.Metadata)
	}
	// Changed files were fetched server-side and stored on jobs.
	s.mu.Lock()
	changed := map[string][]string{}
	for _, j := range s.jobs {
		if j.RunID == runID {
			changed[j.Key] = j.ChangedFiles
		}
	}
	s.mu.Unlock()
	if len(changed) == 0 || len(changed["build"]) != 1 || changed["build"][0] != "src/main.go" {
		t.Fatalf("changed files missing from jobs: %v", changed)
	}
	if s.deliveries["delivery-1"] != runID {
		t.Fatalf("deliveries map not set: %v", s.deliveries)
	}
}

func TestGitHubWebhookDedupe(t *testing.T) {
	s, _ := newGitHubHookServer(t, "hunter2")
	body := pushPayload("9049f1265b7d61be4a8904a9a27120d2064dab3b")
	w := postWebhook(t, s, "hunter2", "push", "dup-delivery", body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("first: want 202 got %d: %s", w.Code, w.Body.String())
	}
	firstID, _ := decodeRun(t, w)

	// A retried delivery (same X-GitHub-Delivery) returns the original run.
	w2 := postWebhook(t, s, "hunter2", "push", "dup-delivery", body)
	if w2.Code != http.StatusOK {
		t.Fatalf("retry: want 200 got %d: %s", w2.Code, w2.Body.String())
	}
	secondID, _ := decodeRun(t, w2)
	if secondID != firstID {
		t.Fatalf("dedupe returned different run: %s vs %s", firstID, secondID)
	}
	s.mu.Lock()
	n := len(s.runs)
	s.mu.Unlock()
	if n != 1 {
		t.Fatalf("dedupe enqueued %d runs", n)
	}
}

func TestGitHubWebhookSignatureRequired(t *testing.T) {
	s, _ := newGitHubHookServer(t, "hunter2")
	req := httptest.NewRequest(http.MethodPost, "/hooks/github", strings.NewReader(pushPayload("sha")))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-Hub-Signature-256", signGitHubPayload("wrong-secret", []byte(pushPayload("sha"))))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 got %d", w.Code)
	}
}

func TestGitHubWebhookTriggerFilter(t *testing.T) {
	// Push to main with a pipeline that only allows release/* must not enqueue.
	filtered := `version: 1
on:
  push:
    branches: ["release/*"]
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/contents/.kiwi/pipeline.yaml") {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"content":  base64.StdEncoding.EncodeToString([]byte(filtered)),
				"encoding": "base64",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer api.Close()
	s2 := New("runner-secret")
	s2.GitHubWebhookSecret = "hunter2"
	s2.gitHubAPIBase = api.URL
	s2.PipelinePath = ".kiwi/pipeline.yaml"

	w := postWebhook(t, s2, "hunter2", "push", "filtered-1", pushPayload("9049f1265b7d61be4a8904a9a27120d2064dab3b"))
	if w.Code != http.StatusNoContent {
		t.Fatalf("non-matching push: want 204 got %d: %s", w.Code, w.Body.String())
	}
	s2.mu.Lock()
	n := len(s2.runs)
	s2.mu.Unlock()
	if n != 0 {
		t.Fatalf("filtered push enqueued %d runs", n)
	}
}

func TestGitHubWebhookPing(t *testing.T) {
	s, _ := newGitHubHookServer(t, "hunter2")
	req := httptest.NewRequest(http.MethodPost, "/hooks/github", strings.NewReader(`{"zen":"ok"}`))
	req.Header.Set("X-GitHub-Event", "ping")
	req.Header.Set("X-Hub-Signature-256", signGitHubPayload("hunter2", []byte(`{"zen":"ok"}`)))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("want 204 got %d", w.Code)
	}
}
