package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// gitHubHookAPI is a configurable fake GitHub API for webhook branch tests.
type gitHubHookAPI struct {
	fileStatus  int    // contents endpoint status (default 200)
	fileBody    string // pipeline text (default webhookPipeline)
	compareCode int    // compare endpoint status (default 200)
	compareBody string // compare JSON (default {"files":[]})
	compareFull bool   // always return a full 100-file page (never complete)
}

func (h *gitHubHookAPI) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/contents/"):
			status := h.fileStatus
			if status == 0 {
				status = http.StatusOK
			}
			if status != http.StatusOK {
				http.Error(w, "nope", status)
				return
			}
			body := h.fileBody
			if body == "" {
				body = webhookPipeline
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"content":  base64.StdEncoding.EncodeToString([]byte(body)),
				"encoding": "base64",
			})
		case strings.Contains(r.URL.Path, "/compare/"):
			if h.compareFull {
				files := make([]map[string]string, 100)
				for i := range files {
					files[i] = map[string]string{"filename": "src/f.go"}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"files": files})
				return
			}
			code := h.compareCode
			if code == 0 {
				code = http.StatusOK
			}
			if code != http.StatusOK {
				http.Error(w, "nope", code)
				return
			}
			body := h.compareBody
			if body == "" {
				body = `{"files":[]}`
			}
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newGitHubSqueezeServer(t *testing.T, api *httptest.Server, secret string) *Server {
	t.Helper()
	s := New("runner-secret")
	s.GitHubWebhookSecret = secret
	s.gitHubAPIBase = api.URL
	s.PipelinePath = ".kiwi/pipeline.yaml"
	return s
}

func githubPRPayload(action, headNS string) string {
	if headNS == "" {
		headNS = "octocat/hello-world"
	}
	return `{
  "action": "` + action + `",
  "number": 7,
  "repository": {
    "id": 42,
    "full_name": "octocat/hello-world",
    "clone_url": "https://github.com/octocat/hello-world.git",
    "default_branch": "main"
  },
  "pull_request": {
    "draft": false,
    "head": {"ref": "feature", "sha": "headsha", "repo": {"full_name": "` + headNS + `", "clone_url": "https://github.com/` + headNS + `.git"}},
    "base": {"ref": "main", "sha": "basesha", "repo": {"full_name": "octocat/hello-world", "clone_url": "https://github.com/octocat/hello-world.git"}}
  }
}`
}

func TestGitHubWebhookMoreBranches(t *testing.T) {
	api := (&gitHubHookAPI{}).server(t)

	t.Run("body too large", func(t *testing.T) {
		s := newGitHubSqueezeServer(t, api, "hunter2")
		big := strings.Repeat("x", 4<<20+1)
		req := httptest.NewRequest(http.MethodPost, "/hooks/github", strings.NewReader(big))
		req.Header.Set("X-GitHub-Event", "push")
		req.Header.Set("X-Hub-Signature-256", signGitHubPayload("hunter2", []byte(big)))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("want 400 got %d", w.Code)
		}
	})

	t.Run("missing secret", func(t *testing.T) {
		s := newGitHubSqueezeServer(t, api, "")
		if w := postWebhook(t, s, "", "push", "", pushPayload("sha")); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("want 503 got %d", w.Code)
		}
	})

	t.Run("bad payload", func(t *testing.T) {
		s := newGitHubSqueezeServer(t, api, "hunter2")
		if w := postWebhook(t, s, "hunter2", "push", "", "not json"); w.Code != http.StatusBadRequest {
			t.Fatalf("want 400 got %d", w.Code)
		}
	})

	t.Run("empty event context", func(t *testing.T) {
		s := newGitHubSqueezeServer(t, api, "hunter2")
		if w := postWebhook(t, s, "hunter2", "push", "", `{}`); w.Code != http.StatusNoContent {
			t.Fatalf("want 204 got %d", w.Code)
		}
	})

	t.Run("branch deletion", func(t *testing.T) {
		s := newGitHubSqueezeServer(t, api, "hunter2")
		body := `{"ref":"refs/heads/gone","deleted":true,"after":"` + strings.Repeat("0", 40) + `","repository":{"id":42,"full_name":"octocat/hello-world"}}`
		if w := postWebhook(t, s, "hunter2", "push", "", body); w.Code != http.StatusNoContent {
			t.Fatalf("want 204 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("pull request opened", func(t *testing.T) {
		s := newGitHubSqueezeServer(t, api, "hunter2")
		w := postWebhook(t, s, "hunter2", "pull_request", "", githubPRPayload("opened", ""))
		if w.Code != http.StatusAccepted {
			t.Fatalf("want 202 got %d: %s", w.Code, w.Body.String())
		}
		runID, _ := decodeRun(t, w)
		s.mu.Lock()
		run := s.runs[runID]
		s.mu.Unlock()
		if run.Event != "pull_request" || run.SHA != "headsha" {
			t.Fatalf("bad run: %+v", run)
		}
	})

	t.Run("pull request ready_for_review", func(t *testing.T) {
		s := newGitHubSqueezeServer(t, api, "hunter2")
		if w := postWebhook(t, s, "hunter2", "pull_request", "", githubPRPayload("ready_for_review", "")); w.Code != http.StatusAccepted {
			t.Fatalf("want 202 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("pull request reopened", func(t *testing.T) {
		s := newGitHubSqueezeServer(t, api, "hunter2")
		if w := postWebhook(t, s, "hunter2", "pull_request", "", githubPRPayload("reopened", "")); w.Code != http.StatusAccepted {
			t.Fatalf("want 202 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("pull request uninteresting action", func(t *testing.T) {
		s := newGitHubSqueezeServer(t, api, "hunter2")
		if w := postWebhook(t, s, "hunter2", "pull_request", "", githubPRPayload("closed", "")); w.Code != http.StatusNoContent {
			t.Fatalf("want 204 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("untrusted fork PR", func(t *testing.T) {
		forkAPI := (&gitHubHookAPI{fileBody: untrustedPipeline}).server(t)
		s := newGitHubSqueezeServer(t, forkAPI, "hunter2")
		w := postWebhook(t, s, "hunter2", "pull_request", "", githubPRPayload("opened", "fork/hello-world"))
		if w.Code != http.StatusAccepted {
			t.Fatalf("want 202 got %d: %s", w.Code, w.Body.String())
		}
		runID, _ := decodeRun(t, w)
		s.mu.Lock()
		run := s.runs[runID]
		s.mu.Unlock()
		if run.Trusted {
			t.Fatalf("fork PR must be untrusted: %+v", run)
		}
	})

	t.Run("pipeline fetch failure", func(t *testing.T) {
		down := (&gitHubHookAPI{fileStatus: http.StatusNotFound}).server(t)
		s := newGitHubSqueezeServer(t, down, "hunter2")
		if w := postWebhook(t, s, "hunter2", "push", "", pushPayload("sha")); w.Code != http.StatusBadGateway {
			t.Fatalf("want 502 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("pipeline parse failure", func(t *testing.T) {
		bad := (&gitHubHookAPI{fileBody: "{{{"}).server(t)
		s := newGitHubSqueezeServer(t, bad, "hunter2")
		if w := postWebhook(t, s, "hunter2", "push", "", pushPayload("sha")); w.Code != http.StatusBadRequest {
			t.Fatalf("want 400 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("include-path trigger fails closed on compare error", func(t *testing.T) {
		paths := (&gitHubHookAPI{
			fileBody: `version: 1
on:
  push:
    paths: ["src/**"]
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`,
			compareCode: http.StatusInternalServerError,
		}).server(t)
		s := newGitHubSqueezeServer(t, paths, "hunter2")
		if w := postWebhook(t, s, "hunter2", "push", "", pushPayload("sha")); w.Code != http.StatusBadGateway {
			t.Fatalf("want 502 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("include-path trigger fails closed on incomplete diff", func(t *testing.T) {
		paths := (&gitHubHookAPI{
			fileBody: `version: 1
on:
  push:
    paths: ["src/**"]
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`,
			compareFull: true,
		}).server(t)
		s := newGitHubSqueezeServer(t, paths, "hunter2")
		if w := postWebhook(t, s, "hunter2", "push", "", pushPayload("sha")); w.Code != http.StatusBadGateway {
			t.Fatalf("want 502 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("ignore-only trigger tolerates compare error", func(t *testing.T) {
		ignore := (&gitHubHookAPI{
			fileBody: `version: 1
on:
  push:
    paths_ignore: ["docs/**"]
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`,
			compareCode: http.StatusInternalServerError,
		}).server(t)
		s := newGitHubSqueezeServer(t, ignore, "hunter2")
		if w := postWebhook(t, s, "hunter2", "push", "", pushPayload("sha")); w.Code != http.StatusAccepted {
			t.Fatalf("want 202 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("enqueue rejection", func(t *testing.T) {
		invalid := (&gitHubHookAPI{fileBody: `version: 1
inputs:
  who:
    required: true
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`}).server(t)
		s := newGitHubSqueezeServer(t, invalid, "hunter2")
		if w := postWebhook(t, s, "hunter2", "push", "", pushPayload("sha")); w.Code != http.StatusBadRequest {
			t.Fatalf("want 400 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("delivery without header skips recordDelivery", func(t *testing.T) {
		s := newGitHubSqueezeServer(t, api, "hunter2")
		if w := postWebhook(t, s, "hunter2", "push", "", pushPayload("9049f1265b7d61be4a8904a9a27120d2064dab3b")); w.Code != http.StatusAccepted {
			t.Fatalf("want 202 got %d: %s", w.Code, w.Body.String())
		}
		s.mu.Lock()
		n := len(s.deliveries)
		s.mu.Unlock()
		if n != 0 {
			t.Fatalf("deliveries = %v, want empty", s.deliveries)
		}
	})
}

func TestGitHubForgeAppBranch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	s := New("runner-secret")
	s.gitHubAPIBase = "https://api.github.example"
	s.GitHubAppID = 42
	s.GitHubAppPrivateKey = pemKey
	g := s.gitHubForge()
	if g.App == nil {
		t.Fatal("App credentials were not wired into the forge adapter")
	}
	if g.App.BaseURL != s.gitHubAPIBase {
		t.Fatalf("App.BaseURL = %q", g.App.BaseURL)
	}

	// Without a key or with a zero App ID the plain token path applies.
	s2 := New("runner-secret")
	s2.GitHubAppID = 42
	if s2.gitHubForge().App != nil {
		t.Fatal("App must not be wired without a private key")
	}
	s3 := New("runner-secret")
	s3.GitHubAppPrivateKey = pemKey
	if s3.gitHubForge().App != nil {
		t.Fatal("App must not be wired with App ID 0")
	}
}

func TestDedupeRunEdges(t *testing.T) {
	s := New("runner-secret")
	if _, ok := s.dedupeRun("", "repo"); ok {
		t.Fatal("empty delivery must not dedupe")
	}
	s.mu.Lock()
	s.deliveries["dangling"] = "no-such-run"
	s.mu.Unlock()
	if _, ok := s.dedupeRun("dangling", "repo"); ok {
		t.Fatal("delivery pointing at a missing run must not dedupe")
	}

	run, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/acme/backend.git", RepoFullName: "acme/backend",
		Ref: "refs/heads/main", SHA: "sha", Event: "push", Pipeline: untrustedPipeline,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.deliveries["cross-repo"] = run.ID
	s.mu.Unlock()
	if _, ok := s.dedupeRun("cross-repo", "other.example/acme/backend"); ok {
		t.Fatal("a delivery colliding across repositories must not dedupe")
	}
	if got, ok := s.dedupeRun("cross-repo", "github.com/acme/backend"); !ok || got.ID != run.ID {
		t.Fatalf("same-repo delivery must dedupe to %s, got %+v ok=%v", run.ID, got, ok)
	}
}

func TestRecordDeliveryDirect(t *testing.T) {
	s := New("runner-secret")
	s.recordDelivery("", "run-1")
	if len(s.deliveries) != 0 {
		t.Fatalf("empty delivery recorded: %v", s.deliveries)
	}
	s.recordDelivery("del-1", "run-1")
	if s.deliveries["del-1"] != "run-1" {
		t.Fatalf("delivery not recorded: %v", s.deliveries)
	}
	// An existing mapping is authoritative and never rewritten.
	s.recordDelivery("del-1", "run-2")
	if s.deliveries["del-1"] != "run-1" {
		t.Fatalf("delivery overwritten: %v", s.deliveries)
	}
}

func TestPipelinePathDefault(t *testing.T) {
	s := New("runner-secret")
	if got := s.pipelinePath(); got != ".kiwi/pipeline.yaml" {
		t.Fatalf("default pipeline path = %q", got)
	}
	s.PipelinePath = "ci/pipeline.yaml"
	if got := s.pipelinePath(); got != "ci/pipeline.yaml" {
		t.Fatalf("configured pipeline path = %q", got)
	}
}
