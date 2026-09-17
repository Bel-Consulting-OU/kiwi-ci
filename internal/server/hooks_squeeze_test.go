package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// hookAPI is a configurable fake forge REST API for the GitLab and Forgejo
// webhook handlers. Each field controls one endpoint's response; the zero
// value serves a valid pipeline and a complete (empty) changed-files list.
type hookAPI struct {
	gitlabFileStatus int    // default 200
	gitlabFileBody   string // default webhookPipeline
	gitlabDiffStatus int    // default 200
	gitlabDiffBody   string // default {"diffs":[]}
	forgejoFileErr   bool   // serve a non-200 pipeline fetch
	forgejoDiffErr   bool
	forgejoFullDiff  bool // always return a full 100-file compare page (incomplete)
}

func (h *hookAPI) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/raw"):
			status := h.gitlabFileStatus
			if status == 0 {
				status = http.StatusOK
			}
			if status != http.StatusOK {
				http.Error(w, "nope", status)
				return
			}
			body := h.gitlabFileBody
			if body == "" {
				body = webhookPipeline
			}
			_, _ = io.WriteString(w, body)
		case strings.Contains(r.URL.Path, "/repository/compare"):
			status := h.gitlabDiffStatus
			if status == 0 {
				status = http.StatusOK
			}
			if status != http.StatusOK {
				http.Error(w, "nope", status)
				return
			}
			body := h.gitlabDiffBody
			if body == "" {
				body = `{"diffs":[]}`
			}
			_, _ = io.WriteString(w, body)
		case strings.Contains(r.URL.Path, "/contents/"):
			if h.forgejoFileErr {
				http.Error(w, "nope", http.StatusNotFound)
				return
			}
			body := webhookPipeline
			if h.gitlabFileBody != "" {
				body = h.gitlabFileBody
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"content":  base64.StdEncoding.EncodeToString([]byte(body)),
				"encoding": "base64",
			})
		case strings.Contains(r.URL.Path, "/compare/"):
			if h.forgejoDiffErr {
				http.Error(w, "nope", http.StatusInternalServerError)
				return
			}
			if h.forgejoFullDiff {
				files := make([]map[string]string, 100)
				for i := range files {
					files[i] = map[string]string{"filename": "src/f.go"}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"files": files})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"files": []any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func signForgejo(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// untrustedPipeline is a container pipeline that passes admission for
// untrusted (fork) submissions.
const untrustedPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    steps:
      - run: echo hi
`

const gitlabPushEvent = `{  "object_kind": "push",
  "ref": "refs/heads/main",
  "before": "6113728f27ae82c7b1a177c8d03f9e96e0adf246",
  "after": "9049f1265b7d61be4a8904a9a27120d2064dab3b",
  "checkout_sha": "9049f1265b7d61be4a8904a9a27120d2064dab3b",
  "project": {
    "id": 7,
    "path_with_namespace": "acme/backend",
    "default_branch": "main",
    "http_url_to_repo": "https://gitlab.example/acme/backend.git"
  },
  "repository": {"name": "backend", "git_http_url": "https://gitlab.example/acme/backend.git"}
}`

func gitlabMRPayload(action, headNS string) string {
	if headNS == "" {
		headNS = "acme/backend"
	}
	return `{
  "object_kind": "merge_request",
  "project": {"id": 7, "path_with_namespace": "acme/backend", "default_branch": "main", "http_url_to_repo": "https://gitlab.example/acme/backend.git"},
  "object_attributes": {
    "iid": 3,
    "action": "` + action + `",
    "source_branch": "feature",
    "target_branch": "main",
    "last_commit": {"id": "headsha"},
    "diff_refs": {"base_sha": "basesha", "head_sha": "headsha", "start_sha": "startsha"},
    "source": {"path_with_namespace": "` + headNS + `", "git_http_url": "https://gitlab.example/` + headNS + `.git", "default_branch": "main"},
    "target": {"path_with_namespace": "acme/backend", "default_branch": "main"}
  }
}`
}

const forgejoPushEvent = `{
  "ref": "refs/heads/main",
  "before": "6113728f27ae82c7b1a177c8d03f9e96e0adf246",
  "after": "9049f1265b7d61be4a8904a9a27120d2064dab3b",
  "repository": {"id": 5, "full_name": "acme/backend", "clone_url": "https://forgejo.example/acme/backend.git", "default_branch": "main"}
}`

func forgejoPREventWithAction(action, headNS string) string {
	if headNS == "" {
		headNS = "acme/backend"
	}
	return `{
  "action": "` + action + `",
  "number": 4,
  "repository": {"id": 5, "full_name": "acme/backend", "clone_url": "https://forgejo.example/acme/backend.git", "default_branch": "main"},
  "pull_request": {
    "draft": false,
    "head": {"ref": "feature", "sha": "headsha", "repo": {"full_name": "` + headNS + `", "clone_url": "https://forgejo.example/` + headNS + `.git"}},
    "base": {"ref": "main", "sha": "basesha", "repo": {"full_name": "acme/backend", "clone_url": "https://forgejo.example/acme/backend.git"}}
  }
}`
}

const forgejoPREvent = `{
  "action": "opened",
  "number": 4,
  "repository": {"id": 5, "full_name": "acme/backend", "clone_url": "https://forgejo.example/acme/backend.git", "default_branch": "main"},
  "pull_request": {
    "draft": false,
    "head": {"ref": "feature", "sha": "headsha", "repo": {"full_name": "acme/backend", "clone_url": "https://forgejo.example/acme/backend.git"}},
    "base": {"ref": "main", "sha": "basesha", "repo": {"full_name": "acme/backend", "clone_url": "https://forgejo.example/acme/backend.git"}}
  }
}`

func newGitLabSqueezeServer(t *testing.T, api *httptest.Server, secret string) *Server {
	t.Helper()
	s := New("runner-secret")
	s.GitLabWebhookSecret = secret
	s.gitLabAPIBase = api.URL
	s.PipelinePath = ".kiwi/pipeline.yaml"
	return s
}

func newForgejoSqueezeServer(t *testing.T, api *httptest.Server, secret string) *Server {
	t.Helper()
	s := New("runner-secret")
	s.ForgejoWebhookSecret = secret
	s.forgejoAPIBase = api.URL
	s.PipelinePath = ".kiwi/pipeline.yaml"
	return s
}

func postGitLab(t *testing.T, s *Server, token, event, delivery, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/hooks/gitlab", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if event != "" {
		req.Header.Set("X-Gitlab-Event", event)
	}
	if token != "" {
		req.Header.Set("X-Gitlab-Token", token)
	}
	if delivery != "" {
		req.Header.Set("X-Gitlab-Event-UUID", delivery)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func postForgejo(t *testing.T, s *Server, secret, event, delivery, body string, giteaHeader bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/hooks/forgejo", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if event != "" {
		if giteaHeader {
			req.Header.Set("X-Gitea-Event", event)
		} else {
			req.Header.Set("X-Forgejo-Event", event)
		}
	}
	if secret != "" {
		req.Header.Set("X-Hub-Signature-256", signForgejo(secret, []byte(body)))
	}
	if delivery != "" {
		req.Header.Set("X-Forgejo-Delivery", delivery)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func TestGitLabWebhookBranches(t *testing.T) {
	api := (&hookAPI{}).server(t)

	t.Run("missing secret", func(t *testing.T) {
		s := newGitLabSqueezeServer(t, api, "")
		if w := postGitLab(t, s, "tok", "Push Hook", "", gitlabPushEvent); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("want 503 got %d", w.Code)
		}
	})

	t.Run("bad token", func(t *testing.T) {
		s := newGitLabSqueezeServer(t, api, "right")
		if w := postGitLab(t, s, "wrong", "Push Hook", "", gitlabPushEvent); w.Code != http.StatusUnauthorized {
			t.Fatalf("want 401 got %d", w.Code)
		}
	})

	t.Run("body too large", func(t *testing.T) {
		s := newGitLabSqueezeServer(t, api, "tok")
		big := strings.Repeat("x", 4<<20+1)
		if w := postGitLab(t, s, "tok", "Push Hook", "", big); w.Code != http.StatusBadRequest {
			t.Fatalf("want 400 got %d", w.Code)
		}
	})

	t.Run("ping", func(t *testing.T) {
		s := newGitLabSqueezeServer(t, api, "tok")
		if w := postGitLab(t, s, "tok", "Ping Hook", "", `{"zen":"ok"}`); w.Code != http.StatusNoContent {
			t.Fatalf("want 204 got %d", w.Code)
		}
	})

	t.Run("bad payload", func(t *testing.T) {
		s := newGitLabSqueezeServer(t, api, "tok")
		if w := postGitLab(t, s, "tok", "Push Hook", "", "not json"); w.Code != http.StatusBadRequest {
			t.Fatalf("want 400 got %d", w.Code)
		}
	})

	t.Run("unknown event", func(t *testing.T) {
		s := newGitLabSqueezeServer(t, api, "tok")
		if w := postGitLab(t, s, "tok", "Push Hook", "", `{"object_kind":"unknown"}`); w.Code != http.StatusNoContent {
			t.Fatalf("want 204 got %d", w.Code)
		}
	})

	t.Run("branch deletion push", func(t *testing.T) {
		s := newGitLabSqueezeServer(t, api, "tok")
		body := `{"object_kind":"push","ref":"refs/heads/gone","checkout_sha":"","after":"` + strings.Repeat("0", 40) + `","project":{"id":1,"path_with_namespace":"acme/backend","http_url_to_repo":"https://gitlab.example/acme/backend.git"}}`
		if w := postGitLab(t, s, "tok", "Push Hook", "", body); w.Code != http.StatusNoContent {
			t.Fatalf("want 204 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("merge request opened enqueues", func(t *testing.T) {
		s := newGitLabSqueezeServer(t, api, "tok")
		w := postGitLab(t, s, "tok", "Merge Request Hook", "gl-mr-1", gitlabMRPayload("open", ""))
		if w.Code != http.StatusAccepted {
			t.Fatalf("want 202 got %d: %s", w.Code, w.Body.String())
		}
		runID, _ := decodeRun(t, w)
		s.mu.Lock()
		run := s.runs[runID]
		s.mu.Unlock()
		if run.Event != "merge_request" || run.SHA != "headsha" {
			t.Fatalf("bad run: %+v", run)
		}
		if run.Metadata["gitlab_delivery"] != "gl-mr-1" {
			t.Fatalf("delivery not recorded: %v", run.Metadata)
		}
		// Replayed delivery returns the original run.
		w2 := postGitLab(t, s, "tok", "Merge Request Hook", "gl-mr-1", gitlabMRPayload("open", ""))
		if w2.Code != http.StatusOK {
			t.Fatalf("dedupe: want 200 got %d: %s", w2.Code, w2.Body.String())
		}
		if id2, _ := decodeRun(t, w2); id2 != runID {
			t.Fatalf("dedupe returned %s want %s", id2, runID)
		}
	})

	t.Run("merge request uninteresting action", func(t *testing.T) {
		s := newGitLabSqueezeServer(t, api, "tok")
		if w := postGitLab(t, s, "tok", "Merge Request Hook", "", gitlabMRPayload("close", "")); w.Code != http.StatusNoContent {
			t.Fatalf("want 204 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("untrusted fork MR uses base sha", func(t *testing.T) {
		forkAPI := (&hookAPI{gitlabFileBody: untrustedPipeline}).server(t)
		s := newGitLabSqueezeServer(t, forkAPI, "tok")
		w := postGitLab(t, s, "tok", "Merge Request Hook", "", gitlabMRPayload("update", "fork/backend"))
		if w.Code != http.StatusAccepted {
			t.Fatalf("want 202 got %d: %s", w.Code, w.Body.String())
		}
		runID, _ := decodeRun(t, w)
		s.mu.Lock()
		run := s.runs[runID]
		s.mu.Unlock()
		if run.Trusted {
			t.Fatalf("fork MR must be untrusted: %+v", run)
		}
	})

	t.Run("pipeline fetch failure", func(t *testing.T) {
		down := (&hookAPI{gitlabFileStatus: http.StatusNotFound}).server(t)
		s := newGitLabSqueezeServer(t, down, "tok")
		if w := postGitLab(t, s, "tok", "Push Hook", "", gitlabPushEvent); w.Code != http.StatusBadGateway {
			t.Fatalf("want 502 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("pipeline parse failure", func(t *testing.T) {
		bad := (&hookAPI{gitlabFileBody: "{{{"}).server(t)
		s := newGitLabSqueezeServer(t, bad, "tok")
		if w := postGitLab(t, s, "tok", "Push Hook", "", gitlabPushEvent); w.Code != http.StatusBadRequest {
			t.Fatalf("want 400 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("include-path trigger with unavailable diff fails closed", func(t *testing.T) {
		api := (&hookAPI{
			gitlabFileBody: `version: 1
on:
  push:
    paths: ["src/**"]
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`,
			gitlabDiffStatus: http.StatusNotFound,
		}).server(t)
		s := newGitLabSqueezeServer(t, api, "tok")
		if w := postGitLab(t, s, "tok", "Push Hook", "", gitlabPushEvent); w.Code != http.StatusBadGateway {
			t.Fatalf("want 502 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("trigger filter no match", func(t *testing.T) {
		filtered := (&hookAPI{gitlabFileBody: `version: 1
on:
  push:
    branches: ["release/*"]
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`}).server(t)
		s := newGitLabSqueezeServer(t, filtered, "tok")
		if w := postGitLab(t, s, "tok", "Push Hook", "", gitlabPushEvent); w.Code != http.StatusNoContent {
			t.Fatalf("want 204 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("enqueue rejection", func(t *testing.T) {
		// A syntactically valid pipeline with a missing required input is
		// rejected by enqueue-time input validation.
		invalid := (&hookAPI{gitlabFileBody: `version: 1
inputs:
  who:
    required: true
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`}).server(t)
		s := newGitLabSqueezeServer(t, invalid, "tok")
		w := postGitLab(t, s, "tok", "Push Hook", "", gitlabPushEvent)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("want 400 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("ignore-only trigger tolerates diff error", func(t *testing.T) {
		ignoreOnly := `version: 1
on:
  push:
    paths_ignore: ["docs/**"]
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`
		errAPI := (&hookAPI{gitlabFileBody: ignoreOnly, gitlabDiffStatus: http.StatusInternalServerError}).server(t)
		s := newGitLabSqueezeServer(t, errAPI, "tok")
		if w := postGitLab(t, s, "tok", "Push Hook", "", gitlabPushEvent); w.Code != http.StatusAccepted {
			t.Fatalf("want 202 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("ignore-only trigger tolerates incomplete diff", func(t *testing.T) {
		ignoreOnly := `version: 1
on:
  push:
    paths_ignore: ["docs/**"]
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`
		shortAPI := (&hookAPI{gitlabFileBody: ignoreOnly, gitlabDiffStatus: http.StatusNotFound}).server(t)
		s := newGitLabSqueezeServer(t, shortAPI, "tok")
		if w := postGitLab(t, s, "tok", "Push Hook", "", gitlabPushEvent); w.Code != http.StatusAccepted {
			t.Fatalf("want 202 got %d: %s", w.Code, w.Body.String())
		}
	})
}

func TestForgejoWebhookBranches(t *testing.T) {
	api := (&hookAPI{}).server(t)

	t.Run("missing secret", func(t *testing.T) {
		s := newForgejoSqueezeServer(t, api, "")
		if w := postForgejo(t, s, "", "push", "", forgejoPushEvent, false); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("want 503 got %d", w.Code)
		}
	})

	t.Run("bad signature", func(t *testing.T) {
		s := newForgejoSqueezeServer(t, api, "right")
		if w := postForgejo(t, s, "wrong", "push", "", forgejoPushEvent, false); w.Code != http.StatusUnauthorized {
			t.Fatalf("want 401 got %d", w.Code)
		}
	})

	t.Run("body too large", func(t *testing.T) {
		s := newForgejoSqueezeServer(t, api, "tok")
		if w := postForgejo(t, s, "tok", "push", "", strings.Repeat("x", 4<<20+1), false); w.Code != http.StatusBadRequest {
			t.Fatalf("want 400 got %d", w.Code)
		}
	})

	t.Run("ping", func(t *testing.T) {
		s := newForgejoSqueezeServer(t, api, "tok")
		if w := postForgejo(t, s, "tok", "ping", "", `{"zen":"ok"}`, false); w.Code != http.StatusNoContent {
			t.Fatalf("want 204 got %d", w.Code)
		}
	})

	t.Run("gitea event header fallback", func(t *testing.T) {
		s := newForgejoSqueezeServer(t, api, "tok")
		if w := postForgejo(t, s, "tok", "ping", "", `{"zen":"ok"}`, true); w.Code != http.StatusNoContent {
			t.Fatalf("want 204 got %d", w.Code)
		}
	})

	t.Run("bad payload", func(t *testing.T) {
		s := newForgejoSqueezeServer(t, api, "tok")
		if w := postForgejo(t, s, "tok", "push", "", "not json", false); w.Code != http.StatusBadRequest {
			t.Fatalf("want 400 got %d", w.Code)
		}
	})

	t.Run("empty event context", func(t *testing.T) {
		s := newForgejoSqueezeServer(t, api, "tok")
		if w := postForgejo(t, s, "tok", "push", "", `{}`, false); w.Code != http.StatusNoContent {
			t.Fatalf("want 204 got %d", w.Code)
		}
	})

	t.Run("branch deletion push", func(t *testing.T) {
		s := newForgejoSqueezeServer(t, api, "tok")
		body := `{"ref":"refs/heads/gone","deleted":true,"after":"` + strings.Repeat("0", 40) + `","repository":{"id":5,"full_name":"acme/backend"}}`
		if w := postForgejo(t, s, "tok", "push", "", body, false); w.Code != http.StatusNoContent {
			t.Fatalf("want 204 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("pull request opened enqueues", func(t *testing.T) {
		s := newForgejoSqueezeServer(t, api, "tok")
		w := postForgejo(t, s, "tok", "pull_request", "fj-pr-1", forgejoPREvent, false)
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
		if run.Metadata["forgejo_delivery"] != "fj-pr-1" {
			t.Fatalf("delivery not recorded: %v", run.Metadata)
		}
		w2 := postForgejo(t, s, "tok", "pull_request", "fj-pr-1", forgejoPREvent, false)
		if w2.Code != http.StatusOK {
			t.Fatalf("dedupe: want 200 got %d: %s", w2.Code, w2.Body.String())
		}
		if id2, _ := decodeRun(t, w2); id2 != runID {
			t.Fatalf("dedupe returned %s want %s", id2, runID)
		}
	})

	t.Run("pull request uninteresting action", func(t *testing.T) {
		s := newForgejoSqueezeServer(t, api, "tok")
		if w := postForgejo(t, s, "tok", "pull_request", "", forgejoPREventWithAction("closed", ""), false); w.Code != http.StatusNoContent {
			t.Fatalf("want 204 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("pull request ready_for_review", func(t *testing.T) {
		s := newForgejoSqueezeServer(t, api, "tok")
		if w := postForgejo(t, s, "tok", "pull_request", "", forgejoPREventWithAction("ready_for_review", ""), false); w.Code != http.StatusAccepted {
			t.Fatalf("want 202 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("untrusted fork PR uses base sha", func(t *testing.T) {
		forkAPI := (&hookAPI{gitlabFileBody: untrustedPipeline}).server(t)
		s := newForgejoSqueezeServer(t, forkAPI, "tok")
		w := postForgejo(t, s, "tok", "pull_request", "", forgejoPREventWithAction("opened", "fork/backend"), false)
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
		down := (&hookAPI{forgejoFileErr: true}).server(t)
		s := newForgejoSqueezeServer(t, down, "tok")
		if w := postForgejo(t, s, "tok", "push", "", forgejoPushEvent, false); w.Code != http.StatusBadGateway {
			t.Fatalf("want 502 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("pipeline parse failure", func(t *testing.T) {
		bad := (&hookAPI{gitlabFileBody: "{{{"}).server(t)
		s := newForgejoSqueezeServer(t, bad, "tok")
		if w := postForgejo(t, s, "tok", "push", "", forgejoPushEvent, false); w.Code != http.StatusBadRequest {
			t.Fatalf("want 400 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("include-path trigger with unavailable diff fails closed", func(t *testing.T) {
		api := (&hookAPI{
			forgejoDiffErr: true,
			gitlabFileBody: `version: 1
on:
  push:
    paths: ["src/**"]
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`,
		}).server(t)
		s := newForgejoSqueezeServer(t, api, "tok")
		if w := postForgejo(t, s, "tok", "push", "", forgejoPushEvent, false); w.Code != http.StatusBadGateway {
			t.Fatalf("want 502 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("trigger filter no match", func(t *testing.T) {
		filtered := (&hookAPI{gitlabFileBody: `version: 1
on:
  push:
    branches: ["release/*"]
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`}).server(t)
		s := newForgejoSqueezeServer(t, filtered, "tok")
		if w := postForgejo(t, s, "tok", "push", "", forgejoPushEvent, false); w.Code != http.StatusNoContent {
			t.Fatalf("want 204 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("enqueue rejection", func(t *testing.T) {
		invalid := (&hookAPI{gitlabFileBody: `version: 1
inputs:
  who:
    required: true
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`}).server(t)
		s := newForgejoSqueezeServer(t, invalid, "tok")
		if w := postForgejo(t, s, "tok", "push", "", forgejoPushEvent, false); w.Code != http.StatusBadRequest {
			t.Fatalf("want 400 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("ignore-only trigger tolerates diff error", func(t *testing.T) {
		ignoreOnly := `version: 1
on:
  push:
    paths_ignore: ["docs/**"]
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`
		errAPI := (&hookAPI{gitlabFileBody: ignoreOnly, forgejoDiffErr: true}).server(t)
		s := newForgejoSqueezeServer(t, errAPI, "tok")
		if w := postForgejo(t, s, "tok", "push", "", forgejoPushEvent, false); w.Code != http.StatusAccepted {
			t.Fatalf("want 202 got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("ignore-only trigger tolerates incomplete diff", func(t *testing.T) {
		ignoreOnly := `version: 1
on:
  push:
    paths_ignore: ["docs/**"]
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`
		shortAPI := (&hookAPI{gitlabFileBody: ignoreOnly, forgejoFullDiff: true}).server(t)
		s := newForgejoSqueezeServer(t, shortAPI, "tok")
		if w := postForgejo(t, s, "tok", "push", "", forgejoPushEvent, false); w.Code != http.StatusAccepted {
			t.Fatalf("want 202 got %d: %s", w.Code, w.Body.String())
		}
	})
}
