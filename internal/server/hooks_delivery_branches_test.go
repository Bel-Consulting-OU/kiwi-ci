package server

// Delivery/gating coverage for the GitLab and Forgejo webhook handlers: the
// schema-compatibility gate, the repository/head identity binding, the
// authenticated rate-limit stage, the terminal ignored-receipt replay and the
// content-mismatch conflict. Every case asserts the HTTP status and (where
// applicable) that nothing was enqueued.

import (
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/ratelimit"
)

func TestGitLabWebhookDeliveryAndGates(t *testing.T) {
	api := (&hookAPI{}).server(t)

	t.Run("schema gate refuses before parse", func(t *testing.T) {
		s := newGitLabSqueezeServer(t, api, "tok")
		s.DB = newDBFakeStore()
		s.mu.Lock()
		s.schemaFloorBad = true
		s.schemaFloor = 9999
		s.schemaFloorCheck = time.Now()
		s.mu.Unlock()
		w := postGitLab(t, s, "tok", "Merge Request Hook", "", gitlabMRPayload("open", ""))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("schema-incompatible webhook = %d, want 503", w.Code)
		}
		if got := w.Header().Get("X-Kiwi-State"); got != "schema-incompatible" {
			t.Fatalf("state header = %q", got)
		}
	})

	t.Run("repository binding mismatch", func(t *testing.T) {
		s := newGitLabSqueezeServer(t, api, "tok")
		body := `{"object_kind":"push","ref":"refs/heads/main","checkout_sha":"9049f1265b7d61be4a8904a9a27120d2064dab3b",
			"project":{"id":1,"path_with_namespace":"acme/backend","http_url_to_repo":"https://gitlab.example/acme/backend.git"},
			"repository":{"name":"backend","git_http_url":"https://gitlab.example/other/repo.git"}}`
		if w := postGitLab(t, s, "tok", "Push Hook", "", body); w.Code != http.StatusBadRequest {
			t.Fatalf("repository binding mismatch = %d, want 400: %s", w.Code, w.Body.String())
		}
	})

	t.Run("head repository binding mismatch", func(t *testing.T) {
		s := newGitLabSqueezeServer(t, api, "tok")
		body := `{"object_kind":"merge_request",
			"project":{"id":7,"path_with_namespace":"acme/backend","default_branch":"main","http_url_to_repo":"https://gitlab.example/acme/backend.git"},
			"object_attributes":{"iid":3,"action":"open","source_branch":"feature","target_branch":"main",
				"last_commit":{"id":"headsha"},"diff_refs":{"base_sha":"basesha","head_sha":"headsha","start_sha":"startsha"},
				"source":{"path_with_namespace":"acme/backend","git_http_url":"https://gitlab.example/other/repo.git","default_branch":"main"},
				"target":{"path_with_namespace":"acme/backend","default_branch":"main"}}}`
		if w := postGitLab(t, s, "tok", "Merge Request Hook", "", body); w.Code != http.StatusBadRequest {
			t.Fatalf("head binding mismatch = %d, want 400: %s", w.Code, w.Body.String())
		}
	})

	t.Run("delivery id reused with different content conflicts", func(t *testing.T) {
		s := newGitLabSqueezeServer(t, api, "tok")
		if w := postGitLab(t, s, "tok", "Merge Request Hook", "gl-conflict-1", gitlabMRPayload("open", "")); w.Code != http.StatusAccepted {
			t.Fatalf("first delivery = %d: %s", w.Code, w.Body.String())
		}
		if w := postGitLab(t, s, "tok", "Merge Request Hook", "gl-conflict-1", gitlabMRPayload("reopen", "")); w.Code != http.StatusConflict {
			t.Fatalf("reused delivery with different content = %d, want 409", w.Code)
		}
	})

	t.Run("ignored receipt replays terminally", func(t *testing.T) {
		s := newGitLabSqueezeServer(t, api, "tok")
		body := gitlabMRPayload("open", "")
		digest := webhookPayloadDigest([]byte(body))
		s.mu.Lock()
		s.deliveries["gl-ignored-1"] = ignoredDeliveryPrefix + digest
		s.mu.Unlock()
		if w := postGitLab(t, s, "tok", "Merge Request Hook", "gl-ignored-1", body); w.Code != http.StatusNoContent {
			t.Fatalf("ignored receipt replay = %d, want 204", w.Code)
		}
		s.mu.Lock()
		runs := len(s.runs)
		s.mu.Unlock()
		if runs != 0 {
			t.Fatalf("ignored replay enqueued %d runs", runs)
		}
	})

	t.Run("post-hmac forge bucket refuses the second delivery", func(t *testing.T) {
		s := newGitLabSqueezeServer(t, api, "tok")
		m := ratelimit.NewMiddleware(map[string]float64{ratelimit.ClassWebhooks: 1000}, 100)
		m.WebhookForge = ratelimit.New(0.000001, 1)
		s.RateLimiter = m
		if w := postGitLab(t, s, "tok", "Merge Request Hook", "gl-rl-1", gitlabMRPayload("open", "")); w.Code != http.StatusAccepted {
			t.Fatalf("first delivery = %d: %s", w.Code, w.Body.String())
		}
		w := postGitLab(t, s, "tok", "Merge Request Hook", "gl-rl-2", gitlabMRPayload("reopen", ""))
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("second delivery = %d, want 429", w.Code)
		}
		if w.Header().Get("Retry-After") == "" {
			t.Fatal("429 without Retry-After")
		}
	})
}

func TestForgejoWebhookDeliveryAndGates(t *testing.T) {
	api := (&hookAPI{}).server(t)

	t.Run("schema gate refuses before parse", func(t *testing.T) {
		s := newForgejoSqueezeServer(t, api, "hmac-secret")
		s.DB = newDBFakeStore()
		s.mu.Lock()
		s.schemaFloorBad = true
		s.schemaFloor = 9999
		s.schemaFloorCheck = time.Now()
		s.mu.Unlock()
		w := postForgejo(t, s, "hmac-secret", "push", "", forgejoPushEvent, false)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("schema-incompatible webhook = %d, want 503", w.Code)
		}
		if got := w.Header().Get("X-Kiwi-State"); got != "schema-incompatible" {
			t.Fatalf("state header = %q", got)
		}
	})

	t.Run("repository binding mismatch", func(t *testing.T) {
		s := newForgejoSqueezeServer(t, api, "hmac-secret")
		body := `{"ref":"refs/heads/main","after":"9049f1265b7d61be4a8904a9a27120d2064dab3b",
			"repository":{"id":5,"full_name":"acme/backend","clone_url":"https://forgejo.example/other/repo.git","default_branch":"main"}}`
		if w := postForgejo(t, s, "hmac-secret", "push", "", body, false); w.Code != http.StatusBadRequest {
			t.Fatalf("repository binding mismatch = %d, want 400: %s", w.Code, w.Body.String())
		}
	})

	t.Run("head repository binding mismatch", func(t *testing.T) {
		s := newForgejoSqueezeServer(t, api, "hmac-secret")
		body := `{"action":"opened","number":4,
			"repository":{"id":5,"full_name":"acme/backend","clone_url":"https://forgejo.example/acme/backend.git","default_branch":"main"},
			"pull_request":{"draft":false,
				"head":{"ref":"feature","sha":"headsha","repo":{"full_name":"acme/backend","clone_url":"https://forgejo.example/other/repo.git"}},
				"base":{"ref":"main","sha":"basesha","repo":{"full_name":"acme/backend","clone_url":"https://forgejo.example/acme/backend.git"}}}}`
		if w := postForgejo(t, s, "hmac-secret", "pull_request", "", body, false); w.Code != http.StatusBadRequest {
			t.Fatalf("head binding mismatch = %d, want 400: %s", w.Code, w.Body.String())
		}
	})

	t.Run("delivery id reused with different content conflicts", func(t *testing.T) {
		s := newForgejoSqueezeServer(t, api, "hmac-secret")
		if w := postForgejo(t, s, "hmac-secret", "pull_request", "fj-conflict-1", forgejoPREventWithAction("opened", ""), false); w.Code != http.StatusAccepted {
			t.Fatalf("first delivery = %d: %s", w.Code, w.Body.String())
		}
		if w := postForgejo(t, s, "hmac-secret", "pull_request", "fj-conflict-1", forgejoPREventWithAction("reopened", ""), false); w.Code != http.StatusConflict {
			t.Fatalf("reused delivery with different content = %d, want 409", w.Code)
		}
	})

	t.Run("ignored receipt replays terminally", func(t *testing.T) {
		s := newForgejoSqueezeServer(t, api, "hmac-secret")
		body := forgejoPREventWithAction("opened", "")
		digest := webhookPayloadDigest([]byte(body))
		s.mu.Lock()
		s.deliveries["fj-ignored-1"] = ignoredDeliveryPrefix + digest
		s.mu.Unlock()
		if w := postForgejo(t, s, "hmac-secret", "pull_request", "fj-ignored-1", body, false); w.Code != http.StatusNoContent {
			t.Fatalf("ignored receipt replay = %d, want 204", w.Code)
		}
		s.mu.Lock()
		runs := len(s.runs)
		s.mu.Unlock()
		if runs != 0 {
			t.Fatalf("ignored replay enqueued %d runs", runs)
		}
	})

	t.Run("gitea event header alias and post-hmac bucket", func(t *testing.T) {
		s := newForgejoSqueezeServer(t, api, "hmac-secret")
		m := ratelimit.NewMiddleware(map[string]float64{ratelimit.ClassWebhooks: 1000}, 100)
		m.WebhookForge = ratelimit.New(0.000001, 1)
		s.RateLimiter = m
		if w := postForgejo(t, s, "hmac-secret", "pull_request", "fj-rl-1", forgejoPREventWithAction("opened", ""), true); w.Code != http.StatusAccepted {
			t.Fatalf("first gitea-header delivery = %d: %s", w.Code, w.Body.String())
		}
		w := postForgejo(t, s, "hmac-secret", "pull_request", "fj-rl-2", forgejoPREventWithAction("reopened", ""), false)
		if w.Code != http.StatusTooManyRequests {
			t.Fatalf("second delivery = %d, want 429", w.Code)
		}
		if w.Header().Get("Retry-After") == "" {
			t.Fatal("429 without Retry-After")
		}
	})
}
