package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// benchGitHubPRPayload is a valid pull_request delivery whose action is not
// a trigger: the handler verifies the signature, parses the payload, binds
// the repository identity and returns 204 without touching the forge API.
// That is the shape of most webhook load.
func benchGitHubPRPayload() []byte {
	return []byte(`{
  "action": "labeled",
  "number": 7,
  "repository": {
    "id": 42,
    "full_name": "octocat/hello-world",
    "clone_url": "https://github.com/octocat/hello-world.git",
    "default_branch": "main"
  },
  "pull_request": {
    "draft": false,
    "head": {"ref": "feature", "sha": "headsha", "repo": {"full_name": "octocat/hello-world", "clone_url": "https://github.com/octocat/hello-world.git"}},
    "base": {"ref": "main", "sha": "basesha", "repo": {"full_name": "octocat/hello-world", "clone_url": "https://github.com/octocat/hello-world.git"}}
  }
}`)
}

// BenchmarkGitHubWebhookDispatchEarlyExit measures the full unauthenticated
// webhook ingress (bounded body read, HMAC verification, JSON parse,
// repository identity binding, trigger decision) for a non-triggering
// delivery.
func BenchmarkGitHubWebhookDispatchEarlyExit(b *testing.B) {
	s := New("runner-secret")
	s.GitHubWebhookSecret = "bench-secret"
	body := benchGitHubPRPayload()
	sig := signGitHubPayload("bench-secret", body)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/hooks/github", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", "pull_request")
		req.Header.Set("X-Hub-Signature-256", sig)
		req.Header.Set("X-GitHub-Delivery", fmt.Sprintf("bench-%d", i))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusNoContent {
			b.Fatalf("dispatch = %d: %s", w.Code, w.Body.String())
		}
	}
}

// BenchmarkGitHubWebhookRejectsBadSignature measures the rejection path
// (the pre-authentication load an attacker controls).
func BenchmarkGitHubWebhookRejectsBadSignature(b *testing.B) {
	s := New("runner-secret")
	s.GitHubWebhookSecret = "bench-secret"
	body := benchGitHubPRPayload()
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/hooks/github", bytes.NewReader(body))
		req.Header.Set("X-GitHub-Event", "pull_request")
		req.Header.Set("X-Hub-Signature-256", "sha256="+fmt.Sprintf("%064x", i))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			b.Fatalf("dispatch = %d: %s", w.Code, w.Body.String())
		}
	}
}
