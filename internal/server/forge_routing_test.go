package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func modelRunForForge(kind, host, full, sha string) model.Run {
	return model.Run{ID: "r-" + kind, RepoID: host + "/" + full, PolicyRepoID: host + "/" + full,
		RepoFullName: full, ForgeKind: kind, ForgeHost: host, SHA: sha, Status: model.StatusFailure}
}

// TestForgeCheckRoutingNeverCrossesForges is the multi-forge regression:
// identical owner/repo names on different forges must dispatch to their own
// adapter, and a GitHub check intent whose payload names GitLab must never
// reach the GitHub API even when GitHub credentials are configured.
func TestForgeCheckRoutingNeverCrossesForges(t *testing.T) {
	// Fake GitLab instance: records every API path it receives.
	gitlabHits := 0
	gitlabAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gitlabHits++
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer gitlabAPI.Close()

	s := New("secret")
	s.GitLabToken = "gl-token"
	s.gitLabAPIBase = gitlabAPI.URL
	s.GitHubToken = "gh-token"
	s.gitHubAPIBase = "https://api.github.invalid"

	run := modelRunForForge("gitlab", "gitlab.example.com", "acme/backend", "sha-1")
	item := s.checkIntent(run, "Pipeline", "completed", "success", "ok", nil)
	if item.Kind != forge.OutboxKindGitLabCheck {
		t.Fatalf("intent kind = %q, want gitlab_check", item.Kind)
	}
	var p forge.CheckPayload
	if err := json.Unmarshal(item.Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.ForgeKind != "gitlab" || p.ForgeHost != "gitlab.example.com" {
		t.Fatalf("payload forge identity = %q/%q", p.ForgeKind, p.ForgeHost)
	}
	if err := s.dispatchOutbox(context.Background(), item); err != nil {
		t.Fatalf("dispatch gitlab check: %v", err)
	}
	if gitlabHits == 0 {
		t.Fatal("gitlab adapter was never invoked for a gitlab run")
	}

	// A github_check intent carrying a gitlab payload is dropped, never
	// sent to the GitHub API.
	misrouted := forge.OutboxItem{Kind: forge.OutboxKindGitHubCheck, Payload: item.Payload}
	if err := s.dispatchOutbox(context.Background(), misrouted); err != nil {
		t.Fatalf("misrouted dispatch must be a silent drop, got %v", err)
	}
	// And publishing a gitlab run must never yield GitHub check intents.
	_ = s.publishForgeStatus(context.Background(), run)
	for _, it := range s.outbox.Pending() {
		if it.Kind == forge.OutboxKindGitHubCheck {
			t.Fatalf("gitlab run queued a github check intent")
		}
	}
	// The NEUTRAL completion path, however, must publish a GitLab run
	// through the GitLab adapter: gitlab_check intents (+ the terminal job).
	s.mu.Lock()
	s.runs[run.ID] = run
	s.jobs["j-gl1"] = model.Job{ID: "j-gl1", RunID: run.ID, Key: "build", Status: model.StatusSuccess}
	s.mu.Unlock()
	s.publishForgeStatus(context.Background(), run)
	pending := s.outbox.Pending()
	if len(pending) == 0 {
		t.Fatal("neutral publication produced no intents for a gitlab run")
	}
	for _, it := range pending {
		if it.Kind != forge.OutboxKindGitLabCheck {
			t.Fatalf("neutral publication emitted %q for a gitlab run, want gitlab_check", it.Kind)
		}
	}
}
