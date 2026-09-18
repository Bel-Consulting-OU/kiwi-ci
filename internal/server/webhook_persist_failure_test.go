package server

import (
	"net/http"
	"testing"
)

// TestWebhookPersistFailureMapsTo503FS pins the shared webhook enqueue
// durability contract for the GitLab and Forgejo handlers: a failed snapshot
// write rolls the enqueue back and answers 503 (not 400), the forge retry
// after heal enqueues exactly one run, the delivery dedupes, and the run is
// durable across a restart.
func TestWebhookPersistFailureMapsTo503FS(t *testing.T) {
	api := (&hookAPI{}).server(t)

	t.Run("gitlab", func(t *testing.T) {
		dir := t.TempDir()
		s, err := NewPersistent("token", "token", dir)
		if err != nil {
			t.Fatal(err)
		}
		s.GitLabWebhookSecret = "gl-secret"
		s.gitLabAPIBase = api.URL
		s.PipelinePath = ".kiwi/pipeline.yaml"

		s.persistFailForTest = errFSMatrixSeam
		w := postGitLab(t, s, "gl-secret", "Push Hook", "gl-fs-delivery", gitlabPushEvent)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("gitlab webhook with a broken snapshot = %d, want 503: %s", w.Code, w.Body.String())
		}
		s.mu.Lock()
		runs := len(s.runs)
		s.mu.Unlock()
		if runs != 0 {
			t.Fatalf("refused gitlab webhook left %d run(s)", runs)
		}

		s.persistFailForTest = nil
		w = postGitLab(t, s, "gl-secret", "Push Hook", "gl-fs-delivery", gitlabPushEvent)
		if w.Code != http.StatusAccepted {
			t.Fatalf("healed gitlab webhook = %d, want 202: %s", w.Code, w.Body.String())
		}
		runID, _ := decodeRun(t, w)
		// The forge retry of the same delivery is an idempotent 200 that
		// returns the original run.
		w = postGitLab(t, s, "gl-secret", "Push Hook", "gl-fs-delivery", gitlabPushEvent)
		if w.Code != http.StatusOK {
			t.Fatalf("gitlab retry = %d, want 200: %s", w.Code, w.Body.String())
		}
		if got, _ := decodeRun(t, w); got != runID {
			t.Fatalf("gitlab retry returned run %q, want %q", got, runID)
		}
		s2 := fsMatrixReload(t, dir)
		s2.mu.Lock()
		_, ok := s2.runs[runID]
		n := len(s2.runs)
		s2.mu.Unlock()
		if !ok || n != 1 {
			t.Fatalf("gitlab enqueue not durable: run=%v runs=%d, want exactly 1", ok, n)
		}
	})

	t.Run("forgejo", func(t *testing.T) {
		dir := t.TempDir()
		s, err := NewPersistent("token", "token", dir)
		if err != nil {
			t.Fatal(err)
		}
		s.ForgejoWebhookSecret = "fj-secret"
		s.forgejoAPIBase = api.URL
		s.PipelinePath = ".kiwi/pipeline.yaml"

		s.persistFailForTest = errFSMatrixSeam
		w := postForgejo(t, s, "fj-secret", "push", "fj-fs-delivery", forgejoPushEvent, false)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("forgejo webhook with a broken snapshot = %d, want 503: %s", w.Code, w.Body.String())
		}
		s.mu.Lock()
		runs := len(s.runs)
		s.mu.Unlock()
		if runs != 0 {
			t.Fatalf("refused forgejo webhook left %d run(s)", runs)
		}

		s.persistFailForTest = nil
		w = postForgejo(t, s, "fj-secret", "push", "fj-fs-delivery", forgejoPushEvent, false)
		if w.Code != http.StatusAccepted {
			t.Fatalf("healed forgejo webhook = %d, want 202: %s", w.Code, w.Body.String())
		}
		runID, _ := decodeRun(t, w)
		w = postForgejo(t, s, "fj-secret", "push", "fj-fs-delivery", forgejoPushEvent, false)
		if w.Code != http.StatusOK {
			t.Fatalf("forgejo retry = %d, want 200: %s", w.Code, w.Body.String())
		}
		if got, _ := decodeRun(t, w); got != runID {
			t.Fatalf("forgejo retry returned run %q, want %q", got, runID)
		}
		s2 := fsMatrixReload(t, dir)
		s2.mu.Lock()
		_, ok := s2.runs[runID]
		n := len(s2.runs)
		s2.mu.Unlock()
		if !ok || n != 1 {
			t.Fatalf("forgejo enqueue not durable: run=%v runs=%d, want exactly 1", ok, n)
		}
	})
}
