package server

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestMemoryCacheCommitHoldsOneCriticalSection pins the filesystem/memory
// cache commit contract: the lease revalidation and the manifest publication
// happen inside ONE s.mu critical section, exactly the lock cancellation
// takes, so no cancellation can interleave between them.
func TestMemoryCacheCommitHoldsOneCriticalSection(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().UTC().Add(time.Hour)
	token := "cache-lease-token"
	s.mu.Lock()
	s.runs["run-a"] = model.Run{ID: "run-a", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", RepoID: "github.com/o/repo-a", Status: model.StatusRunning}
	s.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-a", Key: "build", RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", RepoID: "github.com/o/repo-a",
		Status: model.StatusRunning, Trusted: true, LeaseRunnerID: "runner-a", LeaseTokenHash: hashLeaseToken(s.leaseKey, token), LeaseGeneration: 5, LeaseExpiresAt: &exp}
	s.mu.Unlock()

	entered := make(chan struct{})
	release := make(chan struct{})
	prev := cacheCommitHook
	cacheCommitHook = func() {
		close(entered)
		<-release
	}
	t.Cleanup(func() { cacheCommitHook = prev })

	key := strings.Repeat("a", 64)
	hdrs := map[string]string{"X-Kiwi-Runner-ID": "runner-a", "X-Kiwi-Lease-Token": token, "X-Kiwi-Lease-Generation": "5"}
	type result struct {
		code int
		body string
	}
	done := make(chan result, 1)
	go func() {
		w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "payload", hdrs)
		done <- result{w.Code, w.Body.String()}
	}()
	select {
	case <-entered:
	case r := <-done:
		t.Fatalf("upload finished before the commit section: %d %s", r.code, r.body)
	case <-time.After(5 * time.Second):
		t.Fatal("upload never reached the commit critical section")
	}
	if s.mu.TryLock() {
		s.mu.Unlock()
		t.Fatal("cache commit released s.mu between lease validation and publication")
	}
	close(release)
	if r := <-done; r.code != http.StatusCreated {
		t.Fatalf("cache upload = %d, want 201: %s", r.code, r.body)
	}
}

// TestMemoryCacheCommitRefusedAfterCancellation pins the other direction: a
// cancellation that wins before the commit must prevent the manifest from
// becoming authoritative.
func TestMemoryCacheCommitRefusedAfterCancellation(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().UTC().Add(time.Hour)
	token := "cache-lease-token"
	s.mu.Lock()
	s.runs["run-a"] = model.Run{ID: "run-a", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", RepoID: "github.com/o/repo-a", Status: model.StatusRunning}
	s.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-a", Key: "build", RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", RepoID: "github.com/o/repo-a",
		Status: model.StatusRunning, Trusted: true, LeaseRunnerID: "runner-a", LeaseTokenHash: hashLeaseToken(s.leaseKey, token), LeaseGeneration: 5, LeaseExpiresAt: &exp}
	// Cancellation wins first: the lease is revoked before the upload commits.
	cancelled := s.jobs["job-a"]
	cancelled.Status = model.StatusCancelled
	cancelled.LeaseExpiresAt = nil
	cancelled.LeaseTokenHash = nil
	s.jobs["job-a"] = cancelled
	s.mu.Unlock()

	key := strings.Repeat("a", 64)
	hdrs := map[string]string{"X-Kiwi-Runner-ID": "runner-a", "X-Kiwi-Lease-Token": token, "X-Kiwi-Lease-Generation": "5"}
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "payload", hdrs)
	if w.Code != http.StatusConflict {
		t.Fatalf("cache upload after cancellation = %d, want 409", w.Code)
	}
	matches, gerr := filepath.Glob(filepath.Join(s.store.Root, "cache", "*.manifest.json"))
	if gerr != nil {
		t.Fatal(gerr)
	}
	if len(matches) != 0 {
		t.Fatalf("cancelled upload still published cache manifests: %v", matches)
	}
}
