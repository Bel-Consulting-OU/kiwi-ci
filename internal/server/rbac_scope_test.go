package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// scopedStoreServer builds a server with an admin token and two store
// principals: an admin and a repo-only reader. The readers hold NO global
// read role on purpose — their repository map is the only read capability,
// which must still open the collections (requireReadAny) while every run of
// another repository stays excluded.
func scopedStoreServer(t *testing.T) *Server {
	t.Helper()
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for raw, p := range map[string]auth.Principal{
		"reader": {
			Subject: "repo-reader",
			Repositories: map[string]auth.RepositoryPermission{
				"o/repo-a": {Read: true},
			},
		},
		"artifact-reader": {
			Subject: "artifact-reader",
			Repositories: map[string]auth.RepositoryPermission{
				"o/repo-a": {Read: true, ArtifactRead: true},
			},
		},
	} {
		if err := s.AuthStore.AddToken(raw, p); err != nil {
			t.Fatal(err)
		}
	}
	// Seed two runs in two repositories.
	s.mu.Lock()
	now := time.Now().UTC()
	s.runs["run-a"] = model.Run{ID: "run-a", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Status: model.StatusQueued, CreatedAt: now}
	s.runs["run-b"] = model.Run{ID: "run-b", Repo: "https://github.com/o/repo-b.git", RepoFullName: "o/repo-b", Status: model.StatusQueued, CreatedAt: now}
	s.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-a", Key: "build", RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Status: model.StatusQueued}
	s.jobs["job-b"] = model.Job{ID: "job-b", RunID: "run-b", Key: "build", RepoURL: "https://github.com/o/repo-b.git", RepoFullName: "o/repo-b", Status: model.StatusQueued}
	s.artifacts["art-a"] = model.ArtifactRecord{ID: "art-a", RunID: "run-a", JobID: "job-a", Name: "bin", SHA256: "a", CreatedAt: now}
	s.artifacts["art-b"] = model.ArtifactRecord{ID: "art-b", RunID: "run-b", JobID: "job-b", Name: "bin", SHA256: "a", CreatedAt: now}
	s.snapshots["snap-a"] = model.SnapshotRecord{ID: "snap-a", RunID: "run-a", CreatedAt: now}
	s.snapshots["snap-b"] = model.SnapshotRecord{ID: "snap-b", RunID: "run-b", CreatedAt: now}
	s.runners["r-a"] = model.Runner{ID: "r-a", Name: "r-a", Capacity: 1, ActiveJobs: []string{"job-a"}}
	s.runners["r-b"] = model.Runner{ID: "r-b", Name: "r-b", Capacity: 1, ActiveJobs: []string{"job-b"}}
	s.mu.Unlock()
	return s
}

func runIDs(t *testing.T, body string) []string {
	t.Helper()
	var out []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, r := range out {
		ids = append(ids, r.ID)
	}
	return ids
}

func TestScopedListRunsFiltersByRepo(t *testing.T) {
	s := scopedStoreServer(t)
	// The repo-scoped reader sees only run-a.
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs", "reader", "")
	if w.Code != http.StatusOK {
		t.Fatalf("list runs = %d: %s", w.Code, w.Body.String())
	}
	ids := runIDs(t, w.Body.String())
	if len(ids) != 1 || ids[0] != "run-a" {
		t.Fatalf("scoped reader saw %v, want only run-a", ids)
	}
	// The admin sees everything.
	w = doJSON(t, s, http.MethodGet, "/api/v1/runs", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("admin list runs = %d", w.Code)
	}
	if got := runIDs(t, w.Body.String()); len(got) != 2 {
		t.Fatalf("admin saw %v, want both runs", got)
	}
}

func TestScopedRunReadDeniesForeignRepo(t *testing.T) {
	s := scopedStoreServer(t)
	// Same-repo reads work.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-a", "reader", ""); w.Code != http.StatusOK {
		t.Fatalf("read own repo run: %d: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-a/jobs", "reader", ""); w.Code != http.StatusOK {
		t.Fatalf("read own repo jobs: %d: %s", w.Code, w.Body.String())
	}
	// Foreign-repo reads are forbidden.
	for _, path := range []string{
		"/api/v1/runs/run-b",
		"/api/v1/runs/run-b/jobs",
		"/api/v1/runs/run-b/snapshots",
		"/api/v1/runs/run-b/deployments",
		"/api/v1/runs/run-b/artifacts",
	} {
		if w := doJSON(t, s, http.MethodGet, path, "reader", ""); w.Code != http.StatusForbidden {
			t.Fatalf("reader on %s: want 403 got %d: %s", path, w.Code, w.Body.String())
		}
	}
	// A repository read grant without artifact_read cannot list artifacts
	// even on the allowed repo (the repo entry is authoritative).
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-a/artifacts", "reader", ""); w.Code != http.StatusForbidden {
		t.Fatalf("reader without artifact_read: want 403 got %d", w.Code)
	}
	// With artifact_read the same list works and resolves the artifact.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-a/artifacts", "artifact-reader", ""); w.Code != http.StatusOK {
		t.Fatalf("artifact-reader list: %d: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/artifacts/art-b", "artifact-reader", ""); w.Code != http.StatusForbidden {
		t.Fatalf("artifact-reader on foreign artifact: want 403 got %d", w.Code)
	}
}

func TestScopedRunnersFilteredByActiveJobRepo(t *testing.T) {
	s := scopedStoreServer(t)
	w := doJSON(t, s, http.MethodGet, "/api/v1/runners/serving", "reader", "")
	if w.Code != http.StatusOK {
		t.Fatalf("list serving runners = %d: %s", w.Code, w.Body.String())
	}
	var out []struct {
		ID         string   `json:"id"`
		Name       string   `json:"name"`
		Busy       bool     `json:"busy"`
		LastSeen   string   `json:"last_seen"`
		ActiveJobs []string `json:"active_jobs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range out {
		got[r.ID] = true
	}
	if !got["r-a"] {
		t.Fatal("runner serving the allowed repo is not visible")
	}
	if got["r-b"] {
		t.Fatal("runner serving a foreign repo leaked into the scoped list")
	}
	// The full inventory is an operations surface: a read principal gets 403.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runners", "reader", ""); w.Code != http.StatusForbidden {
		t.Fatalf("full runner inventory for a reader: want 403 got %d", w.Code)
	}
}

func TestScopedTestIntelligenceDeniesForeignRepo(t *testing.T) {
	s := scopedStoreServer(t)
	if w := doJSON(t, s, http.MethodGet, "/api/v1/test-intelligence?repo=o/repo-b", "reader", ""); w.Code != http.StatusForbidden {
		t.Fatalf("foreign repo test intelligence: want 403 got %d", w.Code)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/test-intelligence?repo=o/repo-a", "reader", ""); w.Code != http.StatusOK {
		t.Fatalf("own repo test intelligence: want 200 got %d: %s", w.Code, w.Body.String())
	}
}

func TestScopedPrincipalWithoutReadRoleDenied(t *testing.T) {
	s := storeServer(t, "admin-tok", map[string]auth.Principal{
		"run-tok": {Subject: "runner-bot", Roles: []auth.Role{auth.RoleRun}},
	})
	s.mu.Lock()
	s.runs["run-a"] = model.Run{ID: "run-a", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Status: model.StatusQueued, CreatedAt: time.Now()}
	s.mu.Unlock()
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs", "run-tok", ""); w.Code != http.StatusForbidden {
		t.Fatalf("run-only principal listing runs: want 403 got %d", w.Code)
	}
}
