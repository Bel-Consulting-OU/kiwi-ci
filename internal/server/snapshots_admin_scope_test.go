package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestRequireRunAdminResolvesRunCanonicalRepo pins the handler-level gate the
// snapshot download uses: the admin action is resolved against the RUN's
// canonical repository identity (including a run that carries only a clone
// URL), and no repository grant set can satisfy it — only the global admin
// role does.
func TestRequireRunAdminResolvesRunCanonicalRepo(t *testing.T) {
	s := New("admin-tok")
	// Identity derived from the clone URL alone: the same canonical
	// resolution every other per-run route performs.
	run := model.Run{ID: "run-1", Repo: "https://GitHub.COM:443/o/repo-a.git", RepoFullName: "o/repo-a"}
	if got := repoIDForRun(run); got != "github.com/o/repo-a" {
		t.Fatalf("run canonical repo = %q, want github.com/o/repo-a", got)
	}
	allRepoPerms := auth.RepositoryPermission{
		Read: true, Run: true, TrustedRun: true, Approve: true,
		Cancel: true, Rerun: true, ArtifactRead: true,
	}
	cases := []struct {
		name string
		p    auth.Principal
		want bool
	}{
		{"global read", auth.Principal{Subject: "r", Roles: []auth.Role{auth.RoleRead}}, false},
		{"every repository permission", auth.Principal{Subject: "r", Repositories: map[string]auth.RepositoryPermission{"o/repo-a": allRepoPerms}}, false},
		{"bare-alias repository permission", auth.Principal{Subject: "r", Repositories: map[string]auth.RepositoryPermission{"github.com/o/repo-a": allRepoPerms}}, false},
		{"admin", auth.Principal{Subject: "a", Roles: []auth.Role{auth.RoleAdmin}}, true},
		{"admin with a denying repo entry", auth.Principal{Subject: "a", Roles: []auth.Role{auth.RoleAdmin}, Repositories: map[string]auth.RepositoryPermission{"github.com/o/repo-a": {}}}, true},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/runs/run-1/snapshots/s1", nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), tc.p))
		w := httptest.NewRecorder()
		if got := s.requireRunAdmin(w, req, run); got != tc.want {
			t.Errorf("%s: requireRunAdmin = %v (status %d), want %v", tc.name, got, w.Code, tc.want)
		}
		if !tc.want && w.Code != http.StatusForbidden {
			t.Errorf("%s: denial status = %d, want 403", tc.name, w.Code)
		}
	}
	// No principal is the documented legacy open mode: the outer tier owns
	// the gate and the handler must not invent an identity to deny.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/runs/run-1/snapshots/s1", nil)
	if !s.requireRunAdmin(httptest.NewRecorder(), req, run) {
		t.Fatal("no-principal legacy mode must not be gated in the handler")
	}
}
