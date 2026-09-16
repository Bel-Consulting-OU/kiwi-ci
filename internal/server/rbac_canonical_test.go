package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
)

const simpleContainerPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    steps:
      - run: echo hi
`

// TestCanonicalReposNeverShareAuthorization (P1-21): a principal keyed for
// github.com/acme/service grants NOTHING for gitlab.example/acme/service —
// the bare form is never derived implicitly from canonical keys.
func TestCanonicalReposNeverShareAuthorization(t *testing.T) {
	s := storeServer(t, "", map[string]auth.Principal{
		"github-token": {
			Subject: "github-bot",
			Repositories: map[string]auth.RepositoryPermission{
				"github.com/acme/service": {Run: true},
			},
		},
	})
	c := newTestClient(t, s.Handler(), "github-token")
	// The principal's own forge: authorized.
	w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/acme/service.git", RepoFullName: "acme/service", Ref: "main", Pipeline: simpleContainerPipeline}, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("github submit = %d, want 202: %s", w.Code, w.Body.String())
	}
	// A different forge with the same bare full name: strictly denied.
	w = c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://gitlab.example/acme/service.git", RepoFullName: "acme/service", Ref: "main", Pipeline: simpleContainerPipeline}, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("gitlab submit via github principal = %d, want 403: %s", w.Code, w.Body.String())
	}
	// A BARE identity (no repo URL at all) must not match the canonical
	// key either — the old bare-to-canonical fallback is gone.
	w = c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoFullName: "acme/service", Ref: "main", Pipeline: simpleContainerPipeline}, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("bare submit via canonical principal = %d, want 403: %s", w.Code, w.Body.String())
	}
}

// TestExplicitBareAliasOnlyWhenConfigured (P1-21): a bare key in the
// principal map is honored ONLY when the map literally declares it — as an
// explicitly configured wildcard/migration alias. It then matches the bare
// full name across forges.
func TestExplicitBareAliasOnlyWhenConfigured(t *testing.T) {
	s := storeServer(t, "", map[string]auth.Principal{
		"alias-token": {
			Subject: "migration-bot",
			Repositories: map[string]auth.RepositoryPermission{
				"acme/service": {Run: true},
			},
		},
	})
	c := newTestClient(t, s.Handler(), "alias-token")
	for _, repoURL := range []string{
		"https://gitlab.example/acme/service.git",
		"https://github.com/acme/service.git",
	} {
		w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: repoURL, RepoFullName: "acme/service", Ref: "main", Pipeline: simpleContainerPipeline}, nil)
		if w.Code != http.StatusAccepted {
			t.Fatalf("explicit bare alias submit for %s = %d, want 202: %s", repoURL, w.Code, w.Body.String())
		}
	}
	// The alias does not bleed into other repositories.
	w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/acme/other.git", RepoFullName: "acme/other", Ref: "main", Pipeline: simpleContainerPipeline}, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("alias bleed submit = %d, want 403: %s", w.Code, w.Body.String())
	}
}

// TestRunListVisibilityStrictlyCanonical (P1-21): the scoped list endpoints
// resolve visibility strictly to the canonical identity — runs for
// gitlab.example/acme/service are invisible to a principal keyed only for
// github.com/acme/service (the implicit bare-alias derivation is gone).
func TestRunListVisibilityStrictlyCanonical(t *testing.T) {
	s := storeServer(t, "", map[string]auth.Principal{
		"github-token": {
			Subject: "github-bot",
			Roles:   []auth.Role{auth.RoleRead},
			Repositories: map[string]auth.RepositoryPermission{
				"github.com/acme/service": {Run: true, Read: true},
			},
		},
	})
	// Seed one run per forge directly (enqueue bypasses HTTP auth).
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://github.com/acme/service.git", RepoFullName: "acme/service",
		Ref: "main", Pipeline: simpleContainerPipeline,
	}); err != nil {
		t.Fatalf("seed github run: %v", err)
	}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://gitlab.example/acme/service.git", RepoFullName: "acme/service",
		Ref: "main", Pipeline: simpleContainerPipeline,
	}); err != nil {
		t.Fatalf("seed gitlab run: %v", err)
	}
	c := newTestClient(t, s.Handler(), "github-token")
	w := c.do(http.MethodGet, "/api/v1/runs", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", w.Code, w.Body.String())
	}
	var runs []struct {
		Repo string `json:"repo"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &runs); err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatalf("visible runs = %d, want only the github.com one: %+v", len(runs), runs)
	}
	if runs[0].Repo != "https://github.com/acme/service.git" {
		t.Fatalf("visible run repo = %q", runs[0].Repo)
	}
}
