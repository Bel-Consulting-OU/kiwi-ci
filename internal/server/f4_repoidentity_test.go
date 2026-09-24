package server

// F4-A end-to-end regression: a mixed-case repo_url is folded onto the one
// canonical identity at ingress, so it can neither be stored as a distinct
// identity nor bypass a repository policy keyed by the folded spelling.

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

func TestMixedCaseRepoURLFoldsAndAppliesPolicy(t *testing.T) {
	// Ingress stores the folded identity, not the URL's path case.
	s := New("token")
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token",
		`{"repo_url":"https://github.com/Acme/Backend.git","repo_full_name":"Acme/Backend","ref":"refs/heads/main","pipeline":`+jsonString(simpleContainerPipeline)+`}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit = %d: %s", w.Code, w.Body.String())
	}
	var run model.Run
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	if run.RepoID != "github.com/acme/backend" {
		t.Fatalf("mixed-case repo_url stored RepoID = %q, want github.com/acme/backend", run.RepoID)
	}

	// A repository policy keyed by the folded spelling applies to every path
	// case: before the fix the mixed-case URL fell through it (fail open).
	yes := true
	pol := New("token")
	pol.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{
		auth.RepoIdentity{Host: "github.com", FullName: "acme/backend"}.Serialized(): {RequireDigestPins: &yes},
	}}
	for _, url := range []string{
		"https://github.com/acme/backend.git",
		"https://github.com/Acme/Backend.git",
		"https://GitHub.com/ACME/BACKEND.git",
	} {
		if w := submitPipeline(t, pol, url, "", unpinnedContainerPipeline); w.Code != http.StatusForbidden {
			t.Fatalf("repo_url %q = %d, want 403 (repo policy must apply): %s", url, w.Code, w.Body.String())
		}
	}
}
