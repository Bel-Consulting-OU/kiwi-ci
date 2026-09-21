package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// The tests below pin the unified repository authorization contract: the
// per-run read routes, the scoped run collection and the serving-runner
// projection must all resolve repository grants through the SAME helper in
// internal/auth. An explicit repository deny wins everywhere, a
// repository-only read grant still reaches the collections, canonical host
// spellings (case, default port) and bare aliases resolve identically across
// endpoints, conflicting equivalent grants fail closed and the legacy
// no-principal path stays open (the outer tier decides).

const (
	rauthzAllowedRepoID = "github.com/bel/allowed"
	rauthzDeniedRepoID  = "github.com/acme/private"
)

// rauthzSeed plants two repositories: an allowed one and an explicitly
// deniable one, each with a run and a job. run-cloneurl carries ONLY a clone
// URL spelling (no stored RepoID), so its authorization identity must be
// derived exactly like a persisted run's. runner-mixed serves one job of each
// repository; runner-denied serves only the denied repository.
func rauthzSeed(s *Server) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs["run-allowed"] = model.Run{ID: "run-allowed", RepoID: rauthzAllowedRepoID, Repo: "https://github.com/bel/allowed.git", RepoFullName: "bel/allowed", Status: model.StatusRunning, CreatedAt: now}
	s.runs["run-cloneurl"] = model.Run{ID: "run-cloneurl", Repo: "https://GitHub.COM:443/bel/allowed.git", RepoFullName: "bel/allowed", Status: model.StatusRunning, CreatedAt: now}
	s.runs["run-denied"] = model.Run{ID: "run-denied", RepoID: rauthzDeniedRepoID, Repo: "https://github.com/acme/private.git", RepoFullName: "acme/private", Status: model.StatusRunning, CreatedAt: now}
	s.jobs["job-allowed"] = model.Job{ID: "job-allowed", RunID: "run-allowed", Key: "build", RepoID: rauthzAllowedRepoID, RepoURL: "https://github.com/bel/allowed.git", RepoFullName: "bel/allowed", Status: model.StatusRunning}
	s.jobs["job-cloneurl"] = model.Job{ID: "job-cloneurl", RunID: "run-cloneurl", Key: "build", RepoURL: "https://GitHub.COM:443/bel/allowed.git", RepoFullName: "bel/allowed", Status: model.StatusRunning}
	s.jobs["job-denied"] = model.Job{ID: "job-denied", RunID: "run-denied", Key: "build", RepoID: rauthzDeniedRepoID, RepoURL: "https://github.com/acme/private.git", RepoFullName: "acme/private", Status: model.StatusRunning}
	s.runners["runner-mixed"] = model.Runner{ID: "runner-mixed", Name: "mixed", Capacity: 2, ActiveJobs: []string{"job-allowed", "job-denied"}}
	s.runners["runner-cloneurl"] = model.Runner{ID: "runner-cloneurl", Name: "cloneurl", Capacity: 1, ActiveJobs: []string{"job-cloneurl"}}
	s.runners["runner-denied"] = model.Runner{ID: "runner-denied", Name: "denied-only", Capacity: 1, ActiveJobs: []string{"job-denied"}}
}

// rauthzServer builds an in-memory server with the given store principals
// and the seeded repository fixture.
func rauthzServer(t *testing.T, principals map[string]auth.Principal) *Server {
	t.Helper()
	s := storeServer(t, "admin-tok", principals)
	rauthzSeed(s)
	return s
}

type rauthzServingEntry struct {
	ID         string   `json:"id"`
	ActiveJobs []string `json:"active_jobs"`
}

// rauthzListRunIDs lists the run collection and returns the visible run IDs.
func rauthzListRunIDs(t *testing.T, c *testClient) []string {
	t.Helper()
	w := c.do(http.MethodGet, "/api/v1/runs", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list runs = %d: %s", w.Code, w.Body.String())
	}
	return runIDs(t, w.Body.String())
}

// rauthzServing fetches the serving projection and returns it keyed by
// runner ID, plus the raw body for leak assertions.
func rauthzServing(t *testing.T, c *testClient) (map[string][]string, string) {
	t.Helper()
	w := c.do(http.MethodGet, "/api/v1/runners/serving", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("serving = %d: %s", w.Code, w.Body.String())
	}
	var out []rauthzServingEntry
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	byID := map[string][]string{}
	for _, e := range out {
		byID[e.ID] = e.ActiveJobs
	}
	return byID, w.Body.String()
}

func rauthzHas(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// (a) Global read plus an explicit repository deny: the collection excludes
// the denied run, the per-run endpoint refuses it, and the serving
// projection neither reveals the denied runner nor the denied job. The role
// fallback still reaches every OTHER repository.
func TestRepoAuthorizationExplicitDenyBeatsGlobalRead(t *testing.T) {
	s := rauthzServer(t, map[string]auth.Principal{
		"reader": {
			Subject: "global-reader",
			Roles:   []auth.Role{auth.RoleRead},
			Repositories: map[string]auth.RepositoryPermission{
				rauthzDeniedRepoID: {Read: false},
			},
		},
	})
	c := newTestClient(t, s.Handler(), "reader")

	ids := rauthzListRunIDs(t, c)
	if rauthzHas(ids, "run-denied") {
		t.Fatalf("explicitly denied run leaked into the collection: %v", ids)
	}
	if !rauthzHas(ids, "run-allowed") || !rauthzHas(ids, "run-cloneurl") {
		t.Fatalf("role fallback must still reach unmentioned repositories: %v", ids)
	}
	if w := c.do(http.MethodGet, "/api/v1/runs/run-denied", nil, nil); w.Code != http.StatusForbidden {
		t.Fatalf("denied per-run read = %d, want 403", w.Code)
	}
	if w := c.do(http.MethodGet, "/api/v1/runs/run-allowed", nil, nil); w.Code != http.StatusOK {
		t.Fatalf("role-fallback per-run read = %d, want 200", w.Code)
	}

	serving, raw := rauthzServing(t, c)
	if _, leaked := serving["runner-denied"]; leaked {
		t.Fatalf("runner serving only a denied repository leaked: %s", raw)
	}
	jobs, ok := serving["runner-mixed"]
	if !ok || len(jobs) != 1 || jobs[0] != "job-allowed" {
		t.Fatalf("mixed runner jobs = %v (present=%v): %s", jobs, ok, raw)
	}
	if strings.Contains(raw, "job-denied") {
		t.Fatalf("denied job leaked into the serving projection: %s", raw)
	}
}

// (b) A repository-only Read:true grant with no global read role: the
// grant alone opens the collection (no blanket 403) and exposes exactly the
// granted repository; every other repository stays excluded.
func TestRepoAuthorizationRepoOnlyReaderReachesCollections(t *testing.T) {
	s := rauthzServer(t, map[string]auth.Principal{
		"reader": {
			Subject: "repo-reader",
			Repositories: map[string]auth.RepositoryPermission{
				rauthzAllowedRepoID: {Read: true},
			},
		},
	})
	c := newTestClient(t, s.Handler(), "reader")

	ids := rauthzListRunIDs(t, c)
	if !rauthzHas(ids, "run-allowed") || !rauthzHas(ids, "run-cloneurl") {
		t.Fatalf("granted repository missing from the collection: %v", ids)
	}
	if rauthzHas(ids, "run-denied") {
		t.Fatalf("foreign repository leaked into the collection: %v", ids)
	}
	if w := c.do(http.MethodGet, "/api/v1/runs/run-allowed", nil, nil); w.Code != http.StatusOK {
		t.Fatalf("granted per-run read = %d, want 200", w.Code)
	}
	if w := c.do(http.MethodGet, "/api/v1/runs/run-denied", nil, nil); w.Code != http.StatusForbidden {
		t.Fatalf("foreign per-run read = %d, want 403", w.Code)
	}

	serving, raw := rauthzServing(t, c)
	if _, leaked := serving["runner-denied"]; leaked {
		t.Fatalf("runner serving only a foreign repository leaked: %s", raw)
	}
	if _, ok := serving["runner-cloneurl"]; !ok {
		t.Fatalf("runner serving the granted clone-URL repository missing: %s", raw)
	}
	jobs, ok := serving["runner-mixed"]
	if !ok || len(jobs) != 1 || jobs[0] != "job-allowed" {
		t.Fatalf("mixed runner jobs = %v (present=%v): %s", jobs, ok, raw)
	}
}

// (c) Canonical aliases resolve identically across the per-run endpoint, the
// run collection and the serving projection: host case, the default port,
// the bare full name and a clone-URL-only run identity all address the same
// grant, and the equivalent denied spellings deny everywhere.
func TestRepoAuthorizationCanonicalAliasesAgreeAcrossEndpoints(t *testing.T) {
	for name, repos := range map[string]map[string]auth.RepositoryPermission{
		"exact canonical": {
			"github.com/bel/allowed":  {Read: true},
			"github.com/acme/private": {Read: false},
		},
		"host case and default port": {
			"GitHub.COM:443/bel/allowed":   {Read: true},
			"GitHub.COM.:443/acme/private": {Read: false},
		},
		"bare full name aliases": {
			"bel/allowed":  {Read: true},
			"acme/private": {Read: false},
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := rauthzServer(t, map[string]auth.Principal{
				"reader": {Subject: "alias-reader", Repositories: repos},
			})
			c := newTestClient(t, s.Handler(), "reader")

			if w := c.do(http.MethodGet, "/api/v1/runs/run-allowed", nil, nil); w.Code != http.StatusOK {
				t.Fatalf("alias per-run read (stored RepoID) = %d, want 200: %s", w.Code, w.Body.String())
			}
			if w := c.do(http.MethodGet, "/api/v1/runs/run-cloneurl", nil, nil); w.Code != http.StatusOK {
				t.Fatalf("alias per-run read (clone-URL identity) = %d, want 200: %s", w.Code, w.Body.String())
			}
			if w := c.do(http.MethodGet, "/api/v1/runs/run-denied", nil, nil); w.Code != http.StatusForbidden {
				t.Fatalf("alias per-run read of the denied repo = %d, want 403", w.Code)
			}

			ids := rauthzListRunIDs(t, c)
			for _, want := range []string{"run-allowed", "run-cloneurl"} {
				if !rauthzHas(ids, want) {
					t.Fatalf("alias collection is missing %s: %v", want, ids)
				}
			}
			if rauthzHas(ids, "run-denied") {
				t.Fatalf("alias collection leaked the denied repo: %v", ids)
			}

			serving, raw := rauthzServing(t, c)
			jobs, ok := serving["runner-mixed"]
			if !ok || len(jobs) != 1 || jobs[0] != "job-allowed" {
				t.Fatalf("alias serving jobs = %v (present=%v): %s", jobs, ok, raw)
			}
			if _, ok := serving["runner-cloneurl"]; !ok {
				t.Fatalf("alias serving omitted the clone-URL runner: %s", raw)
			}
			if _, leaked := serving["runner-denied"]; leaked {
				t.Fatalf("alias serving leaked the denied runner: %s", raw)
			}
			if strings.Contains(raw, "job-denied") {
				t.Fatalf("alias serving leaked the denied job: %s", raw)
			}
		})
	}
}

// (d) Two canonically equivalent grant keys with DIFFERENT permission sets
// fail closed (the permissive entry never wins through map iteration order)
// on every endpoint; identical duplicate grants stay deterministic and
// grant.
func TestRepoAuthorizationConflictingGrantsFailClosed(t *testing.T) {
	s := rauthzServer(t, map[string]auth.Principal{
		"conflict": {
			Subject: "conflict",
			Repositories: map[string]auth.RepositoryPermission{
				"github.com/bel/allowed":     {Read: false},
				"GitHub.COM:443/bel/allowed": {Read: true},
			},
		},
		"same": {
			Subject: "same",
			Repositories: map[string]auth.RepositoryPermission{
				"github.com/bel/allowed":     {Read: true},
				"GitHub.COM:443/bel/allowed": {Read: true},
			},
		},
	})

	conflict := newTestClient(t, s.Handler(), "conflict")
	if w := conflict.do(http.MethodGet, "/api/v1/runs/run-allowed", nil, nil); w.Code != http.StatusForbidden {
		t.Fatalf("conflicting grants per-run read = %d, want 403: %s", w.Code, w.Body.String())
	}
	ids := rauthzListRunIDs(t, conflict)
	for _, denied := range []string{"run-allowed", "run-cloneurl", "run-denied"} {
		if rauthzHas(ids, denied) {
			t.Fatalf("conflicting grants leaked %s into the collection: %v", denied, ids)
		}
	}
	serving, raw := rauthzServing(t, conflict)
	if len(serving) != 0 || strings.TrimSpace(raw) != "[]" {
		t.Fatalf("conflicting grants leaked serving runners: %s", raw)
	}

	same := newTestClient(t, s.Handler(), "same")
	if w := same.do(http.MethodGet, "/api/v1/runs/run-allowed", nil, nil); w.Code != http.StatusOK {
		t.Fatalf("identical duplicate grants per-run read = %d, want 200: %s", w.Code, w.Body.String())
	}
	ids = rauthzListRunIDs(t, same)
	if !rauthzHas(ids, "run-allowed") || !rauthzHas(ids, "run-cloneurl") {
		t.Fatalf("identical duplicate grants missing from the collection: %v", ids)
	}
	if rauthzHas(ids, "run-denied") {
		t.Fatalf("identical duplicate grants leaked the denied repo: %v", ids)
	}
	serving, raw = rauthzServing(t, same)
	if jobs, ok := serving["runner-mixed"]; !ok || len(jobs) != 1 || jobs[0] != "job-allowed" {
		t.Fatalf("identical duplicate grants serving jobs = %v (present=%v): %s", jobs, ok, raw)
	}
}

// (e) The legacy no-principal path is unchanged: with no admin token and an
// empty store the outer tier decides and every seeded run/job/runner is
// visible.
func TestRepoAuthorizationLegacyNoPrincipalUnchanged(t *testing.T) {
	s := New("")
	rauthzSeed(s)
	c := newTestClient(t, s.Handler(), "")

	ids := rauthzListRunIDs(t, c)
	for _, want := range []string{"run-allowed", "run-cloneurl", "run-denied"} {
		if !rauthzHas(ids, want) {
			t.Fatalf("legacy collection missing %s: %v", want, ids)
		}
	}
	if w := c.do(http.MethodGet, "/api/v1/runs/run-denied", nil, nil); w.Code != http.StatusOK {
		t.Fatalf("legacy per-run read = %d, want 200", w.Code)
	}
	serving, raw := rauthzServing(t, c)
	for _, want := range []string{"runner-mixed", "runner-cloneurl", "runner-denied"} {
		if _, ok := serving[want]; !ok {
			t.Fatalf("legacy serving missing %s: %s", want, raw)
		}
	}
	if jobs := serving["runner-mixed"]; len(jobs) != 2 {
		t.Fatalf("legacy mixed runner jobs = %v, want both", jobs)
	}
}
