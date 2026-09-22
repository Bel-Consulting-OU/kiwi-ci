package server

// L5-A server-side regression tests: repository resolution must intersect the
// caller's permitted canonical repository identities BEFORE any ambiguity cap,
// report an over-limit bare name explicitly instead of truncating it, and
// never turn a missing grant into someone else's data.
//
// The l5a* helpers and the scoped-resolution implementations below are
// test-only: production resolution lives in storage.ResolveTestHistoryRepoIDsScoped.

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// ResolveTestHistoryRepoIDsScoped mirrors the SQL authorization-aware
// resolution policy for the server fake store: the permitted canonical
// identity set is intersected BEFORE the limit+1 ambiguity check, a canonical
// query is an exact lookup with no cap, and a bare query over the limit
// returns ErrRepoQueryAmbiguous instead of a truncated candidate list.
func (f *dbFakeStore) ResolveTestHistoryRepoIDsScoped(ctx context.Context, query string, permitted []string, limit int) ([]string, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 256 {
		limit = 64
	}
	restricted := permitted != nil
	allowed := map[string]bool{}
	for _, id := range permitted {
		if id = strings.TrimSpace(id); id != "" {
			allowed[id] = true
		}
	}
	if restricted && len(allowed) == 0 {
		return []string{}, nil
	}
	canonical := false
	canonicalID := ""
	if g, err := auth.ParseStoredRepoID(query); err == nil {
		if id, ok := g.Identity(); ok {
			canonical, canonicalID = true, id.ID()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := map[string]bool{}
	out := []string{}
	for _, run := range f.runs {
		id := repoIDForRun(run)
		if id == "" || seen[id] {
			continue
		}
		if restricted && !allowed[id] {
			continue
		}
		if canonical {
			if id != canonicalID {
				continue
			}
		} else if !runMatchesRepoQuery(run, query) {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	if !canonical && len(out) > limit {
		return nil, fmt.Errorf("%w: query %q addresses %d canonical repositories (limit %d)", storage.ErrRepoQueryAmbiguous, query, len(out), limit)
	}
	return out, nil
}

// ResolveTestHistoryRepoIDsScoped keeps the fcStore fault injection of
// TestFlowTestintelIntelligence effective on the scoped path too.
func (f *fcStore) ResolveTestHistoryRepoIDsScoped(ctx context.Context, query string, permitted []string, limit int) ([]string, error) {
	if f.resolveRepoIDsErr != nil {
		return nil, f.resolveRepoIDsErr
	}
	return f.dbFakeStore.ResolveTestHistoryRepoIDsScoped(ctx, query, permitted, limit)
}

// l5aSeedFakeForges seeds n same-named forge runs into the fake store and
// returns their canonical IDs in ascending order.
func l5aSeedFakeForges(t *testing.T, f *dbFakeStore, bare string, n int) []string {
	t.Helper()
	ids := make([]string, 0, n)
	f.mu.Lock()
	for i := 0; i < n; i++ {
		runID := fmt.Sprintf("run-%04d", i)
		repo := fmt.Sprintf("forge%02d.example/%s", i, bare)
		f.runs[runID] = model.Run{ID: runID, RepoID: repo, RepoFullName: bare, Repo: "https://" + repo + ".git", Status: model.StatusSuccess}
		ids = append(ids, repo)
	}
	f.mu.Unlock()
	return ids
}

// TestTestIntelligenceResolutionAuthorizedBeyondAmbiguityCap is the
// reviewer's regression for the server: 65 forges present the same bare name
// and the principal holds a canonical grant for the repository that sorts
// LAST. Pre-fix the resolution window (limit 64, applied before
// authorization) never contained it, so the API silently answered zero; the
// intersection must happen first so the authorized repository's intelligence
// is returned.
func TestTestIntelligenceResolutionAuthorizedBeyondAmbiguityCap(t *testing.T) {
	const bare = "acme/service"
	const n = 65
	t.Run("aggregate_store", func(t *testing.T) {
		f := newDBFakeStore()
		s := New("")
		if err := s.SwitchToDB(f); err != nil {
			t.Fatal(err)
		}
		ids := l5aSeedFakeForges(t, f, bare, n)
		last := ids[len(ids)-1]
		if _, err := f.InsertTestReportWithHistory(context.Background(), model.TestReport{
			ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01", RunID: fmt.Sprintf("run-%04d", n-1), JobKey: "build",
			Tests: 1, CreatedAt: time.Now().UTC(),
			Cases: []model.TestResult{{Name: "auth-only", Passed: true}},
		}, last); err != nil {
			t.Fatal(err)
		}
		forgeIntelGrantReads(t, s, "last-only", last)
		code, got := forgeIntelGet(t, s, "last-only", bare)
		if code != http.StatusOK {
			t.Fatalf("authorized-beyond-cap query = %d, want 200", code)
		}
		if got.Reports != 1 || got.TotalTests != 1 {
			t.Fatalf("authorized-beyond-cap result = %+v, want 1 report/1 test (pre-fix the 65th-sorting authorized repository was omitted)", got)
		}
	})
	t.Run("memory", func(t *testing.T) {
		s := New("")
		s.mu.Lock()
		last := ""
		for i := 0; i < n; i++ {
			runID := fmt.Sprintf("run-%04d", i)
			repo := fmt.Sprintf("forge%02d.example/%s", i, bare)
			s.runs[runID] = model.Run{ID: runID, RepoID: repo, RepoFullName: bare, Repo: "https://" + repo + ".git", Status: model.StatusSuccess}
			last = repo
		}
		s.reports["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02"] = model.TestReport{
			ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02", RunID: fmt.Sprintf("run-%04d", n-1), JobKey: "build",
			Tests: 1, CreatedAt: time.Now().UTC(),
			Cases: []model.TestResult{{Name: "auth-only", Passed: true}},
		}
		s.mu.Unlock()
		forgeIntelGrantReads(t, s, "last-only", last)
		code, got := forgeIntelGet(t, s, "last-only", bare)
		if code != http.StatusOK || got.Reports != 1 || got.TotalTests != 1 {
			t.Fatalf("memory authorized-beyond-cap = %d %+v, want 200 with 1 report/1 test", code, got)
		}
	})
}

// TestTestIntelligenceResolutionBareAliasOverLimitIsOpaqueConflict pins the
// no-silent-truncation rule for an unrestricted (bare-alias) principal: an
// over-limit bare name is refused with an opaque 409 that instructs the
// caller to use the forge-scoped canonical ID and leaks no candidate
// identity, count or repository data.
func TestTestIntelligenceResolutionBareAliasOverLimitIsOpaqueConflict(t *testing.T) {
	const bare = "acme/service"
	f := newDBFakeStore()
	s := New("")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	l5aSeedFakeForges(t, f, bare, 65)
	forgeIntelGrantReads(t, s, "alias", bare)
	w := doJSON(t, s, http.MethodGet, "/api/v1/test-intelligence?repo="+bare, "alias", "")
	if w.Code != http.StatusConflict {
		t.Fatalf("over-limit bare alias = %d, want 409 (pre-fix: 200 with a silently truncated candidate list)", w.Code)
	}
	body := w.Body.String()
	for _, leak := range []string{"forge0", "65", "64", bare} {
		if strings.Contains(body, leak) {
			t.Fatalf("ambiguity refusal leaked %q: %s", leak, body)
		}
	}
	if !strings.Contains(body, "canonical") {
		t.Fatalf("ambiguity refusal does not instruct the caller to use the canonical ID: %s", body)
	}
}

// TestTestIntelligenceResolutionNoMatchingGrantIsDeterministicEmpty covers
// the "no matching grant" shape over an over-limit bare name: the principal
// whose only grant is a canonical repository NOT among the candidates gets a
// deterministic empty answer — never a truncated candidate set and never
// another repository's data.
func TestTestIntelligenceResolutionNoMatchingGrantIsDeterministicEmpty(t *testing.T) {
	const bare = "acme/service"
	f := newDBFakeStore()
	s := New("")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	l5aSeedFakeForges(t, f, bare, 65)
	forgeIntelGrantReads(t, s, "elsewhere", "elsewhere.example/acme/service")
	code, got := forgeIntelGet(t, s, "elsewhere", bare)
	if code != http.StatusOK {
		t.Fatalf("unrelated-grant query = %d, want a deterministic 200 empty", code)
	}
	if got.Reports != 0 || got.TotalTests != 0 || got.Failures != 0 || len(got.Flaky) != 0 {
		t.Fatalf("unrelated-grant query leaked candidates: %+v", got)
	}
}

// TestTestIntelligenceDotlessCanonicalNeverCrossesForge is the server-level
// form of the concrete collision: a grant for the DOTLESS canonical
// repository gitlab/acme/widget must not authorize test-intelligence for the
// unrelated canonical repository forge.example/gitlab/acme/widget, and vice
// versa. The old splitForgeRepoKey dot heuristic classified the grant as a
// bare nested name and let the unrelated forge's query through.
func TestTestIntelligenceDotlessCanonicalNeverCrossesForge(t *testing.T) {
	f := newDBFakeStore()
	s := New("")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.runs["run-dotless"] = model.Run{ID: "run-dotless", RepoID: "gitlab/acme/widget", RepoFullName: "acme/widget", Repo: "https://gitlab/acme/widget.git", Status: model.StatusSuccess}
	f.runs["run-dotted"] = model.Run{ID: "run-dotted", RepoID: "forge.example/gitlab/acme/widget", RepoFullName: "gitlab/acme/widget", Repo: "https://forge.example/gitlab/acme/widget.git", Status: model.StatusSuccess}
	f.mu.Unlock()

	forgeIntelGrantReads(t, s, "dotless", "gitlab/acme/widget")
	if code, _ := forgeIntelGet(t, s, "dotless", "gitlab/acme/widget"); code != http.StatusOK {
		t.Fatalf("own canonical dotless query = %d, want 200", code)
	}
	if code, _ := forgeIntelGet(t, s, "dotless", "forge.example/gitlab/acme/widget"); code != http.StatusForbidden {
		t.Fatalf("dotless grant authorized the unrelated forge.example query: %d, want 403", code)
	}

	forgeIntelGrantReads(t, s, "dotted", "forge.example/gitlab/acme/widget")
	if code, _ := forgeIntelGet(t, s, "dotted", "forge.example/gitlab/acme/widget"); code != http.StatusOK {
		t.Fatalf("own canonical dotted query = %d, want 200", code)
	}
	if code, _ := forgeIntelGet(t, s, "dotted", "gitlab/acme/widget"); code != http.StatusForbidden {
		t.Fatalf("forge.example grant authorized the dotless gitlab query: %d, want 403", code)
	}
}

// TestTestIntelligenceResolutionCanonicalQueryIsExactNoCap proves the
// canonical query form addresses exactly one identity with no ambiguity cap,
// and that an unauthorized canonical query is still refused.
func TestTestIntelligenceResolutionCanonicalQueryIsExactNoCap(t *testing.T) {
	const bare = "acme/service"
	f := newDBFakeStore()
	s := New("")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ids := l5aSeedFakeForges(t, f, bare, 65)
	last := ids[len(ids)-1]
	if _, err := f.InsertTestReportWithHistory(context.Background(), model.TestReport{
		ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa03", RunID: "run-0064", JobKey: "build",
		Tests: 2, Failures: 1, CreatedAt: time.Now().UTC(),
		Cases: []model.TestResult{{Name: "c", Passed: false}, {Name: "c", Passed: true}},
	}, last); err != nil {
		t.Fatal(err)
	}
	forgeIntelGrantReads(t, s, "last-only", last)
	code, got := forgeIntelGet(t, s, "last-only", last)
	if code != http.StatusOK || got.Reports != 1 || got.TotalTests != 2 {
		t.Fatalf("canonical query for the granted repository = %d %+v, want 200 with 1 report/2 tests", code, got)
	}
	// A canonical query for another forge's repository stays forbidden.
	if code, _ := forgeIntelGet(t, s, "last-only", ids[0]); code != http.StatusForbidden {
		t.Fatalf("canonical query for an ungranted repository = %d, want 403", code)
	}
}
