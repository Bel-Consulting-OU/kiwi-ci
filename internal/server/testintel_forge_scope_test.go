package server

// Cross-forge test-intelligence scoping proofs. A bare repository full name
// ("owner/name") is NOT a repository identity: several forges can present the
// same name, so a query in that form is only a candidate-discovery hint. The
// handler resolves candidates first, authorizes every canonical repository ID
// individually (auth.CanReadRepo through canReadRepo) and reads aggregates
// from the authorized subset ONLY. These tests pin that discipline for the
// in-memory server path, the aggregate-store path and the legacy-store path:
// pre-fix each of them returned the other forge's totals/aggregates.

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const (
	forgeIntelGitHub = "github.com/acme/service"
	forgeIntelGitLab = "gitlab.example/acme/service"
	forgeIntelBare   = "acme/service"
)

// forgeIntelResponse is the decoded subset of the test-intelligence response
// under assertion.
type forgeIntelResponse struct {
	Reports    int      `json:"reports"`
	TotalTests int      `json:"total_tests"`
	Failures   int      `json:"failures"`
	Flaky      []string `json:"flaky_tests"`
}

// forgeIntelFixture is one repository's report: the two forges carry
// deliberately different totals so a cross-forge leak is observable, and each
// carries a test with a mixed outcome window so its flaky set is non-empty.
type forgeIntelFixture struct {
	rep  model.TestReport
	repo string
}

func forgeIntelFixtures(base time.Time) []forgeIntelFixture {
	return []forgeIntelFixture{
		{repo: forgeIntelGitHub, rep: model.TestReport{ID: "rep-gh-1", RunID: "run-gh", JobKey: "build", Tests: 2, Failures: 1, CreatedAt: base,
			Cases: []model.TestResult{{Class: "C", Name: "gh-flaky", Passed: false}, {Name: "gh-ok", Passed: true}}}},
		{repo: forgeIntelGitHub, rep: model.TestReport{ID: "rep-gh-2", RunID: "run-gh", JobKey: "build", Tests: 1, CreatedAt: base.Add(time.Second),
			Cases: []model.TestResult{{Class: "C", Name: "gh-flaky", Passed: true}}}},
		{repo: forgeIntelGitLab, rep: model.TestReport{ID: "rep-gl-1", RunID: "run-gl", JobKey: "build", Tests: 3, Failures: 2, CreatedAt: base,
			Cases: []model.TestResult{{Name: "gl-flaky", Passed: false}, {Name: "gl-only", Passed: false}, {Name: "gl-extra", Passed: true}}}},
		{repo: forgeIntelGitLab, rep: model.TestReport{ID: "rep-gl-2", RunID: "run-gl", JobKey: "build", Tests: 1, CreatedAt: base.Add(time.Second),
			Cases: []model.TestResult{{Name: "gl-flaky", Passed: true}}}},
	}
}

var (
	forgeIntelGitHubTotals = forgeIntelResponse{Reports: 2, TotalTests: 3, Failures: 1, Flaky: []string{"C.gh-flaky"}}
	forgeIntelGitLabTotals = forgeIntelResponse{Reports: 2, TotalTests: 4, Failures: 2, Flaky: []string{"gl-flaky"}}
	forgeIntelBothTotals   = forgeIntelResponse{Reports: 4, TotalTests: 7, Failures: 3, Flaky: []string{"C.gh-flaky", "gl-flaky"}}
)

// forgeIntelWanted reports whether repo passes the fixture filter (an empty
// filter keeps every repository).
func forgeIntelWanted(repo string, keep []string) bool {
	if len(keep) == 0 {
		return true
	}
	for _, k := range keep {
		if k == repo {
			return true
		}
	}
	return false
}

// forgeIntelGrantReads registers a store principal that may read exactly the
// given repositories.
func forgeIntelGrantReads(t *testing.T, s *Server, raw string, repos ...string) {
	t.Helper()
	perms := make(map[string]auth.RepositoryPermission, len(repos))
	for _, repo := range repos {
		perms[repo] = auth.RepositoryPermission{Read: true}
	}
	if err := s.AuthStore.AddToken(raw, auth.Principal{Subject: raw, Repositories: perms}); err != nil {
		t.Fatal(err)
	}
}

// forgeIntelGet performs one test-intelligence request and decodes a 200.
func forgeIntelGet(t *testing.T, s *Server, token, repo string) (int, forgeIntelResponse) {
	t.Helper()
	w := doJSON(t, s, http.MethodGet, "/api/v1/test-intelligence?repo="+repo, token, "")
	out := forgeIntelResponse{}
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode test-intelligence: %v", err)
		}
	}
	return w.Code, out
}

// forgeIntelSeedRuns seeds the two same-bare-name runs of both forges.
func forgeIntelSeedRuns(t *testing.T, f *dbFakeStore, keep []string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, repo := range []string{forgeIntelGitHub, forgeIntelGitLab} {
		if !forgeIntelWanted(repo, keep) {
			continue
		}
		id := "run-gh"
		if repo == forgeIntelGitLab {
			id = "run-gl"
		}
		f.runs[id] = model.Run{ID: id, RepoID: repo, RepoFullName: forgeIntelBare, Repo: "https://" + repo + ".git", Status: model.StatusSuccess}
	}
}

// forgeIntelAggregateFixture is a DB-mode server over the aggregate store:
// the selected forges' runs and reports are seeded through
// InsertTestReportWithHistory exactly like uploads.
func forgeIntelAggregateFixture(t *testing.T, keep ...string) *Server {
	t.Helper()
	f := newDBFakeStore()
	s := New("")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	forgeIntelSeedRuns(t, f, keep)
	ctx := context.Background()
	for _, fixture := range forgeIntelFixtures(time.Now().UTC()) {
		if !forgeIntelWanted(fixture.repo, keep) {
			continue
		}
		if _, err := f.InsertTestReportWithHistory(ctx, fixture.rep, fixture.repo); err != nil {
			t.Fatalf("seed %s: %v", fixture.rep.ID, err)
		}
	}
	return s
}

// forgeIntelLegacyFixture hides the aggregate contract behind a
// TestHistoryStore-only wrapper, so the handler takes its legacy
// whole-cache/report-scan path over the same seeded data.
func forgeIntelLegacyFixture(t *testing.T, keep ...string) *Server {
	t.Helper()
	f := newDBFakeStore()
	forgeIntelSeedRuns(t, f, keep)
	for _, fixture := range forgeIntelFixtures(time.Now().UTC()) {
		if forgeIntelWanted(fixture.repo, keep) {
			f.reports = append(f.reports, fixture.rep)
		}
	}
	s := New("")
	s.DB = &legacyHistoryStore{Store: f}
	return s
}

// forgeIntelMemoryFixture seeds the in-memory runs/reports and records the
// persisted history exactly like uploads do, so the response exercises the
// report-derived AND the persisted-flaky merge.
func forgeIntelMemoryFixture(t *testing.T, keep ...string) *Server {
	t.Helper()
	s := New("")
	ctx := context.Background()
	s.mu.Lock()
	for _, repo := range []string{forgeIntelGitHub, forgeIntelGitLab} {
		if !forgeIntelWanted(repo, keep) {
			continue
		}
		id := "run-gh"
		if repo == forgeIntelGitLab {
			id = "run-gl"
		}
		s.runs[id] = model.Run{ID: id, RepoID: repo, RepoFullName: forgeIntelBare, Repo: "https://" + repo + ".git", Status: model.StatusSuccess}
	}
	s.mu.Unlock()
	for _, fixture := range forgeIntelFixtures(time.Now().UTC()) {
		if !forgeIntelWanted(fixture.repo, keep) {
			continue
		}
		s.mu.Lock()
		s.reports[fixture.rep.ID] = fixture.rep
		s.mu.Unlock()
		s.recordTestReportHistory(ctx, fixture.repo, fixture.rep)
	}
	return s
}

// TestTestIntelligenceBareNameNeverCrossesForge is the reviewer's invariant:
// with two forges presenting the SAME bare full name and aggregates for BOTH,
// a principal granted only github.com/acme/service must receive ONLY that
// forge's reports/tests/failures/flaky names. Pre-fix the aggregate path
// re-injected the bare query into TestReportTotals (repo_full_name = $2) and
// the memory/legacy paths accepted run.RepoFullName == query without any
// per-repository authorization, so each subtest observed the GitLab counts.
func TestTestIntelligenceBareNameNeverCrossesForge(t *testing.T) {
	check := func(t *testing.T, s *Server) {
		t.Helper()
		forgeIntelGrantReads(t, s, "gh-only", forgeIntelGitHub)
		code, got := forgeIntelGet(t, s, "gh-only", forgeIntelBare)
		if code != http.StatusOK {
			t.Fatalf("bare-name query = %d, want 200", code)
		}
		if !reflect.DeepEqual(got, forgeIntelGitHubTotals) {
			t.Fatalf("bare-name query crossed the forge boundary:\ngot  %+v\nwant %+v (the GitLab forge must not appear)", got, forgeIntelGitHubTotals)
		}
	}
	t.Run("memory", func(t *testing.T) { check(t, forgeIntelMemoryFixture(t)) })
	t.Run("aggregate_store", func(t *testing.T) { check(t, forgeIntelAggregateFixture(t)) })
	t.Run("legacy_store", func(t *testing.T) { check(t, forgeIntelLegacyFixture(t)) })
}

// TestTestIntelligenceBareNameGrantedSetStillSeesEveryForge proves the fix
// does not over-restrict: when the principal holds a grant for BOTH canonical
// repositories — or an explicit bare alias, which authorizes each canonical
// repository individually through auth.CanReadRepo — the bare-name query
// still returns both forges' aggregates.
func TestTestIntelligenceBareNameGrantedSetStillSeesEveryForge(t *testing.T) {
	for _, tc := range []struct {
		name  string
		repos []string
	}{
		{"both canonical grants", []string{forgeIntelGitHub, forgeIntelGitLab}},
		{"explicit bare alias", []string{forgeIntelBare}},
	} {
		t.Run("memory/"+tc.name, func(t *testing.T) {
			s := forgeIntelMemoryFixture(t)
			forgeIntelGrantReads(t, s, "reader", tc.repos...)
			code, got := forgeIntelGet(t, s, "reader", forgeIntelBare)
			if code != http.StatusOK || !reflect.DeepEqual(got, forgeIntelBothTotals) {
				t.Fatalf("granted-set query = %d %+v, want 200 %+v", code, got, forgeIntelBothTotals)
			}
		})
		t.Run("aggregate_store/"+tc.name, func(t *testing.T) {
			s := forgeIntelAggregateFixture(t)
			forgeIntelGrantReads(t, s, "reader", tc.repos...)
			code, got := forgeIntelGet(t, s, "reader", forgeIntelBare)
			if code != http.StatusOK || !reflect.DeepEqual(got, forgeIntelBothTotals) {
				t.Fatalf("granted-set query = %d %+v, want 200 %+v", code, got, forgeIntelBothTotals)
			}
		})
	}
}

// TestTestIntelligenceUnauthorizedCandidatesContributeNothing covers the two
// "gets nothing" shapes: a principal with no grant addressing the query at
// all is refused up front (403), and a principal whose only grant is the
// OTHER forge's canonical repository (so the bare query passes the coarse
// visibility gate) receives an EMPTY answer — never the candidate
// repository's totals.
func TestTestIntelligenceUnauthorizedCandidatesContributeNothing(t *testing.T) {
	zero := forgeIntelResponse{Flaky: []string{}}
	t.Run("no matching grant is forbidden", func(t *testing.T) {
		for name, s := range map[string]*Server{
			"memory":          forgeIntelMemoryFixture(t),
			"aggregate_store": forgeIntelAggregateFixture(t),
		} {
			forgeIntelGrantReads(t, s, "unrelated", "github.com/other/repo")
			if code, got := forgeIntelGet(t, s, "unrelated", forgeIntelBare); code != http.StatusForbidden {
				t.Fatalf("%s: unrelated principal = %d %+v, want 403", name, code, got)
			}
		}
	})
	t.Run("other forge grant sees zero", func(t *testing.T) {
		// Only the GitHub forge has runs/reports; the principal is granted
		// the GitLab repository, so every resolved candidate is unauthorized.
		for name, s := range map[string]*Server{
			"memory":          forgeIntelMemoryFixture(t, forgeIntelGitHub),
			"aggregate_store": forgeIntelAggregateFixture(t, forgeIntelGitHub),
		} {
			forgeIntelGrantReads(t, s, "gl-only", forgeIntelGitLab)
			code, got := forgeIntelGet(t, s, "gl-only", forgeIntelBare)
			if code != http.StatusOK || !reflect.DeepEqual(got, zero) {
				t.Fatalf("%s: other-forge grant = %d %+v, want 200 %+v (no candidate data may leak)", name, code, got, zero)
			}
		}
	})
}
