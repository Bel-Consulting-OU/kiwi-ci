package server

// Real-PostgreSQL proof of the cross-forge test-intelligence authorization
// discipline: two forges present the SAME bare full name, each with durable
// runs, reports and aggregates. A principal granted only one canonical
// repository receives only that forge's totals/flaky names; a principal
// granted both (or an explicit bare alias) receives both; an unrelated
// principal receives nothing. Gated on KIWI_TEST_POSTGRES_URL like the other
// *_it_test.go files.

import (
	"context"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// pgITForgeSeedRun inserts one queued run whose payload carries the canonical
// repository identity, with its single job.
func pgITForgeSeedRun(t *testing.T, st *storage.PostgresStore, runID, jobID, repoID, fullName string, created time.Time) {
	t.Helper()
	if err := st.InsertCompiledRun(context.Background(), storage.InsertCompiledRunRequest{
		Run: model.Run{ID: runID, RepoID: repoID, PolicyRepoID: repoID, Repo: "https://" + repoID + ".git",
			RepoFullName: fullName, Status: model.StatusQueued, CreatedAt: created},
		Jobs: map[string]model.Job{jobID: {
			ID: jobID, RunID: runID, Key: "build", RepoID: repoID, PolicyRepoID: repoID,
			RepoURL: "https://" + repoID + ".git", RepoFullName: fullName, Status: model.StatusQueued, CreatedAt: created,
		}},
	}); err != nil {
		t.Fatalf("seed run %s: %v", runID, err)
	}
}

// pgITForgeSeedReport renders and inserts one durable report + aggregate fold.
func pgITForgeSeedReport(t *testing.T, st *storage.PostgresStore, runID, id, repoID string, created time.Time, cases ...model.TestResult) {
	t.Helper()
	tests, failures := 0, 0
	for _, c := range cases {
		tests++
		if !c.Passed && !c.Skipped {
			failures++
		}
	}
	rep := model.TestReport{ID: id, RunID: runID, JobKey: "build", Tests: tests, Failures: failures, Cases: cases, CreatedAt: created}
	if _, err := st.InsertTestReportWithHistory(context.Background(), rep, repoID); err != nil {
		t.Fatalf("seed report %s: %v", id, err)
	}
}

func TestPostgresIntegrationServerTestIntelBareNameCrossForgeScoping(t *testing.T) {
	env := pgITServerSetup(t)
	st := env.open(t)
	s := New("token")
	s.DB = st
	base := time.Now().UTC().Truncate(time.Second)

	runGH, jobGH := pgITServerRandomHex(t, 32), pgITServerRandomHex(t, 32)
	runGL, jobGL := pgITServerRandomHex(t, 32), pgITServerRandomHex(t, 32)
	pgITForgeSeedRun(t, st, runGH, jobGH, forgeIntelGitHub, forgeIntelBare, base)
	pgITForgeSeedRun(t, st, runGL, jobGL, forgeIntelGitLab, forgeIntelBare, base.Add(time.Second))

	pgITForgeSeedReport(t, st, runGH, pgITServerRandomHex(t, 32), forgeIntelGitHub, base,
		model.TestResult{Class: "C", Name: "gh-flaky", Passed: false},
		model.TestResult{Name: "gh-ok", Passed: true})
	pgITForgeSeedReport(t, st, runGH, pgITServerRandomHex(t, 32), forgeIntelGitHub, base.Add(time.Second),
		model.TestResult{Class: "C", Name: "gh-flaky", Passed: true})
	pgITForgeSeedReport(t, st, runGL, pgITServerRandomHex(t, 32), forgeIntelGitLab, base,
		model.TestResult{Name: "gl-flaky", Passed: false},
		model.TestResult{Name: "gl-only", Passed: false},
		model.TestResult{Name: "gl-extra", Passed: true})
	pgITForgeSeedReport(t, st, runGL, pgITServerRandomHex(t, 32), forgeIntelGitLab, base.Add(time.Second),
		model.TestResult{Name: "gl-flaky", Passed: true})

	// Premise: candidate discovery really does resolve the bare name to BOTH
	// forges, or the authorization assertions below would be vacuous.
	ids, err := st.ResolveTestHistoryRepoIDs(context.Background(), forgeIntelBare, 10)
	if err != nil || !reflect.DeepEqual(ids, []string{forgeIntelGitHub, forgeIntelGitLab}) {
		t.Fatalf("resolution premise = %v, %v; want both forges", ids, err)
	}

	forgeIntelGrantReads(t, s, "gh-only", forgeIntelGitHub)
	forgeIntelGrantReads(t, s, "gl-only", forgeIntelGitLab)
	forgeIntelGrantReads(t, s, "both", forgeIntelGitHub, forgeIntelGitLab)
	forgeIntelGrantReads(t, s, "alias", forgeIntelBare)
	forgeIntelGrantReads(t, s, "unrelated", "github.com/other/repo")

	if code, got := forgeIntelGet(t, s, "gh-only", forgeIntelBare); code != http.StatusOK || !reflect.DeepEqual(got, forgeIntelGitHubTotals) {
		t.Fatalf("github-only principal on the bare name = %d %+v; want 200 %+v (pre-fix this also carried the GitLab totals)", code, got, forgeIntelGitHubTotals)
	}
	if code, got := forgeIntelGet(t, s, "gl-only", forgeIntelBare); code != http.StatusOK || !reflect.DeepEqual(got, forgeIntelGitLabTotals) {
		t.Fatalf("gitlab-only principal on the bare name = %d %+v; want 200 %+v", code, got, forgeIntelGitLabTotals)
	}
	if code, got := forgeIntelGet(t, s, "both", forgeIntelBare); code != http.StatusOK || !reflect.DeepEqual(got, forgeIntelBothTotals) {
		t.Fatalf("both-grant principal on the bare name = %d %+v; want 200 %+v", code, got, forgeIntelBothTotals)
	}
	if code, got := forgeIntelGet(t, s, "alias", forgeIntelBare); code != http.StatusOK || !reflect.DeepEqual(got, forgeIntelBothTotals) {
		t.Fatalf("explicit bare alias on the bare name = %d %+v; want 200 %+v", code, got, forgeIntelBothTotals)
	}
	if code, _ := forgeIntelGet(t, s, "unrelated", forgeIntelBare); code != http.StatusForbidden {
		t.Fatalf("unrelated principal = %d, want 403", code)
	}
	// The canonical query form is scoped exactly the same way.
	if code, got := forgeIntelGet(t, s, "gh-only", forgeIntelGitHub); code != http.StatusOK || !reflect.DeepEqual(got, forgeIntelGitHubTotals) {
		t.Fatalf("github-only principal on the canonical name = %d %+v; want 200 %+v", code, got, forgeIntelGitHubTotals)
	}
}
