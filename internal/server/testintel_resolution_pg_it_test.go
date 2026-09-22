package server

// L5-A real-PostgreSQL proof over the HTTP endpoint: with 65 forges
// presenting the same bare owner/name, the principal granted ONLY the
// canonical repository that sorts LAST still receives that repository's test
// intelligence (pre-fix the 64-candidate resolution window, applied before
// authorization, silently answered zero), while an unrestricted (bare-alias)
// principal is refused with an opaque 409 instead of a truncated candidate
// list.
//
// Gated on KIWI_TEST_POSTGRES_URL via the shared pgITServer* helpers.

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// pgITSeedManyForges seeds n runs whose repositories present the same bare
// owner/name and returns their canonical IDs (ascending) plus the run ID of
// the last-seeded forge.
func pgITSeedManyForges(t *testing.T, st *storage.PostgresStore, bare string, n int, base time.Time) (ids []string, lastRunID string) {
	t.Helper()
	ids = make([]string, 0, n)
	for i := 0; i < n; i++ {
		repo := fmt.Sprintf("forge%02d.example/%s", i, bare)
		runID, jobID := pgITServerRandomHex(t, 32), pgITServerRandomHex(t, 32)
		pgITForgeSeedRun(t, st, runID, jobID, repo, bare, base.Add(time.Duration(i)*time.Second))
		ids = append(ids, repo)
		lastRunID = runID
	}
	return ids, lastRunID
}

func TestPostgresIntegrationServerTestIntelResolutionAuthorizedBeyondAmbiguityCap(t *testing.T) {
	env := pgITServerSetup(t)
	st := env.open(t)
	s := New("token")
	s.DB = st
	base := time.Now().UTC().Truncate(time.Second)
	const bare = "acme/service"
	ids, lastRunID := pgITSeedManyForges(t, st, bare, 65, base)
	last := ids[len(ids)-1]
	pgITForgeSeedReport(t, st, lastRunID, pgITServerRandomHex(t, 32), last, base,
		model.TestResult{Name: "auth-only", Passed: true})

	forgeIntelGrantReads(t, s, "last-only", last)
	code, got := forgeIntelGet(t, s, "last-only", bare)
	if code != http.StatusOK {
		t.Fatalf("authorized-beyond-cap query = %d, want 200", code)
	}
	if got.Reports != 1 || got.TotalTests != 1 || got.Failures != 0 {
		t.Fatalf("authorized-beyond-cap result = %+v, want 1 report/1 test (pre-fix the authorized repository sorts after the 64-candidate cap and is silently omitted)", got)
	}
	// The canonical query form reaches the same repository with no cap.
	code, got = forgeIntelGet(t, s, "last-only", last)
	if code != http.StatusOK || got.Reports != 1 || got.TotalTests != 1 {
		t.Fatalf("canonical query = %d %+v, want 200 with 1 report/1 test", code, got)
	}
}

func TestPostgresIntegrationServerTestIntelResolutionBareAliasAmbiguityRefused(t *testing.T) {
	env := pgITServerSetup(t)
	st := env.open(t)
	s := New("token")
	s.DB = st
	base := time.Now().UTC().Truncate(time.Second)
	const bare = "acme/service"
	pgITSeedManyForges(t, st, bare, 65, base)

	// A bare-alias grant authorizes every forge presenting the name, so the
	// resolution cannot be identity-restricted: the over-limit query must be
	// refused explicitly (opaque 409), never answered with the first 64
	// candidates presented as a complete result.
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
