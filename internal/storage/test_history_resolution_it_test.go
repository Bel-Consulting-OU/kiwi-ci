package storage

// L5-A real-PostgreSQL proof of the repository resolution policy: a bare
// owner/name that addresses more canonical repositories than the supported
// ambiguity limit is REPORTED (ErrRepoQueryAmbiguous), never silently
// truncated to the first `limit` candidates, while the forge-scoped canonical
// ID resolves exactly with no cap. The scoped resolution intersects the
// principal's permitted canonical identities BEFORE the ambiguity check, so
// an authorized repository that sorts after the cap is reachable.
//
// Gated on KIWI_TEST_POSTGRES_URL via the shared pgIT* helpers.

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITResolveForges seeds n forges presenting the same bare owner/name and
// returns their canonical repository IDs (ascending) plus the run ID of the
// last-seeded forge.
func pgITResolveForges(t *testing.T, st *PostgresStore, bare string, n int, base time.Time) (ids []string, lastRunID string) {
	t.Helper()
	ids = make([]string, 0, n)
	for i := 0; i < n; i++ {
		repo := fmt.Sprintf("forge%02d.example/%s", i, bare)
		runID := pgITNewID(t)
		pgITHistoryRun(t, st, runID, pgITNewID(t), repo, bare, base.Add(time.Duration(i)*time.Second))
		ids = append(ids, repo)
		lastRunID = runID
	}
	return ids, lastRunID
}

func TestPostgresIntegrationTestHistoryResolveAmbiguityAuthorizedIntersection(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second)
	const bare = "acme/service"
	const over = 65
	ids, lastRunID := pgITResolveForges(t, st, bare, over, base)
	last := ids[len(ids)-1]

	// Pre-fix: ORDER BY 1 LIMIT 64 answered 64 ids with no error, hiding the
	// 65th identity behind a result that looked complete.
	got, err := st.ResolveTestHistoryRepoIDs(ctx, bare, 64)
	if !errors.Is(err, ErrRepoQueryAmbiguous) {
		t.Fatalf("over-limit bare resolution = %d ids, %v; want ErrRepoQueryAmbiguous (no silent truncation)", len(got), err)
	}
	if got != nil {
		t.Fatalf("over-limit bare resolution returned candidates too: %v", got)
	}
	// The canonical (forge-scoped) form is an exact lookup with no cap.
	got, err = st.ResolveTestHistoryRepoIDs(ctx, last, 1)
	if err != nil || !reflect.DeepEqual(got, []string{last}) {
		t.Fatalf("canonical exact lookup = %v, %v; want [%s]", got, err, last)
	}
	// The authorized intersection is applied BEFORE the cap: the permitted
	// repository sorting LAST is resolved even though the bare name has 65
	// candidates.
	got, err = st.ResolveTestHistoryRepoIDsScoped(ctx, bare, []string{last}, 64)
	if err != nil || !reflect.DeepEqual(got, []string{last}) {
		t.Fatalf("scoped authorized-last = %v, %v; want [%s] (pre-fix the authorized repository was invisible)", got, err, last)
	}
	got, err = st.ResolveTestHistoryRepoIDsScoped(ctx, bare, []string{last, ids[0]}, 64)
	if err != nil || !reflect.DeepEqual(got, []string{ids[0], last}) {
		t.Fatalf("scoped intersection = %v, %v; want [%s %s]", got, err, ids[0], last)
	}
	// An over-limit intersection is still reported ambiguous.
	got, err = st.ResolveTestHistoryRepoIDsScoped(ctx, bare, ids[:10], 3)
	if !errors.Is(err, ErrRepoQueryAmbiguous) {
		t.Fatalf("over-limit scoped resolution = %d ids, %v; want ErrRepoQueryAmbiguous", len(got), err)
	}
	// A non-nil empty permitted set resolves to no candidates (the caller's
	// deterministic empty/denied answer) without touching the database.
	got, err = st.ResolveTestHistoryRepoIDsScoped(ctx, bare, []string{}, 64)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty permitted set = %v, %v; want no candidates", got, err)
	}
	// Inside the limit the bare query resolves every identity, sorted.
	got, err = st.ResolveTestHistoryRepoIDs(ctx, bare, over)
	if err != nil || !reflect.DeepEqual(got, ids) {
		t.Fatalf("at-limit bare resolution = %d ids, %v; want all %d", len(got), err, over)
	}
	// The authorized repository beyond the cap still answers intelligence:
	// its durable report folds and its totals are read by exact identity.
	rep := pgITHistoryReport(lastRunID, pgITNewID(t), base, model.TestResult{Name: "auth-only", Passed: true})
	if _, err := st.InsertTestReportWithHistory(ctx, rep, last); err != nil {
		t.Fatalf("insert authorized report: %v", err)
	}
	reports, tests, failures, err := st.TestReportTotals(ctx, []string{last}, bare)
	if err != nil || reports != 1 || tests != 1 || failures != 0 {
		t.Fatalf("authorized totals = %d/%d/%d, %v; want 1/1/0", reports, tests, failures, err)
	}
}
