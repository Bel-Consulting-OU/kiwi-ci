package storage

// Real-PostgreSQL integration tests for the AUTHORIZED keyset page
// (RunPageAuthorizedStore). Gated on KIWI_TEST_POSTGRES_URL exactly like the
// other storage integration tests: skipped when the variable is unset and in
// -short mode.
//
// The defect these pin: the pre-fix collection enumerated every repository in
// the collection (SELECT DISTINCT <identity> FROM runs) before each page
// fetch, an O(repository cardinality) pre-scan, and filtered per run
// afterwards. The fix pushes the principal's normalized repository predicate
// into the ordered keyset query itself (LIMIT n+1), so the page boundary is
// authorized by construction and nothing enumerates the collection. The tests
// below assert the no-leak contract, memory/SQL parity for the full grant
// matrix, and the SHAPE of the shipped query (no DISTINCT, index-backed).

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// authzITRun builds a run in repoID with a distinct created_at (one second
// apart) and a fixed-width id whose lexicographic order matches i.
func authzITRun(i int, base time.Time, repoID string) model.Run {
	return model.Run{
		ID:           fmt.Sprintf("%032x", i+1),
		Status:       model.StatusSuccess,
		CreatedAt:    base.Add(time.Duration(i) * time.Second),
		PolicyRepoID: repoID,
	}
}

// authzITPolicy builds the normalized policy of a principal from raw grant
// spellings, exactly as the server does per request.
func authzITPolicy(grants map[string]auth.RepositoryPermission, roles ...auth.Role) RunAuthzPolicy {
	p := auth.Principal{Subject: "reader", Roles: roles, Repositories: grants}
	return RunAuthzPolicyForPrincipal(&p)
}

// authzITSeed inserts runs and returns them.
func authzITSeed(t *testing.T, st *PostgresStore, runs []model.Run) []model.Run {
	t.Helper()
	for _, run := range runs {
		if err := st.InsertRun(context.Background(), run); err != nil {
			t.Fatalf("insert run %s: %v", run.ID, err)
		}
	}
	return runs
}

// TestPostgresIntegrationRunsPageAuthorizedReposNoLeak is the real-PG
// regression for the authorization leak: 2,500 private-B runs surround three
// readable-A runs, and an A-only policy must page exactly the A runs with
// boundaries derived from A rows only. No B id, no B timestamp and no
// B-derived cursor position may ever be observable, and the walk terminates
// after the last visible A run even though 2,499 older B runs exist.
func TestPostgresIntegrationRunsPageAuthorizedReposNoLeak(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	const (
		repoA  = "github.com/o/repo-a"
		repoB  = "github.com/o/repo-b"
		total  = 2500
		firstA = 1200
		lastA  = 1202
	)
	base := time.Now().UTC().Truncate(time.Microsecond)
	runs := make([]model.Run, 0, total)
	for i := 0; i < total; i++ {
		repo := repoB
		if i >= firstA && i <= lastA {
			repo = repoA
		}
		runs = append(runs, authzITRun(i, base, repo))
	}
	authzITSeed(t, st, runs)

	unrestricted := RunAuthzPolicyForPrincipal(nil)
	policy := authzITPolicy(map[string]auth.RepositoryPermission{repoA: {Read: true}})

	// The mixed collection really does contain B rows newer than the newest
	// readable A run (the pre-fix leak source); the unrestricted first page
	// proves it.
	first, err := st.ListRunsPageAuthorized(ctx, unrestricted, time.Time{}, "", 1)
	if err != nil {
		t.Fatalf("unrestricted first page: %v", err)
	}
	if len(first.Runs) != 1 || first.Runs[0].ID != runs[total-1].ID {
		t.Fatalf("unrestricted first page = %v, want the newest B run", runsPageIDs(first))
	}

	// Walk the authorized pages with a deliberately tiny page size so the
	// boundary logic is exercised.
	var seen []model.Run
	afterAt, afterID := time.Time{}, ""
	pages := 0
	for {
		if pages > len(runs) {
			t.Fatal("authorized walk did not terminate")
		}
		page, err := st.ListRunsPageAuthorized(ctx, policy, afterAt, afterID, 2)
		if err != nil {
			t.Fatalf("authorized page %d: %v", pages, err)
		}
		for _, run := range page.Runs {
			if run.PolicyRepoID != repoA {
				t.Fatalf("page %d leaked a %q run (%s)", pages, run.PolicyRepoID, run.ID)
			}
			if run.CreatedAt.After(base.Add(time.Duration(lastA) * time.Second)) {
				t.Fatalf("page %d exposed a run newer than the newest A run", pages)
			}
			seen = append(seen, run)
		}
		pages++
		if !page.HasMore {
			if len(page.Runs) > 0 {
				last := page.Runs[len(page.Runs)-1]
				if page.NextID != "" && page.NextID != last.ID {
					t.Fatalf("terminal next id = %q, want %q", page.NextID, last.ID)
				}
			}
			break
		}
		if page.NextID == "" || page.NextCreatedAt.IsZero() {
			t.Fatalf("page %d reported more data without a visible boundary", pages-1)
		}
		if page.Runs[len(page.Runs)-1].ID != page.NextID {
			t.Fatalf("page %d next id = %q, want the last visible row %q", pages-1, page.NextID, page.Runs[len(page.Runs)-1].ID)
		}
		afterAt, afterID = page.NextCreatedAt, page.NextID
	}
	if pages != 2 {
		t.Fatalf("authorized walk = %d pages, want 2 (2 A runs then 1)", pages)
	}
	wantIDs := []string{runs[lastA].ID, runs[lastA-1].ID, runs[firstA].ID}
	gotIDs := make([]string, 0, len(seen))
	for _, run := range seen {
		gotIDs = append(gotIDs, run.ID)
	}
	if strings.Join(gotIDs, ",") != strings.Join(wantIDs, ",") {
		t.Fatalf("authorized walk = %v, want exactly the A runs %v", gotIDs, wantIDs)
	}
	for _, run := range seen {
		if !run.CreatedAt.Equal(runs[lastA].CreatedAt) && !run.CreatedAt.Equal(runs[lastA-1].CreatedAt) && !run.CreatedAt.Equal(runs[firstA].CreatedAt) {
			t.Fatalf("visible run %s carries an unreadable-row timestamp %v", run.ID, run.CreatedAt)
		}
	}

	// The equivalent A-only data set pages identically: the B rows are
	// invisible, not page filler.
	onlyA := []model.Run{runs[firstA], runs[firstA+1], runs[firstA+2]}
	memA := runsPageMemoryStore(t, onlyA)
	memPage1, err := memA.ListRunsPageAuthorized(ctx, unrestricted, time.Time{}, "", 2)
	if err != nil {
		t.Fatalf("A-only page1: %v", err)
	}
	memPage2, err := memA.ListRunsPageAuthorized(ctx, unrestricted, memPage1.NextCreatedAt, memPage1.NextID, 2)
	if err != nil {
		t.Fatalf("A-only page2: %v", err)
	}
	pgPage1, err := st.ListRunsPageAuthorized(ctx, policy, time.Time{}, "", 2)
	if err != nil {
		t.Fatalf("mixed page1: %v", err)
	}
	pgPage2, err := st.ListRunsPageAuthorized(ctx, policy, pgPage1.NextCreatedAt, pgPage1.NextID, 2)
	if err != nil {
		t.Fatalf("mixed page2: %v", err)
	}
	if strings.Join(runsPageIDs(pgPage1), ",") != strings.Join(runsPageIDs(memPage1), ",") ||
		strings.Join(runsPageIDs(pgPage2), ",") != strings.Join(runsPageIDs(memPage2), ",") ||
		pgPage1.HasMore != memPage1.HasMore || pgPage2.HasMore != memPage2.HasMore {
		t.Fatalf("mixed walk != A-only walk: pg %v/%v (more %v/%v) vs mem %v/%v (more %v/%v)",
			runsPageIDs(pgPage1), runsPageIDs(pgPage2), pgPage1.HasMore, pgPage2.HasMore,
			runsPageIDs(memPage1), runsPageIDs(memPage2), memPage1.HasMore, memPage2.HasMore)
	}

	// A policy with no permitted repository is a terminal empty page: no rows,
	// no cursor, even though the collection is non-empty.
	emptyPolicy := authzITPolicy(map[string]auth.RepositoryPermission{"o/repo-z": {Read: true}})
	empty, err := st.ListRunsPageAuthorized(ctx, emptyPolicy, time.Time{}, "", 10)
	if err != nil {
		t.Fatalf("empty policy: %v", err)
	}
	if len(empty.Runs) != 0 || empty.HasMore || empty.NextID != "" || !empty.NextCreatedAt.IsZero() {
		t.Fatalf("empty policy = %d runs HasMore %v next (%v,%q), want terminal empty page",
			len(empty.Runs), empty.HasMore, empty.NextCreatedAt, empty.NextID)
	}

	// An empty authorized page beyond the visible tail (an old cursor) is
	// terminal even while older B rows exist.
	past, err := st.ListRunsPageAuthorized(ctx, policy, runs[0].CreatedAt.Add(-time.Hour), "", 10)
	if err != nil {
		t.Fatalf("past-tail page: %v", err)
	}
	if len(past.Runs) != 0 || past.HasMore || past.NextID != "" {
		t.Fatalf("past-tail page = %v HasMore %v next %q, want terminal", runsPageIDs(past), past.HasMore, past.NextID)
	}
}

// TestPostgresIntegrationRunsPageAuthorizedReposMatchesMemory pins page-for-
// page parity between the SQL authorized page and the shared memory
// definition (PageRunsAuthorized), including the terminal boundary.
func TestPostgresIntegrationRunsPageAuthorizedReposMatchesMemory(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	const (
		repoA = "github.com/o/repo-a"
		repoB = "github.com/o/repo-b"
	)
	base := time.Now().UTC().Truncate(time.Microsecond)
	runs := make([]model.Run, 0, 60)
	for i := 0; i < 60; i++ {
		repo := repoB
		if i%5 == 0 {
			repo = repoA
		}
		runs = append(runs, authzITRun(i, base, repo))
	}
	authzITSeed(t, st, runs)
	mem := runsPageMemoryStore(t, runs)
	policy := authzITPolicy(map[string]auth.RepositoryPermission{repoA: {Read: true}})
	afterAt, afterID := time.Time{}, ""
	for page := 0; ; page++ {
		if page > len(runs)+2 {
			t.Fatal("walk did not terminate")
		}
		pgPage, err := st.ListRunsPageAuthorized(ctx, policy, afterAt, afterID, 7)
		if err != nil {
			t.Fatalf("pg page %d: %v", page, err)
		}
		memPage, err := mem.ListRunsPageAuthorized(ctx, policy, afterAt, afterID, 7)
		if err != nil {
			t.Fatalf("mem page %d: %v", page, err)
		}
		if strings.Join(runsPageIDs(pgPage), ",") != strings.Join(runsPageIDs(memPage), ",") ||
			pgPage.HasMore != memPage.HasMore || pgPage.NextID != memPage.NextID || !pgPage.NextCreatedAt.Equal(memPage.NextCreatedAt) {
			t.Fatalf("page %d: pg %v (more=%v next=%q) != mem %v (more=%v next=%q)",
				page, runsPageIDs(pgPage), pgPage.HasMore, pgPage.NextID, runsPageIDs(memPage), memPage.HasMore, memPage.NextID)
		}
		if !pgPage.HasMore {
			return
		}
		afterAt, afterID = pgPage.NextCreatedAt, pgPage.NextID
	}
}

// TestPostgresIntegrationRunsPageAuthorizedGrantMatrixParity walks one mixed
// collection under every grant shape and asserts that the SQL page and the
// memory page agree run-for-run and boundary-for-boundary: unrestricted,
// exact canonical, bare alias (host-agnostic), global read with an explicit
// deny override, a host-case canonical spelling, and a conflicting entry set
// (fail closed).
func TestPostgresIntegrationRunsPageAuthorizedGrantMatrixParity(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	const (
		ghRepoA = "github.com/o/repo-a"
		ghRepoB = "github.com/o/repo-b"
		ghRepoC = "github.com/o/repo-c"
		glRepoA = "gitlab.com/o/repo-a"
	)
	base := time.Now().UTC().Truncate(time.Microsecond)
	// Two runs per repository group, one unresolvable identity, and one bare
	// (host-less) identity so the alias arm is exercised in SQL too.
	runs := []model.Run{
		authzITRun(0, base, ghRepoA),
		authzITRun(1, base, ghRepoB),
		authzITRun(2, base, glRepoA),
		authzITRun(3, base, ghRepoA),
		authzITRun(4, base, ghRepoB),
		authzITRun(5, base, glRepoA),
		authzITRun(6, base, ""),
		{ID: fmt.Sprintf("%032x", 8), Status: model.StatusSuccess, CreatedAt: base.Add(7 * time.Second), RepoFullName: "o/repo-a"},
		// Legacy URL-derived identities with a non-canonical host spelling:
		// the SQL predicate canonicalizes them, like the memory derivation.
		{ID: fmt.Sprintf("%032x", 9), Status: model.StatusSuccess, CreatedAt: base.Add(8 * time.Second), Repo: "ssh://git@GitHub.com/o/repo-b.git", RepoFullName: "o/repo-b"},
		{ID: fmt.Sprintf("%032x", 10), Status: model.StatusSuccess, CreatedAt: base.Add(9 * time.Second), Repo: "https://github.com:443/o/repo-c.git", RepoFullName: "o/repo-c"},
	}
	authzITSeed(t, st, runs)
	mem := runsPageMemoryStore(t, runs)

	cases := []struct {
		name   string
		policy RunAuthzPolicy
	}{
		{"unrestricted", RunAuthzPolicyForPrincipal(nil)},
		{"canonical", authzITPolicy(map[string]auth.RepositoryPermission{ghRepoA: {Read: true}})},
		{"bare alias", authzITPolicy(map[string]auth.RepositoryPermission{"o/repo-a": {Read: true}})},
		{"global read with deny override", authzITPolicy(map[string]auth.RepositoryPermission{ghRepoB: {Read: false}}, auth.RoleRead)},
		{"host-case canonical", authzITPolicy(map[string]auth.RepositoryPermission{"GitHub.com/o/repo-a": {Read: true}})},
		{"legacy host spellings", authzITPolicy(map[string]auth.RepositoryPermission{ghRepoB: {Read: true}, ghRepoC: {Read: true}})},
		{"conflict fails closed", authzITPolicy(map[string]auth.RepositoryPermission{
			ghRepoB:               {Read: true},
			"GitHub.com/o/repo-b": {Read: true, Run: true},
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			afterAt, afterID := time.Time{}, ""
			for page := 0; ; page++ {
				if page > len(runs)+2 {
					t.Fatal("walk did not terminate")
				}
				pgPage, err := st.ListRunsPageAuthorized(ctx, tc.policy, afterAt, afterID, 3)
				if err != nil {
					t.Fatalf("pg page %d: %v", page, err)
				}
				memPage, err := mem.ListRunsPageAuthorized(ctx, tc.policy, afterAt, afterID, 3)
				if err != nil {
					t.Fatalf("mem page %d: %v", page, err)
				}
				if strings.Join(runsPageIDs(pgPage), ",") != strings.Join(runsPageIDs(memPage), ",") ||
					pgPage.HasMore != memPage.HasMore || pgPage.NextID != memPage.NextID || !pgPage.NextCreatedAt.Equal(memPage.NextCreatedAt) {
					t.Fatalf("page %d: pg %v (more=%v next=%q) != mem %v (more=%v next=%q)",
						page, runsPageIDs(pgPage), pgPage.HasMore, pgPage.NextID, runsPageIDs(memPage), memPage.HasMore, memPage.NextID)
				}
				for _, run := range pgPage.Runs {
					if !tc.policy.Allows(RepoIDForRun(run)) {
						t.Fatalf("page %d returned %q which the policy denies", page, RepoIDForRun(run))
					}
				}
				if !pgPage.HasMore {
					break
				}
				afterAt, afterID = pgPage.NextCreatedAt, pgPage.NextID
			}
		})
	}
}

// TestPostgresIntegrationRunsPageAuthorizedLargeRepoCountPaginatesPageSized
// seeds a large repository count (200 repositories, 25 runs each) and proves
// one authorized page is exactly page-sized regardless of the collection's
// repository cardinality, with the boundary on the last visible run.
func TestPostgresIntegrationRunsPageAuthorizedLargeRepoCountPaginatesPageSized(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	const (
		repos      = 200
		perRepo    = 25
		pageSize   = 5
		firstGrant = "github.com/o/repo-000"
	)
	base := time.Now().UTC().Truncate(time.Microsecond)
	runs := make([]model.Run, 0, repos*perRepo)
	n := 0
	for r := 0; r < repos; r++ {
		repo := fmt.Sprintf("github.com/o/repo-%03d", r)
		for i := 0; i < perRepo; i++ {
			// Interleave repositories so the granted repository's runs are
			// spread across the collection.
			runs = append(runs, authzITRun(n, base, repo))
			n++
		}
	}
	authzITSeed(t, st, runs)
	policy := authzITPolicy(map[string]auth.RepositoryPermission{firstGrant: {Read: true}})

	page, err := st.ListRunsPageAuthorized(ctx, policy, time.Time{}, "", pageSize)
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	if len(page.Runs) != pageSize {
		t.Fatalf("page = %d runs, want exactly %d page-sized rows", len(page.Runs), pageSize)
	}
	if !page.HasMore || page.NextID == "" || page.NextCreatedAt.IsZero() {
		t.Fatalf("page boundary = HasMore %v next (%v,%q), want a continuing boundary", page.HasMore, page.NextCreatedAt, page.NextID)
	}
	for _, run := range page.Runs {
		if run.PolicyRepoID != firstGrant {
			t.Fatalf("page leaked repository %q", run.PolicyRepoID)
		}
	}
	if page.Runs[len(page.Runs)-1].ID != page.NextID {
		t.Fatalf("next id = %q, want the last visible run %q", page.NextID, page.Runs[len(page.Runs)-1].ID)
	}

	// Follow the boundary to the end: exactly perRepo granted runs, terminal.
	seen := len(page.Runs)
	afterAt, afterID := page.NextCreatedAt, page.NextID
	for pages := 0; pages < repos; pages++ {
		next, err := st.ListRunsPageAuthorized(ctx, policy, afterAt, afterID, pageSize)
		if err != nil {
			t.Fatalf("continuation: %v", err)
		}
		seen += len(next.Runs)
		if !next.HasMore {
			break
		}
		afterAt, afterID = next.NextCreatedAt, next.NextID
	}
	if seen != perRepo {
		t.Fatalf("authorized walk covered %d runs, want %d", seen, perRepo)
	}
}

// TestPostgresIntegrationRunsPageAuthorizedPlanHasNoDISTINCT is the
// plan-based (non-timing) proof that the shipped query shape removed the
// O(repository cardinality) pre-scan: the instrumented query never contains
// DISTINCT, and EXPLAIN over a populated, analyzed table reports an
// index-backed plan rather than a distinct/aggregate scan of runs.
func TestPostgresIntegrationRunsPageAuthorizedPlanHasNoDISTINCT(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	const (
		repoA = "github.com/o/repo-a"
		repoB = "github.com/o/repo-b"
	)
	base := time.Now().UTC().Truncate(time.Microsecond)
	runs := make([]model.Run, 0, 2500)
	for i := 0; i < 2500; i++ {
		repo := repoB
		if i%7 == 0 {
			repo = repoA
		}
		runs = append(runs, authzITRun(i, base, repo))
	}
	authzITSeed(t, st, runs)
	if _, err := st.pool.Exec(ctx, "ANALYZE runs"); err != nil {
		t.Fatalf("analyze: %v", err)
	}

	policy := authzITPolicy(map[string]auth.RepositoryPermission{repoA: {Read: true}})
	query, args := authorizedRunsPageSQL(policy, time.Time{}, "", 50)

	upper := strings.ToUpper(query)
	if strings.Contains(upper, "DISTINCT") {
		t.Fatalf("authorized page query contains DISTINCT:\n%s", query)
	}
	if strings.Contains(upper, "GROUP BY") {
		t.Fatalf("authorized page query contains an aggregate GROUP BY:\n%s", query)
	}

	plan := authzITExplain(t, st, query, args)
	t.Logf("EXPLAIN authorized page query:\n%s", plan)
	if strings.Contains(plan, "HashAggregate") || strings.Contains(plan, "GroupAggregate") || strings.Contains(plan, "Unique") || strings.Contains(plan, "Seq Scan on runs") {
		t.Fatalf("authorized page plan enumerates/aggregates runs:\n%s", plan)
	}
	if !strings.Contains(plan, "Index") {
		t.Fatalf("authorized page plan is not index-backed:\n%s", plan)
	}

	// The equivalent memory page agrees with the SQL page: the plan change is
	// not a behavior change.
	mem := runsPageMemoryStore(t, runs)
	pgPage, err := st.ListRunsPageAuthorized(ctx, policy, time.Time{}, "", 50)
	if err != nil {
		t.Fatalf("pg page: %v", err)
	}
	memPage, err := mem.ListRunsPageAuthorized(ctx, policy, time.Time{}, "", 50)
	if err != nil {
		t.Fatalf("mem page: %v", err)
	}
	if strings.Join(runsPageIDs(pgPage), ",") != strings.Join(runsPageIDs(memPage), ",") {
		t.Fatalf("plan-shaped page differs from memory: pg %d vs mem %d rows", len(pgPage.Runs), len(memPage.Runs))
	}
}

// authzITExplain returns the text plan of query (with args bound).
func authzITExplain(t *testing.T, st *PostgresStore, query string, args []any) string {
	t.Helper()
	rows, err := st.pool.Query(context.Background(), "EXPLAIN "+query, args...)
	if err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	defer rows.Close()
	lines := []string{}
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("EXPLAIN scan: %v", err)
		}
		lines = append(lines, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("EXPLAIN rows: %v", err)
	}
	return strings.Join(lines, "\n")
}

// TestPostgresIntegrationRunsPageAuthorizedClosedPoolFails covers the error
// branch: a closed pool must report an error for every authorized page form,
// never a page that reads as "no runs".
func TestPostgresIntegrationRunsPageAuthorizedClosedPoolFails(t *testing.T) {
	dsn := pgITDSN(t)
	st, err := NewPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatalf("NewPostgres: %v", err)
	}
	_ = st.Close()
	ctx := context.Background()
	policy := authzITPolicy(map[string]auth.RepositoryPermission{"github.com/o/repo-a": {Read: true}})
	if _, err := st.ListRunsPageAuthorized(ctx, policy, time.Time{}, "", 5); err == nil {
		t.Fatal("authorized page on a closed pool = nil error")
	}
	emptyPolicy := authzITPolicy(map[string]auth.RepositoryPermission{"o/repo-z": {Read: true}})
	if _, err := st.ListRunsPageAuthorized(ctx, emptyPolicy, time.Time{}, "", 5); err == nil {
		t.Fatal("empty policy on a closed pool = nil error")
	}
	if _, err := st.ListRunsPageAuthorized(ctx, RunAuthzPolicyForPrincipal(nil), time.Time{}, "", 5); err == nil {
		t.Fatal("unrestricted page on a closed pool = nil error")
	}
}
