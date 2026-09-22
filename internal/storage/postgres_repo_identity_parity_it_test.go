package storage

// Real-PostgreSQL Go<->SQL parity corpus for the materialized run repository
// identity. Gated on KIWI_TEST_POSTGRES_URL exactly like the other storage
// integration tests: skipped when the variable is unset and in -short mode.
//
// R1-A: the pre-fix canonicalHostSQL stripped a default-port suffix from EVERY
// unbracketed host, so an unbracketed IPv6 literal ending in :443/:80/:22 was
// collapsed by SQL ("::1:443" -> "::1") while auth.CanonicalHost preserved it.
// The collection endpoint could then read a run under a grant for a DIFFERENT
// forge than the per-run RBAC path authorized. The corpus below executes the
// SHIPPED SQL canonicalizer against PostgreSQL and requires every decision to
// agree with auth.CanonicalHost / auth.CanReadRepoIdentity, and the collection
// endpoint to agree with the per-run path.
//
// R1-B: the same corpus also pins that the run's normalized identity columns
// (stamped by the runs write path) equal the Go derivation, so the page
// predicate's equality can never hide a canonicalization divergence.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// canonicalHostCorpus is the R1-A parity corpus: bracketed and unbracketed
// IPv6 literals (including ones whose tail looks like a default port), the
// well-known default ports, a non-default port, trailing-dot spellings, mixed
// case, and the legacy host:path spelling.
var canonicalHostCorpus = []string{
	"[::1]:443", "[::1:443]", "::1", "::1:443",
	"2001:db8::22", "2001:db8::443", "2001:db8::22.",
	"host:80", "host:22", "host:443", "host:8080",
	"host.", "Host:8080", "host:abc",
	"github.com.", "GitHub.COM.", "github.com.:443", "GITHUB.COM",
	"[::1]", "[::1]:8443", "a:b:c",
}

// TestPostgresIntegrationCanonicalHostFunctionParityCorpus executes the
// SHIPPED SQL host canonicalizer (kiwi_canonical_host, migration 0034) against
// PostgreSQL for every corpus spelling and requires byte equality with
// auth.CanonicalHost. This is the direct R1-A regression: on the pre-fix
// expression the IPv6 cases ("::1:443" -> "::1", "2001:db8::22" ->
// "2001:db8:") diverged.
func TestPostgresIntegrationCanonicalHostFunctionParityCorpus(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	for _, host := range canonicalHostCorpus {
		var got string
		if err := st.pool.QueryRow(ctx, `SELECT `+canonicalHostFunctionName+`($1)`, host).Scan(&got); err != nil {
			t.Fatalf("SELECT %s(%q): %v", canonicalHostFunctionName, host, err)
		}
		if want := auth.CanonicalHost(host); got != want {
			t.Errorf("SQL %s(%q) = %q, auth.CanonicalHost = %q", canonicalHostFunctionName, host, got, want)
		}
	}
}

// TestPostgresIntegrationRunIdentityDecisionParityCorpus is the end-to-end
// R1-A/R1-B parity: for every corpus host it writes a run whose policy
// repository identity is spelled with that host, grants the principal the
// canonical identity, and requires
//
//   - the materialized columns to equal the Go normalizedRepoColumns pair,
//   - the authorized collection page (SQL) to include the run iff the memory
//     policy allows it,
//   - the per-run RBAC decision (auth.CanReadRepo and the typed
//     auth.CanReadRepoIdentity) to agree with the collection endpoint.
func TestPostgresIntegrationRunIdentityDecisionParityCorpus(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	const full = "acme/repo"
	base := time.Now().UTC().Truncate(time.Microsecond)

	runs := make(map[string]model.Run, len(canonicalHostCorpus))
	runsByID := map[string]string{}
	for i, host := range canonicalHostCorpus {
		run := model.Run{
			ID:           fmt.Sprintf("%032x", i+1),
			Status:       model.StatusSuccess,
			CreatedAt:    base.Add(time.Duration(i) * time.Second),
			RepoFullName: full,
			PolicyRepoID: host + "/" + full,
		}
		if err := st.InsertRun(ctx, run); err != nil {
			t.Fatalf("insert run for host %q: %v", host, err)
		}
		runs[host] = run
		runsByID[run.ID] = host
	}
	mem := runsPageMemoryStore(t, mapRunsSorted(canonicalHostCorpus, runs))

	for _, host := range canonicalHostCorpus {
		run := runs[host]
		canon := auth.CanonicalHost(host)
		grant := canon + "/" + full
		p := auth.Principal{Subject: "reader", Repositories: map[string]auth.RepositoryPermission{grant: {Read: true}}}
		policy := RunAuthzPolicyForPrincipal(&p)

		goAllow := auth.CanReadRepo(p, RepoIDForRun(run))
		ident, err := auth.CanonicalHostIdentity(canon, full)
		if err != nil {
			t.Fatalf("CanonicalHostIdentity(%q,%q): %v", canon, full, err)
		}
		typedAllow := auth.CanReadRepoIdentity(p, ident)
		if goAllow != typedAllow {
			t.Fatalf("host %q: CanReadRepo = %v, CanReadRepoIdentity = %v", host, goAllow, typedAllow)
		}

		var dbIdent, dbFull string
		if err := st.pool.QueryRow(ctx, `SELECT `+normalizedRunRepoIdentityColumn+`, `+normalizedRunRepoFullNameColumn+` FROM runs WHERE id=$1`, run.ID).Scan(&dbIdent, &dbFull); err != nil {
			t.Fatalf("read normalized columns for host %q: %v", host, err)
		}
		wantIdent, wantFull := normalizedRepoColumns(RepoIDForRun(run))
		if dbIdent != wantIdent || dbFull != wantFull {
			t.Fatalf("host %q: normalized columns = (%q,%q), Go = (%q,%q)", host, dbIdent, dbFull, wantIdent, wantFull)
		}

		page, err := st.ListRunsPageAuthorized(ctx, policy, time.Time{}, "", 1000)
		if err != nil {
			t.Fatalf("host %q: authorized page: %v", host, err)
		}
		inSQL := containsID(runsPageIDs(page), run.ID)
		memPage, err := mem.ListRunsPageAuthorized(ctx, policy, time.Time{}, "", 1000)
		if err != nil {
			t.Fatalf("host %q: memory page: %v", host, err)
		}
		inMem := containsID(runsPageIDs(memPage), run.ID)
		if inSQL != inMem {
			t.Fatalf("host %q: SQL page includes run = %v, memory = %v", host, inSQL, inMem)
		}
		if inSQL != goAllow {
			t.Fatalf("host %q: collection endpoint includes run = %v, per-run CanReadRepo = %v (identity grant %q)", host, inSQL, goAllow, grant)
		}
	}
}

// TestPostgresIntegrationRunIdentityGrantMatrixParity walks one collection of
// normalized/legacy/IPv6 identities under several grant shapes and asserts the
// SQL page equals the memory page page-for-page, boundary-for-boundary, and
// never returns a run the policy denies.
func TestPostgresIntegrationRunIdentityGrantMatrixParity(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	const (
		ipv6Full  = "::1:443/o/repo-a"
		ipv6Brack = "[::1:443]/o/repo-a"
		ipv6Plain = "::1/o/repo-a"
		v6Other   = "2001:db8::22/o/repo-a"
		ghPort    = "GitHub.com:443/o/repo-b"
		ghPlain   = "github.com/o/repo-c"
		bare      = "o/repo-a"
	)
	base := time.Now().UTC().Truncate(time.Microsecond)
	runs := []model.Run{
		authzITRun(0, base, ipv6Full),
		authzITRun(1, base, ipv6Brack),
		authzITRun(2, base, ipv6Plain),
		authzITRun(3, base, v6Other),
		authzITRun(4, base, ghPort),
		authzITRun(5, base, ghPlain),
		authzITRun(6, base, bare),
		authzITRun(7, base, ""),
	}
	authzITSeed(t, st, runs)
	mem := runsPageMemoryStore(t, runs)

	cases := []struct {
		name   string
		policy RunAuthzPolicy
	}{
		{"canonical ipv6 unbracketed", authzITPolicy(map[string]auth.RepositoryPermission{ipv6Full: {Read: true}})},
		{"canonical ipv6 bracketed", authzITPolicy(map[string]auth.RepositoryPermission{ipv6Brack: {Read: true}})},
		{"canonical default-port host", authzITPolicy(map[string]auth.RepositoryPermission{"github.com/o/repo-b": {Read: true}})},
		{"bare alias host-agnostic", authzITPolicy(map[string]auth.RepositoryPermission{bare: {Read: true}})},
		{"global read with deny", authzITPolicy(map[string]auth.RepositoryPermission{ghPlain: {Read: false}}, auth.RoleRead)},
		{"conflict fails closed", authzITPolicy(map[string]auth.RepositoryPermission{
			"github.com/o/repo-b": {Read: true},
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

// TestPostgresIntegrationNormalizedRunRepoBackfill seeds raw legacy-shaped runs
// with NULL normalized columns (as a pre-0033 row or a pre-upgrade-binary row
// looks), executes migration 0034's backfill statement, and requires every
// materialized pair to equal the Go derivation normalizedRepoColumns(
// RepoIDForRun(run)) — including a legacy clone-URL-only row, a stored
// mixed-case repo_id, a policy_repo_id override, bracketed/unbracketed IPv6
// and a bare/empty identity.
func TestPostgresIntegrationNormalizedRunRepoBackfill(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Microsecond)
	legacy := []model.Run{
		{ID: fmt.Sprintf("%032x", 1), Status: model.StatusSuccess, CreatedAt: base.Add(time.Second),
			Repo: "https://GitHub.com/Acme/Repo.git", RepoFullName: "Acme/Repo"},
		{ID: fmt.Sprintf("%032x", 2), Status: model.StatusSuccess, CreatedAt: base.Add(2 * time.Second),
			RepoID: "GitHub.com/o/repo", RepoFullName: "o/repo"},
		{ID: fmt.Sprintf("%032x", 3), Status: model.StatusSuccess, CreatedAt: base.Add(3 * time.Second),
			RepoID: "github.com/o/other", PolicyRepoID: "gitlab.com/o/repo", RepoFullName: "o/repo"},
		{ID: fmt.Sprintf("%032x", 4), Status: model.StatusSuccess, CreatedAt: base.Add(4 * time.Second),
			RepoID: "[::1]:443/o/repo", RepoFullName: "o/repo"},
		{ID: fmt.Sprintf("%032x", 5), Status: model.StatusSuccess, CreatedAt: base.Add(5 * time.Second),
			RepoID: "2001:db8::443/o/repo", RepoFullName: "o/repo"},
		{ID: fmt.Sprintf("%032x", 6), Status: model.StatusSuccess, CreatedAt: base.Add(6 * time.Second),
			RepoFullName: "o/repo"},
		{ID: fmt.Sprintf("%032x", 7), Status: model.StatusSuccess, CreatedAt: base.Add(7 * time.Second)},
	}
	for _, run := range legacy {
		payload, err := jsonMarshal(run)
		if err != nil {
			t.Fatalf("marshal legacy run %s: %v", run.ID, err)
		}
		// Deliberately omit the normalized columns: they stay NULL, exactly
		// like a row written before migration 0033.
		if _, err := st.pool.Exec(ctx, `INSERT INTO runs (id, status, started_at, finished_at, created_at, payload) VALUES ($1, $2, $3, $4, $5, $6)`,
			run.ID, string(run.Status), run.StartedAt, run.FinishedAt, run.CreatedAt, payload); err != nil {
			t.Fatalf("raw insert legacy run %s: %v", run.ID, err)
		}
	}

	var nullCount int
	if err := st.pool.QueryRow(ctx, `SELECT COUNT(*) FROM runs WHERE `+normalizedRunRepoIdentityColumn+` IS NULL OR `+normalizedRunRepoFullNameColumn+` IS NULL`).Scan(&nullCount); err != nil {
		t.Fatalf("count NULL normalized rows: %v", err)
	}
	if nullCount != len(legacy) {
		t.Fatalf("pre-backfill NULL rows = %d, want %d", nullCount, len(legacy))
	}

	if _, err := st.pool.Exec(ctx, normalizedRunRepoBackfillSQL()); err != nil {
		t.Fatalf("backfill: %v", err)
	}

	for _, run := range legacy {
		var dbIdent, dbFull string
		if err := st.pool.QueryRow(ctx, `SELECT `+normalizedRunRepoIdentityColumn+`, `+normalizedRunRepoFullNameColumn+` FROM runs WHERE id=$1`, run.ID).Scan(&dbIdent, &dbFull); err != nil {
			t.Fatalf("read backfilled columns for %s: %v", run.ID, err)
		}
		wantIdent, wantFull := normalizedRepoColumns(RepoIDForRun(run))
		if dbIdent != wantIdent || dbFull != wantFull {
			t.Errorf("backfill %s = (%q,%q), Go = (%q,%q) [repo_id=%q policy_repo_id=%q repo=%q full=%q]",
				run.ID, dbIdent, dbFull, wantIdent, wantFull, run.RepoID, run.PolicyRepoID, run.Repo, run.RepoFullName)
		}
	}

	// The backfill is idempotent: a second run changes nothing.
	if _, err := st.pool.Exec(ctx, normalizedRunRepoBackfillSQL()); err != nil {
		t.Fatalf("second backfill: %v", err)
	}
	// The backfilled IPv6 row is now visible to the authorized page under the
	// canonical grant that a naive created-at walk would have missed.
	policy := authzITPolicy(map[string]auth.RepositoryPermission{"2001:db8::443/o/repo": {Read: true}})
	page, err := st.ListRunsPageAuthorized(ctx, policy, time.Time{}, "", 10)
	if err != nil {
		t.Fatalf("authorized page after backfill: %v", err)
	}
	if !containsID(runsPageIDs(page), legacy[4].ID) {
		t.Fatalf("backfilled IPv6 run not visible: page = %v", runsPageIDs(page))
	}
}

// TestPostgresIntegrationRunsPageAuthorizedNormalizedKeysetPlan is the
// EXPLAIN-based (non-timing) R1-B proof: with the normalized columns the
// shipped query is served by runs_repo_identity_normalized_keyset_idx, not by
// a walk of runs_created_at_idx with the identity expression as a per-row
// filter. A sparse tenant (a handful of runs among thousands) is the case the
// pre-fix predicate could not bound.
func TestPostgresIntegrationRunsPageAuthorizedNormalizedKeysetPlan(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	const (
		sparse   = "github.com/o/sparse"
		pageSize = 25
		repos    = 100
		perRepo  = 25
	)
	base := time.Now().UTC().Truncate(time.Microsecond)
	runs := make([]model.Run, 0, repos*perRepo+4)
	n := 0
	for r := 0; r < repos; r++ {
		repo := fmt.Sprintf("github.com/o/repo-%03d", r)
		for i := 0; i < perRepo; i++ {
			runs = append(runs, authzITRun(n, base, repo))
			n++
		}
	}
	for i := 0; i < 4; i++ {
		runs = append(runs, authzITRun(n, base, sparse))
		n++
	}
	authzITSeed(t, st, runs)
	if _, err := st.pool.Exec(ctx, "ANALYZE runs"); err != nil {
		t.Fatalf("analyze: %v", err)
	}

	policy := authzITPolicy(map[string]auth.RepositoryPermission{sparse: {Read: true}})
	query, args := authorizedRunsPageSQL(policy, time.Time{}, "", pageSize)
	predicate := query
	if i := strings.Index(predicate, " FROM runs WHERE "); i >= 0 {
		predicate = predicate[i+len(" FROM runs WHERE "):]
	}
	if !strings.Contains(query, normalizedRunRepoIdentityColumn) {
		t.Fatalf("authorized page query does not use the normalized identity column:\n%s", query)
	}
	for _, forbidden := range []string{"payload", "SUBSTRING", "STRPOS", "REGEXP_REPLACE", "LOWER("} {
		if strings.Contains(predicate, forbidden) {
			t.Fatalf("authorized page predicate parses identity (%q):\n%s", forbidden, predicate)
		}
	}
	plan := authzITExplain(t, st, query, args)
	t.Logf("EXPLAIN authorized page query (normalized columns):\n%s", plan)
	if strings.Contains(plan, "Seq Scan on runs") {
		t.Fatalf("authorized page plan walks runs sequentially:\n%s", plan)
	}
	if !strings.Contains(plan, "runs_repo_identity_normalized_keyset_idx") {
		t.Fatalf("authorized page plan does not use the normalized keyset index:\n%s", plan)
	}
	if !strings.Contains(plan, "Index") && !strings.Contains(plan, "Bitmap") {
		t.Fatalf("authorized page plan is not index-backed:\n%s", plan)
	}
	if !strings.Contains(plan, "Index Cond") {
		t.Fatalf("authorized page plan does not push the normalized equality into the index:\n%s", plan)
	}

	// The sparse page is exactly the sparse runs, newest-first, and agrees
	// with the memory definition.
	page, err := st.ListRunsPageAuthorized(ctx, policy, time.Time{}, "", pageSize)
	if err != nil {
		t.Fatalf("authorized page: %v", err)
	}
	if len(page.Runs) != 4 || page.HasMore {
		t.Fatalf("sparse page = %d runs HasMore %v, want the 4 sparse runs terminal", len(page.Runs), page.HasMore)
	}
	for _, run := range page.Runs {
		if run.PolicyRepoID != sparse {
			t.Fatalf("sparse page leaked %q", run.PolicyRepoID)
		}
	}
	mem := runsPageMemoryStore(t, runs)
	memPage, err := mem.ListRunsPageAuthorized(ctx, policy, time.Time{}, "", pageSize)
	if err != nil {
		t.Fatalf("memory page: %v", err)
	}
	if strings.Join(runsPageIDs(page), ",") != strings.Join(runsPageIDs(memPage), ",") {
		t.Fatalf("sparse page %v != memory %v", runsPageIDs(page), runsPageIDs(memPage))
	}
}

// mapRunsSorted returns the corpus runs ordered by index so the memory store's
// insertion order is deterministic.
func mapRunsSorted(hosts []string, runs map[string]model.Run) []model.Run {
	out := make([]model.Run, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, runs[h])
	}
	return out
}

func containsID(ids []string, id string) bool {
	for _, got := range ids {
		if got == id {
			return true
		}
	}
	return false
}
