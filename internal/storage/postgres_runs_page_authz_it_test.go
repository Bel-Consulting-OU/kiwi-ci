package storage

// Real-PostgreSQL integration tests for the AUTHORIZED keyset page
// (RunPageForPrincipalStore) and candidate enumeration (RunRepoIDStore).
// Gated on KIWI_TEST_POSTGRES_URL exactly like the other storage integration
// tests: skipped when the variable is unset and in -short mode.
//
// The defect these pin: the pre-fix collection paged the GLOBAL runs table
// first and filtered per run afterwards, so a repository-scoped reader could
// page through cursor positions (creation timestamps and run IDs) of runs it
// cannot read. The authorized predicate must bound the page BEFORE ORDER BY
// ... LIMIT, so every returned row, HasMore and next position is visible.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

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

// TestPostgresIntegrationRunsPageAuthorizedReposNoLeak is the real-PG
// regression for the authorization leak: 2,500 private-B runs surround three
// readable-A runs, and an A-only allowlist must page exactly the A runs with
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
		run := authzITRun(i, base, repo)
		if err := st.InsertRun(ctx, run); err != nil {
			t.Fatalf("insert run %d: %v", i, err)
		}
		runs = append(runs, run)
	}

	// The mixed collection really does contain B rows newer than the newest
	// readable A run (the pre-fix leak source); the unrestricted first page
	// proves it.
	first, err := st.ListRunsPageForAuthorizedRepos(ctx, nil, time.Time{}, "", 1)
	if err != nil {
		t.Fatalf("unrestricted first page: %v", err)
	}
	if len(first.Runs) != 1 || first.Runs[0].ID != runs[total-1].ID {
		t.Fatalf("unrestricted first page = %v, want the newest B run", runsPageIDs(first))
	}

	// Walk the authorized pages with a deliberately tiny page size so the
	// boundary logic is exercised.
	allowed := []string{repoA}
	var seen []model.Run
	afterAt, afterID := time.Time{}, ""
	pages := 0
	for {
		if pages > len(runs) {
			t.Fatal("authorized walk did not terminate")
		}
		page, err := st.ListRunsPageForAuthorizedRepos(ctx, allowed, afterAt, afterID, 2)
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
			// The next position must be the last VISIBLE A row, or unset on
			// an empty page — never a B row.
			if len(page.Runs) > 0 {
				last := page.Runs[len(page.Runs)-1]
				if page.NextID != "" && page.NextID != last.ID {
					t.Fatalf("terminal next id = %q, want %q", page.NextID, last.ID)
				}
			}
			break
		}
		// A continuing page must carry its own last visible row as the next
		// position: a boundary derived from an invisible row would change
		// the timestamp/ID pair.
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
	memPage1, err := memA.ListRunsPageForAuthorizedRepos(ctx, nil, time.Time{}, "", 2)
	if err != nil {
		t.Fatalf("A-only page1: %v", err)
	}
	memPage2, err := memA.ListRunsPageForAuthorizedRepos(ctx, nil, memPage1.NextCreatedAt, memPage1.NextID, 2)
	if err != nil {
		t.Fatalf("A-only page2: %v", err)
	}
	pgPage1, err := st.ListRunsPageForAuthorizedRepos(ctx, allowed, time.Time{}, "", 2)
	if err != nil {
		t.Fatalf("mixed page1: %v", err)
	}
	pgPage2, err := st.ListRunsPageForAuthorizedRepos(ctx, allowed, pgPage1.NextCreatedAt, pgPage1.NextID, 2)
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

	// An empty exact allowlist is a terminal empty page: no rows, no cursor.
	empty, err := st.ListRunsPageForAuthorizedRepos(ctx, []string{}, time.Time{}, "", 10)
	if err != nil {
		t.Fatalf("empty allowlist: %v", err)
	}
	if len(empty.Runs) != 0 || empty.HasMore || empty.NextID != "" || !empty.NextCreatedAt.IsZero() {
		t.Fatalf("empty allowlist = %d runs HasMore %v next (%v,%q), want terminal empty page",
			len(empty.Runs), empty.HasMore, empty.NextCreatedAt, empty.NextID)
	}

	// An empty authorized page beyond the visible tail (an old cursor) is
	// terminal even while older B rows exist.
	past, err := st.ListRunsPageForAuthorizedRepos(ctx, allowed, runs[0].CreatedAt.Add(-time.Hour), "", 10)
	if err != nil {
		t.Fatalf("past-tail page: %v", err)
	}
	if len(past.Runs) != 0 || past.HasMore || past.NextID != "" {
		t.Fatalf("past-tail page = %v HasMore %v next %q, want terminal", runsPageIDs(past), past.HasMore, past.NextID)
	}
}

// TestPostgresIntegrationRunsPageAuthorizedReposMatchesMemory pins page-for-
// page parity between the SQL authorized page and the shared memory
// definition (PageRunsForAuthorizedRepos), including the terminal boundary.
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
		run := authzITRun(i, base, repo)
		if err := st.InsertRun(ctx, run); err != nil {
			t.Fatalf("insert run %d: %v", i, err)
		}
		runs = append(runs, run)
	}
	mem := runsPageMemoryStore(t, runs)
	allowed := []string{repoA}
	afterAt, afterID := time.Time{}, ""
	for page := 0; ; page++ {
		if page > len(runs)+2 {
			t.Fatal("walk did not terminate")
		}
		pgPage, err := st.ListRunsPageForAuthorizedRepos(ctx, allowed, afterAt, afterID, 7)
		if err != nil {
			t.Fatalf("pg page %d: %v", page, err)
		}
		memPage, err := mem.ListRunsPageForAuthorizedRepos(ctx, allowed, afterAt, afterID, 7)
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

// TestPostgresIntegrationRunsPageListRunRepoIDs pins the SQL candidate
// enumeration: the distinct canonical policy-first identities, ascending,
// including a fork run whose policy identity differs from its checkout URL,
// the derived identity of a legacy run, and the empty identity.
func TestPostgresIntegrationRunsPageListRunRepoIDs(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Microsecond)
	seed := []model.Run{
		authzITRun(0, base, "github.com/o/repo-b"),
		authzITRun(1, base, "github.com/o/repo-a"),
		authzITRun(2, base, "github.com/o/repo-b"),
		{
			ID: fmt.Sprintf("%032x", 900), Status: model.StatusSuccess, CreatedAt: base.Add(3 * time.Second),
			Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", PolicyRepoID: "github.com/o/repo-b",
		},
		{
			ID: fmt.Sprintf("%032x", 901), Status: model.StatusSuccess, CreatedAt: base.Add(4 * time.Second),
			Repo: "ssh://git@github.com/o/repo-a.git", RepoFullName: "o/repo-a",
		},
		{ID: fmt.Sprintf("%032x", 902), Status: model.StatusSuccess, CreatedAt: base.Add(5 * time.Second)},
	}
	for _, run := range seed {
		if err := st.InsertRun(ctx, run); err != nil {
			t.Fatalf("insert %s: %v", run.ID, err)
		}
	}
	got, err := st.ListRunRepoIDs(ctx)
	if err != nil {
		t.Fatalf("ListRunRepoIDs: %v", err)
	}
	want := []string{"", "github.com/o/repo-a", "github.com/o/repo-b"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ListRunRepoIDs = %q, want %q", got, want)
	}
}

// TestPostgresIntegrationRunsPageAuthorizedReposClosedPoolFails covers the
// error branch: a closed pool must report an error for every authorized page
// form and for candidate enumeration, never a page that reads as "no runs".
func TestPostgresIntegrationRunsPageAuthorizedReposClosedPoolFails(t *testing.T) {
	dsn := pgITDSN(t)
	st, err := NewPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatalf("NewPostgres: %v", err)
	}
	_ = st.Close()
	ctx := context.Background()
	if _, err := st.ListRunsPageForAuthorizedRepos(ctx, []string{"github.com/o/repo-a"}, time.Time{}, "", 5); err == nil {
		t.Fatal("authorized page on a closed pool = nil error")
	}
	if _, err := st.ListRunsPageForAuthorizedRepos(ctx, []string{}, time.Time{}, "", 5); err == nil {
		t.Fatal("empty allowlist on a closed pool = nil error")
	}
	if _, err := st.ListRunsPageForAuthorizedRepos(ctx, nil, time.Time{}, "", 5); err == nil {
		t.Fatal("unrestricted page on a closed pool = nil error")
	}
	if _, err := st.ListRunRepoIDs(ctx); err == nil {
		t.Fatal("ListRunRepoIDs on a closed pool = nil error")
	}
}
