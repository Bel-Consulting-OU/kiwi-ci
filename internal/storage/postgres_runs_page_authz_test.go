package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// authzPageRun builds a run whose canonical policy repository identity is
// repoID (PolicyRepoID is authoritative for RepoIDForRun) with a distinct
// created_at.
func authzPageRun(id string, at time.Time, repoID string) model.Run {
	return model.Run{ID: id, Status: model.StatusSuccess, CreatedAt: at, PolicyRepoID: repoID}
}

// TestPageRunsForAuthorizedReposFiltersBeforePaging pins the memory half of
// the authorized page contract: the permitted repository set is applied
// BEFORE the page boundary, so an invisible run can never occupy a page slot,
// decide HasMore, or become the NextCreatedAt/NextID position.
func TestPageRunsForAuthorizedReposFiltersBeforePaging(t *testing.T) {
	const (
		repoA = "github.com/o/repo-a"
		repoB = "github.com/o/repo-b"
	)
	base := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	// Oldest to newest: b1 A1 b2 A2 A3 b3. The B runs surround the A runs.
	runs := []model.Run{
		authzPageRun("b1", base.Add(0*time.Second), repoB),
		authzPageRun("a1", base.Add(1*time.Second), repoA),
		authzPageRun("b2", base.Add(2*time.Second), repoB),
		authzPageRun("a2", base.Add(3*time.Second), repoA),
		authzPageRun("a3", base.Add(4*time.Second), repoA),
		authzPageRun("b3", base.Add(5*time.Second), repoB),
	}
	allowedA := []string{repoA}

	// First page: only A runs newest-first, boundary on the last visible run.
	page1 := PageRunsForAuthorizedRepos(runs, allowedA, time.Time{}, "", 2)
	if got := strings.Join(runsPageIDs(page1), ","); got != "a3,a2" {
		t.Fatalf("page1 = %s, want the newest two A runs", got)
	}
	if !page1.HasMore || page1.NextID != "a2" || !page1.NextCreatedAt.Equal(base.Add(3*time.Second)) {
		t.Fatalf("page1 boundary = HasMore %v next (%v,%q), want a2's position", page1.HasMore, page1.NextCreatedAt, page1.NextID)
	}

	// Continuation reaches the older A run and terminates on the authorized
	// set: b1 exists strictly older than a1 but is invisible, so HasMore must
	// be false and no cursor may be emitted.
	page2 := PageRunsForAuthorizedRepos(runs, allowedA, page1.NextCreatedAt, page1.NextID, 2)
	if got := strings.Join(runsPageIDs(page2), ","); got != "a1" {
		t.Fatalf("page2 = %s, want a1", got)
	}
	if page2.HasMore || page2.NextID != "" || !page2.NextCreatedAt.IsZero() {
		t.Fatalf("page2 = HasMore %v next (%v,%q), want terminal", page2.HasMore, page2.NextCreatedAt, page2.NextID)
	}

	// An invisible row at the cursor instant is simply absent; the visible
	// rows newer than the cursor still page normally.
	pageAfterB2 := PageRunsForAuthorizedRepos(runs, allowedA, base.Add(2*time.Second), "b2", 10)
	if got := strings.Join(runsPageIDs(pageAfterB2), ","); got != "a1" {
		t.Fatalf("page after b2 = %s, want only a1", got)
	}
	if pageAfterB2.HasMore || pageAfterB2.NextID != "" {
		t.Fatalf("page after b2 = HasMore %v next %q, want terminal and no B-derived cursor", pageAfterB2.HasMore, pageAfterB2.NextID)
	}

	// nil means unrestricted: the same definition as PageRuns.
	unrestricted := PageRunsForAuthorizedRepos(runs, nil, time.Time{}, "", 3)
	if got := strings.Join(runsPageIDs(unrestricted), ","); got != "b3,a3,a2" {
		t.Fatalf("unrestricted page = %s, want the global newest three", got)
	}
	if !unrestricted.HasMore || unrestricted.NextID != "a2" {
		t.Fatalf("unrestricted boundary = HasMore %v next %q", unrestricted.HasMore, unrestricted.NextID)
	}

	// An exact empty allowlist matches nothing and is terminal: no rows, no
	// cursor, and HasMore cannot be inferred from the global collection.
	empty := PageRunsForAuthorizedRepos(runs, []string{}, time.Time{}, "", 10)
	if len(empty.Runs) != 0 || empty.HasMore || empty.NextID != "" || !empty.NextCreatedAt.IsZero() {
		t.Fatalf("empty allowlist = %d runs HasMore %v next (%v,%q), want terminal empty page", len(empty.Runs), empty.HasMore, empty.NextCreatedAt, empty.NextID)
	}

	// A cursor positioned by the last visible run never returns an invisible
	// newer row, even though one exists between the cursor and the visible
	// tail.
	pageFromA3 := PageRunsForAuthorizedRepos(runs, allowedA, base.Add(4*time.Second), "a3", 10)
	if got := strings.Join(runsPageIDs(pageFromA3), ","); got != "a2,a1" {
		t.Fatalf("page after a3 = %s, want a2,a1 only", got)
	}
	if pageFromA3.HasMore {
		t.Fatalf("page after a3 reported more rows despite no older visible run")
	}
}

// TestPageRunsForAuthorizedReposUsesPolicyIdentity pins that the filter uses
// the same canonical policy-first identity as the per-run read routes: a run
// whose POLICY identity is B is excluded from an A allowlist even when its
// checkout URL names A, and a legacy run (no stored identity) derives its
// identity from the clone URL + full name.
func TestPageRunsForAuthorizedReposUsesPolicyIdentity(t *testing.T) {
	base := time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC)
	forkRun := model.Run{
		ID: "fork", Status: model.StatusSuccess, CreatedAt: base.Add(time.Second),
		Repo:         "https://github.com/o/repo-a.git",
		RepoFullName: "o/repo-a",
		PolicyRepoID: "github.com/o/repo-b",
	}
	legacyRun := model.Run{
		ID: "legacy", Status: model.StatusSuccess, CreatedAt: base.Add(2 * time.Second),
		Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a",
	}
	page := PageRunsForAuthorizedRepos(
		[]model.Run{forkRun, legacyRun},
		[]string{"github.com/o/repo-a"}, time.Time{}, "", 10,
	)
	if got := strings.Join(runsPageIDs(page), ","); got != "legacy" {
		t.Fatalf("page = %s, want only the legacy repo-a run (policy identity decides)", got)
	}
}

// TestAuthorizedPageMemoryParity pins that memStore's authorized page is the
// same definition as the exported helper (and therefore the same contract the
// SQL store implements): identical ids, HasMore and next positions across a
// full walk and an empty allowlist.
func TestAuthorizedPageMemoryParity(t *testing.T) {
	const (
		repoA = "github.com/o/repo-a"
		repoB = "github.com/o/repo-b"
	)
	base := time.Date(2026, 4, 3, 0, 0, 0, 0, time.UTC)
	runs := []model.Run{}
	for i := 0; i < 20; i++ {
		repo := repoB
		if i%4 == 0 {
			repo = repoA
		}
		runs = append(runs, authzPageRun(fmt.Sprintf("run-%02d", i), base.Add(time.Duration(i)*time.Second), repo))
	}
	m := runsPageMemoryStore(t, runs)
	ctx := context.Background()
	allowed := []string{repoA}

	afterAt, afterID := time.Time{}, ""
	for page := 0; ; page++ {
		if page > len(runs)+2 {
			t.Fatal("walk did not terminate")
		}
		want := PageRunsForAuthorizedRepos(runs, allowed, afterAt, afterID, 3)
		got, err := m.ListRunsPageForAuthorizedRepos(ctx, allowed, afterAt, afterID, 3)
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		if strings.Join(runsPageIDs(got), ",") != strings.Join(runsPageIDs(want), ",") ||
			got.HasMore != want.HasMore || got.NextID != want.NextID || !got.NextCreatedAt.Equal(want.NextCreatedAt) {
			t.Fatalf("page %d: mem %v (more=%v next=%q) != helper %v (more=%v next=%q)",
				page, runsPageIDs(got), got.HasMore, got.NextID, runsPageIDs(want), want.HasMore, want.NextID)
		}
		if !got.HasMore {
			break
		}
		afterAt, afterID = got.NextCreatedAt, got.NextID
	}

	empty, err := m.ListRunsPageForAuthorizedRepos(ctx, []string{}, time.Time{}, "", 5)
	if err != nil {
		t.Fatalf("empty allowlist: %v", err)
	}
	if len(empty.Runs) != 0 || empty.HasMore || empty.NextID != "" {
		t.Fatalf("empty allowlist = %d runs HasMore %v next %q, want terminal empty page", len(empty.Runs), empty.HasMore, empty.NextID)
	}
}

// TestListRunRepoIDs pins the candidate enumeration used to resolve the
// authorized repository set: distinct canonical policy-first identities,
// ascending, including the derived identity of legacy rows and the empty
// identity of unresolvable rows (the caller decides visibility through the
// repository-grant resolution).
func TestListRunRepoIDs(t *testing.T) {
	base := time.Date(2026, 4, 4, 0, 0, 0, 0, time.UTC)
	m := runsPageMemoryStore(t, []model.Run{
		authzPageRun("r1", base.Add(time.Second), "github.com/o/repo-b"),
		authzPageRun("r2", base.Add(2*time.Second), "github.com/o/repo-a"),
		authzPageRun("r3", base.Add(3*time.Second), "github.com/o/repo-b"),
		{ID: "legacy", Status: model.StatusSuccess, CreatedAt: base.Add(4 * time.Second), Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a"},
		{ID: "hostless", Status: model.StatusSuccess, CreatedAt: base.Add(5 * time.Second), RepoFullName: "o/repo-c"},
		{ID: "none", Status: model.StatusSuccess, CreatedAt: base.Add(6 * time.Second)},
	})
	got, err := m.ListRunRepoIDs(context.Background())
	if err != nil {
		t.Fatalf("ListRunRepoIDs: %v", err)
	}
	want := []string{"", "github.com/o/repo-a", "github.com/o/repo-b", "o/repo-c"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ListRunRepoIDs = %q, want %q", got, want)
	}
}

// TestAuthorizedPageFaultyStoreDelegation proves FaultyStore delegates both
// new capabilities without consuming the mutation-fault counter, and fails
// closed with a diagnosable capability error when Inner lacks them.
func TestAuthorizedPageFaultyStoreDelegation(t *testing.T) {
	base := time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC)
	allowed := []string{"github.com/o/repo-a"}
	m := runsPageMemoryStore(t, []model.Run{
		authzPageRun("b", base.Add(time.Second), "github.com/o/repo-b"),
		authzPageRun("a", base.Add(2*time.Second), "github.com/o/repo-a"),
	})
	fault := &FaultyStore{Inner: m, FailAfter: 1, Err: errors.New("write fault")}
	ctx := context.Background()

	page, err := fault.ListRunsPageForAuthorizedRepos(ctx, allowed, time.Time{}, "", 5)
	if err != nil {
		t.Fatalf("ListRunsPageForAuthorizedRepos through FaultyStore: %v", err)
	}
	if got := strings.Join(runsPageIDs(page), ","); got != "a" {
		t.Fatalf("delegated page = %s, want only a", got)
	}
	ids, err := fault.ListRunRepoIDs(ctx)
	if err != nil {
		t.Fatalf("ListRunRepoIDs through FaultyStore: %v", err)
	}
	if strings.Join(ids, ",") != "github.com/o/repo-a,github.com/o/repo-b" {
		t.Fatalf("delegated ids = %q", ids)
	}
	if fault.Mutations() != 0 {
		t.Fatalf("authorized page reads consumed %d write fault(s)", fault.Mutations())
	}

	missing := &FaultyStore{Inner: storeOnlyInner{}}
	if _, err := missing.ListRunsPageForAuthorizedRepos(ctx, allowed, time.Time{}, "", 5); err == nil || !strings.Contains(err.Error(), "RunPageForPrincipalStore") {
		t.Fatalf("missing inner capability = %v, want RunPageForPrincipalStore error", err)
	}
	if _, err := missing.ListRunRepoIDs(ctx); err == nil || !strings.Contains(err.Error(), "RunRepoIDStore") {
		t.Fatalf("missing inner capability = %v, want RunRepoIDStore error", err)
	}
}
