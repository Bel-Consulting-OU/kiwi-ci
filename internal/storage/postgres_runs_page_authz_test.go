package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// authzPageRun builds a run whose canonical policy repository identity is
// repoID (PolicyRepoID is authoritative for RepoIDForRun) with a distinct
// created_at.
func authzPageRun(id string, at time.Time, repoID string) model.Run {
	return model.Run{ID: id, Status: model.StatusSuccess, CreatedAt: at, PolicyRepoID: repoID}
}

// authzPolicyFor builds the normalized policy of a repository-scoped reader
// from raw grant spellings, exactly as the server does from a request
// principal.
func authzPolicyFor(grants map[string]auth.RepositoryPermission, roles ...auth.Role) RunAuthzPolicy {
	p := auth.Principal{Subject: "reader", Roles: roles, Repositories: grants}
	return RunAuthzPolicyForPrincipal(&p)
}

// TestRunAuthzPolicyGrantMatrix pins the normalized visibility predicate for
// the full grant matrix: unrestricted global read, exact canonical grants,
// explicit bare aliases, explicit deny overrides and conflict fail-closed —
// each candidate resolved with the same typed positional rule as
// auth.CanReadRepo.
func TestRunAuthzPolicyGrantMatrix(t *testing.T) {
	const (
		ghRepoA = "github.com/o/repo-a"
		ghRepoB = "github.com/o/repo-b"
		glRepoA = "gitlab.com/o/repo-a"
		bareA   = "o/repo-a"
	)
	cases := []struct {
		name   string
		policy RunAuthzPolicy
		want   map[string]bool
	}{
		{
			name:   "nil principal is unrestricted",
			policy: RunAuthzPolicyForPrincipal(nil),
			want:   map[string]bool{ghRepoA: true, ghRepoB: true, glRepoA: true, bareA: true, "": true},
		},
		{
			name:   "admin is unrestricted",
			policy: authzPolicyFor(nil, auth.RoleAdmin),
			want:   map[string]bool{ghRepoA: true, ghRepoB: true, glRepoA: true, "": true},
		},
		{
			name:   "global read with no entries is unrestricted",
			policy: authzPolicyFor(nil, auth.RoleRead),
			want:   map[string]bool{ghRepoA: true, ghRepoB: true, "": true},
		},
		{
			name:   "exact canonical grant",
			policy: authzPolicyFor(map[string]auth.RepositoryPermission{ghRepoA: {Read: true}}),
			want:   map[string]bool{ghRepoA: true, ghRepoB: false, glRepoA: false, bareA: false, "": false},
		},
		{
			name:   "bare alias is host-agnostic and authorizes its own bare name",
			policy: authzPolicyFor(map[string]auth.RepositoryPermission{bareA: {Read: true}}),
			want:   map[string]bool{ghRepoA: true, glRepoA: true, ghRepoB: false, bareA: true, "": false},
		},
		{
			name:   "host case canonicalizes",
			policy: authzPolicyFor(map[string]auth.RepositoryPermission{"GitHub.com/o/repo-a": {Read: true}}),
			want:   map[string]bool{ghRepoA: true, ghRepoB: false, glRepoA: false},
		},
		{
			name:   "default port canonicalizes",
			policy: authzPolicyFor(map[string]auth.RepositoryPermission{"github.com:443/o/repo-a": {Read: true}}),
			want:   map[string]bool{ghRepoA: true, ghRepoB: false},
		},
		{
			name:   "trailing dot canonicalizes",
			policy: authzPolicyFor(map[string]auth.RepositoryPermission{"github.com./o/repo-a": {Read: true}}),
			want:   map[string]bool{ghRepoA: true, ghRepoB: false},
		},
		{
			name:   "global read with an explicit deny overrides",
			policy: authzPolicyFor(map[string]auth.RepositoryPermission{ghRepoB: {Read: false}}, auth.RoleRead),
			want:   map[string]bool{ghRepoA: true, glRepoA: true, ghRepoB: false, "": true},
		},
		{
			name: "canonical read with a bare read for another name",
			policy: authzPolicyFor(map[string]auth.RepositoryPermission{
				ghRepoB: {Read: true},
				bareA:   {Read: true},
			}),
			want: map[string]bool{ghRepoB: true, glRepoA: true, ghRepoA: true, "": false},
		},
		{
			name: "conflicting equivalent canonical entries fail closed",
			policy: authzPolicyFor(map[string]auth.RepositoryPermission{
				ghRepoB:               {Read: true},
				"GitHub.com/o/repo-b": {Read: true, Run: true},
			}),
			want: map[string]bool{ghRepoB: false, ghRepoA: false, "": false},
		},
		{
			name:   "grant on a repository with no runs authorizes nothing",
			policy: authzPolicyFor(map[string]auth.RepositoryPermission{"o/repo-z": {Read: true}}),
			want:   map[string]bool{ghRepoA: false, ghRepoB: false, "": false},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for candidate, want := range tc.want {
				if got := tc.policy.Allows(candidate); got != want {
					t.Fatalf("Allows(%q) = %v, want %v", candidate, got, want)
				}
			}
		})
	}
}

// TestPageRunsAuthorizedFiltersBeforePaging pins the memory half of the
// authorized page contract: the policy is applied BEFORE the page boundary,
// so an invisible run can never occupy a page slot, decide HasMore, or become
// the NextCreatedAt/NextID position.
func TestPageRunsAuthorizedFiltersBeforePaging(t *testing.T) {
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
	allowedA := authzPolicyFor(map[string]auth.RepositoryPermission{repoA: {Read: true}})

	// First page: only A runs newest-first, boundary on the last visible run.
	page1 := PageRunsAuthorized(runs, allowedA, time.Time{}, "", 2)
	if got := strings.Join(runsPageIDs(page1), ","); got != "a3,a2" {
		t.Fatalf("page1 = %s, want the newest two A runs", got)
	}
	if !page1.HasMore || page1.NextID != "a2" || !page1.NextCreatedAt.Equal(base.Add(3*time.Second)) {
		t.Fatalf("page1 boundary = HasMore %v next (%v,%q), want a2's position", page1.HasMore, page1.NextCreatedAt, page1.NextID)
	}

	// Continuation reaches the older A run and terminates on the authorized
	// set: b1 exists strictly older than a1 but is invisible, so HasMore must
	// be false and no cursor may be emitted.
	page2 := PageRunsAuthorized(runs, allowedA, page1.NextCreatedAt, page1.NextID, 2)
	if got := strings.Join(runsPageIDs(page2), ","); got != "a1" {
		t.Fatalf("page2 = %s, want a1", got)
	}
	if page2.HasMore || page2.NextID != "" || !page2.NextCreatedAt.IsZero() {
		t.Fatalf("page2 = HasMore %v next (%v,%q), want terminal", page2.HasMore, page2.NextCreatedAt, page2.NextID)
	}

	// An invisible row at the cursor instant is simply absent; the visible
	// rows newer than the cursor still page normally.
	pageAfterB2 := PageRunsAuthorized(runs, allowedA, base.Add(2*time.Second), "b2", 10)
	if got := strings.Join(runsPageIDs(pageAfterB2), ","); got != "a1" {
		t.Fatalf("page after b2 = %s, want only a1", got)
	}
	if pageAfterB2.HasMore || pageAfterB2.NextID != "" {
		t.Fatalf("page after b2 = HasMore %v next %q, want terminal and no B-derived cursor", pageAfterB2.HasMore, pageAfterB2.NextID)
	}

	// The unrestricted policy is the same definition as PageRuns.
	unrestricted := PageRunsAuthorized(runs, RunAuthzPolicyForPrincipal(nil), time.Time{}, "", 3)
	if got := strings.Join(runsPageIDs(unrestricted), ","); got != "b3,a3,a2" {
		t.Fatalf("unrestricted page = %s, want the global newest three", got)
	}
	if !unrestricted.HasMore || unrestricted.NextID != "a2" {
		t.Fatalf("unrestricted boundary = HasMore %v next %q", unrestricted.HasMore, unrestricted.NextID)
	}

	// A policy with no permitted repository matches nothing and is terminal:
	// no rows, no cursor, and HasMore cannot be inferred from the global
	// collection.
	emptyPolicy := authzPolicyFor(map[string]auth.RepositoryPermission{"o/repo-z": {Read: true}})
	empty := PageRunsAuthorized(runs, emptyPolicy, time.Time{}, "", 10)
	if len(empty.Runs) != 0 || empty.HasMore || empty.NextID != "" || !empty.NextCreatedAt.IsZero() {
		t.Fatalf("empty policy = %d runs HasMore %v next (%v,%q), want terminal empty page", len(empty.Runs), empty.HasMore, empty.NextCreatedAt, empty.NextID)
	}

	// A cursor positioned by the last visible run never returns an invisible
	// newer row, even though one exists between the cursor and the visible
	// tail.
	pageFromA3 := PageRunsAuthorized(runs, allowedA, base.Add(4*time.Second), "a3", 10)
	if got := strings.Join(runsPageIDs(pageFromA3), ","); got != "a2,a1" {
		t.Fatalf("page after a3 = %s, want a2,a1 only", got)
	}
	if pageFromA3.HasMore {
		t.Fatalf("page after a3 reported more rows despite no older visible run")
	}
}

// TestPageRunsAuthorizedUsesPolicyIdentity pins that the filter uses the same
// canonical policy-first identity as the per-run read routes: a run whose
// POLICY identity is B is excluded from an A grant even when its checkout URL
// names A, and a legacy run (no stored identity) derives its identity from
// the clone URL + full name.
func TestPageRunsAuthorizedUsesPolicyIdentity(t *testing.T) {
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
	policy := authzPolicyFor(map[string]auth.RepositoryPermission{"github.com/o/repo-a": {Read: true}})
	page := PageRunsAuthorized([]model.Run{forkRun, legacyRun}, policy, time.Time{}, "", 10)
	if got := strings.Join(runsPageIDs(page), ","); got != "legacy" {
		t.Fatalf("page = %s, want only the legacy repo-a run (policy identity decides)", got)
	}
}

// TestAuthorizedPageMemoryParity pins that memStore's authorized page is the
// same definition as the exported helper (and therefore the same contract the
// SQL store implements): identical ids, HasMore and next positions across a
// full walk and an empty policy.
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
	policy := authzPolicyFor(map[string]auth.RepositoryPermission{repoA: {Read: true}})

	afterAt, afterID := time.Time{}, ""
	for page := 0; ; page++ {
		if page > len(runs)+2 {
			t.Fatal("walk did not terminate")
		}
		want := PageRunsAuthorized(runs, policy, afterAt, afterID, 3)
		got, err := m.ListRunsPageAuthorized(ctx, policy, afterAt, afterID, 3)
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

	emptyPolicy := authzPolicyFor(map[string]auth.RepositoryPermission{"o/repo-z": {Read: true}})
	empty, err := m.ListRunsPageAuthorized(ctx, emptyPolicy, time.Time{}, "", 5)
	if err != nil {
		t.Fatalf("empty policy: %v", err)
	}
	if len(empty.Runs) != 0 || empty.HasMore || empty.NextID != "" {
		t.Fatalf("empty policy = %d runs HasMore %v next %q, want terminal empty page", len(empty.Runs), empty.HasMore, empty.NextID)
	}
}

// TestRunAuthzPolicyCanonicalizesLegacyHostCandidates pins that a canonical
// grant matches a legacy candidate whose persisted/derived host is spelled
// with different case, a trailing dot, the scheme's default port or a
// bracketed IPv6 literal — exactly the normalization auth.CanReadRepo applied
// to the candidate before the policy was pushed into SQL.
func TestRunAuthzPolicyCanonicalizesLegacyHostCandidates(t *testing.T) {
	policy := authzPolicyFor(map[string]auth.RepositoryPermission{"github.com/o/repo-a": {Read: true}})
	for _, candidate := range []string{
		"github.com/o/repo-a",
		"GitHub.com/o/repo-a",
		"github.com./o/repo-a",
		"github.com:443/o/repo-a",
	} {
		if !policy.Allows(candidate) {
			t.Fatalf("Allows(%q) = false, want the canonical grant to match", candidate)
		}
	}
	for _, candidate := range []string{"gitlab.com/o/repo-a", "github.com:8443/o/repo-a", "github.com/o/repo-b"} {
		if policy.Allows(candidate) {
			t.Fatalf("Allows(%q) = true, want denied", candidate)
		}
	}

	// A bracketed IPv6 host canonicalizes on both sides: brackets and a
	// default port are dropped, a non-default port is kept.
	bracket := authzPolicyFor(map[string]auth.RepositoryPermission{"[::1]:8443/o/repo-a": {Read: true}})
	if !bracket.Allows("[::1]:8443/o/repo-a") {
		t.Fatal("bracketed identity did not match its own grant")
	}
	if bracket.Allows("[::1]/o/repo-a") || bracket.Allows("[::1]:443/o/repo-a") {
		t.Fatal("a different bracketed identity was authorized")
	}
}

// TestAuthorizedPageFaultyStoreDelegation proves FaultyStore delegates the
// authorized page capability without consuming the mutation-fault counter,
// and fails closed with a diagnosable capability error when Inner lacks it.
func TestAuthorizedPageFaultyStoreDelegation(t *testing.T) {
	base := time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC)
	policy := authzPolicyFor(map[string]auth.RepositoryPermission{"github.com/o/repo-a": {Read: true}})
	m := runsPageMemoryStore(t, []model.Run{
		authzPageRun("b", base.Add(time.Second), "github.com/o/repo-b"),
		authzPageRun("a", base.Add(2*time.Second), "github.com/o/repo-a"),
	})
	fault := &FaultyStore{Inner: m, FailAfter: 1, Err: errors.New("write fault")}
	ctx := context.Background()

	page, err := fault.ListRunsPageAuthorized(ctx, policy, time.Time{}, "", 5)
	if err != nil {
		t.Fatalf("ListRunsPageAuthorized through FaultyStore: %v", err)
	}
	if got := strings.Join(runsPageIDs(page), ","); got != "a" {
		t.Fatalf("delegated page = %s, want only a", got)
	}
	if fault.Mutations() != 0 {
		t.Fatalf("authorized page reads consumed %d write fault(s)", fault.Mutations())
	}

	missing := &FaultyStore{Inner: storeOnlyInner{}}
	if _, err := missing.ListRunsPageAuthorized(ctx, policy, time.Time{}, "", 5); err == nil || !strings.Contains(err.Error(), "RunPageAuthorizedStore") {
		t.Fatalf("missing inner capability = %v, want RunPageAuthorizedStore error", err)
	}
}
