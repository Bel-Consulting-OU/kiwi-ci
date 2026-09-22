package storage

// L5-A regression tests for the repository resolution policy:
//
//   - a canonical (host/owner/name) query is an EXACT identity lookup with no
//     ambiguity cap;
//   - a bare owner/name query is bounded by limit+1 and reported as
//     ErrRepoQueryAmbiguous when more distinct canonical repositories exist,
//     never silently truncated to the first `limit` candidates;
//   - a non-nil permitted set is intersected BEFORE the ambiguity check, so
//     an authorized repository that sorts after the cap is still resolved.

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// l5SeedManyForges seeds n in-memory runs whose repositories present the same
// bare owner/name on n distinct forges. It returns the canonical IDs in
// ascending order.
func l5SeedManyForges(t *testing.T, m *memStore, bare string, n int) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		runID := fmt.Sprintf("%032x", i+1)
		repo := fmt.Sprintf("forge%02d.example/%s", i, bare)
		m.runs[runID] = model.Run{ID: runID, RepoID: repo, RepoFullName: bare, Repo: "https://" + repo + ".git", Status: model.StatusSuccess}
		ids = append(ids, repo)
	}
	return ids
}

func TestMemStoreResolveTestHistoryRepoIDsPolicy(t *testing.T) {
	const bare = "acme/service"
	const over = 65
	m := newMemStore()
	ids := l5SeedManyForges(t, m, bare, over)
	last := ids[len(ids)-1]

	// Canonical exact lookup: never capped, even with limit 1.
	got, err := m.ResolveTestHistoryRepoIDs(ctx(), last, 1)
	if err != nil || !reflect.DeepEqual(got, []string{last}) {
		t.Fatalf("canonical lookup = %v, %v; want [%s]", got, err, last)
	}
	// A canonical query for an unknown repository resolves to nothing.
	if got, err := m.ResolveTestHistoryRepoIDs(ctx(), "forge99.example/acme/service", 1); err != nil || len(got) != 0 {
		t.Fatalf("unknown canonical lookup = %v, %v; want empty", got, err)
	}
	// Bare query over the limit: explicit ambiguity, never a truncated list.
	got, err = m.ResolveTestHistoryRepoIDs(ctx(), bare, 64)
	if !errors.Is(err, ErrRepoQueryAmbiguous) {
		t.Fatalf("over-limit bare query = %v, %v; want ErrRepoQueryAmbiguous", got, err)
	}
	if got != nil {
		t.Fatalf("over-limit bare query returned candidates too: %v", got)
	}
	// The reported count is the exact number of distinct canonical identities.
	var amb *repoQueryAmbiguousError
	if !errors.As(err, &amb) || amb.found != over || amb.limit != 64 || amb.query != bare {
		t.Fatalf("ambiguity details = %+v, want found=%d limit=64 query=%q", amb, over, bare)
	}
	// Bare query within the limit: every identity, sorted.
	got, err = m.ResolveTestHistoryRepoIDs(ctx(), bare, over)
	if err != nil || !reflect.DeepEqual(got, ids) {
		t.Fatalf("at-limit bare query = %d ids, %v; want all %d", len(got), err, over)
	}
}

func TestMemStoreResolveTestHistoryRepoIDsScopedIntersectsBeforeCap(t *testing.T) {
	const bare = "acme/service"
	const over = 65
	m := newMemStore()
	ids := l5SeedManyForges(t, m, bare, over)
	last := ids[len(ids)-1]

	// The authorized repository sorts LAST: intersecting first must reach it
	// even though the bare-name cap is 64.
	got, err := m.ResolveTestHistoryRepoIDsScoped(ctx(), bare, []string{last}, 64)
	if err != nil || !reflect.DeepEqual(got, []string{last}) {
		t.Fatalf("scoped authorized-last = %v, %v; want [%s] (pre-fix the cap excluded it)", got, err, last)
	}
	// The intersection may contain several permitted identities: they are
	// returned in ascending order and the ambiguity check applies to what
	// remains (2 <= 64).
	got, err = m.ResolveTestHistoryRepoIDsScoped(ctx(), bare, []string{last, ids[0]}, 64)
	if err != nil || !reflect.DeepEqual(got, []string{ids[0], last}) {
		t.Fatalf("scoped intersection = %v, %v; want [%s %s]", got, err, ids[0], last)
	}
	// An over-limit INTERSECTION is still reported as ambiguous.
	got, err = m.ResolveTestHistoryRepoIDsScoped(ctx(), bare, ids[:10], 3)
	if !errors.Is(err, ErrRepoQueryAmbiguous) {
		t.Fatalf("over-limit scoped query = %v, %v; want ErrRepoQueryAmbiguous", got, err)
	}
	// A non-nil EMPTY permitted set resolves to no candidates at all.
	got, err = m.ResolveTestHistoryRepoIDsScoped(ctx(), bare, []string{}, 64)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty permitted set = %v, %v; want no candidates", got, err)
	}
	// Permitted identities that do not address the query are not returned.
	other := newMemStore()
	other.runs["cccccccccccccccccccccccccccccccc"] = model.Run{ID: "cccccccccccccccccccccccccccccccc", RepoID: "github.com/other/repo", RepoFullName: "other/repo"}
	got, err = other.ResolveTestHistoryRepoIDsScoped(ctx(), bare, []string{"github.com/other/repo"}, 64)
	if err != nil || len(got) != 0 {
		t.Fatalf("unaddressed permitted identity = %v, %v; want empty", got, err)
	}
	// A nil permitted set keeps the unrestricted policy (ambiguity refusal).
	if _, err := m.ResolveTestHistoryRepoIDsScoped(ctx(), bare, nil, 64); !errors.Is(err, ErrRepoQueryAmbiguous) {
		t.Fatalf("nil permitted over-limit = %v, want ErrRepoQueryAmbiguous", err)
	}
}

func TestMemStoreResolveTestHistoryRepoIDsScopedCanonicalExact(t *testing.T) {
	const bare = "acme/service"
	m := newMemStore()
	ids := l5SeedManyForges(t, m, bare, 3)
	// A canonical query addresses exactly one identity: it resolves exactly,
	// with no ambiguity cap, when it is inside the permitted set.
	got, err := m.ResolveTestHistoryRepoIDsScoped(ctx(), ids[1], []string{ids[1]}, 64)
	if err != nil || !reflect.DeepEqual(got, []string{ids[1]}) {
		t.Fatalf("canonical scoped lookup = %v, %v; want [%s]", got, err, ids[1])
	}
	// Outside the permitted set the identity is not offered as a candidate at
	// all (authorization could never admit it), so the caller's answer is a
	// deterministic empty result rather than a silently resolved foreign
	// repository.
	got, err = m.ResolveTestHistoryRepoIDsScoped(ctx(), ids[1], []string{ids[0]}, 64)
	if err != nil || len(got) != 0 {
		t.Fatalf("canonical lookup outside the permitted set = %v, %v; want empty", got, err)
	}
}

func TestFaultyStoreResolveTestHistoryRepoIDsScopedDelegation(t *testing.T) {
	const bare = "acme/service"
	inner := newMemStore()
	ids := l5SeedManyForges(t, inner, bare, 3)
	f := &FaultyStore{Inner: inner, FailAfter: 1, Err: errBoom}
	// Resolution is a read: the armed mutation fault must not fire.
	got, err := f.ResolveTestHistoryRepoIDsScoped(ctx(), bare, []string{ids[2]}, 64)
	if err != nil || !reflect.DeepEqual(got, []string{ids[2]}) {
		t.Fatalf("wrapper scoped resolution = %v, %v; want [%s]", got, err, ids[2])
	}
	if f.Mutations() != 0 {
		t.Fatalf("wrapper consumed %d mutation faults for a read", f.Mutations())
	}
	// A wrapped store without the scoped contract fails closed with a
	// diagnosable capability error instead of degrading to truncating
	// resolution.
	_, err = (&FaultyStore{Inner: storeOnlyInner{}}).ResolveTestHistoryRepoIDsScoped(ctx(), bare, nil, 64)
	if err == nil || !strings.Contains(err.Error(), "TestHistoryRepoResolutionStore") {
		t.Fatalf("delivery-less inner scoped resolution err = %v, want the missing-interface error", err)
	}
}
