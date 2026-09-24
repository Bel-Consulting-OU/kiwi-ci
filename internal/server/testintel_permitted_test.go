package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
)

// TestIntersectTestHistoryRepoIDs pins the permitted-set intersection: a nil
// set is no restriction, an empty set keeps nothing, and only the exact
// permitted IDs survive.
func TestIntersectTestHistoryRepoIDs(t *testing.T) {
	ids := []string{"github.com/o/a", "github.com/o/b", "o/c"}
	if got := intersectTestHistoryRepoIDs(ids, nil); len(got) != 3 {
		t.Fatalf("nil permitted = %v, want all ids", got)
	}
	if got := intersectTestHistoryRepoIDs(ids, []string{}); len(got) != 0 {
		t.Fatalf("empty permitted = %v, want none", got)
	}
	got := intersectTestHistoryRepoIDs(ids, []string{"github.com/o/b"})
	if len(got) != 1 || got[0] != "github.com/o/b" {
		t.Fatalf("intersection = %v, want only github.com/o/b", got)
	}
}

// TestTestHistoryPermittedRepoIDs covers the identity-restriction resolver:
// no principal/global roles/empty or unparseable query are unrestricted (nil);
// a bare grant is unrestricted; a canonical grant is narrowed to its exact
// identity; an unreadable grant contributes nothing.
func TestTestHistoryPermittedRepoIDs(t *testing.T) {
	s := &Server{}
	req := func(p auth.Principal) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/test-intelligence", nil)
		return r.WithContext(auth.WithPrincipal(r.Context(), p))
	}

	if got := s.testHistoryPermittedRepoIDs(httptest.NewRequest(http.MethodGet, "/", nil), "github.com/o/r"); got != nil {
		t.Fatalf("no principal = %v, want nil", got)
	}
	q := func(p auth.Principal, query string) []string {
		return s.testHistoryPermittedRepoIDs(req(p), query)
	}
	if got := q(auth.Principal{Roles: []auth.Role{auth.RoleAdmin}}, "github.com/o/r"); got != nil {
		t.Fatalf("admin = %v, want nil", got)
	}
	if got := q(auth.Principal{Roles: []auth.Role{auth.RoleRead}}, "github.com/o/r"); got != nil {
		t.Fatalf("global read = %v, want nil", got)
	}
	limited := auth.Principal{Subject: "bot", Repositories: map[string]auth.RepositoryPermission{
		"github.com/o/r": {Read: true},
	}}
	if got := q(limited, ""); got != nil {
		t.Fatalf("empty query = %v, want nil", got)
	}
	if got := q(limited, "bad//query"); got != nil {
		t.Fatalf("unparseable query = %v, want nil", got)
	}

	bare := auth.Principal{Subject: "bot", Repositories: map[string]auth.RepositoryPermission{
		"o/r": {Read: true},
	}}
	if got := q(bare, "o/r"); got != nil {
		t.Fatalf("bare grant = %v, want unrestricted nil", got)
	}

	if got := q(limited, "github.com/o/r"); len(got) != 1 || got[0] != "github.com/o/r" {
		t.Fatalf("canonical grant = %v, want [github.com/o/r]", got)
	}
	// A canonical grant for a different repository is an empty permitted set.
	if got := q(limited, "github.com/o/other"); got == nil || len(got) != 0 {
		t.Fatalf("non-matching canonical grant = %v, want a non-nil empty set", got)
	}
	// A bare query is matched against the canonical grant's full name.
	if got := q(limited, "o/r"); len(got) != 1 || got[0] != "github.com/o/r" {
		t.Fatalf("bare query against canonical grant = %v, want the canonical id", got)
	}
	// A denied canonical grant and an unusable key contribute nothing.
	denied := auth.Principal{Subject: "bot", Repositories: map[string]auth.RepositoryPermission{
		"github.com/o/r": {Read: false},
		"bad//key":       {Read: true},
	}}
	if got := q(denied, "github.com/o/r"); got == nil || len(got) != 0 {
		t.Fatalf("denied grant = %v, want a non-nil empty set", got)
	}
}
