package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAuthorizeAmbiguousBareLookupFailsClosed pins the deterministic
// bare→canonical fallback: when several canonical keys share the bare part
// with different grants the lookup must resolve to no repo entry (fails
// closed) instead of flipping with Go's randomized map iteration order.
func TestAuthorizeAmbiguousBareLookupFailsClosed(t *testing.T) {
	p := Principal{Subject: "bot", Repositories: map[string]RepositoryPermission{
		"github.com/o/r": {TrustedRun: true},
		"gitlab.com/o/r": {},
	}}
	for i := 0; i < 256; i++ {
		if Authorize(p, ActionTrustedRun, "o/r", true) {
			t.Fatal("ambiguous bare lookup granted trusted_run")
		}
	}
	// The canonical lookup stays exact and deterministic.
	if !Authorize(p, ActionTrustedRun, "github.com/o/r", true) {
		t.Fatal("canonical key must grant deterministically")
	}
	if Authorize(p, ActionTrustedRun, "gitlab.com/o/r", true) {
		t.Fatal("canonical key without the grant must deny")
	}
	// Identical permission sets for both canonical keys are unambiguous.
	same := Principal{Subject: "bot", Repositories: map[string]RepositoryPermission{
		"github.com/o/r": {TrustedRun: true},
		"gitlab.com/o/r": {TrustedRun: true},
	}}
	for i := 0; i < 256; i++ {
		if !Authorize(same, ActionTrustedRun, "o/r", true) {
			t.Fatal("unambiguous bare lookup must grant consistently")
		}
	}
	// A conflicting set never leaks the permissive entry through the bare
	// lookup, no matter which iteration order the map yields.
	inverted := Principal{Subject: "bot", Repositories: map[string]RepositoryPermission{
		"github.com/o/r": {},
		"gitlab.com/o/r": {TrustedRun: true},
	}}
	for i := 0; i < 256; i++ {
		if Authorize(inverted, ActionTrustedRun, "o/r", true) {
			t.Fatal("ambiguous inverted lookup granted trusted_run")
		}
	}
	// Ambiguity must not silently widen role-derived grants either: the
	// role fallback still applies for repos with no usable entry.
	role := Principal{Subject: "bot", Roles: []Role{RoleRead}, Repositories: map[string]RepositoryPermission{
		"github.com/o/r": {Read: false},
		"gitlab.com/o/r": {Read: true},
	}}
	if !Authorize(role, ActionRead, "o/r", false) {
		t.Fatal("role fallback must still apply when the bare lookup is ambiguous")
	}
}

// TestAuthorizeRepoIdentityExact pins byte-exact repository identity
// resolution: case differences, trailing whitespace, extra path segments
// and unicode confusables never match a declared entry.
func TestAuthorizeRepoIdentityExact(t *testing.T) {
	p := Principal{Subject: "bot", Repositories: map[string]RepositoryPermission{
		"github.com/o/r": {Read: true},
	}}
	denied := []string{
		"GitHub.com/o/r",
		"github.com/O/R",
		"github.com/o/r ",
		" github.com/o/r",
		"github.com/o/r/extra",
		"github.com/o/r\u0000",
		"github.com/o/\u0433",
		"",
	}
	for _, repo := range denied {
		if Authorize(p, ActionRead, repo, false) {
			t.Fatalf("repo %q matched a declared entry", repo)
		}
	}
	if !Authorize(p, ActionRead, "github.com/o/r", false) {
		t.Fatal("exact repo must be authorized")
	}
	// CanonicalID trims surrounding whitespace before deciding the shape.
	if got := CanonicalRepoID("github.com", "  o/r  "); got != "github.com/o/r" {
		t.Fatalf("CanonicalRepoID = %q", got)
	}
	if got := CanonicalRepoID("", "  "); got != "" {
		t.Fatalf("blank full name must stay empty, got %q", got)
	}
	// A name that already starts with the SAME host is never re-prefixed.
	if got := CanonicalRepoID("github.com", "github.com/o/r"); got != "github.com/o/r" {
		t.Fatalf("same-host full name rewritten: %q", got)
	}
	// A name that embeds a DIFFERENT host is re-prefixed with the
	// authoritative forge host: identities stay host-scoped instead of
	// letting the embedded string pick another forge's canonical identity.
	if got := CanonicalRepoID("gitlab.com", "github.com/o/r"); got != "gitlab.com/github.com/o/r" {
		t.Fatalf("foreign-host full name must be re-prefixed, got %q", got)
	}
	// A dotted first segment without an owner/name is a group, not a host.
	if got := CanonicalRepoID("gitlab.example", "acme.co/service"); got != "gitlab.example/acme.co/service" {
		t.Fatalf("dotted org collapsed to a bare identity: %q", got)
	}
}

// TestMiddlewareTokenEdges pins the bearer parsing edges: strict prefix,
// exact match, digest lookup, and the admin-token/store-token interaction.
func TestMiddlewareTokenEdges(t *testing.T) {
	store := NewTokenStore()
	if err := store.AddToken("store-token", Principal{Subject: "bot", Roles: []Role{RoleRead}}); err != nil {
		t.Fatal(err)
	}
	var reached []string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := PrincipalFrom(r)
		reached = append(reached, p.Subject)
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(store, "admin-token", next, nil)

	cases := []struct {
		name       string
		authHeader string
		wantCode   int
		wantSubj   string
	}{
		{"no header", "", http.StatusUnauthorized, ""},
		{"empty bearer", "Bearer ", http.StatusUnauthorized, ""},
		// Tolerant parsing (shared with the server's bearerOK): a bare
		// token without the "Bearer " scheme is still a full credential
		// presentation, so it authenticates — possession of the secret is
		// what is proven, never the scheme spelling.
		{"prefix missing", "store-token", http.StatusOK, "bot"},
		{"lowercase scheme", "bearer store-token", http.StatusUnauthorized, ""},
		{"trailing space", "Bearer store-token ", http.StatusUnauthorized, ""},
		{"near miss", "Bearer store-toke", http.StatusUnauthorized, ""},
		{"digest as bearer", "Bearer " + TokenDigest("store-token"), http.StatusUnauthorized, ""},
		{"store token", "Bearer store-token", http.StatusOK, "bot"},
		{"admin token", "Bearer admin-token", http.StatusOK, "admin"},
		{"admin near miss", "Bearer admin-toke", http.StatusUnauthorized, ""},
		{"empty admin token", "Bearer ", http.StatusUnauthorized, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached = nil
			req := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantCode)
			}
			if tc.wantSubj == "" {
				if len(reached) != 0 {
					t.Fatalf("handler reached with %v", reached)
				}
				return
			}
			if len(reached) != 1 || reached[0] != tc.wantSubj {
				t.Fatalf("handler saw %v, want [%s]", reached, tc.wantSubj)
			}
		})
	}
}

// TestStoreTokenShadowsAdminToken pins least privilege when the same value
// is registered in the store AND configured as the admin token: the stored
// (non-admin) principal wins, so a conflated credential never silently
// escalates.
func TestStoreTokenShadowsAdminToken(t *testing.T) {
	store := NewTokenStore()
	if err := store.AddToken("shared", Principal{Subject: "limited", Roles: []Role{RoleRead}}); err != nil {
		t.Fatal(err)
	}
	var got Principal
	h := Middleware(store, "shared", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = PrincipalFrom(r)
	}), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	req.Header.Set("Authorization", "Bearer shared")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if got.Subject != "limited" || got.Has(RoleAdmin) {
		t.Fatalf("conflated credential escalated: %+v", got)
	}
	if Authorize(got, ActionAdmin, "", false) {
		t.Fatal("shadowed principal must not hold admin")
	}
}

// TestClassifierBypassesStoreAuthentication pins the runner-route carve-out:
// a classifier hit reaches the server tier gate even when the store would
// reject the bearer, and a classifier miss keeps strict store enforcement.
func TestClassifierBypassesStoreAuthentication(t *testing.T) {
	store := NewTokenStore()
	if err := store.AddToken("store-token", Principal{Subject: "bot"}); err != nil {
		t.Fatal(err)
	}
	var sawPrincipal bool
	h := MiddlewareWithClassifier(store, "admin", func(r *http.Request) bool {
		return strings.HasPrefix(r.URL.Path, "/api/v1/runners/")
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sawPrincipal = PrincipalFrom(r)
		w.WriteHeader(http.StatusOK)
	}), nil)

	// Runner route with a garbage bearer: the middleware must pass it to
	// the tier gate (which owns runner authentication), not 401 here.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/runners/register", nil)
	req.Header.Set("Authorization", "Bearer runner-tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || sawPrincipal {
		t.Fatalf("runner route: code=%d principal=%v", w.Code, sawPrincipal)
	}
	// Non-runner route with the same garbage bearer: strict store rejects.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	req.Header.Set("Authorization", "Bearer runner-tok")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("non-runner route with unknown bearer: %d", w.Code)
	}
}

// TestDottedOrgNameNeverSplitsAsHost pins the canonical-shape rule: a
// two-segment repo identity whose first segment merely contains a dot (a
// GitLab group like "acme.co") must not be read as host + bare name, or an
// unrelated single-segment alias would silently authorize it.
func TestDottedOrgNameNeverSplitsAsHost(t *testing.T) {
	alias := Principal{Subject: "bot", Repositories: map[string]RepositoryPermission{
		"service": {Read: true, Run: true},
	}}
	// "acme.co/service" is a group/repo full name, not host "acme.co" with
	// repo "service".
	if Authorize(alias, ActionRead, "acme.co/service", false) {
		t.Fatal("single-segment alias authorized a dotted-org repository")
	}
	if Authorize(alias, ActionRun, "acme.co/service", false) {
		t.Fatal("single-segment alias authorized a dotted-org run")
	}
	// The literal full-name alias still works wherever it is declared.
	literal := Principal{Subject: "bot", Repositories: map[string]RepositoryPermission{
		"acme.co/service": {Read: true},
	}}
	if !Authorize(literal, ActionRead, "acme.co/service", false) {
		t.Fatal("literal dotted-org alias not honored")
	}
	// A genuine canonical ID (three segments) keeps both directions of the
	// documented fallback.
	canonical := Principal{Subject: "bot", Repositories: map[string]RepositoryPermission{
		"gitlab.example/acme.co/service": {Read: true},
	}}
	if !Authorize(canonical, ActionRead, "gitlab.example/acme.co/service", false) {
		t.Fatal("canonical dotted-org key not honored")
	}
	if !Authorize(canonical, ActionRead, "acme.co/service", false) {
		t.Fatal("canonical key must fall back to the dotted bare name")
	}
	// And a bare "service" alias must not match the canonical three-segment
	// identity either.
	if Authorize(alias, ActionRead, "gitlab.example/acme.co/service", false) {
		t.Fatal("single-segment alias authorized a nested canonical identity")
	}
}
