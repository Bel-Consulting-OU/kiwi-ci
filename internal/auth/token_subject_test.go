package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// subjectConflictPairs returns pairs of principals that share one subject
// but differ in exactly one permission-bearing dimension: global roles,
// trusted_run, admin, a repo grant bool, a repo entry set and a
// repo-vs-role mix.
func subjectConflictPairs() []struct {
	name string
	a, b Principal
} {
	return []struct {
		name string
		a, b Principal
	}{
		{
			"global_roles",
			Principal{Subject: "shared", Roles: []Role{RoleRead, RoleRun}},
			Principal{Subject: "shared", Roles: []Role{RoleRead, RoleRun, RoleApprove}},
		},
		{
			"trusted_run_role",
			Principal{Subject: "shared", Roles: []Role{RoleRead}},
			Principal{Subject: "shared", Roles: []Role{RoleRead, RoleTrustedRun}},
		},
		{
			"admin_role",
			Principal{Subject: "shared", Roles: []Role{RoleRead}},
			Principal{Subject: "shared", Roles: []Role{RoleRead, RoleAdmin}},
		},
		{
			"repo_grant_bool",
			Principal{Subject: "shared", Roles: []Role{RoleRead}, Repositories: map[string]RepositoryPermission{"acme/app": {Run: true}}},
			Principal{Subject: "shared", Roles: []Role{RoleRead}, Repositories: map[string]RepositoryPermission{"acme/app": {Run: false}}},
		},
		{
			"repo_entry_set",
			Principal{Subject: "shared", Roles: []Role{RoleRead}, Repositories: map[string]RepositoryPermission{"acme/app": {Run: true}}},
			Principal{Subject: "shared", Roles: []Role{RoleRead}, Repositories: map[string]RepositoryPermission{"acme/app": {Run: true}, "acme/other": {Read: true}}},
		},
		{
			"repo_grant_vs_role",
			Principal{Subject: "shared", Roles: []Role{RoleTrustedRun}},
			Principal{Subject: "shared", Roles: []Role{RoleRun}, Repositories: map[string]RepositoryPermission{"acme/app": {TrustedRun: true}}},
		},
	}
}

// TestAddTokenRejectsConflictingSubjectDefinitions runs every conflict
// dimension under both insertion orders, several store constructions and
// map-perturbing filler tokens. Rejection must be deterministic, wrap
// ErrSubjectConflict, name the subject and leave the store unchanged.
func TestAddTokenRejectsConflictingSubjectDefinitions(t *testing.T) {
	constructors := []struct {
		name string
		new  func() *TokenStore
	}{
		{"NewTokenStore", NewTokenStore},
		{"zero_value", func() *TokenStore { return &TokenStore{} }},
	}
	for _, tc := range subjectConflictPairs() {
		t.Run(tc.name, func(t *testing.T) {
			for _, ctor := range constructors {
				t.Run(ctor.name, func(t *testing.T) {
					for i := 0; i < 32; i++ {
						first, second := tc.a, tc.b
						if i%2 == 1 {
							first, second = second, first
						}
						s := ctor.new()
						for j := 0; j < i%5; j++ {
							filler := Principal{Subject: fmt.Sprintf("filler-%d", j), Roles: []Role{RoleRead}}
							if err := s.AddToken(fmt.Sprintf("filler-token-%d-%d", i, j), filler); err != nil {
								t.Fatalf("iteration %d: filler AddToken: %v", i, err)
							}
						}
						if err := s.AddToken("raw-first", first); err != nil {
							t.Fatalf("iteration %d: first AddToken: %v", i, err)
						}
						err := s.AddToken("raw-second", second)
						if err == nil {
							t.Fatalf("iteration %d: conflicting subject accepted (first=%+v second=%+v)", i, first, second)
						}
						if !errors.Is(err, ErrSubjectConflict) {
							t.Fatalf("iteration %d: error %v does not wrap ErrSubjectConflict", i, err)
						}
						if !strings.Contains(err.Error(), `subject "shared"`) {
							t.Fatalf("iteration %d: error %v does not name the subject", i, err)
						}
						if _, ok := s.Authenticate("raw-second"); ok {
							t.Fatalf("iteration %d: rejected token was registered", i)
						}
						if _, ok := s.Authenticate("raw-first"); !ok {
							t.Fatalf("iteration %d: rejection must not remove the existing token", i)
						}
						p, ok := s.PrincipalBySubject("shared")
						if !ok || !effectivePrincipalEqual(p, first) {
							t.Fatalf("iteration %d: subject resolution = (%+v, %v), want first principal", i, p, ok)
						}
					}
				})
			}
		})
	}
}

// TestPrincipalBySubjectFailsClosedOnInjectedConflict bypasses AddToken and
// plants conflicting principals straight into the token map. Resolution
// must refuse the subject (and never flip between winners) whether or not
// the subject index was populated.
func TestPrincipalBySubjectFailsClosedOnInjectedConflict(t *testing.T) {
	for _, tc := range subjectConflictPairs() {
		t.Run(tc.name, func(t *testing.T) {
			// Conflict without any index entry.
			s := NewTokenStore()
			s.tokens[TokenDigest("injected-a")] = tc.a
			s.tokens[TokenDigest("injected-b")] = tc.b
			if p, ok := s.PrincipalBySubject("shared"); ok {
				t.Fatalf("injected conflict resolved to %+v", p)
			}
			// Conflict with the index pinned to one of the two principals.
			s.bySubject["shared"] = tc.a
			for i := 0; i < 128; i++ {
				if p, ok := s.PrincipalBySubject("shared"); ok {
					t.Fatalf("iteration %d: indexed conflict resolved to %+v", i, p)
				}
			}
			// Pinned to the other principal: same refusal.
			s.bySubject["shared"] = tc.b
			if p, ok := s.PrincipalBySubject("shared"); ok {
				t.Fatalf("injected conflict resolved to %+v", p)
			}
		})
	}
}

// TestLoadRejectsConflictingSubjectDefinitions proves a persisted store with
// one subject but different effective principals fails closed: Load errors
// deterministically (naming the subject), nothing from the file is loaded
// and the previous in-memory contents survive.
func TestLoadRejectsConflictingSubjectDefinitions(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range subjectConflictPairs() {
		t.Run(tc.name, func(t *testing.T) {
			m := map[string]Principal{
				TokenDigest("persisted-a"): tc.a,
				TokenDigest("persisted-b"): tc.b,
			}
			b, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, tc.name+".json")
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
			s := NewTokenStore()
			if err := s.AddToken("existing", Principal{Subject: "keep", Roles: []Role{RoleRead}}); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 32; i++ {
				err := s.Load(path)
				if err == nil {
					t.Fatalf("iteration %d: conflicting persisted store loaded", i)
				}
				if !errors.Is(err, ErrSubjectConflict) {
					t.Fatalf("iteration %d: error %v does not wrap ErrSubjectConflict", i, err)
				}
				if !strings.Contains(err.Error(), `subject "shared"`) {
					t.Fatalf("iteration %d: error %v does not name the subject", i, err)
				}
				if _, ok := s.Authenticate("existing"); !ok {
					t.Fatalf("iteration %d: failed load clobbered the in-memory store", i)
				}
				if _, ok := s.Authenticate("persisted-a"); ok {
					t.Fatalf("iteration %d: failed load partially loaded the file", i)
				}
				if _, ok := s.PrincipalBySubject("shared"); ok {
					t.Fatalf("iteration %d: failed load exposed the conflicting subject", i)
				}
			}
		})
	}
}

// TestIdenticalEffectivePrincipalsResolveDeterministically covers the
// allowed rotation case: many tokens for one subject whose principals differ
// only in representation (role order, duplicate roles, map rebuild order)
// are accepted and always resolve to the same effective principal.
func TestIdenticalEffectivePrincipalsResolveDeterministically(t *testing.T) {
	canonical := Principal{
		Subject:      "svc",
		Roles:        []Role{RoleRead, RoleRun},
		Repositories: map[string]RepositoryPermission{"acme/app": {Read: true, Run: true}},
	}
	variants := []Principal{
		canonical,
		{Subject: "svc", Roles: []Role{RoleRun, RoleRead}, Repositories: map[string]RepositoryPermission{"acme/app": {Run: true, Read: true}}},
		{Subject: "svc", Roles: []Role{RoleRead, RoleRun, RoleRead}, Repositories: map[string]RepositoryPermission{"acme/app": {Read: true, Run: true}}},
	}
	for i := 0; i < 32; i++ {
		s := NewTokenStore()
		for j := 0; j < len(variants); j++ {
			p := variants[(i+j)%len(variants)]
			if err := s.AddToken(fmt.Sprintf("raw-%d", j), p); err != nil {
				t.Fatalf("iteration %d: identical effective principals rejected: %v", i, err)
			}
		}
		for k := 0; k < 64; k++ {
			p, ok := s.PrincipalBySubject("svc")
			if !ok {
				t.Fatalf("iteration %d: identical effective principals did not resolve", i)
			}
			if !effectivePrincipalEqual(p, canonical) {
				t.Fatalf("iteration %d: resolution = %+v, want an effective match of %+v", i, p, canonical)
			}
		}
	}

	// The same holds for a persisted store: a rotation pair with identical
	// grants loads and resolves deterministically.
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	m := map[string]Principal{
		TokenDigest("persisted-a"): variants[0],
		TokenDigest("persisted-b"): variants[1],
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		s := NewTokenStore()
		if err := s.Load(path); err != nil {
			t.Fatalf("identical effective principals failed to load: %v", err)
		}
		p, ok := s.PrincipalBySubject("svc")
		if !ok || !effectivePrincipalEqual(p, canonical) {
			t.Fatalf("loaded rotation pair resolved to (%+v, %v)", p, ok)
		}
	}
}

// TestRemoveTokenMaintainsSubjectIndex proves revocation rebuilds the index:
// removing one of two identical-principal tokens keeps the subject
// resolvable, removing the last drops it, and unrelated tokens survive.
func TestRemoveTokenMaintainsSubjectIndex(t *testing.T) {
	s := NewTokenStore()
	svc := Principal{Subject: "svc", Roles: []Role{RoleRun}}
	other := Principal{Subject: "other", Roles: []Role{RoleRead}}
	for raw, principal := range map[string]Principal{"a": svc, "b": svc, "c": other} {
		if err := s.AddToken(raw, principal); err != nil {
			t.Fatal(err)
		}
	}
	if !s.RemoveToken("a") {
		t.Fatal("RemoveToken(a) = false, want true")
	}
	if got, ok := s.PrincipalBySubject("svc"); !ok || !effectivePrincipalEqual(got, svc) {
		t.Fatalf("subject lost while a second token remains: (%+v, %v)", got, ok)
	}
	if !s.RemoveToken("b") {
		t.Fatal("RemoveToken(b) = false, want true")
	}
	if _, ok := s.PrincipalBySubject("svc"); ok {
		t.Fatal("subject still resolves after its last token was removed")
	}
	if _, ok := s.Authenticate("c"); !ok {
		t.Fatal("unrelated token was removed")
	}
	if s.RemoveToken("missing") || s.RemoveToken("") {
		t.Fatal("RemoveToken must report false for absent/empty tokens")
	}
	var nilStore *TokenStore
	if nilStore.RemoveToken("a") {
		t.Fatal("nil store RemoveToken must fail closed")
	}
}

// TestSaveLoadRoundTripPreservesSubjectIndex covers reload-after-save: the
// on-disk format stays a plain digest->principal JSON map, tokens keep
// authenticating, and the rebuilt subject index resolves the same unique
// principals.
func TestSaveLoadRoundTripPreservesSubjectIndex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	s := NewTokenStore()
	alpha := Principal{Subject: "alpha", Roles: []Role{RoleRead, RoleRun}}
	alphaRotated := Principal{Subject: "alpha", Roles: []Role{RoleRun, RoleRead}}
	bravo := Principal{Subject: "bravo", Roles: []Role{RoleAdmin}}
	anonymous := Principal{Roles: []Role{RoleRead}}
	for raw, p := range map[string]Principal{
		"alpha-1": alpha,
		"alpha-2": alphaRotated,
		"bravo":   bravo,
		"anon":    anonymous,
	} {
		if err := s.AddToken(raw, p); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted map[string]Principal
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("token file is not the expected digest->principal map: %v", err)
	}
	if len(persisted) != 4 {
		t.Fatalf("persisted %d principals, want 4", len(persisted))
	}
	if got := persisted[TokenDigest("alpha-1")]; got.Subject != "alpha" {
		t.Fatalf("persisted alpha-1 = %+v", got)
	}

	loaded := NewTokenStore()
	if err := loaded.Load(path); err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct {
		raw       string
		principal Principal
	}{
		{"alpha-1", alpha},
		{"alpha-2", alphaRotated},
		{"bravo", bravo},
		{"anon", anonymous},
	} {
		got, ok := loaded.Authenticate(want.raw)
		if !ok || !effectivePrincipalEqual(got, want.principal) {
			t.Fatalf("Authenticate(%q) = (%+v, %v), want %+v", want.raw, got, ok, want.principal)
		}
	}
	if p, ok := loaded.PrincipalBySubject("alpha"); !ok || !effectivePrincipalEqual(p, alpha) {
		t.Fatalf("alpha after reload = (%+v, %v)", p, ok)
	}
	if p, ok := loaded.PrincipalBySubject("bravo"); !ok || !effectivePrincipalEqual(p, bravo) {
		t.Fatalf("bravo after reload = (%+v, %v)", p, ok)
	}
	if _, ok := loaded.PrincipalBySubject(""); ok {
		t.Fatal("anonymous principals must not resolve by subject")
	}
	if _, ok := loaded.PrincipalBySubject("missing"); ok {
		t.Fatal("unknown subject resolved")
	}
}
