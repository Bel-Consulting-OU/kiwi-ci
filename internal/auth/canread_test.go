package auth

import "testing"

// TestCanReadRepo pins the exported repository-visibility helper to the
// Authorize(ActionRead) decision, so every endpoint that shares it resolves
// canonical keys, host-case/default-port aliases, bare aliases and the
// ambiguity fail-closed rule identically.
func TestCanReadRepo(t *testing.T) {
	p := Principal{Subject: "bot", Repositories: map[string]RepositoryPermission{
		"github.com/acme/service": {Read: true},
		"acme/denied":             {Read: false},
	}}
	cases := []struct {
		name string
		repo string
		want bool
	}{
		{"exact canonical", "github.com/acme/service", true},
		{"host case", "GitHub.COM/acme/service", true},
		{"default port", "github.com:443/acme/service", true},
		{"trailing dot", "github.com./acme/service", true},
		{"bare alias falls back to the canonical key", "acme/service", true},
		{"foreign forge is a different identity", "gitlab.example/acme/service", false},
		{"explicit deny", "github.com/acme/denied", false},
		{"explicit deny via the bare spelling", "acme/denied", false},
		{"unmentioned repo without a role", "github.com/acme/other", false},
	}
	for _, tc := range cases {
		if got := CanReadRepo(p, tc.repo); got != tc.want {
			t.Errorf("%s: CanReadRepo(%q) = %v, want %v", tc.name, tc.repo, got, tc.want)
		}
		if got := Authorize(p, ActionRead, tc.repo, false); got != tc.want {
			t.Errorf("%s: Authorize(read, %q) = %v, want %v (must match CanReadRepo)", tc.name, tc.repo, got, tc.want)
		}
	}

	// Roles: admin and global read cover every repository, but an entry the
	// map DOES name stays authoritative (an explicit deny is not overridden
	// by the global read role).
	admin := Principal{Subject: "a", Roles: []Role{RoleAdmin}}
	if !CanReadRepo(admin, "gitlab.example/any/repo") {
		t.Fatal("admin must read every repository")
	}
	global := Principal{Subject: "g", Roles: []Role{RoleRead}, Repositories: map[string]RepositoryPermission{
		"github.com/acme/service": {Read: false},
	}}
	if !CanReadRepo(global, "github.com/acme/other") {
		t.Fatal("global read must cover repositories the map does not mention")
	}
	if CanReadRepo(global, "github.com/acme/service") {
		t.Fatal("an explicit deny must not be overridden by the global read role")
	}

	// Canonically equivalent keys with DIFFERENT grants fail closed no matter
	// the map iteration order.
	ambiguous := Principal{Subject: "x", Repositories: map[string]RepositoryPermission{
		"github.com/acme/service":     {Read: false},
		"GitHub.COM:443/acme/service": {Read: true},
	}}
	for i := 0; i < 64; i++ {
		if CanReadRepo(ambiguous, "github.com/acme/service") {
			t.Fatal("ambiguous equivalent keys granted read")
		}
	}
}

// TestCanReadAnyRepo pins the coarse capability gate used by the collection
// endpoints: global read/admin or at least one repository entry with read,
// with no per-repository decision attached (conflicting duplicates still
// pass the gate; CanReadRepo remains fail-closed for the specific repo).
func TestCanReadAnyRepo(t *testing.T) {
	cases := []struct {
		name string
		p    Principal
		want bool
	}{
		{"admin", Principal{Roles: []Role{RoleAdmin}}, true},
		{"global read", Principal{Roles: []Role{RoleRead}}, true},
		{"repo read grant", Principal{Repositories: map[string]RepositoryPermission{"o/r": {Read: true}}}, true},
		{"repo run-only grant", Principal{Repositories: map[string]RepositoryPermission{"o/r": {Run: true}}}, false},
		{"repo deny-only grant", Principal{Repositories: map[string]RepositoryPermission{"o/r": {Read: false}}}, false},
		{"no roles and no grants", Principal{Subject: "u"}, false},
		{"admin with a deny entry", Principal{Roles: []Role{RoleAdmin}, Repositories: map[string]RepositoryPermission{"o/r": {Read: false}}}, true},
		{"global read with a deny entry", Principal{Roles: []Role{RoleRead}, Repositories: map[string]RepositoryPermission{"o/r": {Read: false}}}, true},
	}
	for _, tc := range cases {
		if got := CanReadAnyRepo(tc.p); got != tc.want {
			t.Errorf("%s: CanReadAnyRepo = %v, want %v", tc.name, got, tc.want)
		}
	}

	conflict := Principal{Subject: "x", Repositories: map[string]RepositoryPermission{
		"github.com/o/r":     {Read: false},
		"GitHub.COM:443/o/r": {Read: true},
	}}
	if !CanReadAnyRepo(conflict) {
		t.Fatal("a conflicting pair with one read entry must still pass the coarse gate")
	}
	if CanReadRepo(conflict, "github.com/o/r") {
		t.Fatal("the coarse gate must never decide a specific repository")
	}
}
