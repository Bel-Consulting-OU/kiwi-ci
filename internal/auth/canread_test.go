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
	// the map iteration order — and the global read role must NOT resurrect
	// the decision: a conflicting explicit pair is not "no entry".
	ambiguous := Principal{Subject: "x", Roles: []Role{RoleRead}, Repositories: map[string]RepositoryPermission{
		"github.com/acme/service":     {Read: false},
		"GitHub.COM:443/acme/service": {Read: true},
	}}
	for i := 0; i < 64; i++ {
		if CanReadRepo(ambiguous, "github.com/acme/service") {
			t.Fatal("ambiguous equivalent keys granted read despite the global read role")
		}
		if CanReadRepo(ambiguous, "acme/service") {
			t.Fatal("ambiguous equivalent keys granted read through the bare spelling")
		}
	}
}

// TestAuthorizeConflictingGrantsDenyDespiteGlobalRoles is the fail-closed
// regression: canonically equivalent explicit grants with DIFFERENT
// permission sets used to resolve to "no entry", so Authorize fell through
// to the global roles and ALLOWED a principal holding them. A conflicting
// pair is now RepoConflict and denies every action; only a repository the
// map genuinely does not mention may fall through to roles.
func TestAuthorizeConflictingGrantsDenyDespiteGlobalRoles(t *testing.T) {
	p := Principal{
		Subject: "x",
		Roles:   []Role{RoleRead, RoleRun, RoleTrustedRun, RoleApprove, RoleCancel, RoleRerun, RoleArtifactRead},
		Repositories: map[string]RepositoryPermission{
			"GITHUB.COM/acme/service":     {Read: true, Run: true, Approve: true, ArtifactRead: true},
			"github.com:443/acme/service": {},
		},
	}
	actions := []Action{
		ActionRead, ActionRun, ActionTrustedRun, ActionApprove, ActionCancel,
		ActionRerun, ActionArtifactRead, ActionAdmin,
	}
	// Every spelling of the conflicting identity is denied, for every
	// action, even though a global role covers each action.
	for _, repo := range []string{"github.com/acme/service", "GITHUB.com:443/acme/service", "acme/service"} {
		for _, action := range actions {
			if Authorize(p, action, repo, false) {
				t.Errorf("conflicting grants allowed %s on %s despite global roles", action, repo)
			}
			if Authorize(p, action, repo, true) {
				t.Errorf("conflicting grants allowed trusted %s on %s despite global roles", action, repo)
			}
		}
	}
	// RepoNoEntry still falls through to the global roles.
	if !Authorize(p, ActionRead, "github.com/acme/other", false) {
		t.Fatal("unmentioned repository must still fall through to the global read role")
	}
	if !Authorize(p, ActionArtifactRead, "github.com/acme/other", false) {
		t.Fatal("unmentioned repository must still fall through to the global artifact_read role")
	}
	// Non-conflicting explicit entries still override global roles in BOTH
	// directions: an explicit deny beats the role, an explicit grant opens
	// a repository the roles would not.
	override := Principal{
		Subject: "y",
		Roles:   []Role{RoleRead, RoleRun, RoleArtifactRead},
		Repositories: map[string]RepositoryPermission{
			"github.com/acme/denied": {Read: false, Run: false, ArtifactRead: false},
			"github.com/acme/only":   {Read: true},
		},
	}
	for _, action := range []Action{ActionRead, ActionRun, ActionArtifactRead} {
		if Authorize(override, action, "github.com/acme/denied", false) {
			t.Errorf("explicit deny must override the global %s role", action)
		}
	}
	if !Authorize(override, ActionRead, "github.com/acme/only", false) {
		t.Fatal("explicit read grant must open its repository")
	}
	if Authorize(override, ActionRun, "github.com/acme/only", false) {
		t.Fatal("repo entry without run must not inherit the global run role")
	}
	noRoles := Principal{Subject: "z", Repositories: map[string]RepositoryPermission{
		"github.com/acme/only": {Read: true},
	}}
	if !Authorize(noRoles, ActionRead, "github.com/acme/only", false) {
		t.Fatal("explicit read grant must work without any global role")
	}
	if Authorize(noRoles, ActionRead, "github.com/acme/other", false) {
		t.Fatal("a repository outside the map must not be readable without a role")
	}
}

// TestCanReadAnyRepo pins the coarse capability gate used by the collection
// endpoints: global read/admin or at least one repository entry with read,
// with no per-repository decision attached (conflicting duplicates still
// pass the gate; CanReadRepo denies the specific repository).
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

	conflict := Principal{Subject: "x", Roles: []Role{RoleRead}, Repositories: map[string]RepositoryPermission{
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
