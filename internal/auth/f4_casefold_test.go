package auth

// F4-A/F4-F regressions: repository PATH case is not identity-bearing, and an
// unparseable repository string must never borrow a global role.

import (
	"encoding/base64"
	"testing"
)

// TestFoldRepoFullNameCanonicalForm pins the ONE folded path form every
// identity constructor/parser/method agrees on.
func TestFoldRepoFullNameCanonicalForm(t *testing.T) {
	if got := FoldRepoFullName("Acme/Backend"); got != "acme/backend" {
		t.Fatalf("FoldRepoFullName = %q, want acme/backend", got)
	}
	if got := FoldRepoFullName("acme/backend"); got != "acme/backend" {
		t.Fatalf("FoldRepoFullName must be idempotent, got %q", got)
	}

	if got := CanonicalRepoID("github.com", "Acme/Backend"); got != "github.com/acme/backend" {
		t.Fatalf("CanonicalRepoID = %q, want github.com/acme/backend", got)
	}

	id := RepoIdentity{Host: "github.com", FullName: "Acme/Backend"}
	if got := id.ID(); got != "github.com/acme/backend" {
		t.Fatalf("RepoIdentity.ID = %q, want github.com/acme/backend", got)
	}

	parsed, err := ParseRepoIdentity(id.Serialized())
	if err != nil {
		t.Fatalf("ParseRepoIdentity: %v", err)
	}
	if parsed.FullName != "acme/backend" {
		t.Fatalf("Serialized/ParseRepoIdentity folded FullName = %q, want acme/backend", parsed.FullName)
	}
	if parsed.Serialized() != id.Serialized() {
		t.Fatalf("serialized spelling not stable: %q then %q", id.Serialized(), parsed.Serialized())
	}

	got, err := ParseStoredRepoID("GitHub.com./Acme/Backend")
	if err != nil {
		t.Fatalf("ParseStoredRepoID: %v", err)
	}
	stored, _ := got.Identity()
	if stored.Host != "github.com" || stored.FullName != "acme/backend" {
		t.Fatalf("ParseStoredRepoID = %+v, want github.com/acme/backend", stored)
	}

	alias, err := CanonicalHostAlias("Acme/Backend")
	if err != nil {
		t.Fatalf("CanonicalHostAlias: %v", err)
	}
	if alias.FullName != "acme/backend" {
		t.Fatalf("CanonicalHostAlias = %q, want acme/backend", alias.FullName)
	}

	// An explicit a1: alias folds its decoded path, and the base64url payload
	// (case-significant) is never lowercased in place.
	tagged := RepoAliasPrefix + base64.RawURLEncoding.EncodeToString([]byte("Group/Sub/Project"))
	a, err := ParseRepoAlias(tagged)
	if err != nil {
		t.Fatalf("ParseRepoAlias: %v", err)
	}
	if a.FullName != "group/sub/project" {
		t.Fatalf("ParseRepoAlias = %q, want group/sub/project", a.FullName)
	}
	reparsed, err := ParseRepoAlias(a.Serialized())
	if err != nil || reparsed.FullName != a.FullName {
		t.Fatalf("a1: round trip = %+v, %v", reparsed, err)
	}
}

// TestAuthorizePathCaseDoesNotBypassDeny is the F4-A regression: an explicit
// deny (or grant) keyed by the folded path must apply to every case variant of
// that path. Before the fix, github.com/Acme/Backend did not equal the
// github.com/acme/backend entry, so the entry was missed and the request fell
// through to the global read role (fail open).
func TestAuthorizePathCaseDoesNotBypassDeny(t *testing.T) {
	denied := Principal{Subject: "bot", Roles: []Role{RoleRead}, Repositories: map[string]RepositoryPermission{
		"github.com/acme/backend": {Read: false},
	}}
	for _, repo := range []string{"github.com/acme/backend", "github.com/Acme/Backend", "GitHub.com/ACME/BACKEND"} {
		if Authorize(denied, ActionRead, repo, false) {
			t.Fatalf("repo %q bypassed the explicit deny via the global read role", repo)
		}
	}

	granted := Principal{Subject: "bot", Repositories: map[string]RepositoryPermission{
		"github.com/acme/backend": {Read: true},
	}}
	for _, repo := range []string{"github.com/Acme/Backend", "GitHub.com/ACME/BACKEND"} {
		if !Authorize(granted, ActionRead, repo, false) {
			t.Fatalf("path-case variant %q did not match the folded grant", repo)
		}
	}
}

// TestAuthorizeUnparseableRepoDenies is the F4-F regression: a non-empty
// repository string that names no identity must not fall through to the global
// roles. Only the deliberately repo-less empty string does.
func TestAuthorizeUnparseableRepoDenies(t *testing.T) {
	reader := Principal{Subject: "reader", Roles: []Role{RoleRead}}
	ops := Principal{Subject: "ops", Roles: []Role{RoleRunnerManage, RolePolicyManage}}

	for _, bad := range []string{"github.com//o", "github.com/o/r\u0000", "bad repo/name"} {
		if Authorize(reader, ActionRead, bad, false) {
			t.Fatalf("global read role authorized unparseable repo %q", bad)
		}
		if Authorize(ops, ActionRunnerManage, bad, false) {
			t.Fatalf("runner_manage role authorized unparseable repo %q", bad)
		}
	}

	if !Authorize(reader, ActionRead, "", false) {
		t.Fatal("repo-less empty string must still use the global read role")
	}
	if !Authorize(ops, ActionRunnerManage, "", false) {
		t.Fatal("repo-less empty string must still use the global runner_manage role")
	}
}
