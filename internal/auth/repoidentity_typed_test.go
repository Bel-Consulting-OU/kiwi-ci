package auth

// Regression tests for the typed repository identity that replaced the
// "first path segment contains a dot" heuristic. The central case is the
// concrete collision this round removes: canonical dotless host
// "gitlab/acme/widget" versus the bare nested-group portion of the unrelated
// canonical repository "forge.example/gitlab/acme/widget". No string shape can
// distinguish them, so identity is explicit and typed.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRepoIdentitySerializedRoundTrip pins the unambiguous ACL spelling
// "r1:<base64url(host)>:<base64url(full_name)>" for dotted hosts, dotless
// hosts and bracketed IPv6 literals (whose canonical host carries ':' and
// could never be recovered from a "host/owner/name" split).
func TestRepoIdentitySerializedRoundTrip(t *testing.T) {
	cases := []struct {
		host     string
		fullName string
		wantHost string
	}{
		{"gitlab", "acme/widget", "gitlab"},
		{"gitlab.company.com", "group/sub/backend", "gitlab.company.com"},
		{"[2001:db8::1]", "acme/widget", "2001:db8::1"},
		{"[::1]:8443", "group/sub/proj", "::1:8443"},
		{"github.com", "owner/name", "github.com"},
	}
	for _, tc := range cases {
		id, err := CanonicalHostIdentity(tc.host, tc.fullName)
		if err != nil {
			t.Fatalf("CanonicalHostIdentity(%q,%q): %v", tc.host, tc.fullName, err)
		}
		if id.Host != tc.wantHost {
			t.Fatalf("CanonicalHostIdentity(%q).Host = %q, want %q", tc.host, id.Host, tc.wantHost)
		}
		s := id.Serialized()
		if !strings.HasPrefix(s, RepoIdentityPrefix) {
			t.Fatalf("Serialized(%+v) = %q, want the %q prefix", id, s, RepoIdentityPrefix)
		}
		back, err := ParseRepoIdentity(s)
		if err != nil {
			t.Fatalf("ParseRepoIdentity(%q): %v", s, err)
		}
		if back != id {
			t.Fatalf("round trip %q: got %+v, want %+v", s, back, id)
		}
		// The same string is an identity grant, never an alias.
		grant, err := ParseRepoGrant(s)
		if err != nil {
			t.Fatalf("ParseRepoGrant(%q): %v", s, err)
		}
		if !grant.IsIdentity() {
			t.Fatalf("ParseRepoGrant(%q) classified as an alias", s)
		}
		if got, _ := grant.Identity(); got != id {
			t.Fatalf("ParseRepoGrant(%q) identity = %+v, want %+v", s, got, id)
		}
	}
	// A bracket literal and its unbracketed canonical host are the same
	// identity; distinct literals never collide.
	a, _ := CanonicalHostIdentity("[2001:db8::1]", "acme/widget")
	b, _ := CanonicalHostIdentity("2001:db8::1", "acme/widget")
	if a != b {
		t.Fatalf("bracketed and canonical IPv6 hosts differ: %+v vs %+v", a, b)
	}
	c, _ := CanonicalHostIdentity("[2001:db8::2]", "acme/widget")
	if a == c {
		t.Fatalf("distinct IPv6 literals collapsed: %q", a.Serialized())
	}
}

// TestParseRepoGrantConfigFailsClosedOnLegacyAmbiguous pins the strict ACL
// configuration schema: a legacy string with three or more path segments is
// ambiguous and is refused with an error naming the string and both accepted
// spellings. It is never guessed into an identity or an alias.
func TestParseRepoGrantConfigFailsClosedOnLegacyAmbiguous(t *testing.T) {
	for _, legacy := range []string{"gitlab/acme/widget", "forge.example/gitlab/acme/widget", "github.com/o/repo-a"} {
		if _, err := ParseRepoGrantConfig(legacy); err == nil {
			t.Fatalf("ParseRepoGrantConfig(%q) accepted an ambiguous legacy grant", legacy)
		} else if !errors.Is(err, ErrRepoGrantAmbiguous) {
			t.Fatalf("ParseRepoGrantConfig(%q) error %v does not match ErrRepoGrantAmbiguous", legacy, err)
		} else {
			msg := err.Error()
			if !strings.Contains(msg, legacy) {
				t.Fatalf("ambiguity error %q does not name the offending string %q", msg, legacy)
			}
			if !strings.Contains(msg, RepoIdentityPrefix) || !strings.Contains(msg, RepoAliasPrefix) {
				t.Fatalf("ambiguity error %q does not name both accepted spellings", msg)
			}
		}
	}
	// Unambiguous legacy bare spellings (zero or one slash) still load.
	for _, bare := range []string{"widget", "acme/widget"} {
		grant, err := ParseRepoGrantConfig(bare)
		if err != nil {
			t.Fatalf("ParseRepoGrantConfig(%q): %v", bare, err)
		}
		if !grant.IsAlias() {
			t.Fatalf("ParseRepoGrantConfig(%q) is not an alias", bare)
		}
	}
	// The explicit forms are accepted.
	id := RepoIdentity{Host: "gitlab", FullName: "acme/widget"}
	if g, err := ParseRepoGrantConfig(id.Serialized()); err != nil || !g.IsIdentity() {
		t.Fatalf("ParseRepoGrantConfig(identity r1:) = (%v, %v)", g, err)
	}
	if g, err := ParseRepoGrantConfig(RepoAlias{FullName: "group/sub/widget"}.Serialized()); err != nil || !g.IsAlias() {
		t.Fatalf("ParseRepoGrantConfig(alias a1:) = (%v, %v)", g, err)
	}
}

// TestLegacyAmbiguousGrantFailsClosedAtLoad pins the startup path: a token
// file carrying a legacy ambiguous repository grant is refused by
// TokenStore.Load with ErrRepoGrantAmbiguous, and the live store is left
// untouched.
func TestLegacyAmbiguousGrantFailsClosedAtLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	m := map[string]Principal{
		TokenDigest("tok"): {Subject: "svc", Repositories: map[string]RepositoryPermission{
			"gitlab/acme/widget": {Read: true},
		}},
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewTokenStore()
	if err := store.AddToken("live", Principal{Subject: "live"}); err != nil {
		t.Fatal(err)
	}
	err = store.Load(path)
	if err == nil {
		t.Fatal("a token file with an ambiguous legacy grant loaded")
	}
	if !errors.Is(err, ErrRepoGrantAmbiguous) {
		t.Fatalf("load error %v does not match ErrRepoGrantAmbiguous", err)
	}
	if !strings.Contains(err.Error(), "gitlab/acme/widget") {
		t.Fatalf("load error %q does not name the offending grant", err.Error())
	}
	if _, ok := store.Authenticate("live"); !ok {
		t.Fatal("a failed load clobbered the live store")
	}
}

// TestDotlessCanonicalGrantDoesNotCrossForge is the concrete collision: a
// canonical grant for the DOTLESS host repository gitlab/acme/widget must not
// authorize the unrelated canonical repository forge.example/gitlab/acme/widget
// (which merely ends with that bare path), and vice versa.
func TestDotlessCanonicalGrantDoesNotCrossForge(t *testing.T) {
	dotless := RepoIdentity{Host: "gitlab", FullName: "acme/widget"}
	dotted := RepoIdentity{Host: "forge.example", FullName: "gitlab/acme/widget"}
	if dotless.ID() == dotted.ID() {
		t.Fatalf("test identities are not distinct: %q", dotless.ID())
	}

	// In-process legacy spellings (the documented migration rule).
	legacy := Principal{Subject: "legacy", Repositories: map[string]RepositoryPermission{
		dotless.ID(): {Read: true},
	}}
	if Authorize(legacy, ActionRead, dotted.ID(), false) {
		t.Fatal("dotless canonical grant authorized the unrelated forge.example repository")
	}
	if !Authorize(legacy, ActionRead, dotless.ID(), false) {
		t.Fatal("dotless canonical grant must authorize its own repository")
	}
	reverse := Principal{Subject: "reverse", Repositories: map[string]RepositoryPermission{
		dotted.ID(): {Read: true},
	}}
	if Authorize(reverse, ActionRead, dotless.ID(), false) {
		t.Fatal("forge.example canonical grant authorized the dotless gitlab repository")
	}
	if !Authorize(reverse, ActionRead, dotted.ID(), false) {
		t.Fatal("forge.example canonical grant must authorize its own repository")
	}

	// The EXPLICIT ACL form behaves identically.
	explicit := Principal{Subject: "explicit", Repositories: map[string]RepositoryPermission{
		dotless.Serialized(): {Read: true},
	}}
	if Authorize(explicit, ActionRead, dotted.ID(), false) {
		t.Fatal("explicit dotless r1: grant authorized the unrelated forge.example repository")
	}
	if !AuthorizeIdentity(explicit, ActionRead, dotless, false) {
		t.Fatal("explicit dotless r1: grant must authorize its own identity")
	}
	if AuthorizeIdentity(explicit, ActionRead, dotted, false) {
		t.Fatal("explicit dotless r1: grant authorized a different identity")
	}
	if CanReadRepoIdentity(explicit, dotted) {
		t.Fatal("CanReadRepoIdentity leaked the dotless grant to another forge")
	}
}

// TestParseStoredRepoIDMigrationRule pins that existing run/profile canonical
// IDs — the strings CanonicalRepoID persisted before typed identity — keep
// parsing into the SAME RepoIdentity they were derived from, dotted or dotless
// host alike, while a name with fewer segments stays a bare alias.
func TestParseStoredRepoIDMigrationRule(t *testing.T) {
	cases := []struct {
		stored   string
		wantHost string
		wantFull string
	}{
		{"github.com/acme/backend", "github.com", "acme/backend"},
		{"gitlab/acme/widget", "gitlab", "acme/widget"},
		{"gitlab.company.com/group/sub/backend", "gitlab.company.com", "group/sub/backend"},
	}
	for _, tc := range cases {
		grant, err := ParseStoredRepoID(tc.stored)
		if err != nil {
			t.Fatalf("ParseStoredRepoID(%q): %v", tc.stored, err)
		}
		id, ok := grant.Identity()
		if !ok {
			t.Fatalf("ParseStoredRepoID(%q) is not a canonical identity", tc.stored)
		}
		if id.Host != tc.wantHost || id.FullName != tc.wantFull {
			t.Fatalf("ParseStoredRepoID(%q) = %+v, want host %q full %q", tc.stored, id, tc.wantHost, tc.wantFull)
		}
		if id.ID() != tc.stored {
			t.Fatalf("ParseStoredRepoID(%q).ID() = %q, want the stored string", tc.stored, id.ID())
		}
	}
	for _, bare := range []string{"acme/backend", "backend", "a1:" + "YWNtZS9iYWNrZW5k"} {
		grant, err := ParseStoredRepoID(bare)
		if err != nil {
			t.Fatalf("ParseStoredRepoID(%q): %v", bare, err)
		}
		if !grant.IsAlias() {
			t.Fatalf("ParseStoredRepoID(%q) is not a bare alias", bare)
		}
	}
}

// TestCanonicalRequiresExplicitHost pins that a canonical identity can never
// be produced without a host, and that a bare alias is wrapped only as an
// alias.
func TestCanonicalRequiresExplicitHost(t *testing.T) {
	if _, err := CanonicalHostIdentity("", "acme/widget"); err == nil {
		t.Fatal("CanonicalHostIdentity accepted an empty host")
	}
	if _, err := ParseRepoIdentity("acme/widget"); err == nil {
		t.Fatal("ParseRepoIdentity accepted a bare string")
	}
	alias, err := CanonicalHostAlias("group/sub/widget")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(alias.Serialized(), RepoAliasPrefix) {
		t.Fatalf("nested alias Serialized = %q, want the %q form", alias.Serialized(), RepoAliasPrefix)
	}
	back, err := ParseRepoAlias(alias.Serialized())
	if err != nil || back != alias {
		t.Fatalf("nested alias round trip = (%+v, %v), want %+v", back, err, alias)
	}
	if !AliasGrant(alias).IsAlias() {
		t.Fatal("AliasGrant is not an alias")
	}
}
