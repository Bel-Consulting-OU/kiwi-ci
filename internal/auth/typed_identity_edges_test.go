package auth

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func enc(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// TestCanReadAnyRepoAlias pins the coarse query-form gate used by
// repository-spanning endpoints that address a bare name: global read/admin,
// an explicit bare read grant for the name, or a canonical read grant whose
// full name is the alias. A run-only grant, an unusable key, a foreign name
// and a canonical grant for a different name must all leave the gate closed.
func TestCanReadAnyRepoAlias(t *testing.T) {
	cases := []struct {
		name  string
		p     Principal
		alias RepoAlias
		want  bool
	}{
		{"admin", Principal{Roles: []Role{RoleAdmin}}, RepoAlias{FullName: "acme/svc"}, true},
		{"global read", Principal{Roles: []Role{RoleRead}}, RepoAlias{FullName: "acme/svc"}, true},
		{"empty alias", Principal{Repositories: map[string]RepositoryPermission{"acme/svc": {Read: true}}}, RepoAlias{}, false},
		{
			"canonical grant sharing the full name",
			Principal{Repositories: map[string]RepositoryPermission{"github.com/acme/svc": {Read: true}}},
			RepoAlias{FullName: "acme/svc"}, true,
		},
		{
			"canonical grant for another name",
			Principal{Repositories: map[string]RepositoryPermission{"github.com/acme/other": {Read: true}}},
			RepoAlias{FullName: "acme/svc"}, false,
		},
		{
			"explicit bare grant",
			Principal{Repositories: map[string]RepositoryPermission{"acme/svc": {Read: true}}},
			RepoAlias{FullName: "acme/svc"}, true,
		},
		{
			"bare grant for another name",
			Principal{Repositories: map[string]RepositoryPermission{"acme/other": {Read: true}}},
			RepoAlias{FullName: "acme/svc"}, false,
		},
		{
			"run-only and unusable keys are skipped",
			Principal{Repositories: map[string]RepositoryPermission{
				"team//bad": {Read: true},
				"acme/svc":  {Run: true},
			}},
			RepoAlias{FullName: "acme/svc"}, false,
		},
	}
	for _, tc := range cases {
		if got := CanReadAnyRepoAlias(tc.p, tc.alias); got != tc.want {
			t.Errorf("%s: CanReadAnyRepoAlias = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestAuthorizeAliasTypedSemantics pins the typed alias entry point: it is an
// explicit statement that the value is host-less, so it matches ONLY explicit
// bare grants and never borrows a canonical grant for one forge.
func TestAuthorizeAliasTypedSemantics(t *testing.T) {
	admin := Principal{Subject: "a", Roles: []Role{RoleAdmin}}
	if !AuthorizeAlias(admin, ActionRead, RepoAlias{FullName: "o/r"}, false) {
		t.Fatal("admin must be authorized through AuthorizeAlias")
	}
	canonicalOnly := Principal{Repositories: map[string]RepositoryPermission{
		"github.com/acme/svc": {Read: true},
	}}
	alias := RepoAlias{FullName: "acme/svc"}
	if CanReadRepoAlias(canonicalOnly, alias) {
		t.Fatal("typed alias must not borrow a canonical grant")
	}
	if AuthorizeAlias(canonicalOnly, ActionRead, alias, false) {
		t.Fatal("AuthorizeAlias must not borrow a canonical grant")
	}
	bare := Principal{Repositories: map[string]RepositoryPermission{"acme/svc": {Read: true}}}
	if !CanReadRepoAlias(bare, alias) {
		t.Fatal("an explicit bare grant must authorize its typed alias")
	}
	if !AuthorizeAlias(bare, ActionRead, alias, false) {
		t.Fatal("AuthorizeAlias must authorize an explicit bare grant")
	}
}

// TestRepoGrantResolutionInvalidInputs covers the two no-identity shortcut
// branches: an unparseable repository string and a zero (invalid) grant both
// resolve to RepoNoEntry, and unusable map keys are skipped without poisoning
// a valid lookup.
func TestRepoGrantResolutionInvalidInputs(t *testing.T) {
	p := Principal{Repositories: map[string]RepositoryPermission{"bad//key": {Read: true}}}
	if _, res := p.repoEntry("bad//repo"); res != RepoNoEntry {
		t.Fatalf("unparseable repo string -> %v, want RepoNoEntry", res)
	}
	if _, res := p.repoEntryGrant(RepoGrant{}); res != RepoNoEntry {
		t.Fatalf("zero grant -> %v, want RepoNoEntry", res)
	}
	// A syntactically valid identity lookup still finds no entry: the only
	// key is unusable and must be skipped (not treated as a match).
	if _, res := p.repoEntryGrant(IdentityGrant(RepoIdentity{Host: "github.com", FullName: "o/r"})); res != RepoNoEntry {
		t.Fatalf("valid lookup with only unusable keys -> %v, want RepoNoEntry", res)
	}
}

// TestRepoIdentityAccessors covers the exported render/parse surface of the
// typed identity and alias values, including the empty-value and folding
// branches.
func TestRepoIdentityAccessors(t *testing.T) {
	id := RepoIdentity{Host: "github.com", FullName: "Acme/Repo"}
	if got := id.ID(); got != "github.com/acme/repo" {
		t.Fatalf("ID = %q", got)
	}
	if got := id.String(); got != id.ID() {
		t.Fatalf("String = %q, want ID %q", got, id.ID())
	}
	if got, want := id.Serialized(), RepoIdentityPrefix+enc("github.com")+":"+enc("acme/repo"); got != want {
		t.Fatalf("Serialized = %q, want %q", got, want)
	}
	parsed, err := ParseRepoIdentity(id.Serialized())
	if err != nil {
		t.Fatalf("ParseRepoIdentity round trip: %v", err)
	}
	if parsed.Host != id.Host || parsed.FullName != FoldRepoFullName(id.FullName) {
		t.Fatalf("round trip = %+v, want folded %+v", parsed, id)
	}

	var emptyID RepoIdentity
	if emptyID.ID() != "" || emptyID.Serialized() != "" {
		t.Fatal("empty identity must render empty")
	}
	if (RepoIdentity{Host: "github.com"}).ID() != "" {
		t.Fatal("identity without a full name must render empty")
	}

	if got := (RepoAlias{FullName: "Owner/Name"}).String(); got != "owner/name" {
		t.Fatalf("alias String = %q", got)
	}
	if got := (RepoAlias{FullName: "owner/name"}).Serialized(); got != "owner/name" {
		t.Fatalf("simple alias Serialized = %q", got)
	}
	if got, want := (RepoAlias{FullName: "Group/Sub/Repo"}).Serialized(), RepoAliasPrefix+enc("group/sub/repo"); got != want {
		t.Fatalf("nested alias Serialized = %q, want %q", got, want)
	}
	var emptyAlias RepoAlias
	if emptyAlias.Serialized() != "" || emptyAlias.String() != "" {
		t.Fatal("empty alias must render empty")
	}

	var invalid RepoGrant
	if invalid.AuthorizationID() != "" || invalid.Serialized() != "" {
		t.Fatal("zero grant must render empty")
	}
}

// TestRepoGrantErrorMessages covers both branches of the operator-facing
// error text: the ambiguous-legacy spelling and the generic malformed grant.
func TestRepoGrantErrorMessages(t *testing.T) {
	ambiguous := &RepoGrantError{Grant: "a/b/c", Ambiguous: true, Detail: "nope"}
	if !errors.Is(ambiguous, ErrRepoGrantAmbiguous) {
		t.Fatal("ambiguous RepoGrantError must match ErrRepoGrantAmbiguous")
	}
	if msg := ambiguous.Error(); !strings.Contains(msg, "a/b/c") || !strings.Contains(msg, RepoIdentityPrefix) {
		t.Fatalf("ambiguous message = %q", msg)
	}
	plain := &RepoGrantError{Grant: "bad//thing", Detail: "empty segment"}
	if errors.Is(plain, ErrRepoGrantAmbiguous) {
		t.Fatal("non-ambiguous RepoGrantError must not match ErrRepoGrantAmbiguous")
	}
	if msg := plain.Error(); !strings.Contains(msg, "invalid repository grant") || !strings.Contains(msg, "bad//thing") {
		t.Fatalf("plain message = %q", msg)
	}
	// ParseRepoGrant("bad//thing") yields the non-ambiguous error in practice.
	if _, err := ParseRepoGrant("bad//thing"); err == nil {
		t.Fatal("malformed grant parsed")
	} else {
		var ge *RepoGrantError
		if !errors.As(err, &ge) || ge.Ambiguous {
			t.Fatalf("malformed grant error = %v (want non-ambiguous RepoGrantError)", err)
		}
		_ = ge.Error()
	}
}

// TestParseRepoIdentityRejections drives every rejection branch of the strict
// canonical-identity parser.
func TestParseRepoIdentityRejections(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"no prefix", "github.com/acme/svc"},
		{"one part", RepoIdentityPrefix + "only"},
		{"empty host part", RepoIdentityPrefix + ":" + enc("o/r")},
		{"padded part", RepoIdentityPrefix + enc("github.com") + "=:" + enc("o/r")},
		{"bad base64 host", RepoIdentityPrefix + "!!!:" + enc("o/r")},
		{"bad base64 full", RepoIdentityPrefix + enc("github.com") + ":!!!"},
		{"host with control content", RepoIdentityPrefix + enc("a\tb") + ":" + enc("o/r")},
		{"full name without owner/name", RepoIdentityPrefix + enc("github.com") + ":" + enc("nope")},
	}
	for _, tc := range cases {
		if _, err := ParseRepoIdentity(tc.in); err == nil {
			t.Errorf("%s: ParseRepoIdentity(%q) succeeded, want error", tc.name, tc.in)
		}
	}
}

// TestParseRepoAliasRejections drives every rejection branch of the strict
// bare-alias parser, plus the accepted nested spelling.
func TestParseRepoAliasRejections(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"no prefix", "group/sub/repo"},
		{"empty part", RepoAliasPrefix},
		{"padded part", RepoAliasPrefix + enc("group/sub") + "="},
		{"bad base64", RepoAliasPrefix + "!!!"},
		{"invalid full name", RepoAliasPrefix + enc("a//b")},
	}
	for _, tc := range cases {
		if _, err := ParseRepoAlias(tc.in); err == nil {
			t.Errorf("%s: ParseRepoAlias(%q) succeeded, want error", tc.name, tc.in)
		}
	}
	got, err := ParseRepoAlias(RepoAliasPrefix + enc("Group/Sub/Repo"))
	if err != nil || got.FullName != "group/sub/repo" {
		t.Fatalf("nested alias parse = %+v, %v", got, err)
	}
}

// TestParseRepoGrantWrapperErrors covers the r1:/a1: error propagation in the
// shared grant parser and the legacy-canonical validation failure.
func TestParseRepoGrantWrapperErrors(t *testing.T) {
	if _, err := ParseRepoGrant(RepoIdentityPrefix + "bad"); err == nil {
		t.Fatal("ParseRepoGrant accepted a malformed r1: grant")
	}
	if _, err := ParseRepoGrant(RepoAliasPrefix + "="); err == nil {
		t.Fatal("ParseRepoGrant accepted a malformed a1: grant")
	}
	// Legacy canonical spelling whose remainder is not a valid owner/name.
	if _, err := ParseRepoGrant("gh/o/"); err == nil {
		t.Fatal("ParseRepoGrant accepted a legacy identity with an empty path segment")
	}
}

// TestValidCanonicalHost pins the host validator, including the bracketed
// IPv6 literal branch and the truncated/malformed variants.
func TestValidCanonicalHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"github.com", true},
		{"gitlab", true},
		{"[::1]", true},
		{"", false},
		{"a b", false},
		{"a/b", false},
		{"a?b", false},
		{"a#b", false},
		{"a@b", false},
		{"[::1", false},
		{"[::1] x", false},
	}
	for _, tc := range cases {
		if got := validCanonicalHost(tc.host); got != tc.want {
			t.Errorf("validCanonicalHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// TestCanonicalHostIdentityRejections covers the constructor error branches:
// an unrepresentable host and a full name that is not owner/name.
func TestCanonicalHostIdentityRejections(t *testing.T) {
	if _, err := CanonicalHostIdentity("a\tb", "o/r"); err == nil {
		t.Fatal("CanonicalHostIdentity accepted a host with control content")
	}
	if _, err := CanonicalHostIdentity("github.com", "nope"); err == nil {
		t.Fatal("CanonicalHostIdentity accepted a full name without owner/name")
	}
	if _, err := CanonicalHostAlias(""); err == nil {
		t.Fatal("CanonicalHostAlias accepted an empty full name")
	}
	id, err := CanonicalHostIdentity("GitHub.com", "Acme/Repo")
	if err != nil || id.Host != "github.com" || id.FullName != "acme/repo" {
		t.Fatalf("CanonicalHostIdentity = %+v, %v", id, err)
	}
}

// TestValidateFullNameBranches pins the shared full-name validator's rejection
// branches.
func TestValidateFullNameBranches(t *testing.T) {
	cases := []struct {
		full         string
		requireSlash bool
		wantErr      bool
	}{
		{"", false, true},
		{" owner/name", false, true},
		{"owner name", false, true},
		{"/owner", false, true},
		{"owner/", false, true},
		{"owner//name", false, true},
		{"owner", true, true},
		{"owner", false, false},
		{"owner/name", true, false},
	}
	for _, tc := range cases {
		err := validateFullName(tc.full, tc.requireSlash)
		if (err != nil) != tc.wantErr {
			t.Errorf("validateFullName(%q, %v) = %v, wantErr %v", tc.full, tc.requireSlash, err, tc.wantErr)
		}
	}
}
