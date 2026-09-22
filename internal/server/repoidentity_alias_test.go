package server

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

// TestBindSubmissionRepoIdentityURLlessStoresExplicitAlias is the R2-B
// regression: a URL-less submission with a NESTED full name must store the
// EXPLICIT a1:<base64url(full_name)> alias, never the plain nested string
// "group/sub/project" that the typed positional rule would later reinterpret
// as host "group" + full name "sub/project".
func TestBindSubmissionRepoIdentityURLlessStoresExplicitAlias(t *testing.T) {
	in := SubmitRun{RepoFullName: "group/sub/project"}
	if err := bindSubmissionRepoIdentity(&in); err != nil {
		t.Fatalf("bindSubmissionRepoIdentity: %v", err)
	}
	want := auth.RepoAlias{FullName: "group/sub/project"}.Serialized()
	if !strings.HasPrefix(want, auth.RepoAliasPrefix) {
		t.Fatalf("nested alias serialization %q is not the a1: form", want)
	}
	if in.RepoID != want || in.PolicyRepoID != want {
		t.Fatalf("stored identity = %q/%q, want the explicit alias %q", in.RepoID, in.PolicyRepoID, want)
	}
	// The stored value classifies as a bare alias, not a canonical identity.
	grant, err := auth.ParseStoredRepoID(in.RepoID)
	if err != nil {
		t.Fatalf("ParseStoredRepoID(%q): %v", in.RepoID, err)
	}
	alias, ok := grant.Alias()
	if !ok || alias.FullName != "group/sub/project" {
		t.Fatalf("stored identity parsed as %+v, want the bare alias group/sub/project", grant)
	}

	// Authorization treats it as a bare alias: an explicit bare grant for the
	// name matches, a canonical grant for one forge does not (typed alias
	// lookup never borrows a canonical grant). The grant keys use the
	// explicit a1: spelling, because a bare nested grant key is itself
	// ambiguous under the positional rule.
	bareGrant := auth.RepoAlias{FullName: "group/sub/project"}.Serialized()
	bare := auth.Principal{Subject: "bare", Repositories: map[string]auth.RepositoryPermission{
		bareGrant: {Read: true},
	}}
	if !auth.CanReadRepoAlias(bare, alias) {
		t.Fatal("bare grant must authorize the stored host-less alias")
	}
	canonical := auth.Principal{Subject: "canonical", Repositories: map[string]auth.RepositoryPermission{
		auth.RepoIdentity{Host: "github.com", FullName: "group/sub/project"}.Serialized(): {Read: true},
	}}
	if auth.CanReadRepoAlias(canonical, alias) {
		t.Fatal("a canonical grant for one forge must not authorize a bare alias")
	}

	// A policy entry for the bare name applies to the stored alias.
	cfg := &policy.Config{Repositories: map[string]policy.RepoPolicy{
		bareGrant: {RequireRootless: policyBool(true)},
	}}
	if _, ok := cfg.RepoPolicyFor(in.RepoID); !ok {
		t.Fatal("bare policy entry must resolve the stored host-less alias")
	}
}

// TestBindSubmissionRepoIdentityURLLessOwnerNameStaysPlain: a URL-less
// owner/name has exactly one slash, so the plain spelling is already the
// unambiguous explicit alias form.
func TestBindSubmissionRepoIdentityURLLessOwnerNameStaysPlain(t *testing.T) {
	in := SubmitRun{RepoFullName: "acme/backend"}
	if err := bindSubmissionRepoIdentity(&in); err != nil {
		t.Fatalf("bindSubmissionRepoIdentity: %v", err)
	}
	if in.RepoID != "acme/backend" || in.PolicyRepoID != "acme/backend" {
		t.Fatalf("stored identity = %q/%q, want acme/backend", in.RepoID, in.PolicyRepoID)
	}
}

// TestBindSubmissionRepoIdentityURLStoresCanonicalIdentity: a URL-bearing
// submission stores the canonical "host/full-name" storage identity (the form
// the SQL identity expressions and the typed positional rule agree on), even
// for a nested path, so the value is never a plain nested string.
func TestBindSubmissionRepoIdentityURLStoresCanonicalIdentity(t *testing.T) {
	for _, tc := range []struct {
		url, full, want string
	}{
		{"https://github.com/acme/backend.git", "acme/backend", "github.com/acme/backend"},
		{"https://gitlab.example/group/sub/project.git", "group/sub/project", "gitlab.example/group/sub/project"},
		{"git@gitlab.example:group/sub/project.git", "", "gitlab.example/group/sub/project"},
	} {
		in := SubmitRun{RepoURL: tc.url, RepoFullName: tc.full}
		if err := bindSubmissionRepoIdentity(&in); err != nil {
			t.Fatalf("bindSubmissionRepoIdentity(%q): %v", tc.url, err)
		}
		if in.RepoID != tc.want || in.PolicyRepoID != tc.want {
			t.Fatalf("stored identity for %q = %q/%q, want %q", tc.url, in.RepoID, in.PolicyRepoID, tc.want)
		}
	}
}

func policyBool(b bool) *bool { return &b }
