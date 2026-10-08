package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseCapabilityKnownAndUnknown(t *testing.T) {
	for _, c := range KnownCapabilities() {
		got, err := ParseCapability(string(c))
		if err != nil || got != c {
			t.Fatalf("ParseCapability(%q) = (%q, %v), want the value", c, got, err)
		}
	}
	for _, bad := range []string{"", "execution.events", "execution.events:write", "execution.events:read ", "Evidence:read", "graph.mutations"} {
		if got, err := ParseCapability(bad); err == nil {
			t.Fatalf("ParseCapability(%q) accepted %q", bad, got)
		}
	}
	// The reserved graph capability parses and round-trips even though no
	// route consults it yet.
	if _, err := ParseCapability(string(CapGraphMutationsWrite)); err != nil {
		t.Fatalf("reserved capability does not parse: %v", err)
	}
}

// TestAddTokenValidatesCapabilityValues pins the fail-closed AddToken
// validation: an unknown capability value (global or repository-scoped) is
// refused and leaves the store unchanged, so a typo can never install an
// identity whose grant silently matches nothing.
func TestAddTokenValidatesCapabilityValues(t *testing.T) {
	store := NewTokenStore()
	err := store.AddToken("bad-global", Principal{Subject: "s", Capabilities: []Capability{"execution.events:reed"}})
	if err == nil || !strings.Contains(err.Error(), "unknown capability") {
		t.Fatalf("unknown global capability = %v, want an unknown-capability error", err)
	}
	err = store.AddToken("bad-repo", Principal{Subject: "s", RepositoryCapabilities: map[string][]Capability{
		"o/repo-a": {"evidence:read", "nope"},
	}})
	if err == nil || !strings.Contains(err.Error(), "unknown capability") || !strings.Contains(err.Error(), "o/repo-a") {
		t.Fatalf("unknown repo capability = %v, want an unknown-capability error naming the grant", err)
	}
	if !store.Empty() {
		t.Fatal("a rejected AddToken changed the store")
	}
	// Valid capabilities (including the reserved one) are accepted.
	if err := store.AddToken("good", Principal{
		Subject:                "s",
		Capabilities:           []Capability{CapGraphMutationsWrite},
		RepositoryCapabilities: map[string][]Capability{"o/repo-a": {CapRunsCancel}},
	}); err != nil {
		t.Fatalf("valid capabilities rejected: %v", err)
	}
}

// TestEffectivePrincipalEqualComparesCapabilities is the rotation-safety pin:
// capability order/duplicates are irrelevant to identity, any difference in
// the global set or in a repository-scoped set is a different identity, and a
// different grant-key spelling is a different identity exactly like the
// permission map.
func TestEffectivePrincipalEqualComparesCapabilities(t *testing.T) {
	base := Principal{Subject: "svc", Capabilities: []Capability{CapExecutionEventsRead, CapEvidenceRead}}
	reordered := Principal{Subject: "svc", Capabilities: []Capability{CapEvidenceRead, CapExecutionEventsRead, CapExecutionEventsRead}}
	if !effectivePrincipalEqual(base, reordered) {
		t.Fatal("capability order/duplicates changed the effective identity")
	}
	subset := Principal{Subject: "svc", Capabilities: []Capability{CapExecutionEventsRead}}
	if effectivePrincipalEqual(base, subset) {
		t.Fatal("a missing capability compared equal")
	}
	extra := Principal{Subject: "svc", Capabilities: []Capability{CapExecutionEventsRead, CapEvidenceRead, CapRunsCancel}}
	if effectivePrincipalEqual(base, extra) {
		t.Fatal("an extra capability compared equal")
	}

	repoBase := Principal{Subject: "svc", RepositoryCapabilities: map[string][]Capability{
		"o/repo-a": {CapRunsCancel, CapExecutionEventsRead},
	}}
	repoReordered := Principal{Subject: "svc", RepositoryCapabilities: map[string][]Capability{
		"o/repo-a": {CapExecutionEventsRead, CapRunsCancel},
	}}
	if !effectivePrincipalEqual(repoBase, repoReordered) {
		t.Fatal("repository capability order changed the effective identity")
	}
	repoDifferent := Principal{Subject: "svc", RepositoryCapabilities: map[string][]Capability{
		"o/repo-a": {CapExecutionEventsRead},
	}}
	if effectivePrincipalEqual(repoBase, repoDifferent) {
		t.Fatal("a different repository capability set compared equal")
	}
	canonicalKey, err := ParseRepoGrant("github.com/o/repo-a")
	if err != nil {
		t.Fatal(err)
	}
	repoOtherKey := Principal{Subject: "svc", RepositoryCapabilities: map[string][]Capability{
		canonicalKey.Serialized(): {CapRunsCancel, CapExecutionEventsRead},
	}}
	if effectivePrincipalEqual(repoBase, repoOtherKey) {
		t.Fatal("canonically equivalent but literally different grant keys compared equal; rotation must not merge spellings")
	}
}

// TestTokenStoreCapabilityRotationConflict pins the subject index behavior:
// two tokens for one subject with equal capability sets (any order) rotate
// cleanly, while a different capability set is a conflict.
func TestTokenStoreCapabilityRotationConflict(t *testing.T) {
	store := NewTokenStore()
	if err := store.AddToken("rot-1", Principal{Subject: "svc", Capabilities: []Capability{CapEvidenceRead, CapRunsCancel}}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddToken("rot-2", Principal{Subject: "svc", Capabilities: []Capability{CapRunsCancel, CapEvidenceRead}}); err != nil {
		t.Fatalf("rotation pair with reordered capabilities: %v", err)
	}
	if _, ok := store.PrincipalBySubject("svc"); !ok {
		t.Fatal("rotation pair does not resolve")
	}
	if err := store.AddToken("weak", Principal{Subject: "svc", Capabilities: []Capability{CapEvidenceRead}}); !errors.Is(err, ErrSubjectConflict) {
		t.Fatalf("weaker capability definition = %v, want ErrSubjectConflict", err)
	}
}

// TestAuthorizeCapabilityMatrix pins the full decision matrix: admin, global
// grants, canonical and bare repository grants, the legacy bare fallback,
// conflicting entries (fail closed, except an unambiguous global grant),
// empty/malformed repositories and unknown capabilities.
func TestAuthorizeCapabilityMatrix(t *testing.T) {
	admin := Principal{Subject: "admin", Roles: []Role{RoleAdmin}}
	global := Principal{Subject: "global", Capabilities: []Capability{CapEvidenceRead}}
	canonical := Principal{Subject: "canon", RepositoryCapabilities: map[string][]Capability{
		"github.com/o/repo-a": {CapExecutionEventsRead},
	}}
	canonicalSerialized, err := ParseRepoGrant("github.com/o/repo-a")
	if err != nil {
		t.Fatal(err)
	}
	explicit := Principal{Subject: "explicit", RepositoryCapabilities: map[string][]Capability{
		canonicalSerialized.Serialized(): {CapExecutionEventsRead},
	}}
	bare := Principal{Subject: "bare", RepositoryCapabilities: map[string][]Capability{
		"o/repo-a": {CapExecutionEventsRead},
	}}
	conflict := Principal{Subject: "conflict", RepositoryCapabilities: map[string][]Capability{
		"github.com/o/repo-a":            {CapExecutionEventsRead},
		canonicalSerialized.Serialized(): {CapEvidenceRead},
	}}
	globalPlusConflict := Principal{Subject: "global-conflict", Capabilities: []Capability{CapExecutionEventsRead}, RepositoryCapabilities: conflict.RepositoryCapabilities}
	other := Principal{Subject: "other", RepositoryCapabilities: map[string][]Capability{
		"github.com/o/repo-b": {CapExecutionEventsRead},
	}}
	repoReader := Principal{Subject: "reader", Repositories: map[string]RepositoryPermission{
		"github.com/o/repo-a": {Read: true},
	}}

	cases := []struct {
		name string
		p    Principal
		cap  Capability
		repo string
		want bool
	}{
		{"admin covers a repository", admin, CapExecutionEventsRead, "github.com/o/repo-a", true},
		{"admin covers the unscoped read", admin, CapExecutionEventsRead, "", true},
		{"admin covers another repository's capability", admin, CapCheckpointsRead, "gitlab.com/x/y", true},
		{"global capability covers a repository", global, CapEvidenceRead, "github.com/o/repo-a", true},
		{"global capability covers the unscoped read", global, CapEvidenceRead, "", true},
		{"global capability does not imply a sibling", global, CapRunsCancel, "github.com/o/repo-a", false},
		{"canonical grant matches its identity", canonical, CapExecutionEventsRead, "github.com/o/repo-a", true},
		{"canonical grant matches default-port spelling", canonical, CapExecutionEventsRead, "github.com:443/o/repo-a", true},
		{"canonical grant does not match another forge", canonical, CapExecutionEventsRead, "gitlab.com/o/repo-a", false},
		{"canonical grant does not match another repo", canonical, CapExecutionEventsRead, "github.com/o/repo-b", false},
		{"canonical grant grants only the listed capability", canonical, CapRunsCancel, "github.com/o/repo-a", false},
		{"explicit r1: grant matches its identity", explicit, CapExecutionEventsRead, "github.com/o/repo-a", true},
		{"bare grant matches the identity (legacy fallback)", bare, CapExecutionEventsRead, "github.com/o/repo-a", true},
		{"bare grant matches the same name on another forge", bare, CapExecutionEventsRead, "gitlab.com/o/repo-a", true},
		{"conflicting entries deny even a listed capability", conflict, CapExecutionEventsRead, "github.com/o/repo-a", false},
		{"conflicting entries deny the other listed capability", conflict, CapEvidenceRead, "github.com/o/repo-a", false},
		{"a global grant survives repository conflicts", globalPlusConflict, CapExecutionEventsRead, "github.com/o/repo-a", true},
		{"a global grant does not cover the conflicted other capability", globalPlusConflict, CapEvidenceRead, "github.com/o/repo-a", false},
		{"unrelated repository grant denies", other, CapExecutionEventsRead, "github.com/o/repo-a", false},
		{"repo-scoped-only grant denies the unscoped read", canonical, CapExecutionEventsRead, "", false},
		{"repo-scoped-only grant denies a whitespace-only scope", canonical, CapExecutionEventsRead, "   ", false},
		{"malformed repository scope denies", canonical, CapExecutionEventsRead, "not a repo", false},
		{"unknown capability denies", global, Capability("bogus:read"), "github.com/o/repo-a", false},
		{"unknown capability denies unscoped", global, Capability("bogus:read"), "", false},
		{"reserved graph capability authorizes only where granted", global, CapGraphMutationsWrite, "github.com/o/repo-a", false},
		{"plain repository read does not imply a capability", repoReader, CapExecutionEventsRead, "github.com/o/repo-a", false},
	}
	for _, tc := range cases {
		if got := AuthorizeCapability(tc.p, tc.cap, tc.repo); got != tc.want {
			t.Errorf("%s: AuthorizeCapability(%s, %q) = %v, want %v", tc.name, tc.cap, tc.repo, got, tc.want)
		}
	}
	// HasCapabilityInAnyScope is the coarse tier screen: true for a
	// repo-scoped grant the matrix denies in the wrong scope, but it is
	// never the decision (AuthorizeCapability above is).
	if !canonical.HasCapabilityInAnyScope(CapExecutionEventsRead) || canonical.HasCapabilityInAnyScope(CapCheckpointsRead) {
		t.Fatal("HasCapabilityInAnyScope misreports the repo-scoped grant")
	}
	if repoReader.HasCapabilityInAnyScope(CapExecutionEventsRead) {
		t.Fatal("plain read access reported as carrying the capability")
	}
}

// TestTokenStoreLoadValidatesCapabilities pins the strict Load schema: an
// unknown capability value and a repository-capability key that fails the ACL
// schema both refuse the whole file and leave the live store untouched.
func TestTokenStoreLoadValidatesCapabilities(t *testing.T) {
	write := func(t *testing.T, p Principal) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "tokens.json")
		b, err := json.Marshal(map[string]Principal{TokenDigest("tok"): p})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	store := NewTokenStore()
	if err := store.AddToken("live", Principal{Subject: "live"}); err != nil {
		t.Fatal(err)
	}

	err := store.Load(write(t, Principal{Subject: "s", Capabilities: []Capability{"evidence:reed"}}))
	if err == nil || !strings.Contains(err.Error(), "unknown capability") {
		t.Fatalf("load of an unknown global capability = %v", err)
	}
	err = store.Load(write(t, Principal{Subject: "s", RepositoryCapabilities: map[string][]Capability{
		"gitlab/acme/widget": {CapEvidenceRead},
	}}))
	if !errors.Is(err, ErrRepoGrantAmbiguous) {
		t.Fatalf("load of an ambiguous repository capability key = %v, want ErrRepoGrantAmbiguous", err)
	}
	err = store.Load(write(t, Principal{Subject: "s", RepositoryCapabilities: map[string][]Capability{
		"o/repo-a": {CapEvidenceRead, "bogus"},
	}}))
	if err == nil || !strings.Contains(err.Error(), "unknown capability") {
		t.Fatalf("load of an unknown repo capability = %v", err)
	}
	if _, ok := store.Authenticate("live"); !ok {
		t.Fatal("a failed load clobbered the live store")
	}

	// The valid controller principal loads with both scopes intact.
	p := Principal{
		Subject:                "faktor",
		Capabilities:           []Capability{CapEvidenceRead},
		RepositoryCapabilities: map[string][]Capability{"o/repo-a": {CapExecutionEventsRead, CapRunsCancel}},
	}
	if err := store.Load(write(t, p)); err != nil {
		t.Fatalf("valid controller principal rejected: %v", err)
	}
	got, ok := store.Authenticate("tok")
	if !ok || !reflect.DeepEqual(got, p) {
		t.Fatalf("loaded principal = (%+v, %v), want %+v", got, ok, p)
	}
}

// TestTokenStoreSaveNormalizesCapabilities proves Save is the migration point
// for capability grants: legacy canonical keys persist under the explicit
// spelling, capability lists are deduped and sorted, and the file reloads
// through the strict Load schema. A conflicting pair fails Save closed before
// anything is written.
func TestTokenStoreSaveNormalizesCapabilities(t *testing.T) {
	store := NewTokenStore()
	if err := store.AddToken("tok", Principal{
		Subject:                "faktor",
		Capabilities:           []Capability{CapRunsCancel, CapEvidenceRead, CapRunsCancel},
		RepositoryCapabilities: map[string][]Capability{"github.com/o/repo-a": {CapExecutionEventsRead, CapExecutionEventsRead}},
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tokens.json")
	if err := store.Save(path); err != nil {
		t.Fatalf("Save with migratable capability grants: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]Principal
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	legacy, err := ParseRepoGrant("github.com/o/repo-a")
	if err != nil {
		t.Fatal(err)
	}
	p := m[TokenDigest("tok")]
	if !sameCapabilitySet(p.Capabilities, []Capability{CapEvidenceRead, CapRunsCancel}) {
		t.Fatalf("saved global capabilities = %v, want the deduped set", p.Capabilities)
	}
	if len(p.Capabilities) != 2 {
		t.Fatalf("saved global capabilities not deduped: %v", p.Capabilities)
	}
	got, ok := p.RepositoryCapabilities[legacy.Serialized()]
	if !ok || len(got) != 1 || got[0] != CapExecutionEventsRead {
		t.Fatalf("saved repository capabilities = %v, want the explicit %s key", p.RepositoryCapabilities, legacy.Serialized())
	}
	reloaded := NewTokenStore()
	if err := reloaded.Load(path); err != nil {
		t.Fatalf("strict Load of the migrated file: %v", err)
	}
	if _, ok := reloaded.Authenticate("tok"); !ok {
		t.Fatal("migrated token does not authenticate after reload")
	}

	// A canonically equivalent pair with DIFFERENT capability sets fails Save
	// closed and publishes no file.
	conflict := NewTokenStore()
	if err := conflict.AddToken("tok-b", Principal{Subject: "s", RepositoryCapabilities: map[string][]Capability{
		"github.com/o/repo-b":                     {CapEvidenceRead},
		legacySerializedOf("github.com/o/repo-b"): {CapRunsCancel},
	}}); err != nil {
		t.Fatal(err)
	}
	conflictPath := filepath.Join(t.TempDir(), "conflict.json")
	if err := conflict.Save(conflictPath); err == nil {
		t.Fatal("Save collapsed conflicting capability grants instead of failing closed")
	}
	if _, err := os.Stat(conflictPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed Save left a file behind: %v", err)
	}
}

// legacySerializedOf renders the explicit ACL spelling of a legacy identity.
func legacySerializedOf(s string) string {
	g, err := ParseRepoGrant(s)
	if err != nil {
		panic(err)
	}
	return g.Serialized()
}
