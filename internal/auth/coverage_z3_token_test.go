package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestEffectivePrincipalEqualSubjectMismatch pins the first discriminator:
// two principals naming different subjects are never the same identity, even
// with identical grants.
func TestEffectivePrincipalEqualSubjectMismatch(t *testing.T) {
	a := Principal{Subject: "alice", Roles: []Role{RoleAdmin}}
	b := Principal{Subject: "bob", Roles: []Role{RoleAdmin}}
	if effectivePrincipalEqual(a, b) {
		t.Fatal("different subjects compared equal")
	}
	if !effectivePrincipalEqual(a, a) {
		t.Fatal("identical principal not equal")
	}
}

// TestNormalizePrincipalRepoGrantsFailClosed covers the migration contract:
// a malformed legacy key is rejected naming the string, two canonically
// equivalent keys with different permission sets are rejected instead of
// silently collapsing to one, and equivalent keys with identical permissions
// dedup to the explicit spelling.
func TestNormalizePrincipalRepoGrantsFailClosed(t *testing.T) {
	if _, err := normalizePrincipalRepoGrants(Principal{Repositories: map[string]RepositoryPermission{"  o/repo-a  ": {Read: true}}}); err == nil {
		t.Fatal("malformed grant key accepted by normalization")
	}

	legacyGrant, err := ParseRepoGrant("github.com/o/repo-a")
	if err != nil {
		t.Fatal(err)
	}
	explicit := legacyGrant.Serialized()
	conflict := Principal{Repositories: map[string]RepositoryPermission{
		"github.com/o/repo-a": {Read: true},
		explicit:              {Read: true, Run: true},
	}}
	_, err = normalizePrincipalRepoGrants(conflict)
	var ge *RepoGrantError
	if !errors.As(err, &ge) || ge.Grant == "" {
		t.Fatalf("conflicting equivalent grants = %v, want a RepoGrantError naming the key", err)
	}

	same := Principal{Repositories: map[string]RepositoryPermission{
		"github.com/o/repo-a": {Read: true, Run: true},
		explicit:              {Read: true, Run: true},
	}}
	got, err := normalizePrincipalRepoGrants(same)
	if err != nil {
		t.Fatalf("equivalent identical grants: %v", err)
	}
	if len(got.Repositories) != 1 {
		t.Fatalf("normalized grants = %v, want the single explicit spelling", got.Repositories)
	}
	if _, ok := got.Repositories[explicit]; !ok {
		t.Fatalf("normalized grants = %v, want the %s spelling", got.Repositories, explicit)
	}
}

// TestTokenStoreSaveMigratesLegacyGrantsAndReloads proves Save is the
// migration point: an in-process legacy canonical grant is persisted under
// its explicit r1: spelling and reloads through the strict Load schema, while
// a persisted conflict fails Save closed before any file is written.
func TestTokenStoreSaveMigratesLegacyGrantsAndReloads(t *testing.T) {
	store := NewTokenStore()
	perm := RepositoryPermission{Read: true, Run: true}
	if err := store.AddToken("tok-a", Principal{Subject: "s", Repositories: map[string]RepositoryPermission{"github.com/o/repo-a": perm}}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tokens.json")
	if err := store.Save(path); err != nil {
		t.Fatalf("Save with a migratable legacy grant: %v", err)
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
	p := m[TokenDigest("tok-a")]
	if _, ok := p.Repositories[legacy.Serialized()]; !ok {
		t.Fatalf("saved grants = %v, want the explicit %s spelling", p.Repositories, legacy.Serialized())
	}
	reloaded := NewTokenStore()
	if err := reloaded.Load(path); err != nil {
		t.Fatalf("strict Load of the migrated file: %v", err)
	}
	if _, ok := reloaded.Authenticate("tok-a"); !ok {
		t.Fatal("migrated token does not authenticate after reload")
	}

	conflict := NewTokenStore()
	legacyB, err := ParseRepoGrant("github.com/o/repo-b")
	if err != nil {
		t.Fatal(err)
	}
	explicitB := legacyB.Serialized()
	if err := conflict.AddToken("tok-b", Principal{Subject: "one", Repositories: map[string]RepositoryPermission{
		"github.com/o/repo-b": {Read: true},
		explicitB:             {Read: true, Run: true},
	}}); err != nil {
		t.Fatal(err)
	}
	conflictPath := filepath.Join(t.TempDir(), "conflict.json")
	if err := conflict.Save(conflictPath); err == nil {
		t.Fatal("Save collapsed a conflicting grant pair instead of failing closed")
	}
	if _, err := os.Stat(conflictPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed Save published a file: %v", err)
	}
}

// TestRemoveTokenFailsClosedOnInjectedSubjectConflict covers the fail-closed
// rebuild: a conflict injected straight into the token map (unreachable
// through AddToken) turns a successful removal into an ambiguous state that
// resolves nothing rather than picking a winner.
func TestRemoveTokenFailsClosedOnInjectedSubjectConflict(t *testing.T) {
	store := NewTokenStore()
	if err := store.AddToken("tok-a", Principal{Subject: "victim"}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddToken("tok-b", Principal{Subject: "shared"}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddToken("tok-c", Principal{Subject: "shared"}); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	conflicting := store.tokens[TokenDigest("tok-c")]
	conflicting.Roles = []Role{RoleAdmin}
	store.tokens[TokenDigest("tok-c")] = conflicting
	store.bySubject["shared"] = store.tokens[TokenDigest("tok-b")]
	store.mu.Unlock()

	if !store.RemoveToken("tok-a") {
		t.Fatal("existing token was not removed")
	}
	store.mu.RLock()
	index := store.bySubject
	store.mu.RUnlock()
	if index != nil {
		t.Fatalf("subject index = %v, want nil after a conflicted rebuild", index)
	}
	if _, ok := store.PrincipalBySubject("shared"); ok {
		t.Fatal("ambiguous subject resolved after the conflicted rebuild")
	}
}

// TestPrincipalBySubjectRefusesIndexDesync pins the guard against an index
// pointing at a subject no token carries: the resolution must fail closed
// instead of trusting the stale index entry.
func TestPrincipalBySubjectRefusesIndexDesync(t *testing.T) {
	store := NewTokenStore()
	store.mu.Lock()
	store.bySubject["ghost"] = Principal{Subject: "ghost", Roles: []Role{RoleAdmin}}
	store.mu.Unlock()
	if p, ok := store.PrincipalBySubject("ghost"); ok {
		t.Fatalf("desynced subject resolved: %+v", p)
	}
}
