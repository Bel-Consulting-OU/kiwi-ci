package auth

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestTokenStoreNilMapAndSubjectBranches(t *testing.T) {
	store := &TokenStore{}
	if !store.Empty() {
		t.Fatal("zero-value store must be empty")
	}
	if err := store.AddToken("raw", Principal{Subject: "sub", Roles: []Role{RoleRead}}); err != nil {
		t.Fatal(err)
	}
	if store.Empty() {
		t.Fatal("AddToken must populate the map")
	}
	if err := store.AddToken("", Principal{}); err == nil {
		t.Fatal("empty raw token must be rejected")
	}
	if _, ok := store.PrincipalBySubject(""); ok {
		t.Fatal("empty subject must not resolve")
	}
	p, ok := store.PrincipalBySubject("sub")
	if !ok || p.Subject != "sub" {
		t.Fatalf("PrincipalBySubject = (%+v, %v)", p, ok)
	}
	if _, ok := store.PrincipalBySubject("missing"); ok {
		t.Fatal("unknown subject must not resolve")
	}
}

func TestTokenStoreLoadAndSaveErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewTokenStore()
	if err := store.Load(bad); err == nil {
		t.Fatal("malformed token file must fail to load")
	}
	if err := store.Load(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing token file must fail to load")
	}

	blocking := filepath.Join(dir, "blocking")
	if err := os.WriteFile(blocking, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(filepath.Join(blocking, "nested", "tokens.json")); err == nil {
		t.Fatal("Save under a regular file must fail creating the parent directory")
	}

	// A stale fixed temp path from a pre-fsutil release is inert: durable
	// writes use unique temp names, so Save must succeed and leave the stale
	// entry untouched.
	staleTmp := filepath.Join(dir, "tokens.json.tmp")
	if err := os.MkdirAll(staleTmp, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(filepath.Join(dir, "tokens.json")); err != nil {
		t.Fatalf("Save must ignore a stale fixed temp path: %v", err)
	}
	if fi, err := os.Stat(staleTmp); err != nil || !fi.IsDir() {
		t.Fatalf("stale temp path was modified: fi=%v err=%v", fi, err)
	}
}

func TestRequestIDFromFallback(t *testing.T) {
	if got := requestIDFrom(&http.Request{Header: http.Header{}}); got != "-" {
		t.Fatalf("requestIDFrom without header = %q, want %q", got, "-")
	}
	r, err := http.NewRequest(http.MethodGet, "/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-Kiwi-Request-ID", "abc")
	if got := requestIDFrom(r); got != "abc" {
		t.Fatalf("requestIDFrom = %q, want abc", got)
	}
}

func TestAuthorizeRepoEntryLeafActions(t *testing.T) {
	p := Principal{
		Roles: []Role{RoleRead},
		Repositories: map[string]RepositoryPermission{
			"org/app": {Rerun: true, ArtifactRead: true},
		},
	}
	if !Authorize(p, ActionRerun, "org/app", false) {
		t.Fatal("repo rerun grant must authorize rerun")
	}
	if !Authorize(p, ActionArtifactRead, "org/app", false) {
		t.Fatal("repo artifact_read grant must authorize artifact reads")
	}
	if Authorize(p, ActionRerun, "org/other", false) {
		t.Fatal("unrelated repo must not inherit the grant")
	}
	if Authorize(p, Action("unknown"), "org/app", false) {
		t.Fatal("unknown actions must fall through to deny")
	}
	if Authorize(p, Action("unknown"), "", false) {
		t.Fatal("unknown actions without repo entries must deny")
	}
	if Authorize(p, ActionRead, "org/app", false) {
		t.Fatal("repo entry is authoritative: role read must not leak through")
	}
}

func TestTokenStoreNilReceiverFailsClosed(t *testing.T) {
	var store *TokenStore
	if p, ok := store.Authenticate("any"); ok || p.Subject != "" {
		t.Fatalf("nil store Authenticate = (%+v, %v), want zero principal and false", p, ok)
	}
	if p, ok := store.PrincipalBySubject("sub"); ok || p.Subject != "" {
		t.Fatalf("nil store PrincipalBySubject = (%+v, %v), want zero principal and false", p, ok)
	}
	if p, ok := store.PrincipalBySubject(""); ok || p.Subject != "" {
		t.Fatalf("nil store PrincipalBySubject(empty) = (%+v, %v), want zero principal and false", p, ok)
	}
	if !store.Empty() {
		t.Fatal("nil store must report empty")
	}
	if err := store.AddToken("raw", Principal{Subject: "s"}); err == nil {
		t.Fatal("nil store AddToken must fail closed")
	}
	path := filepath.Join(t.TempDir(), "tokens.json")
	if err := store.Load(path); err == nil {
		t.Fatal("nil store Load must fail closed")
	}
	if err := store.Save(path); err == nil {
		t.Fatal("nil store Save must fail closed")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("nil store Save must not write a file: %v", err)
	}
}
