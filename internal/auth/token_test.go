package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTokenStoreAddAndAuthenticate(t *testing.T) {
	s := NewTokenStore()
	p := Principal{Subject: "ci-bot", Roles: []Role{RoleRun}}
	if err := s.AddToken("s3cret-token", p); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Authenticate("s3cret-token")
	if !ok || got.Subject != "ci-bot" || !got.Has(RoleRun) {
		t.Fatalf("authenticate: ok=%v principal=%+v", ok, got)
	}
	if _, ok := s.Authenticate("wrong"); ok {
		t.Fatal("wrong token authenticated")
	}
	if _, ok := s.Authenticate("s3cret-tokenx"); ok {
		t.Fatal("near-miss token authenticated")
	}
	if err := s.AddToken("", p); err == nil {
		t.Fatal("empty token accepted")
	}
}

func TestTokenStoreSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	s := NewTokenStore()
	if err := s.AddToken("alpha", Principal{Subject: "a", Roles: []Role{RoleRun}}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddToken("bravo", Principal{Subject: "b", Roles: []Role{RoleAdmin}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}

	// The persisted file must never contain raw tokens, only digests.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "alpha") || strings.Contains(string(raw), "bravo") {
		t.Fatalf("raw token leaked to disk: %s", raw)
	}
	var m map[string]Principal
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("token file is not the expected JSON: %v", err)
	}
	if _, ok := m[TokenDigest("alpha")]; !ok {
		t.Fatal("digest of alpha missing from file")
	}
	if _, ok := m[TokenDigest("bravo")]; !ok {
		t.Fatal("digest of bravo missing from file")
	}
	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode = %o, want 600", fi.Mode().Perm())
	}

	// Load into a fresh store: both tokens authenticate with their
	// principals.
	s2 := NewTokenStore()
	if err := s2.Load(path); err != nil {
		t.Fatal(err)
	}
	a, ok := s2.Authenticate("alpha")
	if !ok || a.Subject != "a" || !a.Has(RoleRun) {
		t.Fatalf("alpha after load: ok=%v %+v", ok, a)
	}
	b, ok := s2.Authenticate("bravo")
	if !ok || b.Subject != "b" || !b.Has(RoleAdmin) {
		t.Fatalf("bravo after load: ok=%v %+v", ok, b)
	}
}

func TestTokenStoreLoadReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	s1 := NewTokenStore()
	if err := s1.AddToken("old", Principal{Subject: "old"}); err != nil {
		t.Fatal(err)
	}
	if err := s1.Save(path); err != nil {
		t.Fatal(err)
	}
	s2 := NewTokenStore()
	if err := s2.AddToken("new", Principal{Subject: "new"}); err != nil {
		t.Fatal(err)
	}
	if err := s2.Load(path); err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Authenticate("new"); ok {
		t.Fatal("load must replace, not merge")
	}
	if _, ok := s2.Authenticate("old"); !ok {
		t.Fatal("loaded token missing")
	}
}

func TestTokenStoreLoadMissingFile(t *testing.T) {
	if err := NewTokenStore().Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("load of missing file must error")
	}
}
