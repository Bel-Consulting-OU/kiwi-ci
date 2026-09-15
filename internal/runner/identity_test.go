package runner

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestIdentityStoreRoundTrip saves an identity and loads it back: every
// field must survive, and the private key must be owner-only (0600) with
// the store directory created 0700.
func TestIdentityStoreRoundTrip(t *testing.T) {
	// The store directory is created on first Save (0700), so point the
	// store at a not-yet-existing subdirectory to exercise the creation
	// mode instead of the parent test temp dir's own mode.
	dir := filepath.Join(t.TempDir(), "store")
	store := IdentityStore{Dir: dir}

	if _, ok := store.Load(); ok {
		t.Fatal("empty store reported a complete identity")
	}
	if _, ok := store.LoadID(); ok {
		t.Fatal("empty store reported a runner ID")
	}

	want := Identity{
		ID:        "runner-1",
		KeyPEM:    []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"),
		CertPEM:   []byte("-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n"),
		CACertPEM: []byte("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n"),
	}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	got, ok := store.Load()
	if !ok {
		t.Fatal("saved identity not loadable")
	}
	if got.ID != want.ID {
		t.Fatalf("ID = %q, want %q", got.ID, want.ID)
	}
	if string(got.KeyPEM) != string(want.KeyPEM) {
		t.Fatal("key PEM changed across round trip")
	}
	if string(got.CertPEM) != string(want.CertPEM) {
		t.Fatal("cert PEM changed across round trip")
	}
	if string(got.CACertPEM) != string(want.CACertPEM) {
		t.Fatal("CA PEM changed across round trip")
	}
	if id, ok := store.LoadID(); !ok || id != want.ID {
		t.Fatalf("LoadID = %q, %v; want %q", id, ok, want.ID)
	}

	if runtime.GOOS == "windows" {
		// Windows file modes do not encode permissions; the 0700 store
		// directory ACL is the owner-only boundary there.
		return
	}
	if fi, err := os.Stat(filepath.Join(dir, identityKeyFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key.pem mode = %v, want 0600", fi.Mode().Perm())
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("store dir mode = %v, want 0700", fi.Mode().Perm())
	}
}

// TestIdentityStoreRejectsPartialSave guards against persisting an identity
// that could never be reused: a partial store silently corrupts the next
// startup's reuse check.
func TestIdentityStoreRejectsPartialSave(t *testing.T) {
	store := IdentityStore{Dir: t.TempDir()}
	if err := store.Save(Identity{ID: "runner-1"}); err == nil {
		t.Fatal("identity without key/cert must be rejected")
	}
	if err := store.Save(Identity{KeyPEM: []byte("k"), CertPEM: []byte("c")}); err == nil {
		t.Fatal("identity without ID must be rejected")
	}
	if _, ok := store.Load(); ok {
		t.Fatal("partial saves must not yield a complete identity")
	}
}

// TestIdentityStoreClearCertKeepsID verifies the disabled/revoked cleanup:
// the certificate is removed, the runner ID survives, and clearing is
// idempotent.
func TestIdentityStoreClearCertKeepsID(t *testing.T) {
	dir := t.TempDir()
	store := IdentityStore{Dir: dir}
	if err := store.Save(Identity{ID: "runner-9", KeyPEM: []byte("k"), CertPEM: []byte("c"), CACertPEM: []byte("ca")}); err != nil {
		t.Fatal(err)
	}
	if err := store.ClearCert(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, identityCertFile)); !os.IsNotExist(err) {
		t.Fatal("cert.pem must be removed")
	}
	if id, ok := store.LoadID(); !ok || id != "runner-9" {
		t.Fatalf("runner ID lost: %q, %v", id, ok)
	}
	if err := store.ClearCert(); err != nil {
		t.Fatalf("second clear must be a no-op, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, identityKeyFile)); err != nil {
		t.Fatal("key.pem must be kept for re-enrollment")
	}
}
