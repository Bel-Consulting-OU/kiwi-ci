package server

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// TestWebSessionSecretMalformedEnvFailsStartup pins the finding-4 contract:
// a configured-but-malformed KIWI_WEB_SESSION_SECRET is a startup error in
// every construction path, never a silent random fallback. The previous code
// quietly generated a process-local key, so replicas (or restarts) diverged
// while appearing healthy.
func TestWebSessionSecretMalformedEnvFailsStartup(t *testing.T) {
	const malformed = "not-64-hex"
	t.Setenv("KIWI_WEB_SESSION_SECRET", malformed)

	// Persistent (fs) construction refuses, even when a valid persisted key
	// exists: the operator clearly configured the value, so ignoring it would
	// silently use a different key.
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, webSessionKeyFile), []byte(strings.Repeat("ab", 32)))
	if _, err := NewPersistent("t", "t", dir); err == nil || !strings.Contains(err.Error(), "KIWI_WEB_SESSION_SECRET") {
		t.Fatalf("NewPersistent with malformed env = %v, want the malformed-secret refusal", err)
	}

	// The shared cluster store path refuses too (before loading).
	if _, err := (&FSClusterKeyStore{Dir: t.TempDir()}).LoadOrCreate(clusterKindWebSession); err == nil || !strings.Contains(err.Error(), "KIWI_WEB_SESSION_SECRET") {
		t.Fatalf("cluster web-session create with malformed env = %v, want the refusal", err)
	}

	// The in-memory mode must not silently random either: the lazy initializer
	// surfaces the error and login answers 500 instead of minting a key.
	s := New("t")
	if err := s.ensureWebSessionSecret(); err == nil {
		t.Fatal("in-memory ensureWebSessionSecret with malformed env = nil, want the refusal")
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/login", "", `{"token":"t"}`); w.Code != http.StatusInternalServerError {
		t.Fatalf("login with a malformed configured secret = %d, want 500", w.Code)
	}
}

// TestWebSessionKeySharedAcrossDBBackedReplicas pins the HA agreement
// contract: two DB-mode servers wired to the same cluster key blob store
// derive the SAME session key, so a session minted on one is valid on the
// other behind a non-sticky load balancer.
func TestWebSessionKeySharedAcrossDBBackedReplicas(t *testing.T) {
	t.Setenv("KIWI_WEB_SESSION_SECRET", "")

	a, err := NewPersistent("t", "admin-token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewPersistent("t", "admin-token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Without a shared store each replica holds a different random key.
	if bytes.Equal(a.WebSessionSecret, b.WebSessionSecret) {
		t.Fatal("two independent replicas unexpectedly share a session key before the cluster store is wired")
	}
	blobs := newMemClusterKeyBlobs()
	if err := a.UseClusterKeyStore(&DBClusterKeyStore{Blobs: blobs, Seed: a.ClusterKeys}); err != nil {
		t.Fatal(err)
	}
	if err := b.UseClusterKeyStore(&DBClusterKeyStore{Blobs: blobs, Seed: b.ClusterKeys}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.WebSessionSecret, b.WebSessionSecret) {
		t.Fatalf("DB-backed replicas diverged: a=%x b=%x", a.WebSessionSecret, b.WebSessionSecret)
	}
	// The shared row is durable material, not a per-process value.
	stored, ok, err := blobs.GetClusterKey(t.Context(), clusterKindWebSession)
	if err != nil || !ok || !bytes.Equal(stored, a.WebSessionSecret) {
		t.Fatalf("shared web-session row: ok=%v err=%v", ok, err)
	}

	// Login on A: the cookie it mints validates on B (same admin token, same
	// shared secret).
	cookie, _, code := login(t, a, "admin-token")
	if code != http.StatusOK {
		t.Fatalf("login on replica A = %d", code)
	}
	if w := serveWithSession(b, http.MethodGet, "/api/v1/runs", cookie, ""); w.Code != http.StatusOK {
		t.Fatalf("session minted on replica A rejected by replica B: %d %s", w.Code, w.Body.String())
	}
}

// TestWebSessionKeyEnvOverrideSharedAcrossReplicas proves the explicit
// KIWI_WEB_SESSION_SECRET still wins and is identical on every replica.
func TestWebSessionKeyEnvOverrideSharedAcrossReplicas(t *testing.T) {
	want := strings.Repeat("cd", 32)
	t.Setenv("KIWI_WEB_SESSION_SECRET", want)
	a, err := NewPersistent("t", "t", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewPersistent("t", "t", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, srv := range map[string]*Server{"a": a, "b": b} {
		if hex.EncodeToString(srv.WebSessionSecret) != want {
			t.Fatalf("replica %s did not use the configured shared key", name)
		}
	}
}

// TestWebSessionKeyRandomWithoutSharedStore proves the documented dev/fs
// behavior is preserved: with no configured secret and no shared cluster key
// store, each process generates its own random key.
func TestWebSessionKeyRandomWithoutSharedStore(t *testing.T) {
	t.Setenv("KIWI_WEB_SESSION_SECRET", "")
	a, err := NewPersistent("t", "t", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewPersistent("t", "t", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(a.WebSessionSecret) != 32 || len(b.WebSessionSecret) != 32 {
		t.Fatalf("dev random key sizes = %d/%d", len(a.WebSessionSecret), len(b.WebSessionSecret))
	}
	if bytes.Equal(a.WebSessionSecret, b.WebSessionSecret) {
		t.Fatal("dev servers without a shared store must keep process-local random keys")
	}
}
