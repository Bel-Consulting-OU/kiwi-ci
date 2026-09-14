package cache

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func signTestManifest(t *testing.T, m CacheManifest) ([]byte, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SignManifest(m, "test-key", priv)
	if err != nil {
		t.Fatal(err)
	}
	return b, pub
}

func TestManifestSignVerify(t *testing.T) {
	m := CacheManifest{
		Version: 1, Repository: "org/app", TrustDomain: "trusted",
		LogicalKey: "go-deps", BlobSHA256: strings64("a"),
		BlobSize: 123, ProducerRun: "r1", ProducerJob: "j1", CreatedAt: time.Now().UTC(),
	}
	b, pub := signTestManifest(t, m)
	got, err := VerifyManifest(b, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got.LogicalKey != m.LogicalKey || got.BlobSHA256 != m.BlobSHA256 || got.BlobSize != m.BlobSize {
		t.Fatalf("manifest mismatch: %+v", got)
	}
}

func TestManifestTamperRejected(t *testing.T) {
	m := CacheManifest{Version: 1, LogicalKey: "k", BlobSHA256: strings64("a"), BlobSize: 1}
	b, pub := signTestManifest(t, m)
	var env manifestEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	env.Payload = "dGFtcGVyZWQ="
	b2, _ := json.Marshal(env)
	if _, err := VerifyManifest(b2, pub); err == nil {
		t.Fatal("tampered manifest accepted")
	}
}

func TestManifestValidation(t *testing.T) {
	if err := ValidateManifest(CacheManifest{Version: 2, LogicalKey: "k", BlobSHA256: strings64("a")}); err == nil {
		t.Fatal("version 2 must be rejected")
	}
	if err := ValidateManifest(CacheManifest{Version: 1, LogicalKey: "k", BlobSHA256: "zz"}); err == nil {
		t.Fatal("bad digest must be rejected")
	}
	if err := ValidateManifest(CacheManifest{Version: 1, LogicalKey: "", BlobSHA256: strings64("a")}); err == nil {
		t.Fatal("empty logical key must be rejected")
	}
}

func strings64(c string) string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = c[0]
	}
	return string(out)
}

func TestRestoreRejectsSymlinkParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on windows")
	}
	ws := t.TempDir()
	root := t.TempDir()
	s := &Store{Root: root}
	// Build a cache archive containing cache-dir/file.
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "cache-dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "cache-dir", "file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	key := strings64("k")
	if err := s.Save(key, src, []string{"cache-dir"}); err != nil {
		t.Fatal(err)
	}
	// Pre-create workspace cache-dir as a symlink to outside.
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(ws, "cache-dir")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Restore(key, ws, []string{"cache-dir"}); err == nil {
		t.Fatal("restore through symlink parent must fail")
	}
	if _, err := os.Stat(filepath.Join(outside, "file")); !os.IsNotExist(err) {
		t.Fatal("file written through symlink")
	}
}
