package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIDCovProvenanceKeyLoadPaths covers loadProvenanceKey in ephemeral,
// persisted-reload and failure form, plus ensureProvenanceKey.
func TestIDCovProvenanceKeyLoadPaths(t *testing.T) {
	s := New("t")
	s.provenance = nil
	ephemeral := s.ensureProvenanceKey()
	if ephemeral == nil || ephemeral.KID == "" || len(ephemeral.Public) != ed25519.PublicKeySize {
		t.Fatal("ensureProvenanceKey did not install an ephemeral key")
	}
	if again := s.ensureProvenanceKey(); again != ephemeral {
		t.Fatal("ensureProvenanceKey replaced an existing key")
	}

	// create-routes through an empty data dir stay ephemeral.
	s2 := New("t")
	s2.provenance = nil
	if err := s2.loadProvenanceKey(""); err != nil {
		t.Fatalf("loadProvenanceKey(\"\") = %v", err)
	}
	if s2.provenance == nil || s2.provenance.KID == "" {
		t.Fatal("ephemeral provenance key not installed")
	}

	dir := t.TempDir()
	s3 := New("t")
	if err := s3.loadProvenanceKey(dir); err != nil {
		t.Fatalf("loadProvenanceKey(dir) = %v", err)
	}
	for _, name := range []string{"provenance.key", "provenance.pub"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("persisted %s missing: %v", name, err)
		}
	}
	// Reload from the same dir keeps the key id.
	s4 := New("t")
	if err := s4.loadProvenanceKey(dir); err != nil {
		t.Fatal(err)
	}
	if s4.provenance.KID != s3.provenance.KID {
		t.Fatalf("provenance key id changed across load: %q vs %q", s3.provenance.KID, s4.provenance.KID)
	}

	// A directory in the key file's place is a hard load failure.
	bad := t.TempDir()
	if err := os.Mkdir(filepath.Join(bad, "provenance.key"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := New("t").loadProvenanceKey(bad); err == nil {
		t.Fatal("loadProvenanceKey with a directory as key file = nil, want error")
	}
}

// TestIDCovCacheSignerLoadPaths covers loadCacheSigner's generation,
// reload, corrupt-PEM, incomplete-pair and mismatched-pair branches.
func TestIDCovCacheSignerLoadPaths(t *testing.T) {
	// Ephemeral: empty data dir and the ensure fallback.
	s := New("t")
	s.cacheSigner = nil
	if err := s.loadCacheSigner(""); err != nil {
		t.Fatalf("loadCacheSigner(\"\") = %v", err)
	}
	if s.cacheSigner == nil || len(s.cacheSigner.Public) != ed25519.PublicKeySize {
		t.Fatal("ephemeral cache signer not installed")
	}
	if s.ensureCacheSigner() != s.cacheSigner {
		t.Fatal("ensureCacheSigner replaced an existing signer")
	}
	bare := &Server{}
	if bare.ensureCacheSigner() == nil {
		t.Fatal("ensureCacheSigner did not install an ephemeral signer")
	}

	// Generation persists both halves and the reload is stable.
	dir := t.TempDir()
	gen := New("t")
	if err := gen.loadCacheSigner(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{cacheSigningKeyFile, cacheSigningPubFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("persisted %s missing: %v", name, err)
		}
	}
	reload := New("t")
	if err := reload.loadCacheSigner(dir); err != nil {
		t.Fatal(err)
	}
	if reload.cacheSigner.KID != gen.cacheSigner.KID {
		t.Fatalf("cache signer key id changed: %q vs %q", gen.cacheSigner.KID, reload.cacheSigner.KID)
	}

	// Corrupt private PEM.
	corruptPriv := t.TempDir()
	writeTestFile(t, filepath.Join(corruptPriv, cacheSigningKeyFile), []byte("not a pem"))
	writeTestFile(t, filepath.Join(corruptPriv, cacheSigningPubFile), []byte(pubPEMForTest(t)))
	if err := New("t").loadCacheSigner(corruptPriv); err == nil || !strings.Contains(err.Error(), "cache signing key") {
		t.Fatalf("corrupt private PEM error = %v", err)
	}

	// Corrupt public PEM.
	privPEM, _, _ := testKeyPairPEM(t)
	corruptPub := t.TempDir()
	writeTestFile(t, filepath.Join(corruptPub, cacheSigningKeyFile), privPEM)
	writeTestFile(t, filepath.Join(corruptPub, cacheSigningPubFile), []byte("not a pem"))
	if err := New("t").loadCacheSigner(corruptPub); err == nil || !strings.Contains(err.Error(), "cache signing public key") {
		t.Fatalf("corrupt public PEM error = %v", err)
	}

	// Mismatched pair: private from one key, public from another.
	_, otherPubPEM, _ := testKeyPairPEM(t)
	mismatch := t.TempDir()
	writeTestFile(t, filepath.Join(mismatch, cacheSigningKeyFile), privPEM)
	writeTestFile(t, filepath.Join(mismatch, cacheSigningPubFile), otherPubPEM)
	if err := New("t").loadCacheSigner(mismatch); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched pair error = %v", err)
	}

	// Incomplete pair: only one half present.
	partial := t.TempDir()
	writeTestFile(t, filepath.Join(partial, cacheSigningKeyFile), privPEM)
	if err := New("t").loadCacheSigner(partial); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("incomplete pair error = %v", err)
	}
}

// TestIDCovWebSessionSecretLoadPaths covers loadWebSessionSecret: persisted
// file, env override, invalid file shapes and generation.
func TestIDCovWebSessionSecretLoadPaths(t *testing.T) {
	t.Setenv("KIWI_WEB_SESSION_SECRET", "")

	// Empty data dir: fresh random key, no persistence.
	s := New("t")
	if err := s.loadWebSessionSecret(""); err != nil {
		t.Fatal(err)
	}
	if len(s.WebSessionSecret) != 32 {
		t.Fatalf("generated secret size = %d", len(s.WebSessionSecret))
	}

	// Existing valid file wins.
	dir := t.TempDir()
	want := strings.Repeat("ab", 32)
	writeTestFile(t, filepath.Join(dir, webSessionKeyFile), []byte(want+"\n"))
	s2 := New("t")
	if err := s2.loadWebSessionSecret(dir); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(s2.WebSessionSecret) != want {
		t.Fatalf("persisted secret not loaded: %x", s2.WebSessionSecret)
	}

	// Env override applies when no file exists.
	t.Setenv("KIWI_WEB_SESSION_SECRET", strings.Repeat("cd", 32))
	dir2 := t.TempDir()
	s3 := New("t")
	if err := s3.loadWebSessionSecret(dir2); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(s3.WebSessionSecret) != strings.Repeat("cd", 32) {
		t.Fatalf("env secret not honored: %x", s3.WebSessionSecret)
	}
	t.Setenv("KIWI_WEB_SESSION_SECRET", "")

	// Generation persists a key that a restart reuses.
	dir3 := t.TempDir()
	s4 := New("t")
	if err := s4.loadWebSessionSecret(dir3); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir3, webSessionKeyFile))
	if err != nil {
		t.Fatalf("generated secret not persisted: %v", err)
	}
	if strings.TrimSpace(string(raw)) != hex.EncodeToString(s4.WebSessionSecret) {
		t.Fatal("persisted secret does not match the in-memory secret")
	}

	// Invalid file shapes are refused.
	short := t.TempDir()
	writeTestFile(t, filepath.Join(short, webSessionKeyFile), []byte(strings.Repeat("ab", 31)))
	if err := New("t").loadWebSessionSecret(short); err == nil || !strings.Contains(err.Error(), "invalid size") {
		t.Fatalf("short secret error = %v", err)
	}
	notHex := t.TempDir()
	writeTestFile(t, filepath.Join(notHex, webSessionKeyFile), []byte("zzzz"))
	if err := New("t").loadWebSessionSecret(notHex); err == nil || !strings.Contains(err.Error(), "not hex") {
		t.Fatalf("non-hex secret error = %v", err)
	}
	asDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(asDir, webSessionKeyFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := New("t").loadWebSessionSecret(asDir); err == nil {
		t.Fatal("secret path that is a directory = nil, want error")
	}
}

// TestIDCovPEMParsers covers every parser branch, including non-Ed25519 and
// malformed PEM inputs.
func TestIDCovPEMParsers(t *testing.T) {
	privPEM, pubPEM, priv := testKeyPairPEM(t)
	gotPriv, err := parseEd25519PrivatePEM(privPEM)
	if err != nil || !gotPriv.Equal(priv) {
		t.Fatalf("parseEd25519PrivatePEM roundtrip: %v", err)
	}
	gotPub, err := parseEd25519PublicPEM(pubPEM)
	if err != nil || !gotPub.Equal(priv.Public().(ed25519.PublicKey)) {
		t.Fatalf("parseEd25519PublicPEM roundtrip: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	privCases := []struct {
		name string
		in   []byte
	}{
		{"garbage", []byte("nope")},
		{"wrong-type", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})},
		{"bad-der", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")})},
		{"non-ed25519", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER})},
	}
	for _, tc := range privCases {
		if _, err := parseEd25519PrivatePEM(tc.in); err == nil {
			t.Errorf("parseEd25519PrivatePEM(%s) = nil, want error", tc.name)
		}
	}
	pubCases := []struct {
		name string
		in   []byte
	}{
		{"garbage", []byte("nope")},
		{"wrong-type", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})},
		{"bad-der", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("junk")})},
		{"non-ed25519", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaPubDER})},
	}
	for _, tc := range pubCases {
		if _, err := parseEd25519PublicPEM(tc.in); err == nil {
			t.Errorf("parseEd25519PublicPEM(%s) = nil, want error", tc.name)
		}
	}

	// Encoding helpers round-trip through the parsers.
	encPriv, err := encodeEd25519PrivatePEM(priv)
	if err != nil || encPriv == nil {
		t.Fatalf("encodeEd25519PrivatePEM: %v", err)
	}
	encPub, err := encodeEd25519PublicPEM(priv.Public().(ed25519.PublicKey))
	if err != nil || encPub == nil {
		t.Fatalf("encodeEd25519PublicPEM: %v", err)
	}
	if _, err := parseEd25519PrivatePEM(encPriv); err != nil {
		t.Fatal(err)
	}
	if _, err := parseEd25519PublicPEM(encPub); err != nil {
		t.Fatal(err)
	}
	// The stable key id is derived from the public key hash.
	if kidForPublicKey(gotPub) == "" || kidForPublicKey(gotPub) != kidForPublicKey(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("kidForPublicKey is not stable")
	}
}

// TestIDCovFileHelpers covers writeFileAtomic, marshalJSONFile,
// readFileIfExists, jsonUnmarshal and joinDataDir.
func TestIDCovFileHelpers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "atomic.txt")
	if err := writeFileAtomic(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "data" {
		t.Fatalf("writeFileAtomic did not write: %v %q", err, b)
	}
	if err := writeFileAtomic(filepath.Join(dir, "missing", "x.txt"), []byte("data"), 0o600); err == nil {
		t.Fatal("writeFileAtomic in a missing directory = nil, want error")
	}

	jpath := filepath.Join(dir, "state.json")
	if err := marshalJSONFile(jpath, map[string]string{"a": "b"}); err != nil {
		t.Fatal(err)
	}
	var back map[string]string
	raw, err := os.ReadFile(jpath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &back); err != nil || back["a"] != "b" {
		t.Fatalf("marshalJSONFile roundtrip: %v %v", err, back)
	}
	if err := marshalJSONFile(filepath.Join(dir, "bad.json"), make(chan int)); err == nil {
		t.Fatal("marshalJSONFile(chan) = nil, want error")
	}

	if b, err := readFileIfExists(dir, "atomic.txt"); err != nil || string(b) != "data" {
		t.Fatalf("readFileIfExists present: %v %q", err, b)
	}
	if b, err := readFileIfExists(dir, "nope.txt"); err != nil || b != nil {
		t.Fatalf("readFileIfExists missing = %v %q, want nil,nil", err, b)
	}
	if _, err := readFileIfExists(dir, "."); err == nil {
		t.Fatal("readFileIfExists(directory) = nil, want error")
	}

	var v map[string]int
	if err := jsonUnmarshal([]byte(`{"n":1}`), &v); err != nil || v["n"] != 1 {
		t.Fatalf("jsonUnmarshal: %v %v", err, v)
	}
	if err := jsonUnmarshal([]byte(`{`), &v); err == nil {
		t.Fatal("jsonUnmarshal(bad) = nil, want error")
	}
	if got := joinDataDir(dir, "x.json"); got != filepath.Join(dir, "x.json") {
		t.Fatalf("joinDataDir = %q", got)
	}
}

// TestIDCovLoadLeaseKey covers loadLeaseKey's load, regenerate, corrupt and
// I/O-error branches.
func TestIDCovLoadLeaseKey(t *testing.T) {
	dir := t.TempDir()
	key, err := loadLeaseKey(dir)
	if err != nil || len(key) != 32 {
		t.Fatalf("loadLeaseKey fresh = %v (%d bytes)", err, len(key))
	}
	if b, err := os.ReadFile(filepath.Join(dir, "lease.key")); err != nil || strings.TrimSpace(string(b)) != hex.EncodeToString(key) {
		t.Fatalf("lease key not persisted: %v %q", err, b)
	}
	again, err := loadLeaseKey(dir)
	if err != nil || hex.EncodeToString(again) != hex.EncodeToString(key) {
		t.Fatalf("loadLeaseKey reload = %v", err)
	}

	badHex := t.TempDir()
	writeTestFile(t, filepath.Join(badHex, "lease.key"), []byte("zz"))
	if _, err := loadLeaseKey(badHex); err == nil {
		t.Fatal("loadLeaseKey(non-hex) = nil, want error")
	}
	short := t.TempDir()
	writeTestFile(t, filepath.Join(short, "lease.key"), []byte("abcd"))
	if _, err := loadLeaseKey(short); err == nil || !strings.Contains(err.Error(), "invalid lease key size") {
		t.Fatalf("loadLeaseKey(short) error = %v", err)
	}
	// A file where the directory should be is a read error, not a missing key.
	asFile := filepath.Join(t.TempDir(), "not-a-dir")
	writeTestFile(t, asFile, []byte("x"))
	if _, err := loadLeaseKey(asFile); err == nil {
		t.Fatal("loadLeaseKey(file-as-dir) = nil, want error")
	}
}

// TestIDCovNewPersistentLegacyLoaders drives NewPersistentWithCluster with a
// nil cluster store so every legacy data-dir loader runs, including the
// admin-token fallback.
func TestIDCovNewPersistentLegacyLoaders(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistentWithCluster("runner-tok", "", dir, nil)
	if err != nil {
		t.Fatalf("NewPersistentWithCluster(nil cluster) = %v", err)
	}
	if s.AdminToken != "runner-tok" {
		t.Fatalf("admin token fallback = %q", s.AdminToken)
	}
	if s.oidc == nil || s.provenance == nil || s.cacheSigner == nil || len(s.leaseKey) != 32 || len(s.WebSessionSecret) != 32 {
		t.Fatal("legacy loaders did not initialize all signing roots")
	}
	if s.ClusterKeys != nil {
		t.Fatal("nil cluster store was installed")
	}
	// A restart on the same data dir reuses the same material.
	s2, err := NewPersistentWithCluster("runner-tok", "", dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s2.oidc.KID != s.oidc.KID || s2.cacheSigner.KID != s.cacheSigner.KID ||
		s2.provenance.KID != s.provenance.KID ||
		hex.EncodeToString(s2.leaseKey) != hex.EncodeToString(s.leaseKey) ||
		hex.EncodeToString(s2.WebSessionSecret) != hex.EncodeToString(s.WebSessionSecret) {
		t.Fatal("legacy loaders rotated key material across restart")
	}

	// A corrupt OIDC ring aborts construction.
	badDir := t.TempDir()
	writeTestFile(t, filepath.Join(badDir, oidcKeyRingFile), []byte("{"))
	if _, err := NewPersistentWithCluster("t", "t", badDir, nil); err == nil {
		t.Fatal("corrupt OIDC ring = nil error")
	}
	// A corrupt cache-signing private key aborts construction.
	badDir2 := t.TempDir()
	writeTestFile(t, filepath.Join(badDir2, cacheSigningKeyFile), []byte("junk"))
	writeTestFile(t, filepath.Join(badDir2, cacheSigningPubFile), []byte("junk"))
	if _, err := NewPersistentWithCluster("t", "t", badDir2, nil); err == nil {
		t.Fatal("corrupt cache signing key = nil error")
	}
	// A directory that cannot be used as a data dir aborts construction.
	asFile := filepath.Join(t.TempDir(), "file")
	writeTestFile(t, asFile, []byte("x"))
	if _, err := NewPersistentWithCluster("t", "t", asFile, nil); err == nil {
		t.Fatal("file as data dir = nil error")
	}
}

// writeTestFile writes a test fixture file, failing the test on error.
func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// testKeyPairPEM returns a fresh Ed25519 key pair in PKCS8/PKIX PEM form.
func testKeyPairPEM(t *testing.T) (privPEM, pubPEM []byte, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err = encodeEd25519PrivatePEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err = encodeEd25519PublicPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	return privPEM, pubPEM, priv
}

func pubPEMForTest(t *testing.T) []byte {
	t.Helper()
	_, pubPEM, _ := testKeyPairPEM(t)
	return pubPEM
}
