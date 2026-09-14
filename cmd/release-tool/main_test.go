package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
)

const testContent = "kiwi release test binary"

func writeTempBinary(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kiwi-test-binary")
	if err := os.WriteFile(path, []byte(testContent), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTempKey(t *testing.T) (string, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := provenance.NewProvenanceKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "release.key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return keyPath, priv, pub
}

func testInput(t *testing.T, binary string) releaseInput {
	return releaseInput{
		Binary:  binary,
		Name:    "kiwi",
		Version: "1.2.3",
		Commit:  "deadbeef",
		Repo:    "https://github.com/Bel-Consulting-OU/kiwi-ci",
		Ref:     "refs/tags/v1.2.3",
		OutDir:  t.TempDir(),
	}
}

func TestEmitSBOM(t *testing.T) {
	binary := writeTempBinary(t)
	sum := sha256.Sum256([]byte(testContent))
	b, err := emitSBOM(testInput(t, binary), "kiwi-test-binary", sum, int64(len(testContent)))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["bomFormat"] != "CycloneDX" || doc["specVersion"] != "1.5" {
		t.Fatalf("unexpected bom format/version: %v %v", doc["bomFormat"], doc["specVersion"])
	}
	components, ok := doc["components"].([]any)
	if !ok || len(components) != 1 {
		t.Fatalf("unexpected components %v", doc["components"])
	}
	c := components[0].(map[string]any)
	if c["type"] != "file" || c["name"] != "kiwi-test-binary" {
		t.Fatalf("unexpected component %v", c)
	}
	hashes, ok := c["hashes"].([]any)
	if !ok || len(hashes) != 1 {
		t.Fatalf("unexpected hashes %v", c["hashes"])
	}
	h := hashes[0].(map[string]any)
	if h["alg"] != "SHA-256" || h["content"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("unexpected hash %v", h)
	}
}

func TestEmitProvenanceVerifies(t *testing.T) {
	binary := writeTempBinary(t)
	sum := sha256.Sum256([]byte(testContent))
	keyPath, priv, pub := writeTempKey(t)
	loaded, keyID, err := loadSigningKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Equal(loaded) {
		t.Fatal("loaded key differs from generated key")
	}
	wantKeyID := hex.EncodeToString(func() []byte {
		s := sha256.Sum256(pub)
		return s[:8]
	}())
	if keyID != wantKeyID {
		t.Fatalf("keyID = %q, want %q", keyID, wantKeyID)
	}

	envBytes, err := emitProvenance(testInput(t, binary), "kiwi-test-binary", sum, priv, keyID)
	if err != nil {
		t.Fatal(err)
	}
	var env provenance.Envelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		t.Fatal(err)
	}
	if err := provenance.Verify(env, pub); err != nil {
		t.Fatalf("provenance envelope does not verify: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var st provenance.Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		t.Fatal(err)
	}
	if st.PredicateType != provenance.PredicateType {
		t.Fatalf("predicate type = %q, want %q", st.PredicateType, provenance.PredicateType)
	}
	if got := st.Subject[0].Digest["sha256"]; got != hex.EncodeToString(sum[:]) {
		t.Fatalf("subject digest = %q, want %q", got, hex.EncodeToString(sum[:]))
	}
	ep := st.Predicate.BuildDefinition.ExternalParameters
	if ep["repository"] != "https://github.com/Bel-Consulting-OU/kiwi-ci" ||
		ep["ref"] != "refs/tags/v1.2.3" || ep["commit"] != "deadbeef" {
		t.Fatalf("unexpected external parameters %v", ep)
	}
	if st.Builder != "kiwi-ci@1.2.3" {
		t.Fatalf("builder = %q, want %q", st.Builder, "kiwi-ci@1.2.3")
	}
	if env.Signatures[0].KeyID != keyID {
		t.Fatalf("signature keyid = %q, want %q", env.Signatures[0].KeyID, keyID)
	}

	otherPub, _, err := provenance.NewProvenanceKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := provenance.Verify(env, otherPub); err == nil {
		t.Fatal("envelope must not verify against a different key")
	}
}

func TestRunWritesSBOMAndProvenance(t *testing.T) {
	binary := writeTempBinary(t)
	keyPath, _, pub := writeTempKey(t)
	in := testInput(t, binary)
	in.KeyFile = keyPath
	if err := run(in); err != nil {
		t.Fatal(err)
	}
	sbomPath := filepath.Join(in.OutDir, "kiwi-test-binary.sbom.cdx.json")
	envPath := filepath.Join(in.OutDir, "kiwi-test-binary.provenance.json")
	for _, p := range []string{sbomPath, envPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s to exist: %v", p, err)
		}
	}
	envBytes, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	var env provenance.Envelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		t.Fatal(err)
	}
	if err := provenance.Verify(env, pub); err != nil {
		t.Fatalf("written envelope does not verify: %v", err)
	}
}

func TestRunWithoutKeySkipsProvenance(t *testing.T) {
	binary := writeTempBinary(t)
	in := testInput(t, binary)
	if err := run(in); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(in.OutDir, "kiwi-test-binary.sbom.cdx.json")); err != nil {
		t.Fatalf("expected sbom to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(in.OutDir, "kiwi-test-binary.provenance.json")); err == nil {
		t.Fatal("provenance must not exist without a signing key")
	}
}

func TestLoadSigningKeyRejectsInvalid(t *testing.T) {
	dir := t.TempDir()

	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadSigningKey(garbage); err == nil {
		t.Fatal("garbage key file must error")
	}

	pub, _, err := provenance.NewProvenanceKey()
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	wrongBlock := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(wrongBlock, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadSigningKey(wrongBlock); err == nil {
		t.Fatal("public-key PEM must error as a signing key")
	}

	missing := filepath.Join(dir, "missing.pem")
	if _, _, err := loadSigningKey(missing); err == nil {
		t.Fatal("missing key file must error")
	}
}
