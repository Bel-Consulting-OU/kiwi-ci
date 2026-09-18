package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/version"
)

const testContent = "kiwi release test binary"

// stubModuleGraph makes run()/runCLI() hermetic: the fake test binary carries
// no embedded build info, so the module graph is supplied as fixture data.
func stubModuleGraph(t *testing.T) {
	t.Helper()
	orig := readModuleGraph
	readModuleGraph = func(string) (moduleGraph, error) { return fixtureGraph(), nil }
	t.Cleanup(func() { readModuleGraph = orig })
}

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
	b, err := emitSBOM(testInput(t, binary), "kiwi-test-binary", sum, fixtureGraph())
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
	metadata, ok := doc["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected metadata %v", doc["metadata"])
	}
	root, ok := metadata["component"].(map[string]any)
	if !ok || root["name"] != "kiwi" || root["version"] != "1.2.3" {
		t.Fatalf("unexpected root component %v", metadata["component"])
	}
	components, ok := doc["components"].([]any)
	if !ok || len(components) != 4 {
		t.Fatalf("unexpected components %v", doc["components"])
	}
	names := map[string]bool{}
	var fileComponent map[string]any
	for _, c := range components {
		component := c.(map[string]any)
		names[component["name"].(string)] = true
		if component["name"] == "kiwi-test-binary" {
			fileComponent = component
		}
	}
	for _, want := range []string{"github.com/jackc/pgx/v5", "github.com/jackc/pgpassfile", "github.com/example/new", "kiwi-test-binary"} {
		if !names[want] {
			t.Fatalf("component %q missing from %v", want, names)
		}
	}
	if fileComponent["type"] != "file" {
		t.Fatalf("artifact component = %v", fileComponent)
	}
	hashes, ok := fileComponent["hashes"].([]any)
	if !ok || len(hashes) != 1 {
		t.Fatalf("artifact hashes = %v", fileComponent["hashes"])
	}
	if h := hashes[0].(map[string]any); h["alg"] != "SHA-256" || h["content"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("artifact hash = %v, want %s", h, hex.EncodeToString(sum[:]))
	}
	deps, ok := doc["dependencies"].([]any)
	if !ok || len(deps) != 1 {
		t.Fatalf("unexpected dependencies %v", doc["dependencies"])
	}
	rootDep := deps[0].(map[string]any)
	if rootDep["ref"] != root["bom-ref"] {
		t.Fatalf("dependency root ref = %v, want %v", rootDep["ref"], root["bom-ref"])
	}
	if dependsOn, ok := rootDep["dependsOn"].([]any); !ok || len(dependsOn) != 3 {
		t.Fatalf("root dependsOn = %v, want all 3 modules", rootDep["dependsOn"])
	}
}

func TestEmitSBOMRootName(t *testing.T) {
	binary := writeTempBinary(t)
	sum := sha256.Sum256([]byte(testContent))
	const wantBOMRef = "pkg:golang/github.com/Bel-Consulting-OU/kiwi-ci@1.2.3"
	for _, tt := range []struct {
		label string
		name  string
		want  string
	}{
		{"default", "", "github.com/Bel-Consulting-OU/kiwi-ci"},
		{"override", "kiwi-darwin-arm64", "kiwi-darwin-arm64"},
	} {
		t.Run(tt.label, func(t *testing.T) {
			in := testInput(t, binary)
			in.Name = tt.name
			b, err := emitSBOM(in, "kiwi-test-binary", sum, fixtureGraph())
			if err != nil {
				t.Fatal(err)
			}
			var doc cdxDocument
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			if doc.Metadata.Component == nil || doc.Metadata.Component.Name != tt.want {
				t.Fatalf("-name %q: root component = %+v, want name %q", tt.name, doc.Metadata.Component, tt.want)
			}
			if doc.Metadata.Component.BOMRef != wantBOMRef {
				t.Fatalf("-name %q: root bom-ref = %q, want %q", tt.name, doc.Metadata.Component.BOMRef, wantBOMRef)
			}
		})
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
	if st.Builder != releaseToolBuilderPrefix+version.Version {
		t.Fatalf("builder extension = %q, want %q", st.Builder, releaseToolBuilderPrefix+version.Version)
	}
	if got := st.Predicate.RunDetails.Builder.ID; got != releaseToolBuilderPrefix+version.Version {
		t.Fatalf("predicate builder = %q, want %q", got, releaseToolBuilderPrefix+version.Version)
	}
	if env.Signatures[0].KeyID != keyID {
		t.Fatalf("signature keyid = %q, want %q", env.Signatures[0].KeyID, keyID)
	}
	if _, err := provenance.VerifyWith(envBytes, nil, provenance.VerifyOptions{
		TrustedKey: pub, Builder: releaseToolBuilderPrefix + version.Version,
	}); err != nil {
		t.Fatalf("constrained builder verification failed: %v", err)
	}
	if _, err := provenance.VerifyWith(envBytes, nil, provenance.VerifyOptions{
		TrustedKey: pub, Builder: releaseToolBuilderPrefix + "9.9.9",
	}); err == nil {
		t.Fatal("wrong expected builder must fail verification")
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
	stubModuleGraph(t)
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
	stubModuleGraph(t)
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

func TestRunCLIExitCodes(t *testing.T) {
	stubModuleGraph(t)
	binary := writeTempBinary(t)

	if code := runCLI([]string{"--no-such-flag"}); code != 2 {
		t.Fatalf("bad flag exit = %d, want 2", code)
	}
	if code := runCLI([]string{"--help"}); code != 0 {
		t.Fatalf("help exit = %d, want 0", code)
	}
	if code := runCLI(nil); code != 2 {
		t.Fatalf("missing -binary exit = %d, want 2", code)
	}
	if code := runCLI([]string{"-binary", binary, "extra"}); code != 2 {
		t.Fatalf("positional arg exit = %d, want 2", code)
	}
	if code := runCLI([]string{"-binary", binary, "-out", t.TempDir()}); code != 0 {
		t.Fatalf("success exit = %d, want 0", code)
	}
	if code := runCLI([]string{"-binary", filepath.Join(t.TempDir(), "missing"), "-out", t.TempDir()}); code != 1 {
		t.Fatalf("missing binary exit = %d, want 1", code)
	}
}

func TestParseFlags(t *testing.T) {
	in, err := parseFlags([]string{
		"-binary", "/tmp/kiwi", "-name", "kiwi-darwin", "-version", "9.9.9",
		"-commit", "cafe", "-repo", "https://example.test/repo", "-ref", "refs/tags/v9.9.9",
		"-out", "/tmp/out", "-key", "/tmp/key.pem", "-builder", "https://kiwi-ci.dev/builders/release-tool@9.9.9",
	})
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	want := releaseInput{
		Binary: "/tmp/kiwi", Name: "kiwi-darwin", Version: "9.9.9", Commit: "cafe",
		Repo: "https://example.test/repo", Ref: "refs/tags/v9.9.9", OutDir: "/tmp/out", KeyFile: "/tmp/key.pem",
		Builder: "https://kiwi-ci.dev/builders/release-tool@9.9.9",
	}
	if in != want {
		t.Fatalf("parseFlags = %+v, want %+v", in, want)
	}
	if got := in.builderID(); got != want.Builder {
		t.Fatalf("builderID override = %q, want %q", got, want.Builder)
	}

	in, err = parseFlags([]string{"-binary", "/tmp/kiwi"})
	if err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if in.Name != "" || in.OutDir != "." || in.KeyFile != "" {
		t.Fatalf("defaults = %+v", in)
	}
	if got, want := in.builderID(), releaseToolBuilderPrefix+version.Version; got != want {
		t.Fatalf("default builderID = %q, want %q", got, want)
	}

	for _, args := range [][]string{
		{"-no-such-flag"},
		{"-binary", "/tmp/kiwi", "stray"},
		{},
	} {
		if _, err := parseFlags(args); err == nil {
			t.Fatalf("parseFlags(%v) = nil error, want failure", args)
		}
	}
}

func TestRunFailureBranches(t *testing.T) {
	stubModuleGraph(t)
	binary := writeTempBinary(t)

	in := testInput(t, filepath.Join(t.TempDir(), "missing-binary"))
	if err := run(in); err == nil {
		t.Fatal("run with missing binary must fail")
	}

	in = testInput(t, binary)
	in.OutDir = filepath.Join(t.TempDir(), "no-such-dir")
	if err := run(in); err == nil {
		t.Fatal("run with missing output directory must fail")
	}

	in = testInput(t, binary)
	in.KeyFile = filepath.Join(t.TempDir(), "missing.key")
	if err := run(in); err == nil {
		t.Fatal("run with missing signing key must fail")
	}

	in = testInput(t, binary)
	outAsFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(outAsFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	in.OutDir = outAsFile
	if err := run(in); err == nil {
		t.Fatal("run with a file as output directory must fail")
	}
}

func TestRunProvenanceWriteFailure(t *testing.T) {
	stubModuleGraph(t)
	binary := writeTempBinary(t)
	keyPath, _, _ := writeTempKey(t)
	in := testInput(t, binary)
	in.KeyFile = keyPath
	base := filepath.Base(in.Binary)
	if err := os.MkdirAll(filepath.Join(in.OutDir, base+".provenance.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := run(in)
	if err == nil {
		t.Fatal("run must fail when the provenance path is a directory")
	}
	if !strings.Contains(err.Error(), "provenance.json") {
		t.Fatalf("error = %v, want provenance path failure", err)
	}
	if _, serr := os.Stat(filepath.Join(in.OutDir, base+".sbom.cdx.json")); serr != nil {
		t.Fatalf("sbom should have been written before the provenance failure: %v", serr)
	}
}

func TestLoadSigningKeyRejectsMalformedPKCS8(t *testing.T) {
	dir := t.TempDir()

	badDER := filepath.Join(dir, "bad-der.pem")
	if err := os.WriteFile(badDER, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not der")}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadSigningKey(badDER); err == nil {
		t.Fatal("malformed PKCS#8 body must error")
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongType := filepath.Join(dir, "rsa.pem")
	if err := os.WriteFile(wrongType, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadSigningKey(wrongType); err == nil {
		t.Fatal("a non-Ed25519 PKCS#8 key must error")
	}
}
