package provenance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func provKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func extendedStatement() Statement {
	start := time.Unix(100, 0).UTC()
	end := time.Unix(200, 0).UTC()
	return Statement{
		Type: StatementType,
		Subject: []Subject{{
			Name:   "app.tar.gz",
			Digest: map[string]string{"sha256": strings.Repeat("c", 64)},
		}},
		PredicateType: PredicateType,
		Predicate: Predicate{
			BuildDefinition: BuildDefinition{
				BuildType: "https://kiwi-ci.dev/build/v1",
				ExternalParameters: map[string]any{
					"repository": "example/repo", "ref": "main", "commit": "abc123", "job": "build", "trusted": true,
				},
			},
			RunDetails: RunDetails{
				Builder:  Builder{ID: "https://kiwi-ci.dev/runner/runner-7"},
				Metadata: Metadata{InvocationID: "run1/job1"},
			},
		},
		ResolvedPipelineSHA256: strings.Repeat("a", 64),
		PipelineDigest:         strings.Repeat("b", 64),
		Builder:                "kiwi-ci@0.1.0",
		CompilerVersion:        "go1.23",
		RunnerIdentity:         "runner-7",
		Runtime:                "container",
		ImageDigest:            "sha256:" + strings.Repeat("d", 64),
		Issuer:                 "https://issuer.example",
		Materials:              []MaterialEntry{{Path: "pipeline.yaml", SHA256: strings.Repeat("e", 64)}},
		EffectivePolicyDigest:  strings.Repeat("f", 64),
		StartTime:              &start,
		EndTime:                &end,
		ArtifactSize:           999,
	}
}

func TestExtendedFieldsRoundTrip(t *testing.T) {
	pub, priv := provKey(t)
	st := extendedStatement()
	env, err := Sign(st, "kid", priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyWith(raw, nil, VerifyOptions{
		TrustedKey: pub,
		Repository: "example/repo", Commit: "abc123", Ref: "main", Job: "build",
		Builder: "https://kiwi-ci.dev/runner/runner-7", Issuer: "https://issuer.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ResolvedPipelineSHA256 != st.ResolvedPipelineSHA256 || got.PipelineDigest != st.PipelineDigest {
		t.Fatalf("pipeline digests lost: %+v", got)
	}
	if got.Builder != "kiwi-ci@0.1.0" || got.CompilerVersion != "go1.23" || got.RunnerIdentity != "runner-7" {
		t.Fatalf("extended identity fields lost: %+v", got)
	}
	if got.Runtime != "container" || got.ImageDigest != st.ImageDigest || got.Issuer != "https://issuer.example" {
		t.Fatalf("extended runtime fields lost: %+v", got)
	}
	if len(got.Materials) != 1 || got.Materials[0] != st.Materials[0] {
		t.Fatalf("materials lost: %+v", got.Materials)
	}
	if got.EffectivePolicyDigest != st.EffectivePolicyDigest || got.ArtifactSize != 999 {
		t.Fatalf("policy digest or size lost: %+v", got)
	}
	if got.StartTime == nil || !got.StartTime.Equal(*st.StartTime) || got.EndTime == nil || !got.EndTime.Equal(*st.EndTime) {
		t.Fatalf("timestamps lost: %+v", got)
	}
}

func TestSignWithBuilderOption(t *testing.T) {
	_, priv := provKey(t)
	env, err := SignWith(Statement{Type: StatementType, PredicateType: PredicateType}, "kid", priv, SignOptions{Builder: BuilderPlaceholder})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var st Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		t.Fatal(err)
	}
	if st.Builder != BuilderPlaceholder {
		t.Fatalf("builder not applied: %q", st.Builder)
	}
}

// TestArtifactStatementBuilderOverride proves the additive ArtifactInput
// Builder option populates the standard SLSA predicate builder identity,
// while an empty option keeps the runner-derived default.
func TestArtifactStatementBuilderOverride(t *testing.T) {
	const want = "https://kiwi-ci.dev/builders/release-tool@1.2.3"
	st := ArtifactStatement(ArtifactInput{Name: "app", SHA256: strings.Repeat("c", 64), Builder: want})
	if got := st.Predicate.RunDetails.Builder.ID; got != want {
		t.Fatalf("predicate builder = %q, want %q", got, want)
	}
	if st.Builder != "" {
		t.Fatalf("builder override must not set the top-level extension: %q", st.Builder)
	}
	def := ArtifactStatement(ArtifactInput{Name: "app", SHA256: strings.Repeat("c", 64), Runner: "runner-7"})
	if got := def.Predicate.RunDetails.Builder.ID; got != "https://kiwi-ci.dev/runner/runner-7" {
		t.Fatalf("default predicate builder = %q", got)
	}
}

// TestVerifyWithConstrainedBuilder proves a caller-supplied builder
// expectation accepts the recorded builder and rejects any other.
func TestVerifyWithConstrainedBuilder(t *testing.T) {
	pub, priv := provKey(t)
	const builder = "https://kiwi-ci.dev/builders/release-tool@1.2.3"
	env, err := Sign(ArtifactStatement(ArtifactInput{
		Name: "app", SHA256: strings.Repeat("c", 64),
		Repository: "example/repo", Ref: "refs/tags/v1.2.3", Commit: strings.Repeat("a", 40),
		JobKey: "release", Builder: builder,
	}), "kidA", priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWith(raw, nil, VerifyOptions{TrustedKey: pub, Repository: "example/repo", Builder: builder}); err != nil {
		t.Fatalf("matching builder constraint must verify: %v", err)
	}
	if _, err := VerifyWith(raw, nil, VerifyOptions{TrustedKey: pub, Builder: "https://kiwi-ci.dev/builders/release-tool@9.9.9"}); err == nil {
		t.Fatal("wrong expected builder must fail verification")
	}
}

func TestLoadOrCreateProvenanceKeyReusesKey(t *testing.T) {
	dir := t.TempDir()
	pub1, priv1, err := LoadOrCreateProvenanceKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := LoadOrCreateProvenanceKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub1, pub2) || !bytes.Equal(priv1, priv2) {
		t.Fatal("key pair must be stable across loads")
	}
	if _, err := os.Stat(filepath.Join(dir, provenanceKeyFile)); err != nil {
		t.Fatalf("missing %s: %v", provenanceKeyFile, err)
	}
	if _, err := os.Stat(filepath.Join(dir, provenancePubFile)); err != nil {
		t.Fatalf("missing %s: %v", provenancePubFile, err)
	}
}

func TestLoadOrCreateProvenanceKeyFreshDirsDistinct(t *testing.T) {
	pub1, _, err := LoadOrCreateProvenanceKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := LoadOrCreateProvenanceKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pub1, pub2) {
		t.Fatal("fresh directories must yield distinct keys")
	}
}

func TestLoadOrCreateProvenanceKeyCorruptFileRejected(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := LoadOrCreateProvenanceKey(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, provenanceKeyFile), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateProvenanceKey(dir); err == nil {
		t.Fatal("corrupt key file must not be silently regenerated")
	}
}

func TestVerifyWithPinnedKeyIgnoresRemote(t *testing.T) {
	pubA, privA := provKey(t)
	wrongPub, _ := provKey(t)
	remoteCalled := false
	jwks := func(kid string) (ed25519.PublicKey, bool) {
		remoteCalled = true
		return wrongPub, true
	}
	env, err := Sign(ArtifactStatement(ArtifactInput{Name: "app", SHA256: strings.Repeat("c", 64), Repository: "example/repo", Ref: "main", Commit: "abc123", JobKey: "build"}), "kidA", privA)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWith(raw, jwks, VerifyOptions{TrustedKey: pubA}); err != nil {
		t.Fatalf("pinned key must verify: %v", err)
	}
	if remoteCalled {
		t.Fatal("pinned verification must not consult the key resolver")
	}
}

func TestVerifyWithWrongPinRejects(t *testing.T) {
	pubA, privA := provKey(t)
	wrongPub, _ := provKey(t)
	jwks := func(kid string) (ed25519.PublicKey, bool) {
		return pubA, true
	}
	env, err := Sign(ArtifactStatement(ArtifactInput{Name: "app", SHA256: strings.Repeat("c", 64)}), "kidA", privA)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWith(raw, jwks, VerifyOptions{TrustedKey: wrongPub}); err == nil {
		t.Fatal("a mismatched pin must reject even when the remote key would verify")
	}
}

func TestVerifyWithRemoteKeyResolution(t *testing.T) {
	pubA, privA := provKey(t)
	jwks := func(kid string) (ed25519.PublicKey, bool) {
		if kid == "kidA" {
			return pubA, true
		}
		return nil, false
	}
	env, err := Sign(ArtifactStatement(ArtifactInput{Name: "app", SHA256: strings.Repeat("c", 64)}), "kidA", privA)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWith(raw, jwks, VerifyOptions{}); err != nil {
		t.Fatalf("remote key must verify: %v", err)
	}
	env2, err := Sign(ArtifactStatement(ArtifactInput{Name: "app", SHA256: strings.Repeat("c", 64)}), "kidB", privA)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := json.Marshal(env2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWith(raw2, jwks, VerifyOptions{}); err == nil {
		t.Fatal("unknown key id must be rejected")
	}
}

func TestVerifyWithConstraintMismatch(t *testing.T) {
	pubA, privA := provKey(t)
	jwks := func(kid string) (ed25519.PublicKey, bool) {
		return pubA, true
	}
	env, err := Sign(ArtifactStatement(ArtifactInput{Name: "app", SHA256: strings.Repeat("c", 64), Repository: "example/repo", Commit: "abc123", Ref: "main", JobKey: "build"}), "kidA", privA)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	for label, opts := range map[string]VerifyOptions{
		"repository": {Repository: "other/repo"},
		"commit":     {Commit: "ffff"},
		"ref":        {Ref: "dev"},
		"job":        {Job: "test"},
		"issuer":     {Issuer: "https://other"},
	} {
		if _, err := VerifyWith(raw, jwks, opts); err == nil {
			t.Fatalf("%s constraint mismatch must be rejected", label)
		}
	}
}
