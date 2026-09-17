package provenance

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

// signedEnvelope signs an arbitrary payload with priv so tests can reach the
// post-signature decode stages of VerifyWith.
func signedEnvelope(payload []byte, kid string, priv ed25519.PrivateKey) Envelope {
	return Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{{KeyID: kid, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, dssePAE(PayloadType, payload)))}},
	}
}

// TestSignVerifyRoundTrip proves the simple Verify accepts a genuine
// envelope and rejects every malformed shape.
func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := provKey(t)
	st := ArtifactStatement(ArtifactInput{Name: "app", SHA256: strings.Repeat("a", 64)})
	env, err := Sign(st, "kid", priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(env, pub); err != nil {
		t.Fatalf("Verify genuine envelope: %v", err)
	}

	// Wrong payload type.
	bad := env
	bad.PayloadType = "text/plain"
	if err := Verify(bad, pub); err == nil {
		t.Fatal("wrong payload type must fail")
	}

	// Undecodable payload.
	bad = env
	bad.Payload = "!!!"
	if err := Verify(bad, pub); err == nil {
		t.Fatal("undecodable payload must fail")
	}

	// Missing signatures.
	bad = env
	bad.Signatures = nil
	if err := Verify(bad, pub); err == nil {
		t.Fatal("missing signature must fail")
	}

	// Undecodable signature.
	bad = env
	bad.Signatures = []Signature{{KeyID: "kid", Sig: "!!!"}}
	if err := Verify(bad, pub); err == nil {
		t.Fatal("undecodable signature must fail")
	}

	// Tampered payload with a valid signature.
	tampered, err := Sign(st, "kid", priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(tampered.Payload)
	if err != nil {
		t.Fatal(err)
	}
	tampered.Payload = base64.StdEncoding.EncodeToString(append(raw, ' '))
	if err := Verify(tampered, pub); err == nil {
		t.Fatal("tampered payload must fail")
	}

	// Wrong key.
	other, _ := provKey(t)
	if err := Verify(env, other); err == nil {
		t.Fatal("wrong key must fail")
	}
}

// TestSignWithMarshalError proves a statement that cannot be serialized is
// rejected at signing time.
func TestSignWithMarshalError(t *testing.T) {
	_, priv := provKey(t)
	st := ArtifactStatement(ArtifactInput{Name: "app"})
	st.Predicate.BuildDefinition.ExternalParameters = map[string]any{"bad": make(chan int)}
	if _, err := SignWith(st, "kid", priv, SignOptions{}); err == nil {
		t.Fatal("unserializable statement must fail")
	}
}

// TestVerifyWithDecodeErrors proves VerifyWith rejects undecodable
// envelopes, payloads, and signatures before touching any key material.
func TestVerifyWithDecodeErrors(t *testing.T) {
	_, priv := provKey(t)
	_, opts := verifyOpts(t, priv)

	// Undecodable envelope JSON.
	if _, err := VerifyWith([]byte("{"), nil, opts); err == nil {
		t.Fatal("invalid envelope JSON must fail")
	}

	// Undecodable payload base64.
	env := Envelope{PayloadType: PayloadType, Payload: "!!!", Signatures: []Signature{{Sig: "AA=="}}}
	raw, _ := json.Marshal(env)
	if _, err := VerifyWith(raw, nil, opts); err == nil {
		t.Fatal("undecodable payload must fail")
	}

	// Undecodable signature base64.
	env = Envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString([]byte("{}")), Signatures: []Signature{{Sig: "!!!"}}}
	raw, _ = json.Marshal(env)
	if _, err := VerifyWith(raw, nil, opts); err == nil {
		t.Fatal("undecodable signature must fail")
	}
}

// verifyOpts returns a resolver and options pinned to the supplied key.
func verifyOpts(t *testing.T, priv ed25519.PrivateKey) (func(string) (ed25519.PublicKey, bool), VerifyOptions) {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	resolver := func(string) (ed25519.PublicKey, bool) { return pub, true }
	return resolver, VerifyOptions{TrustedKey: pub}
}

// TestVerifyWithUnresolvedKey proves the missing-resolver and unknown-key
// branches and that the statement decode/type checks run only after a valid
// signature.
func TestVerifyWithUnresolvedKey(t *testing.T) {
	_, priv := provKey(t)
	st := ArtifactStatement(ArtifactInput{Name: "app", SHA256: strings.Repeat("a", 64)})
	env, err := Sign(st, "kid", priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	// No pinned key and no resolver.
	if _, err := VerifyWith(raw, nil, VerifyOptions{}); err == nil {
		t.Fatal("no key and no resolver must fail")
	}
	// Resolver does not know the key id.
	unknown := func(string) (ed25519.PublicKey, bool) { return nil, false }
	if _, err := VerifyWith(raw, unknown, VerifyOptions{}); err == nil {
		t.Fatal("unknown key id must fail")
	}
	// Resolver hit: verification succeeds.
	resolver, _ := verifyOpts(t, priv)
	if _, err := VerifyWith(raw, resolver, VerifyOptions{}); err != nil {
		t.Fatalf("resolver hit: %v", err)
	}
}

// TestVerifyWithStatementErrors proves the payload-level checks: payload
// that is validly signed but not valid JSON, and a statement of the wrong
// type.
func TestVerifyWithStatementErrors(t *testing.T) {
	pub, priv := provKey(t)

	// Correctly signed non-JSON payload.
	env := signedEnvelope([]byte("this is not json"), "kid", priv)
	raw, _ := json.Marshal(env)
	if _, err := VerifyWith(raw, nil, VerifyOptions{TrustedKey: pub}); err == nil {
		t.Fatal("non-JSON statement payload must fail")
	}

	// Correctly signed statement of the wrong type.
	wrongType := Statement{Type: "https://example.com/other"}
	body, _ := json.Marshal(wrongType)
	env = signedEnvelope(body, "kid", priv)
	raw, _ = json.Marshal(env)
	if _, err := VerifyWith(raw, nil, VerifyOptions{TrustedKey: pub}); err == nil {
		t.Fatal("wrong statement type must fail")
	}
}

// TestNewProvenanceKeyEntropyFailure proves key generation surfaces entropy
// failures.
func TestNewProvenanceKeyEntropyFailure(t *testing.T) {
	orig := randReader
	randReader = failingReader{}
	defer func() { randReader = orig }()
	if _, _, err := NewProvenanceKey(); err == nil {
		t.Fatal("entropy failure must surface")
	}
}

// writeFile writes b at path, creating the directory as needed.
func writeFile(t *testing.T, path string, b []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, mode); err != nil {
		t.Fatal(err)
	}
}

func keyPEMs(t *testing.T) (keyPEM, pubPEM []byte) {
	t.Helper()
	pub, priv := provKey(t)
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
}

// TestLoadOrCreateProvenanceKeyPairErrors proves a mismatched, incomplete, or
// corrupt stored pair is rejected rather than silently replaced.
func TestLoadOrCreateProvenanceKeyPairErrors(t *testing.T) {
	dir := t.TempDir()
	keyPEM, pubPEM := keyPEMs(t)

	// Mismatched pair: the public key belongs to another private key.
	otherPub, _ := provKey(t)
	otherPubDER, err := x509.MarshalPKIXPublicKey(otherPub)
	if err != nil {
		t.Fatal(err)
	}
	otherPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: otherPubDER})
	writeFile(t, filepath.Join(dir, provenanceKeyFile), keyPEM, 0o600)
	writeFile(t, filepath.Join(dir, provenancePubFile), otherPubPEM, 0o644)
	if _, _, err := LoadOrCreateProvenanceKey(dir); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched pair = %v, want mismatch error", err)
	}

	// Corrupt public key next to a valid private key.
	dir2 := t.TempDir()
	writeFile(t, filepath.Join(dir2, provenanceKeyFile), keyPEM, 0o600)
	writeFile(t, filepath.Join(dir2, provenancePubFile), []byte("not pem"), 0o644)
	if _, _, err := LoadOrCreateProvenanceKey(dir2); err == nil {
		t.Fatal("corrupt public key must fail")
	}

	// Corrupt private key next to a valid public key.
	dir3 := t.TempDir()
	writeFile(t, filepath.Join(dir3, provenanceKeyFile), []byte("not pem"), 0o600)
	writeFile(t, filepath.Join(dir3, provenancePubFile), pubPEM, 0o644)
	if _, _, err := LoadOrCreateProvenanceKey(dir3); err == nil {
		t.Fatal("corrupt private key must fail")
	}

	// Incomplete pair: only the private key exists.
	dir4 := t.TempDir()
	writeFile(t, filepath.Join(dir4, provenanceKeyFile), keyPEM, 0o600)
	if _, _, err := LoadOrCreateProvenanceKey(dir4); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("only private key = %v, want incomplete error", err)
	}

	// Incomplete pair: only the public key exists.
	dir5 := t.TempDir()
	writeFile(t, filepath.Join(dir5, provenancePubFile), pubPEM, 0o644)
	if _, _, err := LoadOrCreateProvenanceKey(dir5); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("only public key = %v, want incomplete error", err)
	}
}

// TestLoadOrCreateProvenanceKeyWriteErrors proves generation failures are
// surfaced: an uncreatable directory, an occupied private-key path, an
// occupied public-key path, and entropy failure.
func TestLoadOrCreateProvenanceKeyWriteErrors(t *testing.T) {
	// Uncreatable directory.
	blocker := filepath.Join(t.TempDir(), "file")
	writeFile(t, blocker, []byte("x"), 0o600)
	if _, _, err := LoadOrCreateProvenanceKey(filepath.Join(blocker, "keys")); err == nil {
		t.Fatal("keys directory under a regular file must fail")
	}

	// Private-key path occupied by a directory.
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, provenanceKeyFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateProvenanceKey(dir); err == nil {
		t.Fatal("private key path occupied by a directory must fail")
	}

	// Public-key path occupied by a directory.
	dir2 := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir2, provenancePubFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateProvenanceKey(dir2); err == nil {
		t.Fatal("public key path occupied by a directory must fail")
	}

	// Entropy failure during generation.
	orig := randReader
	randReader = failingReader{}
	defer func() { randReader = orig }()
	if _, _, err := LoadOrCreateProvenanceKey(t.TempDir()); err == nil {
		t.Fatal("entropy failure must surface")
	}
}

// TestParseProvenanceKeyErrors proves the private/public key parsers reject
// non-PEM input, wrong PEM types, non-PKCS8/PKIX bodies, and non-Ed25519
// keys.
func TestParseProvenanceKeyErrors(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPrivDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPrivDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}

	privCases := map[string][]byte{
		"empty":        nil,
		"not pem":      []byte("garbage"),
		"wrong type":   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}),
		"bad der":      pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not der")}),
		"not ed25519":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaPrivDER}),
		"ec not 25519": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecPrivDER}),
	}
	for label, b := range privCases {
		if _, err := parseProvenancePrivateKey(b); err == nil {
			t.Errorf("private %s: accepted, want error", label)
		}
	}

	pubCases := map[string][]byte{
		"empty":       nil,
		"not pem":     []byte("garbage"),
		"wrong type":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}),
		"bad der":     pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not der")}),
		"not ed25519": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaPubDER}),
	}
	for label, b := range pubCases {
		if _, err := parseProvenancePublicKey(b); err == nil {
			t.Errorf("public %s: accepted, want error", label)
		}
	}

	// Valid round trip through the parsers.
	keyPEM, pubPEM := keyPEMs(t)
	priv, err := parseProvenancePrivateKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := parseProvenancePublicKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(priv.Public()) {
		t.Fatal("parsed pair does not match")
	}
}

// TestSignFile proves SignFile reads the artifact, binds its digest, and
// surfaces read and entropy failures.
func TestSignFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.bin")
	body := []byte("signed artifact bytes")
	writeFile(t, path, body, 0o644)

	env, err := SignFile("run1", "repo", "commit", path)
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
	sum := sha256.Sum256(body)
	if st.Subject[0].Digest["sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("subject digest = %q", st.Subject[0].Digest["sha256"])
	}
	if st.Subject[0].Name != path {
		t.Fatalf("subject name = %q", st.Subject[0].Name)
	}
	if len(env.Signatures) != 1 || env.Signatures[0].KeyID == "" {
		t.Fatalf("signature = %+v", env.Signatures)
	}

	// Missing file.
	if _, err := SignFile("run", "repo", "commit", filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file must fail")
	}

	// Entropy failure.
	orig := randReader
	randReader = failingReader{}
	defer func() { randReader = orig }()
	if _, err := SignFile("run", "repo", "commit", path); err == nil {
		t.Fatal("entropy failure must surface")
	}
}

// TestVerifyWithConstraintLabels exercises each constraint label with a
// mismatch and with a match so the label reporting is pinned.
func TestVerifyWithConstraintLabels(t *testing.T) {
	pub, priv := provKey(t)
	st := ArtifactStatement(ArtifactInput{
		Name:       "app",
		SHA256:     strings.Repeat("a", 64),
		RunID:      "run",
		JobID:      "job",
		JobKey:     "build",
		Repository: "example/repo",
		Ref:        "refs/heads/main",
		Commit:     "abc",
		Runner:     "runner-1",
	})
	st.Issuer = "https://issuer.example"
	st.Predicate.RunDetails.Builder.ID = "https://kiwi-ci.dev/runner/runner-1"
	env, err := Sign(st, "kid", priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	base := VerifyOptions{
		Repository: "example/repo",
		Commit:     "abc",
		Ref:        "refs/heads/main",
		Job:        "build",
		Builder:    "https://kiwi-ci.dev/runner/runner-1",
		Issuer:     "https://issuer.example",
		Digest:     strings.Repeat("a", 64),
		TrustedKey: pub,
	}
	if _, err := VerifyWith(raw, nil, base); err != nil {
		t.Fatalf("matching constraints: %v", err)
	}
	for label, mutate := range map[string]func(o *VerifyOptions){
		"repository": func(o *VerifyOptions) { o.Repository = "other" },
		"commit":     func(o *VerifyOptions) { o.Commit = "other" },
		"ref":        func(o *VerifyOptions) { o.Ref = "other" },
		"job":        func(o *VerifyOptions) { o.Job = "other" },
		"builder":    func(o *VerifyOptions) { o.Builder = "other" },
		"issuer":     func(o *VerifyOptions) { o.Issuer = "other" },
		"digest":     func(o *VerifyOptions) { o.Digest = strings.Repeat("b", 64) },
	} {
		o := base
		mutate(&o)
		if _, err := VerifyWith(raw, nil, o); err == nil || !strings.Contains(err.Error(), label) {
			t.Errorf("%s mismatch error = %v, want label in error", label, err)
		}
	}
}

// TestVerifyWithSubjectDigestMissing proves a subject without a sha256
// digest is rejected.
func TestVerifyWithSubjectDigestMissing(t *testing.T) {
	pub, priv := provKey(t)
	st := Statement{Type: StatementType, Subject: []Subject{{Name: "app"}}}
	body, _ := json.Marshal(st)
	env := signedEnvelope(body, "kid", priv)
	raw, _ := json.Marshal(env)
	if _, err := VerifyWith(raw, nil, VerifyOptions{TrustedKey: pub}); err == nil {
		t.Fatal("subject without digest must fail")
	}
}
