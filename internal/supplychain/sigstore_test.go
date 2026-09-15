package supplychain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sigKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

const sigDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const bundleIssuer = "https://issuer.example"

const bundleIdentity = "ci/kiwi"

func signForTest(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	env, err := SignArtifact(priv, "kid-1", sigDigest, "example/repo", "refs/heads/main", SignOptions{
		Issuer:    bundleIssuer,
		Identity:  bundleIdentity,
		Builder:   "kiwi-ci@0.1.0",
		CreatedAt: time.Unix(1000, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestSignArtifactVerifyRoundTrip(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	st, err := VerifyAttestation(env, pub, VerifyOptions{
		Digest:     sigDigest,
		Issuer:     bundleIssuer,
		Identity:   bundleIdentity,
		Repository: "example/repo",
		Ref:        "refs/heads/main",
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.Type != StatementType || st.PredicateType != PredicateType {
		t.Fatalf("unexpected statement types: %q %q", st.Type, st.PredicateType)
	}
	if len(st.Subject) != 1 || st.Subject[0].Digest["sha256"] != sigDigest {
		t.Fatalf("unexpected subject %+v", st.Subject)
	}
	if st.Subject[0].Name != "example/repo@refs/heads/main" {
		t.Fatalf("unexpected subject name %q", st.Subject[0].Name)
	}
	if st.Predicate.Builder != "kiwi-ci@0.1.0" {
		t.Fatalf("unexpected builder %q", st.Predicate.Builder)
	}
}

func TestVerifyAttestationDigestMismatch(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	if _, err := VerifyAttestation(env, pub, VerifyOptions{Digest: strings.Repeat("f", 64)}); err == nil {
		t.Fatal("digest mismatch must be rejected")
	}
}

func TestVerifyAttestationClaimMismatch(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	for label, want := range map[string]VerifyOptions{
		"issuer":     {Issuer: "https://evil.example"},
		"identity":   {Identity: "other/subject"},
		"repository": {Repository: "other/repo"},
		"ref":        {Ref: "refs/tags/v9"},
	} {
		if _, err := VerifyAttestation(env, pub, want); err == nil {
			t.Fatalf("%s mismatch must be rejected", label)
		}
	}
}

func TestVerifyAttestationTamperRejected(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	var e dsseEnvelope
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload[len(payload)-1] ^= 0xff
	e.Payload = base64.StdEncoding.EncodeToString(payload)
	tampered, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAttestation(tampered, pub, VerifyOptions{}); err == nil {
		t.Fatal("tampered payload must be rejected")
	}
}

func TestVerifyAttestationWrongKey(t *testing.T) {
	_, privA := sigKey(t)
	pubB, _ := sigKey(t)
	env := signForTest(t, privA)
	if _, err := VerifyAttestation(env, pubB, VerifyOptions{}); err == nil {
		t.Fatal("wrong key must be rejected")
	}
}

func TestVerifyAttestationOversizeRejected(t *testing.T) {
	pub, _ := sigKey(t)
	huge := make([]byte, maxEnvelopeBytes+1)
	for i := range huge {
		huge[i] = ' '
	}
	if _, err := VerifyAttestation(huge, pub, VerifyOptions{}); err == nil {
		t.Fatal("oversized envelope must be rejected")
	}
}

// bundleForTest crafts a Sigstore bundle signed by priv with pub embedded
// as verification material and the given log entries.
func bundleForTest(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, entries []bundleLogEntry) []byte {
	t.Helper()
	env := signForTest(t, priv)
	var e dsseEnvelope
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatal(err)
	}
	b := sigstoreBundle{
		MediaType: SigstoreBundleMediaType,
		VerificationMaterial: bundleVerificationMaterial{
			PublicKey: &bundlePublicKey{
				RawBytes:   base64.StdEncoding.EncodeToString(pub),
				KeyDetails: "PKIX_ED25519",
			},
			LogEntries: entries,
		},
		DSSEEnvelope: &e,
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// payloadOf extracts the raw statement payload bytes of a DSSE envelope.
func payloadOf(t *testing.T, envelope []byte) []byte {
	t.Helper()
	var e dsseEnvelope
	if err := json.Unmarshal(envelope, &e); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func payloadHash(t *testing.T, envelope []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(payloadOf(t, envelope))
	return sum[:]
}

// logEntryForTest builds a bundle log entry whose body hash matches the
// statement payload of env.
func logEntryForTest(t *testing.T, env []byte, uuid string, integratedTime int64) bundleLogEntry {
	t.Helper()
	return bundleLogEntry{
		UUID:           uuid,
		IntegratedTime: integratedTime,
		BodyHash:       base64.StdEncoding.EncodeToString(payloadHash(t, env)),
	}
}

// pinKeys returns a trust root pinning pub under keyID.
func pinKeys(keyID string, pub ed25519.PublicKey) SigstoreTrustRoot {
	return SigstoreTrustRoot{Keys: map[string]ed25519.PublicKey{keyID: pub}}
}

func verifyCfgFor(t *testing.T, root SigstoreTrustRoot) SigstoreVerifyConfig {
	t.Helper()
	return SigstoreVerifyConfig{
		ExpectedIssuer:   bundleIssuer,
		ExpectedIdentity: bundleIdentity,
		TrustRoot:        root,
	}
}

func TestVerifySigstoreBundleHappyPath(t *testing.T) {
	pub, priv := sigKey(t)
	bundle := bundleForTest(t, priv, pub, nil)
	cfg := verifyCfgFor(t, pinKeys("kid-1", pub))
	cfg.ExpectedRepo = "example/repo"
	cfg.ExpectedRef = "refs/heads/main"
	if err := VerifySigstoreBundle(bundle, sigDigest, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySigstoreBundleNoTrustRootFailsClosed(t *testing.T) {
	pub, priv := sigKey(t)
	bundle := bundleForTest(t, priv, pub, nil)
	err := VerifySigstoreBundle(bundle, sigDigest, SigstoreVerifyConfig{ExpectedIssuer: bundleIssuer, ExpectedIdentity: bundleIdentity})
	if err == nil || !strings.Contains(err.Error(), "no sigstore trust root") {
		t.Fatalf("self-signed bundle without a trust root must fail closed, got %v", err)
	}
}

func TestVerifySigstoreBundlePinnedKey(t *testing.T) {
	pub, priv := sigKey(t)
	bundle := bundleForTest(t, priv, pub, nil)
	if err := VerifySigstoreBundle(bundle, sigDigest, verifyCfgFor(t, pinKeys("kid-1", pub))); err != nil {
		t.Fatal(err)
	}
	_, otherPriv := sigKey(t)
	otherPub, _ := sigKey(t)
	otherBundle := bundleForTest(t, otherPriv, otherPub, nil)
	if err := VerifySigstoreBundle(otherBundle, sigDigest, verifyCfgFor(t, pinKeys("kid-1", pub))); err == nil {
		t.Fatal("pinned key must reject a bundle signed by another key")
	}
}

func TestVerifySigstoreBundlePinnedKeyByContent(t *testing.T) {
	// Content matching works even when the key IDs differ.
	pub, priv := sigKey(t)
	bundle := bundleForTest(t, priv, pub, nil)
	root := SigstoreTrustRoot{Keys: map[string]ed25519.PublicKey{"other-key-id": pub}}
	if err := VerifySigstoreBundle(bundle, sigDigest, verifyCfgFor(t, root)); err != nil {
		t.Fatalf("content-pinned key must be accepted: %v", err)
	}
}

func TestVerifySigstoreBundlePinnedKeyIDWithoutEmbeddedKey(t *testing.T) {
	// A bundle may omit its embedded key when the signature key ID names
	// a pinned key.
	pub, priv := sigKey(t)
	bundle := bundleForTest(t, priv, pub, nil)
	var b sigstoreBundle
	if err := json.Unmarshal(bundle, &b); err != nil {
		t.Fatal(err)
	}
	b.VerificationMaterial.PublicKey = nil
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigstoreBundle(raw, sigDigest, verifyCfgFor(t, pinKeys("kid-1", pub))); err != nil {
		t.Fatalf("keyID-pinned bundle without embedded key must be accepted: %v", err)
	}
}

func TestVerifySigstoreBundleEmbeddedKeyMismatchRejected(t *testing.T) {
	pubA, _ := sigKey(t)
	_, privB := sigKey(t)
	pubB, _ := sigKey(t)
	bundle := bundleForTest(t, privB, pubB, nil)
	// The key ID names a pinned key, but the embedded key material
	// disagrees with the pin.
	if err := VerifySigstoreBundle(bundle, sigDigest, verifyCfgFor(t, pinKeys("kid-1", pubA))); err == nil {
		t.Fatal("embedded key inconsistent with the keyID pin must be rejected")
	}
}

func TestVerifySigstoreBundleLegacyTrustedKey(t *testing.T) {
	pub, priv := sigKey(t)
	bundle := bundleForTest(t, priv, pub, nil)
	if err := VerifySigstoreBundle(bundle, sigDigest, SigstoreVerifyConfig{TrustedKey: pub}); err != nil {
		t.Fatal(err)
	}
	_, otherPriv := sigKey(t)
	otherPub, _ := sigKey(t)
	otherBundle := bundleForTest(t, otherPriv, otherPub, nil)
	if err := VerifySigstoreBundle(otherBundle, sigDigest, SigstoreVerifyConfig{TrustedKey: pub}); err == nil {
		t.Fatal("legacy pinned key must reject a bundle signed by another key")
	}
}

func TestVerifySigstoreBundleBadMediaType(t *testing.T) {
	pub, priv := sigKey(t)
	bundle := bundleForTest(t, priv, pub, nil)
	var m map[string]any
	if err := json.Unmarshal(bundle, &m); err != nil {
		t.Fatal(err)
	}
	m["mediaType"] = "application/vnd.dev.sigstore.bundle.v0.1+json"
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigstoreBundle(raw, sigDigest, verifyCfgFor(t, pinKeys("kid-1", pub))); err == nil {
		t.Fatal("bad media type must be rejected")
	}
}

func TestVerifySigstoreBundleLogEntriesRequireRekor(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	bundle := bundleForTest(t, priv, pub, []bundleLogEntry{logEntryForTest(t, env, "aaaa", 1700000000)})
	if err := VerifySigstoreBundle(bundle, sigDigest, verifyCfgFor(t, pinKeys("kid-1", pub))); err == nil {
		t.Fatal("log entries without a configured Rekor root must be rejected")
	}
}

func TestVerifySigstoreBundleTooManyLogEntries(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	entries := make([]bundleLogEntry, maxLogEntries+1)
	for i := range entries {
		entries[i] = logEntryForTest(t, env, strings.Repeat("a", 64), int64(1700000000+i))
	}
	bundle := bundleForTest(t, priv, pub, entries)
	cfg := verifyCfgFor(t, pinKeys("kid-1", pub))
	cfg.TrustRoot.Rekor = &RekorConfig{PublicKey: pub, BaseURL: "https://rekor.example"}
	if err := VerifySigstoreBundle(bundle, sigDigest, cfg); err == nil {
		t.Fatal("too many log entries must be rejected")
	}
}

func TestVerifySigstoreBundleMissingIntegratedTime(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	le := logEntryForTest(t, env, "aaaa", 1700000000)
	le.IntegratedTime = 0
	bundle := bundleForTest(t, priv, pub, []bundleLogEntry{le})
	cfg := verifyCfgFor(t, pinKeys("kid-1", pub))
	cfg.TrustRoot.Rekor = &RekorConfig{PublicKey: pub, BaseURL: "https://rekor.example"}
	if err := VerifySigstoreBundle(bundle, sigDigest, cfg); err == nil {
		t.Fatal("missing integratedTime must be rejected")
	}
}

func TestVerifySigstoreBundleBodyHashMismatch(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	le := logEntryForTest(t, env, "aaaa", 1700000000)
	le.BodyHash = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32))
	bundle := bundleForTest(t, priv, pub, []bundleLogEntry{le})
	cfg := verifyCfgFor(t, pinKeys("kid-1", pub))
	cfg.TrustRoot.Rekor = &RekorConfig{PublicKey: pub, BaseURL: "https://rekor.example"}
	if err := VerifySigstoreBundle(bundle, sigDigest, cfg); err == nil {
		t.Fatal("log entry body hash mismatch must be rejected")
	}
}

func TestVerifySigstoreBundleMissingUUID(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	le := logEntryForTest(t, env, "aaaa", 1700000000)
	le.UUID = ""
	bundle := bundleForTest(t, priv, pub, []bundleLogEntry{le})
	cfg := verifyCfgFor(t, pinKeys("kid-1", pub))
	cfg.TrustRoot.Rekor = &RekorConfig{PublicKey: pub, BaseURL: "https://rekor.example"}
	if err := VerifySigstoreBundle(bundle, sigDigest, cfg); err == nil {
		t.Fatal("log entry without uuid must be rejected")
	}
}

func TestVerifySigstoreBundleInvalidRekorPublicKey(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	bundle := bundleForTest(t, priv, pub, []bundleLogEntry{logEntryForTest(t, env, "aaaa", 1700000000)})
	cfg := verifyCfgFor(t, pinKeys("kid-1", pub))
	cfg.TrustRoot.Rekor = &RekorConfig{PublicKey: []byte("short"), BaseURL: "https://rekor.example"}
	if err := VerifySigstoreBundle(bundle, sigDigest, cfg); err == nil {
		t.Fatal("invalid Rekor public key must be rejected")
	}
}

func TestVerifySigstoreBundleOversize(t *testing.T) {
	huge := []byte(`{"mediaType":"` + strings.Repeat("a", maxEnvelopeBytes) + `"}`)
	if err := VerifySigstoreBundle(huge, sigDigest, SigstoreVerifyConfig{}); err == nil {
		t.Fatal("oversized bundle must be rejected")
	}
}
