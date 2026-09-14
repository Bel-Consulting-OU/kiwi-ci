package supplychain

import (
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

func signForTest(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	env, err := SignArtifact(priv, "kid-1", sigDigest, "example/repo", "refs/heads/main", SignOptions{
		Issuer:    "https://issuer.example",
		Identity:  "ci/kiwi",
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
		Issuer:     "https://issuer.example",
		Identity:   "ci/kiwi",
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

func bundleForTest(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, bodyHash []byte, logEntries int) []byte {
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
		},
		DSSEEnvelope: &e,
	}
	for i := 0; i < logEntries; i++ {
		b.VerificationMaterial.LogEntries = append(b.VerificationMaterial.LogEntries, bundleLogEntry{
			IntegratedTime: 1700000000 + int64(i),
			BodyHash:       base64.StdEncoding.EncodeToString(bodyHash),
		})
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func payloadHash(t *testing.T, envelope []byte) []byte {
	t.Helper()
	var e dsseEnvelope
	if err := json.Unmarshal(envelope, &e); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	return sum[:]
}

func TestVerifySigstoreBundleHappyPath(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	bundle := bundleForTest(t, priv, pub, payloadHash(t, env), 2)
	if err := VerifySigstoreBundle(bundle, sigDigest, SigstoreVerifyConfig{
		ExpectedIssuer:   "https://issuer.example",
		ExpectedIdentity: "ci/kiwi",
		ExpectedRepo:     "example/repo",
		ExpectedRef:      "refs/heads/main",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySigstoreBundlePinnedKey(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	bundle := bundleForTest(t, priv, pub, payloadHash(t, env), 0)
	if err := VerifySigstoreBundle(bundle, sigDigest, SigstoreVerifyConfig{TrustedKey: pub}); err != nil {
		t.Fatal(err)
	}
	_, otherPriv := sigKey(t)
	otherPub, _ := sigKey(t)
	otherEnv := signForTest(t, otherPriv)
	otherBundle := bundleForTest(t, otherPriv, otherPub, payloadHash(t, otherEnv), 0)
	if err := VerifySigstoreBundle(otherBundle, sigDigest, SigstoreVerifyConfig{TrustedKey: pub}); err == nil {
		t.Fatal("pinned key must reject a bundle signed by another key")
	}
}

func TestVerifySigstoreBundleBadMediaType(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	bundle := bundleForTest(t, priv, pub, payloadHash(t, env), 0)
	var m map[string]any
	if err := json.Unmarshal(bundle, &m); err != nil {
		t.Fatal(err)
	}
	m["mediaType"] = "application/vnd.dev.sigstore.bundle.v0.1+json"
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigstoreBundle(raw, sigDigest, SigstoreVerifyConfig{}); err == nil {
		t.Fatal("bad media type must be rejected")
	}
}

func TestVerifySigstoreBundleHashMismatch(t *testing.T) {
	pub, priv := sigKey(t)
	bundle := bundleForTest(t, priv, pub, []byte("wrong body hash"), 1)
	if err := VerifySigstoreBundle(bundle, sigDigest, SigstoreVerifyConfig{}); err == nil {
		t.Fatal("log entry hash mismatch must be rejected")
	}
}

func TestVerifySigstoreBundleMissingKey(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	var b sigstoreBundle
	if err := json.Unmarshal(bundleForTest(t, priv, pub, payloadHash(t, env), 0), &b); err != nil {
		t.Fatal(err)
	}
	b.VerificationMaterial.PublicKey = nil
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigstoreBundle(raw, sigDigest, SigstoreVerifyConfig{}); err == nil {
		t.Fatal("missing verification key must be rejected")
	}
}

func TestVerifySigstoreBundleTooManyLogEntries(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	bundle := bundleForTest(t, priv, pub, payloadHash(t, env), maxLogEntries+1)
	if err := VerifySigstoreBundle(bundle, sigDigest, SigstoreVerifyConfig{}); err == nil {
		t.Fatal("too many log entries must be rejected")
	}
}

func TestVerifySigstoreBundleOversize(t *testing.T) {
	huge := []byte(`{"mediaType":"` + strings.Repeat("a", maxEnvelopeBytes) + `"}`)
	if err := VerifySigstoreBundle(huge, sigDigest, SigstoreVerifyConfig{}); err == nil {
		t.Fatal("oversized bundle must be rejected")
	}
}

func TestVerifySigstoreBundleMissingIntegratedTime(t *testing.T) {
	pub, priv := sigKey(t)
	env := signForTest(t, priv)
	var b sigstoreBundle
	if err := json.Unmarshal(bundleForTest(t, priv, pub, payloadHash(t, env), 1), &b); err != nil {
		t.Fatal(err)
	}
	b.VerificationMaterial.LogEntries[0].IntegratedTime = 0
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigstoreBundle(raw, sigDigest, SigstoreVerifyConfig{}); err == nil {
		t.Fatal("missing integratedTime must be rejected")
	}
}
