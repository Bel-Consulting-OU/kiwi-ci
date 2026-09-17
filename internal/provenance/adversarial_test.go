package provenance

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func signRaw(t *testing.T, st Statement, priv ed25519.PrivateKey) []byte {
	t.Helper()
	env, err := Sign(st, "kid", priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func resolverFor(pub ed25519.PublicKey) func(string) (ed25519.PublicKey, bool) {
	return func(string) (ed25519.PublicKey, bool) { return pub, true }
}

// TestVerifyWithRejectsSubjectlessStatement verifies a signed statement that
// binds no subject digest is rejected instead of being returned as a
// "verified" provenance record.
func TestVerifyWithRejectsSubjectlessStatement(t *testing.T) {
	pub, priv := provKey(t)
	st := Statement{Type: StatementType, PredicateType: PredicateType}
	raw := signRaw(t, st, priv)
	if _, err := VerifyWith(raw, resolverFor(pub), VerifyOptions{}); err == nil {
		t.Fatal("subjectless statement must be rejected")
	}
	st.Subject = []Subject{{Name: "app", Digest: map[string]string{}}}
	raw = signRaw(t, st, priv)
	if _, err := VerifyWith(raw, resolverFor(pub), VerifyOptions{}); err == nil {
		t.Fatal("subject without a sha256 digest must be rejected")
	}
}

// TestVerifyWithDigestConstraint verifies the digest option binds the
// envelope to exact artifact bytes.
func TestVerifyWithDigestConstraint(t *testing.T) {
	pub, priv := provKey(t)
	digest := strings.Repeat("c", 64)
	raw := signRaw(t, ArtifactStatement(ArtifactInput{Name: "app", SHA256: digest}), priv)
	if _, err := VerifyWith(raw, resolverFor(pub), VerifyOptions{Digest: digest}); err != nil {
		t.Fatalf("matching digest must verify: %v", err)
	}
	if _, err := VerifyWith(raw, resolverFor(pub), VerifyOptions{Digest: strings.Repeat("d", 64)}); err == nil {
		t.Fatal("digest mismatch must be rejected")
	}
	// An empty digest map on the statement is rejected even without a
	// requested digest.
	st := ArtifactStatement(ArtifactInput{Name: "app", SHA256: digest})
	st.Subject[0].Digest = map[string]string{}
	if _, err := VerifyWith(signRaw(t, st, priv), resolverFor(pub), VerifyOptions{}); err == nil {
		t.Fatal("statement with an empty digest map must be rejected")
	}
}

// TestVerifyWithMissingSignatureRejected verifies an envelope without any
// signature cannot pass.
func TestVerifyWithMissingSignatureRejected(t *testing.T) {
	pub, priv := provKey(t)
	env, err := Sign(ArtifactStatement(ArtifactInput{Name: "app", SHA256: strings.Repeat("c", 64)}), "kid", priv)
	if err != nil {
		t.Fatal(err)
	}
	env.Signatures = nil
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWith(raw, resolverFor(pub), VerifyOptions{}); err == nil {
		t.Fatal("signature-less envelope must be rejected")
	}
}

// TestVerifyWithWrongPayloadTypeRejected verifies the DSSE payload type is
// part of the authenticated envelope contract.
func TestVerifyWithWrongPayloadTypeRejected(t *testing.T) {
	pub, priv := provKey(t)
	env, err := Sign(ArtifactStatement(ArtifactInput{Name: "app", SHA256: strings.Repeat("c", 64)}), "kid", priv)
	if err != nil {
		t.Fatal(err)
	}
	env.PayloadType = "application/json"
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWith(raw, resolverFor(pub), VerifyOptions{}); err == nil {
		t.Fatal("wrong payload type must be rejected")
	}
}

// TestVerifyWithInvalidPinRejected verifies a malformed pinned key never
// verifies anything.
func TestVerifyWithInvalidPinRejected(t *testing.T) {
	_, priv := provKey(t)
	raw := signRaw(t, ArtifactStatement(ArtifactInput{Name: "app", SHA256: strings.Repeat("c", 64)}), priv)
	if _, err := VerifyWith(raw, nil, VerifyOptions{TrustedKey: ed25519.PublicKey([]byte("short"))}); err == nil {
		t.Fatal("invalid pinned key must be rejected")
	}
}

// TestVerifyWithEnvelopeSizeBound verifies the envelope byte bound.
func TestVerifyWithEnvelopeSizeBound(t *testing.T) {
	raw := make([]byte, maxEnvelopeBytes+1)
	if _, err := VerifyWith(raw, resolverFor(ed25519.PublicKey(make([]byte, 32))), VerifyOptions{}); err == nil {
		t.Fatal("oversized envelope must be rejected")
	}
}

// TestVerifyWithPinnedKeyIgnoresResolver verifies the pinned key is used and
// the resolver is never consulted, even when it would return a different key.
func TestVerifyWithPinnedKeyIgnoresResolver(t *testing.T) {
	pub, priv := provKey(t)
	otherPub, _ := provKey(t)
	called := false
	resolver := func(string) (ed25519.PublicKey, bool) { called = true; return otherPub, true }
	raw := signRaw(t, ArtifactStatement(ArtifactInput{Name: "app", SHA256: strings.Repeat("c", 64)}), priv)
	if _, err := VerifyWith(raw, resolver, VerifyOptions{TrustedKey: pub}); err != nil {
		t.Fatalf("pinned key must verify: %v", err)
	}
	if called {
		t.Fatal("resolver consulted despite a pinned key")
	}
}

// TestVerifySimpleRejectsTamperedPayload verifies the legacy Verify entry
// point still rejects a payload mutated after signing.
func TestVerifySimpleRejectsTamperedPayload(t *testing.T) {
	pub, priv := provKey(t)
	env, err := Sign(ArtifactStatement(ArtifactInput{Name: "app", SHA256: strings.Repeat("c", 64)}), "kid", priv)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload[0] ^= 0xff
	env.Payload = base64.StdEncoding.EncodeToString(payload)
	if err := Verify(env, pub); err == nil {
		t.Fatal("tampered payload must not verify")
	}
}
