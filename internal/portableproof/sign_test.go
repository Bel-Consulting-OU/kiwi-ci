package portableproof_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/portableproof"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/verifyapi"
)

// testDigest builds a deterministic 64-hex digest from a seed so fixtures
// stay readable.
func testDigest(t *testing.T, seed string) verifyapi.Digest {
	t.Helper()
	sum := sha256.Sum256([]byte(seed))
	return verifyapi.Digest(hex.EncodeToString(sum[:]))
}

// sealedProof builds a REAL sealed VerificationProof through the verifyapi
// acceptance path: obligation + claim + evidence-derived outcome + HMAC
// acceptance record. The portable layer signs this proof; nothing is faked.
func sealedProof(t *testing.T) (verifyapi.VerificationProof, *verifyapi.AcceptanceKeyring) {
	t.Helper()
	at := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	ob := verifyapi.VerificationObligation{
		ObligationID:               "ob-portable-1",
		Subject:                    "cand-portable-1",
		ImmutableCandidateDigest:   testDigest(t, "candidate"),
		SourceSnapshotDigest:       testDigest(t, "snapshot"),
		VerificationContractDigest: testDigest(t, "contract"),
		RequiredChecks:             []string{verifyapi.CheckJobStatusSuccess, verifyapi.CheckEvidenceRoot},
		RequiredAssurance:          "uncontrolled",
		Freshness:                  verifyapi.FreshnessPolicy{MaxAgeSeconds: 86400},
		IssuedAt:                   at.Add(-time.Hour),
	}
	claim := verifyapi.VerificationOutcome{
		VerificationID:   "ver-portable-1",
		ObligationID:     ob.ObligationID,
		CandidateDigest:  ob.ImmutableCandidateDigest,
		SnapshotDigest:   ob.SourceSnapshotDigest,
		ContractDigest:   ob.VerificationContractDigest,
		Outcome:          verifyapi.OutcomePass,
		AssuranceProfile: ob.RequiredAssurance,
		CompletedChecks:  []string{verifyapi.CheckJobStatusSuccess, verifyapi.CheckEvidenceRoot},
		EvidenceRoot:     testDigest(t, "root"),
		Resources: verifyapi.ResourceFacts{
			RunnerClass: "native",
		},
		ProvenanceRefs: []string{"att-portable-1"},
		StartedAt:      at.Add(-30 * time.Minute),
		CompletedAt:    at.Add(-20 * time.Minute),
	}
	f := &verifyapi.FuncEvidenceVerifier{
		Identity: "portableproof-test-verifier/v1",
		Resolve: func(context.Context, string) (verifyapi.ResolvedAttestation, error) {
			return verifyapi.ResolvedAttestation{
				ExecutionID:       "exec-portable-1",
				EvidenceRoot:      testDigest(t, "root"),
				AttestationDigest: testDigest(t, "att"),
				Status:            "success",
				Attested: &verifyapi.AttestedResourceFacts{
					StartedAt:  claim.StartedAt,
					FinishedAt: claim.CompletedAt,
				},
				Checks: []verifyapi.VerifiedCheck{
					{Name: verifyapi.CheckJobStatusSuccess, Outcome: verifyapi.CheckOutcomePass, EvidenceDigest: testDigest(t, "root")},
					{Name: verifyapi.CheckEvidenceRoot, Outcome: verifyapi.CheckOutcomePass, EvidenceDigest: testDigest(t, "root")},
				},
			}, nil
		},
	}
	sealed, err := f.Verify(context.Background(), ob, claim)
	if err != nil {
		t.Fatalf("derive sealed outcome: %v", err)
	}
	if !sealed.ProvenPass() {
		t.Fatal("sealed outcome must be a proven pass")
	}
	key, err := verifyapi.NewHMACAcceptanceKey("K1", []byte("portable-proof-hmac-secret-32bytes!!"))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := verifyapi.AcceptWithKeyring(ob, sealed, nil, mustRing(t, key), at)
	if err != nil {
		t.Fatalf("acceptance-sign: %v", err)
	}
	proof := verifyapi.NewVerificationProof(verifyapi.PersistedVerified{
		Obligation:     ob,
		SubmittedClaim: sealed.SubmittedClaim,
		Outcome:        sealed.Outcome,
		Evidence:       sealed.Evidence,
		Acceptance:     rec,
	})
	ring, err := verifyapi.NewSingleKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proof.Verify(ring); err != nil {
		t.Fatalf("internal proof.Verify: %v", err)
	}
	return proof, ring
}

func mustRing(t *testing.T, key verifyapi.AcceptanceKey) *verifyapi.AcceptanceKeyring {
	t.Helper()
	ring, err := verifyapi.NewSingleKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

// TestSignAndVerifyWithPublicKeyOnly is the happy path: the consumer holds
// only the Ed25519 public key and the envelope verifies. The consumer
// cannot forge — the private half never leaves the signer.
func TestSignAndVerifyWithPublicKeyOnly(t *testing.T) {
	proof, _ := sealedProof(t)
	signer, pub, err := portableproof.GenerateSigner("pk-1")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.SignProof(proof, time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("SignProof: %v", err)
	}
	if signed.Signature.Algorithm != portableproof.AlgorithmEd25519 {
		t.Fatalf("algorithm = %q, want %s", signed.Signature.Algorithm, portableproof.AlgorithmEd25519)
	}
	if signed.Signature.KeyID != "pk-1" {
		t.Fatalf("key id = %q, want pk-1", signed.Signature.KeyID)
	}
	if err := portableproof.Verify(signed, "pk-1", pub); err != nil {
		t.Fatalf("Verify with public key only = %v", err)
	}
	got, err := portableproof.VerifySignedProof(signed, "pk-1", pub)
	if err != nil {
		t.Fatalf("VerifySignedProof = %v", err)
	}
	if got.Obligation.ObligationID != proof.Obligation.ObligationID || got.Outcome.VerificationID != proof.Outcome.VerificationID {
		t.Fatalf("round-tripped proof identity mismatch: %+v", got)
	}
	// The internal HMAC layer is untouched by the portable signature.
	if _, err := proof.Verify(mustRing(t, mustHMAC(t))); err != nil {
		t.Fatalf("internal HMAC proof.Verify after portable sign = %v", err)
	}
}

func mustHMAC(t *testing.T) *verifyapi.HMACAcceptanceKey {
	t.Helper()
	k, err := verifyapi.NewHMACAcceptanceKey("K1", []byte("portable-proof-hmac-secret-32bytes!!"))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestTamperedProofFails: any byte-level change to the signed proof bytes
// breaks the portable signature. The consumer must not accept a mutated
// proof even when the mutation is "just one field".
func TestTamperedProofFails(t *testing.T) {
	proof, _ := sealedProof(t)
	signer, pub, err := portableproof.GenerateSigner("pk-tamper")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.SignProof(proof, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	// Tamper 1: flip a byte in the raw proof bytes.
	tampered := signed
	raw := append([]byte(nil), tampered.Proof...)
	raw[len(raw)/2] ^= 0x1
	tampered.Proof = raw
	if err := portableproof.Verify(tampered, "pk-tamper", pub); err == nil {
		t.Fatal("byte-flipped proof must not verify")
	}
	// Tamper 2: decode, mutate a field, re-encode — the signature covers
	// the exact bytes, so a re-encoded mutation also fails.
	var p verifyapi.VerificationProof
	if err := json.Unmarshal(signed.Proof, &p); err != nil {
		t.Fatal(err)
	}
	p.Outcome.Outcome = verifyapi.OutcomePass
	p.Acceptance.KeyID = "forged"
	re, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	forged := signed
	forged.Proof = re
	if err := portableproof.Verify(forged, "pk-tamper", pub); err == nil {
		t.Fatal("field-mutated proof must not verify")
	}
	// The original still verifies.
	if err := portableproof.Verify(signed, "pk-tamper", pub); err != nil {
		t.Fatalf("original proof after tamper attempts = %v", err)
	}
}

// TestWrongKeyFails: a signature made under key A must not verify under
// key B, and a consumer holding only B cannot be convinced by A's envelope.
func TestWrongKeyFails(t *testing.T) {
	proof, _ := sealedProof(t)
	signerA, _, err := portableproof.GenerateSigner("pk-A")
	if err != nil {
		t.Fatal(err)
	}
	_, pubB, err := portableproof.GenerateSigner("pk-B")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signerA.SignProof(proof, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	// Same key id label but the wrong public key.
	if err := portableproof.Verify(signed, "pk-A", pubB); err == nil {
		t.Fatal("signature under A must not verify under B's public key")
	}
	// Right public key, wrong trusted id.
	_, pubA, err := portableproof.GenerateSigner("pk-A")
	if err != nil {
		t.Fatal(err)
	}
	// pubA above is a DIFFERENT keypair than signerA (GenerateSigner mints
	// fresh material). Regenerate the true A public key from the signer's
	// envelope path instead: sign with A and verify under a fresh A-labeled
	// key — must fail because the bytes were signed by a different key.
	if err := portableproof.Verify(signed, "pk-A", pubA); err == nil {
		t.Fatal("same key id label must not launder a different keypair")
	}
	if err := portableproof.Verify(signed, "pk-B", pubB); err == nil {
		t.Fatal("envelope key id mismatch must fail closed")
	}
}

// TestDiscoveryRotationAndRevocation: the public-key discovery document
// carries the rotation / revocation note, and verification follows the key
// lifecycle (active ok, rotated ok for history, revoked refused).
func TestDiscoveryRotationAndRevocation(t *testing.T) {
	proof, _ := sealedProof(t)
	signer1, pub1, err := portableproof.GenerateSigner("pk-1")
	if err != nil {
		t.Fatal(err)
	}
	signer2, pub2, err := portableproof.GenerateSigner("pk-2")
	if err != nil {
		t.Fatal(err)
	}
	doc1, err := portableproof.PublishDoc("pk-1", pub1, portableproof.KeyActive, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), "initial portable signing key")
	if err != nil {
		t.Fatal(err)
	}
	doc2, err := portableproof.PublishDoc("pk-2", pub2, portableproof.KeyActive, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), "successor")
	if err != nil {
		t.Fatal(err)
	}
	disc := portableproof.NewDiscovery(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	disc.Keys = []portableproof.PublicKeyDoc{doc1, doc2}

	signed1, err := signer1.SignProof(proof, time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	signed2, err := signer2.SignProof(proof, time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := portableproof.VerifyWithDiscovery(signed1, disc); err != nil {
		t.Fatalf("active key verify = %v", err)
	}
	// Rotate pk-1 → pk-2 with an operator note.
	if err := disc.Rotate("pk-1", "pk-2", "rotated 2026-02-01: annual key rollover; pk-1 remains valid for historical signatures"); err != nil {
		t.Fatal(err)
	}
	got, _ := disc.Find("pk-1")
	if got.Status != portableproof.KeyRotated || got.SupersededByKeyID != "pk-2" {
		t.Fatalf("rotated key doc = %+v, want rotated → pk-2", got)
	}
	if !strings.Contains(got.Note, "annual key rollover") {
		t.Fatalf("rotation note lost: %q", got.Note)
	}
	// Historical signatures under the rotated key still verify; new ones
	// under the successor verify.
	if err := portableproof.VerifyWithDiscovery(signed1, disc); err != nil {
		t.Fatalf("rotated-key historical verify = %v", err)
	}
	if err := portableproof.VerifyWithDiscovery(signed2, disc); err != nil {
		t.Fatalf("successor verify = %v", err)
	}
	// Revoke pk-1 (compromise): historical signatures are now refused.
	if err := disc.Revoke("pk-1", "revoked 2026-03-01: private key compromise suspected"); err != nil {
		t.Fatal(err)
	}
	if err := portableproof.VerifyWithDiscovery(signed1, disc); err == nil {
		t.Fatal("revoked key must not verify")
	}
	// The successor is untouched by the revocation.
	if err := portableproof.VerifyWithDiscovery(signed2, disc); err != nil {
		t.Fatalf("successor after predecessor revoke = %v", err)
	}
	// Unknown keys are refused.
	unsigned, err := signer2.SignProof(proof, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	unsigned.Signature.KeyID = "pk-missing"
	if err := portableproof.VerifyWithDiscovery(unsigned, disc); err == nil {
		t.Fatal("unknown key id must not verify")
	}
}

// TestSignedProofRoundTripJSON: the envelope survives a JSON round trip
// byte-for-byte on the signed proof payload — the signature covers the
// transmission, so transport encoding must not disturb it.
func TestSignedProofRoundTripJSON(t *testing.T) {
	proof, _ := sealedProof(t)
	signer, pub, err := portableproof.GenerateSigner("pk-rt")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.SignProof(proof, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var back portableproof.SignedProof
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	if err := portableproof.Verify(back, "pk-rt", pub); err != nil {
		t.Fatalf("JSON round-tripped envelope = %v", err)
	}
}
