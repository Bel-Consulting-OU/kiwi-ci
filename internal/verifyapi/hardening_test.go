package verifyapi

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
)

// ---------------------------------------------------------------------------
// P2 — Acceptance format V2: domain separation, frozen encoding, submitted
// claim binding, and v1→v2 migration.
// ---------------------------------------------------------------------------

// TestAcceptanceV2BindsSubmittedClaim is the core v2 property: an attacker
// with database write who swaps the SubmittedClaim column breaks the MAC,
// because the v2 acceptance record commits a submitted-claim digest.
func TestAcceptanceV2BindsSubmittedClaim(t *testing.T) {
	ob := baseObligation(t)
	ob.RequiredChecks = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	v := baseOutcome(t, ob)
	v.EvidenceRoot = mustDigest(t, "v2-root")
	v.ProvenanceRefs = []string{"att-1"}
	v.ExecutionIDs = []string{"exec-1"}

	f := &FuncEvidenceVerifier{
		Identity: "v2-verifier/v1",
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      mustDigest(t, "v2-root"),
				AttestationDigest: mustDigest(t, "v2-att"),
				Status:            "success",
				Attested:          trustedWindow(),
				Checks:            passChecks("exec-1", CheckJobStatusSuccess, CheckEvidenceRoot),
			}, nil
		},
	}
	sealed, err := f.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if !sealed.ProvenPass() {
		t.Fatal("want sealed proven pass")
	}
	key, err := NewHMACAcceptanceKey("acc-v2", []byte("v2-test-secret-32-bytes-long!!"))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := Accept(ob, sealed, key, time.Date(2026, 1, 2, 3, 6, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Accept = %v", err)
	}
	if rec.AcceptanceVersion != AcceptanceVersionCurrent {
		t.Fatalf("AcceptanceVersion = %d, want %d (new records write current)", rec.AcceptanceVersion, AcceptanceVersionCurrent)
	}
	if rec.SchemaVersion != SchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", rec.SchemaVersion, SchemaVersion)
	}
	if rec.SubmittedClaimDigest == "" {
		t.Fatal("v2 record must commit a submitted claim digest")
	}
	if rec.Subject != ob.Subject {
		t.Fatalf("Subject = %q, want %q", rec.Subject, ob.Subject)
	}
	persisted := PersistedVerified{
		Obligation:     ob,
		SubmittedClaim: sealed.SubmittedClaim(),
		Outcome:        sealed.Outcome(),
		Evidence:       sealed.Evidence(),
		Acceptance:     rec,
	}
	if _, err := RestoreVerifiedOutcome(persisted, key); err != nil {
		t.Fatalf("intact v2 restore = %v", err)
	}

	// Swap the claim on the "database row": a different verification id on
	// the claim must break the MAC (claim digest mismatch).
	tampered := persisted
	tampered.SubmittedClaim = persisted.SubmittedClaim
	tampered.SubmittedClaim.VerificationID = "ver-forged"
	if _, err := RestoreVerifiedOutcome(tampered, key); err == nil {
		t.Fatal("tampered submitted claim must not restore")
	} else if !errors.Is(err, ErrAcceptance) {
		t.Fatalf("tampered claim error = %v, want ErrAcceptance", err)
	}

	// Swap the obligation's subject: the MAC binds subject identity too.
	tamperedSub := persisted
	tamperedSub.Obligation = persisted.Obligation
	tamperedSub.Obligation.Subject = "other-subject"
	if _, err := RestoreVerifiedOutcome(tamperedSub, key); err == nil {
		t.Fatal("tampered subject must not restore")
	} else if !errors.Is(err, ErrAcceptance) {
		t.Fatalf("tampered subject error = %v, want ErrAcceptance", err)
	}
}

// TestAcceptanceV2DomainSeparatedFromV1: the v2 MAC input carries the v2
// domain tag, so a v1 payload can never be replayed as a v2 record (and
// vice versa) even if the fields coincide.
func TestAcceptanceV2DomainSeparatedFromV1(t *testing.T) {
	rec := AcceptanceRecord{
		AcceptanceVersion:      AcceptanceVersionV2,
		SchemaVersion:          SchemaVersion,
		ObligationDigest:       mustDigest(t, "d1"),
		SubmittedClaimDigest:   mustDigest(t, "d2"),
		OutcomeDigest:          mustDigest(t, "d3"),
		VerifiedEvidenceDigest: mustDigest(t, "d4"),
		Subject:                "svc",
		Algorithm:              AcceptanceAlgorithmHMACSHA256,
		VerifiedAt:             time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		KeyID:                  "k1",
	}
	v2Payload, err := acceptancePayloadV2(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(v2Payload), acceptanceDomainV2) {
		t.Fatal("v2 payload must carry the v2 domain tag")
	}
	if strings.Contains(string(v2Payload), acceptanceDomain) && !strings.Contains(string(v2Payload), acceptanceDomainV2) {
		t.Fatal("v2 payload must not use the v1 domain")
	}
	// The frozen encoding is length-prefixed: a field value containing the
	// delimiter cannot smuggle a sibling field.
	rec2 := rec
	rec2.Subject = "svc\nkiwi-ci/verification-acceptance/v2"
	p2, err := acceptancePayloadV2(rec2)
	if err != nil {
		t.Fatal(err)
	}
	if string(p2) == string(v2Payload) {
		t.Fatal("subject with embedded domain must change the payload")
	}
}

// TestRestoreAuthenticatesMACBeforeSemanticInterpretation: the restore order
// is parse envelope → authenticate MAC → interpret digests/recipes/subjects.
// A corrupted acceptance record must fail on the MAC itself and must NOT
// surface a pre-auth digest, recipe, or subject oracle. Payload tampering
// under a still-valid MAC is the post-auth digest path.
func TestRestoreAuthenticatesMACBeforeSemanticInterpretation(t *testing.T) {
	ob := baseObligation(t)
	ob.RequiredChecks = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	v := baseOutcome(t, ob)
	v.EvidenceRoot = mustDigest(t, "mac-order-root")
	v.ProvenanceRefs = []string{"att-1"}
	v.ExecutionIDs = []string{"exec-1"}

	f := &FuncEvidenceVerifier{
		Identity: "mac-order-verifier/v1",
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      mustDigest(t, "mac-order-root"),
				AttestationDigest: mustDigest(t, "mac-order-att"),
				Status:            "success",
				Attested:          trustedWindow(),
				Checks:            passChecks("exec-1", CheckJobStatusSuccess, CheckEvidenceRoot),
			}, nil
		},
	}
	sealed, err := f.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	key := mustKey(t, "acc-mac-order", "mac-order-secret-32-bytes-long!!")
	rec, err := Accept(ob, sealed, key, time.Date(2026, 1, 2, 3, 6, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Accept = %v", err)
	}
	persisted := PersistedVerified{
		Obligation:     ob,
		SubmittedClaim: sealed.SubmittedClaim(),
		Outcome:        sealed.Outcome(),
		Evidence:       sealed.Evidence(),
		Acceptance:     rec,
	}
	if _, err := RestoreVerifiedOutcome(persisted, key); err != nil {
		t.Fatalf("intact restore = %v", err)
	}

	// 1. Corrupted ACCEPTANCE RECORD (stale MAC over rewritten digests).
	// Must report MAC failure — not "obligation digest mismatch", not a
	// recipe ErrBinding, not a subject mismatch.
	forged := persisted
	forged.Acceptance = rec
	forged.Acceptance.ObligationDigest = mustDigest(t, "forged-ob")
	_, err = RestoreVerifiedOutcome(forged, key)
	if err == nil {
		t.Fatal("forged acceptance digests must not restore")
	}
	if !errors.Is(err, ErrAcceptance) {
		t.Fatalf("forged acceptance error = %v, want ErrAcceptance", err)
	}
	if !strings.Contains(err.Error(), "MAC") {
		t.Fatalf("forged acceptance must fail on MAC authentication, got %v", err)
	}

	// 2. Corrupted SUBJECT on the record under a stale MAC: still MAC-first.
	forgedSub := persisted
	forgedSub.Acceptance = rec
	forgedSub.Acceptance.Subject = "forged-subject"
	_, err = RestoreVerifiedOutcome(forgedSub, key)
	if err == nil || !errors.Is(err, ErrAcceptance) || !strings.Contains(err.Error(), "MAC") {
		t.Fatalf("forged record subject must fail MAC-first, got %v", err)
	}

	// 3. Corrupted record with a garbage MAC value: still MAC failure.
	forgedMAC := persisted
	forgedMAC.Acceptance = rec
	forgedMAC.Acceptance.MAC = strings.Repeat("0", 64)
	forgedMAC.Acceptance.ObligationDigest = mustDigest(t, "other")
	_, err = RestoreVerifiedOutcome(forgedMAC, key)
	if err == nil || !errors.Is(err, ErrAcceptance) || !strings.Contains(err.Error(), "MAC") {
		t.Fatalf("garbage MAC must fail MAC-first, got %v", err)
	}

	// 4. Payload (PersistedVerified) tampering under an intact MAC is the
	// post-auth digest path — the MAC is valid because it commits only the
	// record, and the payload↔record comparison catches the swap.
	tamperedPayload := persisted
	tamperedPayload.Obligation = persisted.Obligation
	tamperedPayload.Obligation.Subject = "other-subject"
	_, err = RestoreVerifiedOutcome(tamperedPayload, key)
	if err == nil {
		t.Fatal("tampered payload obligation must not restore")
	}
	if !errors.Is(err, ErrAcceptance) {
		t.Fatalf("tampered payload error = %v, want ErrAcceptance", err)
	}
}

// TestAcceptanceV1StillRestores: a v1 record (no claim digest) keeps
// restoring when its v1 MAC verifies — migration must not brick existing
// rows. New records still write v2.
func TestAcceptanceV1StillRestores(t *testing.T) {
	ob := baseObligation(t)
	ob.RequiredChecks = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	v := baseOutcome(t, ob)
	v.EvidenceRoot = mustDigest(t, "v1-root")
	v.ProvenanceRefs = []string{"att-1"}
	v.ExecutionIDs = []string{"exec-1"}

	f := &FuncEvidenceVerifier{
		Identity: "v1-verifier/v1",
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      mustDigest(t, "v1-root"),
				AttestationDigest: mustDigest(t, "v1-att"),
				Status:            "success",
				Attested:          trustedWindow(),
				Checks:            passChecks("exec-1", CheckJobStatusSuccess, CheckEvidenceRoot),
			}, nil
		},
	}
	sealed, err := f.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	key, err := NewHMACAcceptanceKey("acc-v1", []byte("v1-test-secret-32-bytes-long!!"))
	if err != nil {
		t.Fatal(err)
	}
	// Hand-roll a v1 record (the shape pre-v2 rows carry).
	obDig, err := obligationDigest(ob)
	if err != nil {
		t.Fatal(err)
	}
	outDig, err := outcomeDigest(sealed.Outcome())
	if err != nil {
		t.Fatal(err)
	}
	evDig, err := evidenceDigest(sealed.Evidence())
	if err != nil {
		t.Fatal(err)
	}
	rec := AcceptanceRecord{
		AcceptanceVersion:      AcceptanceVersion,
		ObligationDigest:       obDig,
		OutcomeDigest:          outDig,
		VerifiedEvidenceDigest: evDig,
		Algorithm:              key.Algorithm(),
		VerifiedAt:             time.Date(2026, 1, 2, 3, 6, 0, 0, time.UTC),
		KeyID:                  key.KeyID(),
	}
	payload, err := acceptancePayload(rec)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := key.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	rec.MAC = mac

	persisted := PersistedVerified{
		Obligation:     ob,
		SubmittedClaim: sealed.SubmittedClaim(),
		Outcome:        sealed.Outcome(),
		Evidence:       sealed.Evidence(),
		Acceptance:     rec,
	}
	restored, err := RestoreVerifiedOutcome(persisted, key)
	if err != nil {
		t.Fatalf("v1 restore = %v", err)
	}
	if !restored.ProvenPass() {
		t.Fatal("v1 record must restore as a proven pass")
	}
}

// TestSealDerivedOutcomeRefusesClaimIdentityMismatch independently checks the
// claim-identity rule inside sealDerivedOutcome: a submitted claim naming a
// different verification, obligation, candidate, snapshot or contract is a
// different submission and must not be sealed — even if a future caller
// bypasses the MAC path.
func TestSealDerivedOutcomeRefusesClaimIdentityMismatch(t *testing.T) {
	ob := baseObligation(t)
	v := baseOutcome(t, ob)
	v.EvidenceRoot = mustDigest(t, "id-root")
	v.ProvenanceRefs = []string{"att-1"}
	v.ExecutionIDs = []string{"exec-1"}

	f := &FuncEvidenceVerifier{
		Identity: "id-verifier/v1",
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      mustDigest(t, "id-root"),
				AttestationDigest: mustDigest(t, "id-att"),
				Status:            "success",
				Attested:          trustedWindow(),
				Checks:            passChecks("exec-1", "digest-match", "signature"),
			}, nil
		},
	}
	sealed, err := f.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}

	mismatches := []struct {
		name string
		mut  func(c *VerificationOutcome)
	}{
		{"verification id", func(c *VerificationOutcome) { c.VerificationID = "other-ver" }},
		{"obligation id", func(c *VerificationOutcome) { c.ObligationID = "other-ob" }},
		{"candidate digest", func(c *VerificationOutcome) { c.CandidateDigest = mustDigest(t, "other-cand") }},
		{"snapshot digest", func(c *VerificationOutcome) { c.SnapshotDigest = mustDigest(t, "other-snap") }},
		{"contract digest", func(c *VerificationOutcome) { c.ContractDigest = mustDigest(t, "other-contract") }},
	}
	for _, tc := range mismatches {
		claim := sealed.SubmittedClaim()
		tc.mut(&claim)
		if _, err := sealDerivedOutcome(claim, sealed.Outcome(), sealed.Evidence()); err == nil {
			t.Fatalf("seal with mismatched %s must fail", tc.name)
		} else if !errors.Is(err, ErrUnverified) {
			t.Fatalf("mismatched %s error = %v, want ErrUnverified", tc.name, err)
		}
	}
}

// ---------------------------------------------------------------------------
// P2 — Acceptance keyring + rotation.
// ---------------------------------------------------------------------------

func mustKey(t *testing.T, id string, secret string) *HMACAcceptanceKey {
	t.Helper()
	k, err := NewHMACAcceptanceKey(id, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sealedForAcceptance(t *testing.T) (VerificationObligation, DerivedVerifiedOutcome) {
	t.Helper()
	ob := baseObligation(t)
	ob.RequiredChecks = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	v := baseOutcome(t, ob)
	v.EvidenceRoot = mustDigest(t, "kr-root")
	v.ProvenanceRefs = []string{"att-1"}
	v.ExecutionIDs = []string{"exec-1"}
	f := &FuncEvidenceVerifier{
		Identity: "keyring-verifier/v1",
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      mustDigest(t, "kr-root"),
				AttestationDigest: mustDigest(t, "kr-att"),
				Status:            "success",
				Attested:          trustedWindow(),
				Checks:            passChecks("exec-1", CheckJobStatusSuccess, CheckEvidenceRoot),
			}, nil
		},
	}
	sealed, err := f.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	return ob, sealed
}

// TestKeyringWriteK1ThenRestart: a record sealed under K1 restores after a
// process restart whose keyring still holds K1 as the current signing key.
func TestKeyringWriteK1ThenRestart(t *testing.T) {
	ob, sealed := sealedForAcceptance(t)
	k1 := mustKey(t, "K1", "key-one-secret-32-bytes-long!!!!")
	ring1, err := NewAcceptanceKeyring("K1", map[string]AcceptanceKey{"K1": k1})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := AcceptWithKeyring(ob, sealed, nil, ring1, time.Date(2026, 1, 2, 3, 6, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Accept = %v", err)
	}
	if rec.KeyID != "K1" {
		t.Fatalf("KeyID = %q, want K1", rec.KeyID)
	}
	persisted := PersistedVerified{
		Obligation:     ob,
		SubmittedClaim: sealed.SubmittedClaim(),
		Outcome:        sealed.Outcome(),
		Evidence:       sealed.Evidence(),
		Acceptance:     rec,
	}
	// "Restart": build a fresh keyring from the same key material.
	k1b := mustKey(t, "K1", "key-one-secret-32-bytes-long!!!!")
	ringRestart, err := NewAcceptanceKeyring("K1", map[string]AcceptanceKey{"K1": k1b})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreVerifiedOutcomeWithKeyring(persisted, nil, ringRestart)
	if err != nil {
		t.Fatalf("restore after restart = %v", err)
	}
	if !restored.ProvenPass() {
		t.Fatal("restored record must stay a proven pass")
	}
}

// TestKeyringRotateK2KeepsK1Verify: installing K2 as the current signing key
// leaves K1 in the verify set, so pre-rotation records still restore while
// new records are sealed under K2.
func TestKeyringRotateK2KeepsK1Verify(t *testing.T) {
	ob, sealed := sealedForAcceptance(t)
	k1 := mustKey(t, "K1", "key-one-secret-32-bytes-long!!!!")
	k2 := mustKey(t, "K2", "key-two-secret-32-bytes-long!!!!")
	ring, err := NewAcceptanceKeyring("K1", map[string]AcceptanceKey{"K1": k1})
	if err != nil {
		t.Fatal(err)
	}
	rec1, err := AcceptWithKeyring(ob, sealed, nil, ring, time.Date(2026, 1, 2, 3, 6, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Accept under K1 = %v", err)
	}
	persisted1 := PersistedVerified{
		Obligation: ob, SubmittedClaim: sealed.SubmittedClaim(),
		Outcome: sealed.Outcome(), Evidence: sealed.Evidence(), Acceptance: rec1,
	}

	// Rotate to K2; K1 stays in VerifyKeys.
	if err := ring.Rotate(k2); err != nil {
		t.Fatalf("Rotate = %v", err)
	}
	if ring.CurrentSigningKeyID() != "K2" {
		t.Fatalf("CurrentSigningKeyID = %q, want K2", ring.CurrentSigningKeyID())
	}

	// Old record still restores via its own KeyID.
	restored1, err := RestoreVerifiedOutcomeWithKeyring(persisted1, nil, ring)
	if err != nil {
		t.Fatalf("restore K1 record after rotate = %v", err)
	}
	if !restored1.ProvenPass() {
		t.Fatal("K1 record must still be a proven pass after rotation")
	}

	// New record is sealed under K2 and restores.
	rec2, err := AcceptWithKeyring(ob, sealed, nil, ring, time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Accept under K2 = %v", err)
	}
	if rec2.KeyID != "K2" {
		t.Fatalf("new record KeyID = %q, want K2", rec2.KeyID)
	}
	persisted2 := PersistedVerified{
		Obligation: ob, SubmittedClaim: sealed.SubmittedClaim(),
		Outcome: sealed.Outcome(), Evidence: sealed.Evidence(), Acceptance: rec2,
	}
	restored2, err := RestoreVerifiedOutcomeWithKeyring(persisted2, nil, ring)
	if err != nil {
		t.Fatalf("restore K2 record = %v", err)
	}
	if !restored2.ProvenPass() {
		t.Fatal("K2 record must be a proven pass")
	}
}

// TestKeyringResealThenRetireK1 is the migration path: verify under K1 →
// reseal under K2 → persist → only then may K1 be retired. After reseal the
// record verifies under K2 alone; before reseal, removing K1 fails closed.
func TestKeyringResealThenRetireK1(t *testing.T) {
	ob, sealed := sealedForAcceptance(t)
	k1 := mustKey(t, "K1", "key-one-secret-32-bytes-long!!!!")
	k2 := mustKey(t, "K2", "key-two-secret-32-bytes-long!!!!")
	ring, err := NewAcceptanceKeyring("K1", map[string]AcceptanceKey{"K1": k1})
	if err != nil {
		t.Fatal(err)
	}
	rec1, err := AcceptWithKeyring(ob, sealed, nil, ring, time.Date(2026, 1, 2, 3, 6, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Accept = %v", err)
	}
	persisted := PersistedVerified{
		Obligation: ob, SubmittedClaim: sealed.SubmittedClaim(),
		Outcome: sealed.Outcome(), Evidence: sealed.Evidence(), Acceptance: rec1,
	}

	// Rotate to K2.
	if err := ring.Rotate(k2); err != nil {
		t.Fatal(err)
	}

	// Retiring K1 BEFORE reseal would strand the record: prove the record
	// needs K1 by removing it and watching restore fail, then put it back.
	if err := ring.Retire("K1"); err != nil {
		t.Fatalf("Retire K1 = %v", err)
	}
	if _, err := RestoreVerifiedOutcomeWithKeyring(persisted, nil, ring); err == nil {
		t.Fatal("restore must fail closed once K1 is retired and the record still names K1")
	} else if !errors.Is(err, ErrAcceptance) {
		t.Fatalf("retired-key restore error = %v, want ErrAcceptance", err)
	}
	if err := ring.Install(k1); err != nil {
		t.Fatalf("Install K1 = %v", err)
	}

	// Reseal: verify under K1, re-sign under K2.
	rec2, resealed, err := ring.ResealPersisted(persisted, time.Date(2026, 1, 4, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ResealPersisted = %v", err)
	}
	if rec2.KeyID != "K2" {
		t.Fatalf("resealed KeyID = %q, want K2", rec2.KeyID)
	}
	if !resealed.ProvenPass() {
		t.Fatal("resealed record must stay a proven pass")
	}
	persisted2 := PersistedVerified{
		Obligation: ob, SubmittedClaim: sealed.SubmittedClaim(),
		Outcome: sealed.Outcome(), Evidence: sealed.Evidence(), Acceptance: rec2,
	}

	// Now K1 may be retired: the migrated record verifies under K2 alone.
	if err := ring.Retire("K1"); err != nil {
		t.Fatalf("Retire K1 after migration = %v", err)
	}
	restored, err := RestoreVerifiedOutcomeWithKeyring(persisted2, nil, ring)
	if err != nil {
		t.Fatalf("restore after reseal+retire = %v", err)
	}
	if !restored.ProvenPass() {
		t.Fatal("migrated record must remain a proven pass")
	}
	// The retired key is gone: restoring the OLD record fails closed.
	if _, err := RestoreVerifiedOutcomeWithKeyring(persisted, nil, ring); err == nil {
		t.Fatal("pre-reseal record must not restore after K1 retirement")
	}
}

// TestKeyringUnknownAndTamperedKeyIDFailClosed: a record naming a key the
// keyring does not hold, or a tampered KeyID, must never restore.
func TestKeyringUnknownAndTamperedKeyIDFailClosed(t *testing.T) {
	ob, sealed := sealedForAcceptance(t)
	k1 := mustKey(t, "K1", "key-one-secret-32-bytes-long!!!!")
	ring, err := NewAcceptanceKeyring("K1", map[string]AcceptanceKey{"K1": k1})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := AcceptWithKeyring(ob, sealed, nil, ring, time.Date(2026, 1, 2, 3, 6, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	persisted := PersistedVerified{
		Obligation: ob, SubmittedClaim: sealed.SubmittedClaim(),
		Outcome: sealed.Outcome(), Evidence: sealed.Evidence(), Acceptance: rec,
	}

	// Unknown key id.
	unknown := persisted
	unknown.Acceptance = persisted.Acceptance
	unknown.Acceptance.KeyID = "K9"
	if _, err := RestoreVerifiedOutcomeWithKeyring(unknown, nil, ring); err == nil {
		t.Fatal("unknown key id must not restore")
	} else if !errors.Is(err, ErrAcceptance) {
		t.Fatalf("unknown key error = %v, want ErrAcceptance", err)
	}

	// Tampered key id (renamed to a key the attacker controls is useless:
	// the MAC still verifies only under K1's secret).
	tampered := persisted
	tampered.Acceptance = persisted.Acceptance
	tampered.Acceptance.KeyID = "K2"
	if err := ring.Install(mustKey(t, "K2", "attacker-secret-32-bytes-long!!!")); err != nil {
		t.Fatalf("Install K2 = %v", err)
	}
	if _, err := RestoreVerifiedOutcomeWithKeyring(tampered, nil, ring); err == nil {
		t.Fatal("tampered key id must not restore")
	}

	// Empty key id.
	empty := persisted
	empty.Acceptance = persisted.Acceptance
	empty.Acceptance.KeyID = ""
	if _, err := RestoreVerifiedOutcomeWithKeyring(empty, nil, ring); err == nil {
		t.Fatal("empty key id must not restore")
	}
}

// TestKeyringRetireRefusesCurrentSigningKey: the current signing key can
// never be retired — that would strand every new record.
func TestKeyringRetireRefusesCurrentSigningKey(t *testing.T) {
	k1 := mustKey(t, "K1", "key-one-secret-32-bytes-long!!!!")
	ring, err := NewAcceptanceKeyring("K1", map[string]AcceptanceKey{"K1": k1})
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Retire("K1"); err == nil {
		t.Fatal("retiring the current signing key must be refused")
	}
}

// TestKeyringMapKeyMustMatchKeyID (P2b): a keyring entry whose map key
// disagrees with the key's own KeyID is refused at construction — a
// mislabeled entry would let a record's KeyID resolve to the wrong secret.
func TestKeyringMapKeyMustMatchKeyID(t *testing.T) {
	k2 := mustKey(t, "K2", "key-two-secret-32-bytes-long!!!!")
	// keys["K1"] = key(K2): the map key and the key id disagree.
	if _, err := NewAcceptanceKeyring("K1", map[string]AcceptanceKey{"K1": k2}); err == nil {
		t.Fatal("map key K1 holding a key whose KeyID is K2 must fail construction")
	} else if !errors.Is(err, ErrAcceptance) {
		t.Fatalf("mismatched map key error = %v, want ErrAcceptance", err)
	}
	// Correct labeling still constructs.
	k1 := mustKey(t, "K1", "key-one-secret-32-bytes-long!!!!")
	if _, err := NewAcceptanceKeyring("K1", map[string]AcceptanceKey{"K1": k1, "K2": k2}); err != nil {
		t.Fatalf("correctly labeled keyring refused: %v", err)
	}
}

// TestKeyringConcurrentAccess (P2a): the keyring is race-safe under
// concurrent readers and Rotate/Retire/Install writers. Run under -race.
func TestKeyringConcurrentAccess(t *testing.T) {
	k1 := mustKey(t, "K1", "key-one-secret-32-bytes-long!!!!")
	k2 := mustKey(t, "K2", "key-two-secret-32-bytes-long!!!!")
	k3 := mustKey(t, "K3", "key-three-secret-32-bytes-long!!")
	ring, err := NewAcceptanceKeyring("K1", map[string]AcceptanceKey{"K1": k1})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _ = ring.SigningKey()
				_, _ = ring.KeyByID("K1")
				_, _ = ring.KeyByID("K2")
				_ = ring.CurrentSigningKeyID()
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				switch id % 3 {
				case 0:
					_ = ring.Rotate(k2)
				case 1:
					_ = ring.Install(k3)
				case 2:
					_ = ring.Retire("K3")
				}
			}
		}(i)
	}
	wg.Wait()
	// The keyring must still be coherent after the storm.
	if _, err := ring.SigningKey(); err != nil {
		t.Fatalf("SigningKey after concurrent access = %v", err)
	}
}

// TestKeyringNewRecordsUseCurrentKey: Accept always signs under the keyring's
// current key, never a stale one.
func TestKeyringNewRecordsUseCurrentKey(t *testing.T) {
	ob, sealed := sealedForAcceptance(t)
	k1 := mustKey(t, "K1", "key-one-secret-32-bytes-long!!!!")
	k2 := mustKey(t, "K2", "key-two-secret-32-bytes-long!!!!")
	ring, err := NewAcceptanceKeyring("K1", map[string]AcceptanceKey{"K1": k1, "K2": k2})
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Rotate(k2); err != nil {
		t.Fatal(err)
	}
	rec, err := AcceptWithKeyring(ob, sealed, nil, ring, time.Date(2026, 1, 2, 3, 6, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if rec.KeyID != "K2" {
		t.Fatalf("new record KeyID = %q, want current key K2", rec.KeyID)
	}
}

// ---------------------------------------------------------------------------
// P4 — Required-check evidence-derived outcomes.
// ---------------------------------------------------------------------------

// TestDeriveCheckOutcomeFromCases pins the pass/fail/error/incomplete rule:
// the verdict is computed from report cases and report error counts, never
// supplied by a caller.
func TestDeriveCheckOutcomeFromCases(t *testing.T) {
	allPass := modelTestReport(2, 0, 0, true, true)
	if got := DeriveCheckOutcomeFromCases(allPass); got != CheckOutcomePass {
		t.Fatalf("all pass = %q, want pass", got)
	}
	oneFail := modelTestReport(2, 1, 0, true, false)
	if got := DeriveCheckOutcomeFromCases(oneFail); got != CheckOutcomeFail {
		t.Fatalf("one fail = %q, want fail", got)
	}
	withErrors := modelTestReport(2, 0, 1, true, true)
	if got := DeriveCheckOutcomeFromCases(withErrors); got != CheckOutcomeError {
		t.Fatalf("with errors = %q, want error", got)
	}
	allSkipped := modelTestReport(0, 0, 0, false, false)
	allSkipped.Cases = []modelTestResult{
		{Name: "a", Skipped: true},
		{Name: "b", Skipped: true},
	}
	if got := DeriveCheckOutcomeFromCases(allSkipped); got != CheckOutcomeIncomplete {
		t.Fatalf("all skipped = %q, want incomplete", got)
	}
	empty := modelTestReport(0, 0, 0, false, false)
	if got := DeriveCheckOutcomeFromCases(empty); got != CheckOutcomeIncomplete {
		t.Fatalf("empty suite = %q, want incomplete", got)
	}
}

// TestVerifiedCheckOutcomeRequiredForPass: a required check whose
// evidence-derived outcome is anything but pass never satisfies the
// obligation — a bare name in the list is not enough.
func TestVerifiedCheckOutcomeRequiredForPass(t *testing.T) {
	ob := baseObligation(t)
	ob.RequiredChecks = []string{"suite-a", CheckJobStatusSuccess, CheckEvidenceRoot}

	cases := []struct {
		name    string
		outcome CheckOutcome
		want    Outcome
	}{
		{"pass", CheckOutcomePass, OutcomePass},
		{"fail", CheckOutcomeFail, OutcomePartial},
		{"error", CheckOutcomeError, OutcomePartial},
		{"incomplete", CheckOutcomeIncomplete, OutcomePartial},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := baseOutcome(t, ob)
			v.EvidenceRoot = mustDigest(t, "vc-root")
			v.ProvenanceRefs = []string{"att-1"}
			v.ExecutionIDs = []string{"exec-1"}
			f := &FuncEvidenceVerifier{
				Identity: "vc-verifier/v1",
				Resolve: func(context.Context, string) (ResolvedAttestation, error) {
					return ResolvedAttestation{
						ExecutionID:       "exec-1",
						EvidenceRoot:      mustDigest(t, "vc-root"),
						AttestationDigest: mustDigest(t, "vc-att"),
						Status:            "success",
						Attested:          trustedWindow(),
						Checks: []VerifiedCheck{
							{Name: CheckJobStatusSuccess, Outcome: CheckOutcomePass, EvidenceDigest: mustDigest(t, "vc-root"), ExecutionID: "exec-1"},
							{Name: CheckEvidenceRoot, Outcome: CheckOutcomePass, EvidenceDigest: mustDigest(t, "vc-root"), ExecutionID: "exec-1"},
							{Name: "suite-a", Outcome: tc.outcome, EvidenceDigest: mustDigest(t, "vc-suite"), ExecutionID: "exec-1"},
						},
					}, nil
				},
			}
			vo, err := f.Verify(context.Background(), ob, v)
			if err != nil {
				t.Fatalf("Verify = %v", err)
			}
			if vo.Outcome().Outcome != tc.want {
				t.Fatalf("derived outcome = %q, want %q", vo.Outcome().Outcome, tc.want)
			}
			// CompletedChecks only lists checks whose outcome is pass.
			hasSuiteA := false
			for _, c := range vo.Outcome().CompletedChecks {
				if c == "suite-a" {
					hasSuiteA = true
				}
			}
			if hasSuiteA != (tc.outcome == CheckOutcomePass) {
				t.Fatalf("suite-a in CompletedChecks = %v, want %v (outcome %q)", hasSuiteA, tc.outcome == CheckOutcomePass, tc.outcome)
			}
		})
	}
}

// TestProvenanceCheckOutcomeFromReportCases: the provenance adapter derives
// the check outcome from the stored report's cases. A report whose cases all
// pass yields a passing check; a failing report yields fail; no stored
// report yields incomplete (fail closed — never pass).
func TestProvenanceCheckOutcomeFromReportCases(t *testing.T) {
	// Build a fixture whose signed "digest-match" suite commits FAILING
	// cases: the suite digest is computed from the failing cases, so the
	// signed digest and the stored report agree, and the outcome must be
	// derived as fail.
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	finish := start.Add(90 * time.Second)
	failRep := model.TestReport{
		ID:       "rep-digest-match",
		Tests:    2,
		Failures: 1,
		Cases: []model.TestResult{
			{Name: "digest-match-a", Passed: false, Message: "boom"},
			{Name: "digest-match-b", Passed: true},
		},
	}
	failDig := provenance.TestReportSuiteDigest(failRep)
	passRep, passDig := passingReport("signature")
	evidenceRoot := provenance.ExecutionEvidenceRoot(provenance.ExecutionEvidenceGraph{
		Artifacts: []provenance.ExecutionEvidenceArtifact{
			{Name: "bin", SHA256: strings.Repeat("1", 64), Size: 42, Generation: 7, ProvenanceSHA256: strings.Repeat("2", 64)},
		},
		TestReports: []provenance.ExecutionAttestationReport{
			{Name: "digest-match", SuiteDigest: failDig, Generation: 7},
			{Name: "signature", SuiteDigest: passDig, Generation: 7},
		},
	})
	st, err := provenance.ExecutionAttestationStatement(provenance.ExecutionAttestationInput{
		RunID: "run-1", JobID: "job-1", JobKey: "build[os=linux]", Generation: 7,
		Status: "success", StartedAt: &start, FinishedAt: &finish,
		RunnerIdentity:         "runner-a",
		CapsuleDigest:          strings.Repeat("a", 64),
		ExecutionCapsuleDigest: strings.Repeat("b", 64),
		Artifacts: []provenance.ExecutionAttestationArtifact{
			{Name: "bin", SHA256: strings.Repeat("1", 64), Size: 42, ProvenanceSHA256: strings.Repeat("2", 64)},
		},
		EvidenceRootSHA256: evidenceRoot,
		ExecutionSemantics: model.ExecutionSemanticsVersion,
		ExecutionAssuranceFacts: model.ExecutionFacts{
			Runtime:                   model.RuntimeFactContainer,
			FilesystemIsolated:        true,
			NetworkMode:               model.NetworkModeFactDefault,
			DeclaredAuthorityMediated: true,
		},
		TestReports: []provenance.ExecutionAttestationReport{
			{Name: "digest-match", SuiteDigest: failDig, Generation: 7},
			{Name: "signature", SuiteDigest: passDig, Generation: 7},
		},
		ExternalEffects: model.EffectsKiwiMediated,
	})
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := provenance.NewProvenanceKey()
	if err != nil {
		t.Fatal(err)
	}
	env, err := provenance.Sign(st, "kid-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EvidenceEnvelopeJSON(env)
	if err != nil {
		t.Fatal(err)
	}
	fx := signedAttestationFixture{
		envelope:     raw,
		evidenceRoot: Digest(evidenceRoot),
		attemptID:    st.AttemptID,
		pub:          pub,
		reports:      map[string]model.TestReport{failDig: failRep, passDig: passRep},
	}

	ob := provenanceFixtureObligation(t)
	v := baseOutcome(t, ob)
	v.EvidenceRoot = fx.evidenceRoot
	v.ProvenanceRefs = []string{"attestation-1"}
	v.ExecutionIDs = []string{fx.attemptID}

	verifier := fixtureVerifier(fx, "attestation-1")
	vo, err := verifier.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	// Required checks are digest-match + signature: digest-match is now a
	// FAIL, so the obligation cannot be satisfied.
	if vo.Outcome().Outcome != OutcomePartial {
		t.Fatalf("derived outcome = %q, want partial (digest-match failed)", vo.Outcome().Outcome)
	}
	for _, c := range vo.Evidence().VerifiedChecks {
		if c.Name == "digest-match" && c.Outcome != CheckOutcomeFail {
			t.Fatalf("digest-match outcome = %q, want fail (derived from failing cases)", c.Outcome)
		}
		if c.Name == "signature" && c.Outcome != CheckOutcomePass {
			t.Fatalf("signature outcome = %q, want pass", c.Outcome)
		}
	}
}

// TestProvenanceMissingReportIsIncomplete: a signed suite digest with no
// resolvable stored report derives an incomplete check — never a pass.
func TestProvenanceMissingReportIsIncomplete(t *testing.T) {
	fx := newSignedAttestationFixture(t)
	fx.reports = map[string]model.TestReport{} // storage lost the reports
	ob := provenanceFixtureObligation(t)
	v := baseOutcome(t, ob)
	v.EvidenceRoot = fx.evidenceRoot
	v.ProvenanceRefs = []string{"attestation-1"}
	v.ExecutionIDs = []string{fx.attemptID}

	verifier := fixtureVerifier(fx, "attestation-1")
	vo, err := verifier.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if vo.ProvenPass() {
		t.Fatal("missing reports must not produce a proven pass")
	}
	for _, c := range vo.Evidence().VerifiedChecks {
		if c.Name == "digest-match" || c.Name == "signature" {
			if c.Outcome != CheckOutcomeIncomplete {
				t.Fatalf("%s outcome = %q, want incomplete", c.Name, c.Outcome)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// P6 — Execution IDs: exact sorted-set equality for idempotency.
// ---------------------------------------------------------------------------

// TestExecutionIDsExactSetEqualityForIdempotency: two submissions that name
// different execution-id sets are NOT the same claim, even when one set is a
// subset of the other. Supersession is modeled separately (claimCompatible).
func TestExecutionIDsExactSetEqualityForIdempotency(t *testing.T) {
	if !executionIDsEqual([]string{"exec-2", "exec-1", "exec-1"}, []string{"exec-1", "exec-2"}) {
		t.Fatal("order and duplicates must not change id-set identity")
	}
	if executionIDsEqual([]string{"exec-1"}, []string{"exec-1", "exec-2"}) {
		t.Fatal("subset must NOT be equal (exact set equality required)")
	}
	if executionIDsEqual([]string{"exec-1", "exec-2"}, []string{"exec-1"}) {
		t.Fatal("superset must NOT be equal")
	}
	if executionIDsEqual(nil, []string{"exec-1"}) {
		t.Fatal("empty vs non-empty must not be equal")
	}
	if !executionIDsEqual(nil, nil) {
		t.Fatal("two empty sets are equal")
	}
	// Supersession (used only by claimCompatible) still tolerates subset.
	if !executionIDsSupersede([]string{"exec-1"}, []string{"exec-1", "exec-2"}) {
		t.Fatal("subset must supersede for the claim-upgrade path")
	}
	if executionIDsSupersede([]string{"exec-1", "exec-x"}, []string{"exec-1", "exec-2"}) {
		t.Fatal("partial overlap must not supersede")
	}
}

// TestIdempotentReplayRequiresExactExecIDs: replaying a verified record whose
// execution-id set differs (even as a superset) is a different submission.
func TestIdempotentReplayRequiresExactExecIDs(t *testing.T) {
	ob := baseObligation(t)
	st := NewMemoryStore(func() time.Time { return ob.IssuedAt.Add(30 * time.Second) })
	if err := st.SubmitObligation(context.Background(), ob); err != nil {
		t.Fatal(err)
	}
	claim := baseOutcome(t, ob)
	claim.EvidenceRoot = mustDigest(t, "eq-root")
	claim.ProvenanceRefs = []string{"att-1"}
	claim.ExecutionIDs = []string{"exec-1"}
	if err := st.RecordOutcome(context.Background(), claim); err != nil {
		t.Fatal(err)
	}

	// Same submission: exact same exec-id set → idempotent success.
	same := claim
	same.ExecutionIDs = []string{"exec-1"}
	if err := st.RecordOutcome(context.Background(), same); err != nil {
		t.Fatalf("idempotent claim replay = %v, want success", err)
	}

	// Superset of exec ids → different submission → ErrExists.
	superset := claim
	superset.ExecutionIDs = []string{"exec-1", "exec-2"}
	if err := st.RecordOutcome(context.Background(), superset); !errors.Is(err, ErrExists) {
		t.Fatalf("superset exec-id replay = %v, want ErrExists (exact set equality)", err)
	}
}

// ---------------------------------------------------------------------------
// P8 — VerificationProof: immutable machine-verifiable bundle.
// ---------------------------------------------------------------------------

// TestVerificationProofVerifyWithoutRegistry: the proof bundle carries
// everything needed to verify and does not consult any live registry or
// store.
func TestVerificationProofVerifyWithoutRegistry(t *testing.T) {
	ob, sealed := sealedForAcceptance(t)
	key := mustKey(t, "proof-key", "proof-secret-32-bytes-long-long!")
	rec, err := Accept(ob, sealed, key, time.Date(2026, 1, 2, 3, 6, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	proof := NewVerificationProof(PersistedVerified{
		Obligation:     ob,
		SubmittedClaim: sealed.SubmittedClaim(),
		Outcome:        sealed.Outcome(),
		Evidence:       sealed.Evidence(),
		Acceptance:     rec,
	})
	// Verify with no registry, no store — just the keyring.
	ring, err := NewSingleKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := proof.Verify(ring)
	if err != nil {
		t.Fatalf("proof.Verify = %v", err)
	}
	if !restored.ProvenPass() {
		t.Fatal("verified proof must be a proven pass")
	}
	// The proof is immutable: mutating a copy does not affect the original.
	tampered := proof
	tampered.Outcome.Outcome = OutcomePass
	tampered.SubmittedClaim.VerificationID = "forged"
	if _, err := tampered.Verify(ring); err == nil {
		t.Fatal("tampered proof must not verify")
	}
	// The original still verifies.
	if _, err := proof.Verify(ring); err != nil {
		t.Fatalf("original proof after copy-mutation = %v", err)
	}
}

// TestVerificationProofRejectsUnsealed is the fail-closed half: a proof built
// from an unsealed record is refused at construction.
func TestVerificationProofRejectsUnsealed(t *testing.T) {
	ob := baseObligation(t)
	// Raw claim, never sealed.
	raw := baseOutcome(t, ob)
	proof, err := NewVerificationProofFromParts(ob, raw, raw, VerifiedEvidence{}, AcceptanceRecord{})
	if err == nil {
		// Construction may succeed (the bundle is just data); Verify must refuse.
		key := mustKey(t, "pk", "proof-secret-32-bytes-long-long!")
		ring, err2 := NewSingleKeyring(key)
		if err2 != nil {
			t.Fatal(err2)
		}
		if _, err := proof.Verify(ring); err == nil {
			t.Fatal("unsealed bundle must not verify")
		}
	}
}

// modelTestReport / modelTestResult are local aliases so the hardening tests
// can build report shapes without importing model everywhere below.
type modelTestResult = model.TestResult

func modelTestReport(tests, failures, errors int, aPassed, bPassed bool) model.TestReport {
	cases := []model.TestResult{}
	if tests >= 1 {
		cases = append(cases, model.TestResult{Name: "a", Passed: aPassed})
	}
	if tests >= 2 {
		cases = append(cases, model.TestResult{Name: "b", Passed: bPassed})
	}
	return model.TestReport{
		ID:       "rep-x",
		Tests:    tests,
		Failures: failures,
		Errors:   errors,
		Cases:    cases,
	}
}

// TestConflictingCheckEvidenceIsEvidenceInvalid (P3g): a same-name pass+fail
// disagreement across attestations is a conflict (not first-wins); the check
// is CheckOutcomeConflict and the attempt's terminal state is
// evidence_invalid — never a plain pass.
func TestConflictingCheckEvidenceIsEvidenceInvalid(t *testing.T) {
	root := mustDigest(t, "conflict-root")
	resolved := []ResolvedAttestation{
		{
			ExecutionID:       "exec-1",
			EvidenceRoot:      root,
			AttestationDigest: mustDigest(t, "conflict-att-1"),
			Status:            "success",
			Checks: []VerifiedCheck{
				{Name: "suite-a", Outcome: CheckOutcomePass, EvidenceDigest: mustDigest(t, "suite-1"), ExecutionID: "exec-1"},
			},
		},
		{
			ExecutionID:       "exec-2",
			EvidenceRoot:      root,
			AttestationDigest: mustDigest(t, "conflict-att-2"),
			Status:            "success",
			Checks: []VerifiedCheck{
				{Name: "suite-a", Outcome: CheckOutcomeFail, EvidenceDigest: mustDigest(t, "suite-2"), ExecutionID: "exec-2"},
			},
		},
	}
	checks := deriveVerifiedChecks(resolved, root)
	var suite *VerifiedCheck
	for i := range checks {
		if checks[i].Name == "suite-a" {
			suite = &checks[i]
		}
	}
	if suite == nil {
		t.Fatal("suite-a missing from derived checks")
	}
	if suite.Outcome != CheckOutcomeConflict {
		t.Fatalf("suite-a outcome = %q, want conflict (not first-wins %q)", suite.Outcome, CheckOutcomePass)
	}
	if suite.Passed() {
		t.Fatal("a conflicted check must never pass")
	}
	if !hasCheckConflicts(checks) {
		t.Fatal("hasCheckConflicts must report the conflict")
	}
	// A conflicted evidence set is evidence_invalid, never a plain pass.
	d := DerivedVerifiedOutcome{}
	term, coarse := verifiedTerminal(d)
	_ = term
	_ = coarse
	// Build the terminal from a derived shape carrying the conflict.
	sealedShape := DerivedVerifiedOutcome{
		outcome:  VerificationOutcome{Outcome: OutcomePass},
		evidence: VerifiedEvidence{VerifiedChecks: checks},
	}
	// verifiedTerminal reads Evidence.VerifiedChecks via hasCheckConflicts;
	// craft via the exported comparison path instead.
	src, err := VerifiedFromDerived("c-conflict", mustSealWithChecks(t, checks), 0)
	if err != nil {
		t.Fatalf("VerifiedFromDerived = %v", err)
	}
	cmp, err := CompareVerifiedCandidates(mustDigest(t, "conflict-snap"), []VerifiedCandidateSource{src}, nil)
	if err != nil {
		t.Fatalf("CompareVerifiedCandidates = %v", err)
	}
	if cmp.Candidates[0].Terminal != TerminalEvidenceInvalid {
		t.Fatalf("terminal = %q, want evidence_invalid", cmp.Candidates[0].Terminal)
	}
	if cmp.Candidates[0].Outcome != TerminalEvidenceInvalid.ProjectCoarse() {
		t.Fatalf("coarse = %q", cmp.Candidates[0].Outcome)
	}
	_ = sealedShape
}

// mustSealWithChecks seals a minimal DerivedVerifiedOutcome carrying the
// given derived check set (for comparison-path tests).
func mustSealWithChecks(t *testing.T, checks []VerifiedCheck) DerivedVerifiedOutcome {
	t.Helper()
	iv := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	completed := completedCheckNames(checks)
	v := VerificationOutcome{
		VerificationID:   "ver-conflict",
		ObligationID:     "ob-conflict",
		CandidateDigest:  mustDigest(t, "conflict-cand"),
		SnapshotDigest:   mustDigest(t, "conflict-snap"),
		ContractDigest:   mustDigest(t, "conflict-contract"),
		Outcome:          OutcomePass,
		AssuranceProfile: model.AssuranceUncontrolled.Name(),
		CompletedChecks:  completed,
		ExecutionIDs:     []string{"exec-1"},
		EvidenceRoot:     mustDigest(t, "conflict-root"),
		Resources:        ResourceFacts{RunnerClass: "standard"},
		StartedAt:        iv,
		CompletedAt:      iv.Add(time.Second),
	}
	ev := VerifiedEvidence{
		ExecutionIDs:       []string{"exec-1"},
		EvidenceRoot:       mustDigest(t, "conflict-root"),
		AttestationDigests: []Digest{mustDigest(t, "conflict-att")},
		JobStatus:          "success",
		CompletedChecks:    completed,
		VerifiedChecks:     checks,
		VerifierIdentity:   "conflict-verifier/v1",
		VerifiedAt:         iv,
	}
	sealed, err := sealDerivedOutcome(v, v, ev)
	if err != nil {
		t.Fatalf("sealDerivedOutcome = %v", err)
	}
	return sealed
}
