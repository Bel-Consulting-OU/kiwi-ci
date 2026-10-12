package verifyapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/provenance"
)

// signedAttestationFixture builds a REAL signed execution attestation: the
// evidence root is computed from the artifact-side evidence graph with
// provenance.ExecutionEvidenceRoot, the statement is built with
// provenance.ExecutionAttestationStatement, and the envelope is Ed25519-signed.
// The returned evidence root, attempt id and envelope bytes are what the
// verifier must cryptographically resolve.
type signedAttestationFixture struct {
	envelope     []byte
	evidenceRoot Digest
	attemptID    string
	pub          ed25519.PublicKey
	priv         ed25519.PrivateKey
}

func newSignedAttestationFixture(t *testing.T) signedAttestationFixture {
	t.Helper()
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	finish := start.Add(90 * time.Second)

	// The evidence root binds the FULL artifact-side evidence graph.
	evidenceRoot := provenance.ExecutionEvidenceRoot(provenance.ExecutionEvidenceGraph{
		Artifacts: []provenance.ExecutionEvidenceArtifact{
			{Name: "bin", SHA256: strings.Repeat("1", 64), Size: 42, Generation: 7, ProvenanceSHA256: strings.Repeat("2", 64)},
		},
		TestReports: []provenance.ExecutionAttestationReport{
			{Name: "test", SuiteDigest: strings.Repeat("3", 64), Generation: 7},
		},
		Snapshots: []provenance.ExecutionAttestationSnapshot{
			{ID: "snap-1", Phase: model.SnapshotPhasePreJob, SHA256: strings.Repeat("4", 64), Generation: 7},
		},
	})
	if err := validateDigest("fixture evidence root", Digest(evidenceRoot)); err != nil {
		t.Fatalf("fixture evidence root is not a digest: %v", err)
	}

	st, err := provenance.ExecutionAttestationStatement(provenance.ExecutionAttestationInput{
		RunID:                  "run-1",
		JobID:                  "job-1",
		JobKey:                 "build[os=linux]",
		Generation:             7,
		Status:                 "success",
		StartedAt:              &start,
		FinishedAt:             &finish,
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
		ExternalEffects: model.EffectsKiwiMediated,
	})
	if err != nil {
		t.Fatalf("build attestation statement: %v", err)
	}
	pub, priv, err := provenance.NewProvenanceKey()
	if err != nil {
		t.Fatalf("new provenance key: %v", err)
	}
	env, err := provenance.Sign(st, "kid-1", priv)
	if err != nil {
		t.Fatalf("sign attestation: %v", err)
	}
	raw, err := EvidenceEnvelopeJSON(env)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	return signedAttestationFixture{
		envelope:     raw,
		evidenceRoot: Digest(evidenceRoot),
		attemptID:    st.AttemptID,
		pub:          pub,
		priv:         priv,
	}
}

func fixtureVerifier(fx signedAttestationFixture, ref string) *ProvenanceEvidenceVerifier {
	return &ProvenanceEvidenceVerifier{
		Identity: "verifyapi-test-verifier/v1",
		Resolve: func(_ context.Context, got string) ([]byte, error) {
			if got != ref {
				return nil, errors.New("unknown evidence ref")
			}
			return fx.envelope, nil
		},
		TrustedKey: fx.pub,
	}
}

// TestRawPassWithFakeEvidenceRootIsNotAuthoritative is the P1 negative half:
// a caller can submit Result=pass with matching digests and an arbitrary
// evidence_root. Structural binding accepts the claim, but the claim is never
// authoritative — QueryOutcome refuses it as a proven pass, and
// RecordVerifiedOutcome refuses an unsealed value outright.
func TestRawPassWithFakeEvidenceRootIsNotAuthoritative(t *testing.T) {
	ob := baseObligation(t)
	reg := NewRegistry(func() time.Time { return ob.IssuedAt.Add(30 * time.Second) })
	if err := reg.SubmitObligation(ob); err != nil {
		t.Fatalf("SubmitObligation = %v", err)
	}

	v := baseOutcome(t, ob)
	// A well-formed but fake evidence root: structurally valid, matches no
	// attestation, and was never cryptographically resolved.
	v.EvidenceRoot = mustDigest(t, "fake-evidence-root")
	v.ProvenanceRefs = []string{"forged-ref"}
	v.ExecutionIDs = []string{"exec-1"}

	if err := reg.RecordOutcome(v); err != nil {
		t.Fatalf("RecordOutcome claim = %v (claims are kept)", err)
	}

	if _, err := reg.QueryOutcome(v.VerificationID); !errors.Is(err, ErrUnverified) {
		t.Fatalf("QueryOutcome on raw claim = %v, want ErrUnverified (must NOT be a proven pass)", err)
	}

	// The zero (unsealed) VerifiedOutcome is not server-created authority.
	if err := reg.RecordVerifiedOutcome(VerifiedOutcome{Outcome: v}); !errors.Is(err, ErrUnverified) {
		t.Fatalf("RecordVerifiedOutcome unsealed = %v, want ErrUnverified", err)
	}

	// A claim stays readable as a claim, and still does not discharge.
	got, err := reg.Outcome(v.VerificationID)
	if err != nil {
		t.Fatalf("Outcome(claim) = %v", err)
	}
	if got.Outcome != OutcomePass {
		t.Fatalf("claim outcome = %v, want pass stored as claim", got.Outcome)
	}
}

// TestVerifiedOutcomeWithRealProvenanceFixtureIsAuthoritative is the P1
// positive half: a real signed execution attestation (Ed25519 DSSE + attested
// evidence root) is resolved by the provenance-backed adapter, and only then
// does the outcome satisfy QueryOutcome as a proven pass.
func TestVerifiedOutcomeWithRealProvenanceFixtureIsAuthoritative(t *testing.T) {
	fx := newSignedAttestationFixture(t)
	ob := baseObligation(t)
	reg := NewRegistry(func() time.Time { return ob.IssuedAt.Add(30 * time.Second) })
	if err := reg.SubmitObligation(ob); err != nil {
		t.Fatalf("SubmitObligation = %v", err)
	}

	v := baseOutcome(t, ob)
	v.EvidenceRoot = fx.evidenceRoot
	v.ProvenanceRefs = []string{"attestation-1"}
	v.ExecutionIDs = []string{fx.attemptID}

	verifier := fixtureVerifier(fx, "attestation-1")
	vo, err := verifier.Verify(context.Background(), v)
	if err != nil {
		t.Fatalf("Verify real provenance fixture = %v", err)
	}
	if !vo.Sealed() {
		t.Fatal("verified outcome is not sealed")
	}
	if !vo.ProvenPass() {
		t.Fatalf("ProvenPass = false, want true (outcome %q)", vo.Outcome.Outcome)
	}
	if vo.Evidence.VerifierIdentity != "verifyapi-test-verifier/v1" {
		t.Fatalf("verifier identity = %q", vo.Evidence.VerifierIdentity)
	}
	if vo.Evidence.EvidenceRoot != fx.evidenceRoot {
		t.Fatalf("resolved evidence root = %s, want %s", vo.Evidence.EvidenceRoot, fx.evidenceRoot)
	}
	if len(vo.Evidence.AttestationDigests) != 1 || vo.Evidence.AttestationDigests[0] == "" {
		t.Fatalf("attestation digests = %v, want one real digest", vo.Evidence.AttestationDigests)
	}
	if len(vo.Evidence.ExecutionIDs) != 1 || vo.Evidence.ExecutionIDs[0] != fx.attemptID {
		t.Fatalf("resolved execution ids = %v, want [%s]", vo.Evidence.ExecutionIDs, fx.attemptID)
	}

	if err := reg.RecordVerifiedOutcome(vo); err != nil {
		t.Fatalf("RecordVerifiedOutcome = %v", err)
	}
	got, err := reg.QueryOutcome(v.VerificationID)
	if err != nil {
		t.Fatalf("QueryOutcome = %v, want authoritative record", err)
	}
	if !got.ProvenPass() {
		t.Fatal("QueryOutcome did not return a proven pass")
	}
	if got.Evidence.AttestationDigests[0] != vo.Evidence.AttestationDigests[0] {
		t.Fatal("stored attestation digest drifted")
	}
}

// TestRecordVerifiedOutcomeFillsAttestedWallTime proves the measured facts
// gain a second, attested quantity: when the resolved execution attestation
// carries a job window (started_at/finished_at), the registry fills
// Measured.WallTimeNS from those signed facts — while DurationNS stays the
// derived outcome window and cannot be caller-inflated.
func TestRecordVerifiedOutcomeFillsAttestedWallTime(t *testing.T) {
	fx := newSignedAttestationFixture(t)
	ob := baseObligation(t)
	reg := NewRegistry(func() time.Time { return ob.IssuedAt.Add(30 * time.Second) })
	if err := reg.SubmitObligation(ob); err != nil {
		t.Fatalf("SubmitObligation = %v", err)
	}

	v := baseOutcome(t, ob)
	v.EvidenceRoot = fx.evidenceRoot
	v.ProvenanceRefs = []string{"attestation-1"}
	v.ExecutionIDs = []string{fx.attemptID}
	// Dishonest reporter attempts to inflate both measured quantities.
	v.Resources.Measured = &MeasuredResourceFacts{DurationNS: 1 << 40, WallTimeNS: 1 << 40}

	verifier := fixtureVerifier(fx, "attestation-1")
	vo, err := verifier.Verify(context.Background(), v)
	if err != nil {
		t.Fatalf("Verify real provenance fixture = %v", err)
	}
	if vo.Evidence.Attested == nil {
		t.Fatal("verified evidence has no attested facts; the fixture carries a job window")
	}
	// The fixture attestation binds a 90s job window (started_at →
	// finished_at) — that is the number that must surface, not the caller's.
	const wantWallNS = int64(90 * time.Second)
	if vo.Evidence.Attested.WallTimeNS() != wantWallNS {
		t.Fatalf("attested wall time = %d, want %d", vo.Evidence.Attested.WallTimeNS(), wantWallNS)
	}

	if err := reg.RecordVerifiedOutcome(vo); err != nil {
		t.Fatalf("RecordVerifiedOutcome = %v", err)
	}
	got, err := reg.QueryOutcome(v.VerificationID)
	if err != nil {
		t.Fatalf("QueryOutcome = %v", err)
	}
	m := got.Outcome.Resources.Measured
	if m == nil {
		t.Fatal("Measured is nil after verified record")
	}
	wantDerived := v.CompletedAt.Sub(v.StartedAt).Nanoseconds()
	if m.DurationNS != wantDerived {
		t.Fatalf("Measured.DurationNS = %d, want derived %d", m.DurationNS, wantDerived)
	}
	if m.WallTimeNS != wantWallNS {
		t.Fatalf("Measured.WallTimeNS = %d, want attested %d", m.WallTimeNS, wantWallNS)
	}
}

// TestMeasuredWallTimeUnfilledWithoutAttestedWindow: an attestation that
// carries no job window resolves without attested facts, so the measured wall
// time stays zero rather than being guessed from the claim.
func TestMeasuredWallTimeUnfilledWithoutAttestedWindow(t *testing.T) {
	ob := baseObligation(t)
	v := baseOutcome(t, ob)
	v.ExecutionIDs = v.ExecutionIDs[:1]
	root := v.EvidenceRoot
	v.ProvenanceRefs = []string{"bare-att"}
	f := &FuncEvidenceVerifier{
		Identity: "verifyapi-bare-verifier/v1",
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       v.ExecutionIDs[0],
				EvidenceRoot:      root,
				AttestationDigest: mustDigest(t, "bare-att-digest"),
				// No Attested facts: older statements carry no job window.
			}, nil
		},
	}
	vo, err := f.Verify(context.Background(), v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if vo.Evidence.Attested != nil {
		t.Fatalf("Attested = %+v, want nil when the attestation carries no window", vo.Evidence.Attested)
	}
	if m := DeriveMeasuredFacts(vo.Outcome, vo.Evidence.Attested); m.WallTimeNS != 0 {
		t.Fatalf("Measured.WallTimeNS = %d, want 0 without attested facts", m.WallTimeNS)
	}
}

// TestMergeAttestedFailsClosedOnPartialFacts: a mixed evidence set (some
// attestations with a window, some without) must not produce a partially
// attested wall time — the merged facts are dropped entirely.
func TestMergeAttestedFailsClosedOnPartialFacts(t *testing.T) {
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	finish := start.Add(time.Minute)
	withFacts := ResolvedAttestation{Attested: &AttestedResourceFacts{StartedAt: start, FinishedAt: finish}}
	withoutFacts := ResolvedAttestation{}

	if got := mergeAttested([]ResolvedAttestation{withFacts, withoutFacts}); got != nil {
		t.Fatalf("mergeAttested(partial) = %+v, want nil", got)
	}
	if got := mergeAttested([]ResolvedAttestation{withoutFacts}); got != nil {
		t.Fatalf("mergeAttested(no facts) = %+v, want nil", got)
	}
	inverted := ResolvedAttestation{Attested: &AttestedResourceFacts{StartedAt: finish, FinishedAt: start}}
	if got := mergeAttested([]ResolvedAttestation{inverted}); got != nil {
		t.Fatalf("mergeAttested(inverted) = %+v, want nil", got)
	}
	// Two complete windows merge to their envelope (earliest start, latest finish).
	second := ResolvedAttestation{Attested: &AttestedResourceFacts{
		StartedAt:  start.Add(30 * time.Second),
		FinishedAt: finish.Add(30 * time.Second),
	}}
	got := mergeAttested([]ResolvedAttestation{withFacts, second})
	if got == nil {
		t.Fatal("mergeAttested(two windows) = nil, want envelope")
	}
	if !got.StartedAt.Equal(start) || !got.FinishedAt.Equal(finish.Add(30*time.Second)) {
		t.Fatalf("merged window = [%s, %s], want [%s, %s]", got.StartedAt, got.FinishedAt, start, finish.Add(30*time.Second))
	}
}

// TestVerifiedOutcomeWithContractAttestationV6Fixture proves the committed
// historical contract fixture (testdata/contracts/attestation_v6.json) can be
// signed and resolved end-to-end through the acceptance boundary.
func TestVerifiedOutcomeWithContractAttestationV6Fixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", "attestation_v6.json"))
	if err != nil {
		t.Fatalf("read attestation_v6 fixture: %v", err)
	}
	var st provenance.Statement
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("parse attestation_v6 fixture: %v", err)
	}
	if st.Attestation == nil {
		t.Fatal("fixture has no attestation block")
	}
	pub, priv, err := provenance.NewProvenanceKey()
	if err != nil {
		t.Fatalf("new provenance key: %v", err)
	}
	env, err := provenance.Sign(st, "kid-6", priv)
	if err != nil {
		t.Fatalf("sign fixture statement: %v", err)
	}
	envBytes, err := EvidenceEnvelopeJSON(env)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}

	root := Digest(st.Attestation.EvidenceRootSHA256)
	ob := baseObligation(t)
	reg := NewRegistry(func() time.Time { return ob.IssuedAt.Add(30 * time.Second) })
	if err := reg.SubmitObligation(ob); err != nil {
		t.Fatalf("SubmitObligation = %v", err)
	}

	v := baseOutcome(t, ob)
	v.EvidenceRoot = root
	v.ProvenanceRefs = []string{"contract-fixture-attestation-v6"}
	v.ExecutionIDs = []string{st.Attestation.AttemptID}

	verifier := &ProvenanceEvidenceVerifier{
		Identity: "verifyapi-contract-verifier/v1",
		Resolve: func(_ context.Context, ref string) ([]byte, error) {
			if ref != "contract-fixture-attestation-v6" {
				return nil, errors.New("unknown ref")
			}
			return envBytes, nil
		},
		TrustedKey: pub,
	}
	vo, err := verifier.Verify(context.Background(), v)
	if err != nil {
		t.Fatalf("Verify attestation_v6 fixture = %v", err)
	}
	if vo.Evidence.EvidenceRoot != root {
		t.Fatalf("resolved root = %s, want fixture %s", vo.Evidence.EvidenceRoot, root)
	}
	if err := reg.RecordVerifiedOutcome(vo); err != nil {
		t.Fatalf("RecordVerifiedOutcome = %v", err)
	}
	got, err := reg.QueryOutcome(v.VerificationID)
	if err != nil {
		t.Fatalf("QueryOutcome = %v", err)
	}
	if !got.ProvenPass() {
		t.Fatal("fixture-backed outcome is not a proven pass")
	}
}

// TestEvidenceVerifierRefusesFakeRootLaundering proves the verifier will not
// seal a pass whose claimed evidence_root disagrees with what the signatures
// prove — the fake-root laundering path is closed before anything is stored.
func TestEvidenceVerifierRefusesFakeRootLaundering(t *testing.T) {
	fx := newSignedAttestationFixture(t)
	ob := baseObligation(t)
	v := baseOutcome(t, ob)
	v.EvidenceRoot = mustDigest(t, "totally-fake-root")
	v.ProvenanceRefs = []string{"attestation-1"}
	v.ExecutionIDs = []string{fx.attemptID}

	verifier := fixtureVerifier(fx, "attestation-1")
	if _, err := verifier.Verify(context.Background(), v); !errors.Is(err, ErrEvidence) {
		t.Fatalf("Verify fake root = %v, want ErrEvidence", err)
	}
}

// TestEvidenceVerifierRefusesClaimedUnboundExecutionID: a claimed execution
// id that no verified attestation binds is refused.
func TestEvidenceVerifierRefusesClaimedUnboundExecutionID(t *testing.T) {
	fx := newSignedAttestationFixture(t)
	ob := baseObligation(t)
	v := baseOutcome(t, ob)
	v.EvidenceRoot = fx.evidenceRoot
	v.ProvenanceRefs = []string{"attestation-1"}
	v.ExecutionIDs = []string{fx.attemptID, "forged-exec"}

	verifier := fixtureVerifier(fx, "attestation-1")
	if _, err := verifier.Verify(context.Background(), v); !errors.Is(err, ErrEvidence) {
		t.Fatalf("Verify forged execution id = %v, want ErrEvidence", err)
	}
}

// TestEvidenceVerifierRefusesUnsignedOrTamperedEnvelope: no signature, or a
// tampered payload, never resolves to evidence.
func TestEvidenceVerifierRefusesUnsignedOrTamperedEnvelope(t *testing.T) {
	fx := newSignedAttestationFixture(t)
	ob := baseObligation(t)

	t.Run("tampered payload", func(t *testing.T) {
		var env provenance.Envelope
		if err := json.Unmarshal(fx.envelope, &env); err != nil {
			t.Fatal(err)
		}
		// Flip a byte in the signed payload: the signature must fail.
		payload := []byte(env.Payload)
		if len(payload) == 0 {
			t.Fatal("empty payload")
		}
		if payload[len(payload)-1] == 'A' {
			payload[len(payload)-1] = 'B'
		} else {
			payload[len(payload)-1] = 'A'
		}
		env.Payload = string(payload)
		tampered, _ := EvidenceEnvelopeJSON(env)

		v := baseOutcome(t, ob)
		v.EvidenceRoot = fx.evidenceRoot
		v.ProvenanceRefs = []string{"attestation-1"}
		v.ExecutionIDs = []string{fx.attemptID}
		verifier := &ProvenanceEvidenceVerifier{
			Identity:   "verifyapi-test-verifier/v1",
			Resolve:    func(context.Context, string) ([]byte, error) { return tampered, nil },
			TrustedKey: fx.pub,
		}
		if _, err := verifier.Verify(context.Background(), v); !errors.Is(err, ErrEvidence) {
			t.Fatalf("Verify tampered envelope = %v, want ErrEvidence", err)
		}
	})

	t.Run("untrusted key", func(t *testing.T) {
		otherPub, otherPriv, err := provenance.NewProvenanceKey()
		if err != nil {
			t.Fatal(err)
		}
		env, err := provenance.Sign(provenance.Statement{
			Type:          provenance.StatementType,
			Subject:       []provenance.Subject{{Name: "x", Digest: map[string]string{"sha256": strings.Repeat("f", 64)}}},
			PredicateType: provenance.ExecutionAttestationPredicateType,
		}, "kid-x", otherPriv)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := EvidenceEnvelopeJSON(env)
		v := baseOutcome(t, ob)
		v.EvidenceRoot = fx.evidenceRoot
		v.ProvenanceRefs = []string{"attestation-1"}
		verifier := &ProvenanceEvidenceVerifier{
			Identity:   "verifyapi-test-verifier/v1",
			Resolve:    func(context.Context, string) ([]byte, error) { return raw, nil },
			TrustedKey: fx.pub, // trust a DIFFERENT key than the signer
		}
		if _, err := verifier.Verify(context.Background(), v); !errors.Is(err, ErrEvidence) {
			t.Fatalf("Verify under wrong key = %v, want ErrEvidence", err)
		}
		_ = otherPub
	})
}

// TestEvidenceVerifierRequiresRefs: an outcome citing no evidence can never
// resolve, so it can never become authoritative.
func TestEvidenceVerifierRequiresRefs(t *testing.T) {
	fx := newSignedAttestationFixture(t)
	ob := baseObligation(t)
	v := baseOutcome(t, ob)
	v.EvidenceRoot = fx.evidenceRoot
	v.ProvenanceRefs = nil

	verifier := fixtureVerifier(fx, "attestation-1")
	if _, err := verifier.Verify(context.Background(), v); !errors.Is(err, ErrEvidence) {
		t.Fatalf("Verify without refs = %v, want ErrEvidence", err)
	}
}

// TestFuncEvidenceVerifierSealRules: the injected-resolver adapter seals only
// complete evidence and refuses empty verifier identity.
func TestFuncEvidenceVerifierSealRules(t *testing.T) {
	ob := baseObligation(t)
	v := baseOutcome(t, ob)
	v.EvidenceRoot = mustDigest(t, "resolved-root")
	v.ProvenanceRefs = []string{"ref-1"}
	v.ExecutionIDs = []string{"exec-1"}

	ok := ResolvedAttestation{
		ExecutionID:       "exec-1",
		EvidenceRoot:      mustDigest(t, "resolved-root"),
		AttestationDigest: mustDigest(t, "att-digest"),
	}
	f := &FuncEvidenceVerifier{
		Identity: "func-verifier/v1",
		Resolve:  func(context.Context, string) (ResolvedAttestation, error) { return ok, nil },
	}
	vo, err := f.Verify(context.Background(), v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if !vo.ProvenPass() {
		t.Fatal("want proven pass")
	}

	noIdent := *f
	noIdent.Identity = ""
	if _, err := noIdent.Verify(context.Background(), v); !errors.Is(err, ErrUnverified) {
		t.Fatalf("Verify without identity = %v, want ErrUnverified", err)
	}

	incomplete := ok
	incomplete.EvidenceRoot = ""
	f2 := &FuncEvidenceVerifier{
		Identity: "func-verifier/v1",
		Resolve:  func(context.Context, string) (ResolvedAttestation, error) { return incomplete, nil },
	}
	if _, err := f2.Verify(context.Background(), v); !errors.Is(err, ErrEvidence) {
		t.Fatalf("Verify incomplete resolution = %v, want ErrEvidence", err)
	}
}

// TestRestoreVerifiedOutcomeRoundTrip: durable stores cannot serialize the
// unexported seal, so RestoreVerifiedOutcome rehydrates a previously sealed
// record and ProvenPass survives the round trip. Incomplete evidence is
// refused instead of quietly losing the proven-pass bit.
func TestRestoreVerifiedOutcomeRoundTrip(t *testing.T) {
	ob := baseObligation(t)
	v := baseOutcome(t, ob)
	v.EvidenceRoot = mustDigest(t, "resolved-root")
	v.ProvenanceRefs = []string{"att-1"}
	v.ExecutionIDs = []string{"exec-1"}

	f := &FuncEvidenceVerifier{
		Identity: "restore-verifier/v1",
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      mustDigest(t, "resolved-root"),
				AttestationDigest: mustDigest(t, "att-digest"),
			}, nil
		},
	}
	sealed, err := f.Verify(context.Background(), v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if !sealed.Sealed() || !sealed.ProvenPass() {
		t.Fatal("want sealed proven pass before restore")
	}

	restored, err := RestoreVerifiedOutcome(sealed.Outcome, sealed.Evidence)
	if err != nil {
		t.Fatalf("RestoreVerifiedOutcome = %v", err)
	}
	if !restored.Sealed() || !restored.ProvenPass() {
		t.Fatal("restored record must stay sealed and proven")
	}
	if restored.Evidence.VerifierIdentity != sealed.Evidence.VerifierIdentity {
		t.Fatalf("restored verifier identity = %q, want %q", restored.Evidence.VerifierIdentity, sealed.Evidence.VerifierIdentity)
	}

	// Truncated evidence must not restore as authoritative.
	bad := sealed.Evidence
	bad.VerifierIdentity = ""
	if _, err := RestoreVerifiedOutcome(sealed.Outcome, bad); !errors.Is(err, ErrUnverified) {
		t.Fatalf("restore without identity = %v, want ErrUnverified", err)
	}
	bad = sealed.Evidence
	bad.AttestationDigests = nil
	if _, err := RestoreVerifiedOutcome(sealed.Outcome, bad); !errors.Is(err, ErrUnverified) {
		t.Fatalf("restore without attestation digests = %v, want ErrUnverified", err)
	}
}
