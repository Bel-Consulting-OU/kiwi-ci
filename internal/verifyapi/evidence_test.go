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
//
// The test-report suites are backed by REAL stored reports whose
// provenance.TestReportSuiteDigest matches the signed suite digests, so the
// verifier can resolve each signed SuiteDigest to report cases and derive the
// check outcome (pass) from them — never from a caller string.
type signedAttestationFixture struct {
	envelope     []byte
	evidenceRoot Digest
	attemptID    string
	pub          ed25519.PublicKey
	priv         ed25519.PrivateKey
	// reports maps suite digest → the stored test report it commits.
	reports map[string]model.TestReport
}

// passingReport builds a stored test report whose cases all pass, and returns
// it together with its provenance.TestReportSuiteDigest (the value the signed
// attestation must commit).
func passingReport(name string) (model.TestReport, string) {
	rep := model.TestReport{
		ID:       "rep-" + name,
		RunID:    "run-1",
		JobID:    "job-1",
		JobKey:   "build[os=linux]",
		Path:     "testdata/" + name + ".xml",
		Tests:    2,
		Failures: 0,
		Cases: []model.TestResult{
			{Name: name + "-a", Passed: true, Duration: 0.5},
			{Name: name + "-b", Passed: true, Duration: 0.25},
		},
	}
	return rep, provenance.TestReportSuiteDigest(rep)
}

func newSignedAttestationFixture(t *testing.T) signedAttestationFixture {
	t.Helper()
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	finish := start.Add(90 * time.Second)

	// Real stored reports back the signed suite digests: the verifier
	// resolves each signed SuiteDigest to its cases and derives the check
	// outcome from them (never from a caller string).
	repDM, digDM := passingReport("digest-match")
	repSig, digSig := passingReport("signature")
	reports := map[string]model.TestReport{digDM: repDM, digSig: repSig}

	// The evidence root binds the FULL artifact-side evidence graph. The
	// test-report suite names are the structured signed check results the
	// verifier will derive as CompletedChecks authority.
	evidenceRoot := provenance.ExecutionEvidenceRoot(provenance.ExecutionEvidenceGraph{
		Artifacts: []provenance.ExecutionEvidenceArtifact{
			{Name: "bin", SHA256: strings.Repeat("1", 64), Size: 42, Generation: 7, ProvenanceSHA256: strings.Repeat("2", 64)},
		},
		TestReports: []provenance.ExecutionAttestationReport{
			{Name: "digest-match", SuiteDigest: digDM, Generation: 7},
			{Name: "signature", SuiteDigest: digSig, Generation: 7},
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
		TestReports: []provenance.ExecutionAttestationReport{
			{Name: "digest-match", SuiteDigest: digDM, Generation: 7},
			{Name: "signature", SuiteDigest: digSig, Generation: 7},
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
		reports:      reports,
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
		LookupTestReport: func(_ context.Context, suiteDigest string) (*model.TestReport, bool) {
			if rep, ok := fx.reports[suiteDigest]; ok {
				r := rep
				return &r, true
			}
			return nil, false
		},
	}
}

// provenanceFixtureObligation returns an obligation whose RequiredAssurance
// equals the DERIVED profile of the signed attestation fixture: its container
// + mediated-authority facts derive model.AssuranceKiwiMediatedAuthority.
// RequiredChecks stay the suite names the fixture's test reports bind.
func provenanceFixtureObligation(t *testing.T) VerificationObligation {
	t.Helper()
	ob := baseObligation(t)
	ob.RequiredAssurance = model.AssuranceKiwiMediatedAuthority.Name()
	return ob
}

// bareResolvedAttestation is the injected-resolver shape that binds the
// obligation's required checks explicitly and reports a successful job.
func bareResolvedAttestation(t *testing.T, execID string, root Digest) ResolvedAttestation {
	t.Helper()
	return ResolvedAttestation{
		ExecutionID:       execID,
		EvidenceRoot:      root,
		AttestationDigest: mustDigest(t, "bare-att-digest"),
		Status:            "success",
		Attested:          trustedWindow(),
		Checks:            passChecks(execID, "digest-match", "signature"),
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
	if err := reg.RecordVerifiedOutcome(VerifiedOutcome{outcome: v}); !errors.Is(err, ErrUnverified) {
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
	ob := provenanceFixtureObligation(t)
	reg := NewRegistry(func() time.Time { return ob.IssuedAt.Add(30 * time.Second) })
	if err := reg.SubmitObligation(ob); err != nil {
		t.Fatalf("SubmitObligation = %v", err)
	}

	v := baseOutcome(t, ob)
	v.EvidenceRoot = fx.evidenceRoot
	v.ProvenanceRefs = []string{"attestation-1"}
	v.ExecutionIDs = []string{fx.attemptID}

	verifier := fixtureVerifier(fx, "attestation-1")
	vo, err := verifier.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify real provenance fixture = %v", err)
	}
	if !vo.Sealed() {
		t.Fatal("verified outcome is not sealed")
	}
	if !vo.ProvenPass() {
		t.Fatalf("ProvenPass = false, want true (outcome %q)", vo.Outcome().Outcome)
	}
	if vo.Evidence().VerifierIdentity != "verifyapi-test-verifier/v1" {
		t.Fatalf("verifier identity = %q", vo.Evidence().VerifierIdentity)
	}
	if vo.Evidence().EvidenceRoot != fx.evidenceRoot {
		t.Fatalf("resolved evidence root = %s, want %s", vo.Evidence().EvidenceRoot, fx.evidenceRoot)
	}
	if len(vo.Evidence().AttestationDigests) != 1 || vo.Evidence().AttestationDigests[0] == "" {
		t.Fatalf("attestation digests = %v, want one real digest", vo.Evidence().AttestationDigests)
	}
	if len(vo.Evidence().ExecutionIDs) != 1 || vo.Evidence().ExecutionIDs[0] != fx.attemptID {
		t.Fatalf("resolved execution ids = %v, want [%s]", vo.Evidence().ExecutionIDs, fx.attemptID)
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
	if got.Evidence().AttestationDigests[0] != vo.Evidence().AttestationDigests[0] {
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
	ob := provenanceFixtureObligation(t)
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
	vo, err := verifier.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify real provenance fixture = %v", err)
	}
	if vo.Evidence().Attested == nil {
		t.Fatal("verified evidence has no attested facts; the fixture carries a job window")
	}
	// The fixture attestation binds a 90s job window (started_at →
	// finished_at) — that is the number that must surface, not the caller's.
	const wantWallNS = int64(90 * time.Second)
	if vo.Evidence().Attested.WallTimeNS() != wantWallNS {
		t.Fatalf("attested wall time = %d, want %d", vo.Evidence().Attested.WallTimeNS(), wantWallNS)
	}

	if err := reg.RecordVerifiedOutcome(vo); err != nil {
		t.Fatalf("RecordVerifiedOutcome = %v", err)
	}
	got, err := reg.QueryOutcome(v.VerificationID)
	if err != nil {
		t.Fatalf("QueryOutcome = %v", err)
	}
	m := got.Outcome().Resources.Measured
	if m == nil {
		t.Fatal("Measured is nil after verified record")
	}
	// Model A: the authoritative window is the ATTESTED job window when the
	// evidence carries one, so DurationNS follows that window — not the
	// caller's proposed window.
	const wantDerived = int64(90 * time.Second)
	if m.DurationNS != wantDerived {
		t.Fatalf("Measured.DurationNS = %d, want attested-window derived %d", m.DurationNS, wantDerived)
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
				Status:            "success",
				Checks:            passChecks(v.ExecutionIDs[0], "digest-match", "signature"),
				// No Attested facts: older statements carry no job window.
			}, nil
		},
	}
	vo, err := f.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if vo.Evidence().Attested != nil {
		t.Fatalf("Attested = %+v, want nil when the attestation carries no window", vo.Evidence().Attested)
	}
	if m := DeriveMeasuredFacts(vo.Outcome(), vo.Evidence().Attested); m.WallTimeNS != 0 {
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
// signed and resolved end-to-end through the acceptance boundary. The
// fixture's synthetic suite digest is replaced with the digest of a real
// stored report (and the subject recomputed) so the verifier can resolve the
// signed SuiteDigest to report cases and derive the "test" check outcome
// from them.
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
	// Back the fixture's named suite with a real stored report and recommit
	// the attestation digest so the statement stays self-consistent.
	testRep, testDig := passingReport("test")
	st.Attestation.TestReports = []provenance.ExecutionAttestationReport{
		{Name: "test", SuiteDigest: testDig, Generation: 1},
	}
	provenance.SortAttestationEvidence(st.Attestation)
	attDig, err := provenance.ExecutionAttestationDigest(*st.Attestation)
	if err != nil {
		t.Fatalf("recompute attestation digest: %v", err)
	}
	st.Subject = []provenance.Subject{{Name: st.Attestation.AttemptID, Digest: map[string]string{"sha256": attDig}}}
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
	// The committed fixture attests sealed_pinned_no_network facts and binds
	// the named test-report suite "test": the obligation must demand exactly
	// what the signed evidence can derive.
	ob.RequiredAssurance = model.AssuranceSealedPinnedNoNetwork.Name()
	ob.RequiredChecks = []string{"test", CheckJobStatusSuccess, CheckEvidenceRoot}
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
		LookupTestReport: func(_ context.Context, suiteDigest string) (*model.TestReport, bool) {
			if suiteDigest == testDig {
				r := testRep
				return &r, true
			}
			return nil, false
		},
	}
	vo, err := verifier.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify attestation_v6 fixture = %v", err)
	}
	if vo.Evidence().EvidenceRoot != root {
		t.Fatalf("resolved root = %s, want fixture %s", vo.Evidence().EvidenceRoot, root)
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

// TestEvidenceVerifierDerivesRootOverFakeClaimedRoot is the P1 laundering
// close: a caller may CLAIM pass with a fabricated evidence_root, but the
// derived record carries only the root the signatures prove. The fake value
// survives solely as the SubmittedClaim proposal and never becomes authority.
func TestEvidenceVerifierDerivesRootOverFakeClaimedRoot(t *testing.T) {
	fx := newSignedAttestationFixture(t)
	ob := provenanceFixtureObligation(t)
	v := baseOutcome(t, ob)
	v.EvidenceRoot = mustDigest(t, "totally-fake-root")
	v.ProvenanceRefs = []string{"attestation-1"}
	v.ExecutionIDs = []string{fx.attemptID}
	v.Outcome = OutcomePass
	v.AssuranceProfile = "sealed_pinned_no_network" // caller inflation

	verifier := fixtureVerifier(fx, "attestation-1")
	vo, err := verifier.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify fake root = %v (Model A keeps the proposal and derives truth)", err)
	}
	if vo.Outcome().EvidenceRoot != fx.evidenceRoot {
		t.Fatalf("derived evidence root = %s, want resolved %s", vo.Outcome().EvidenceRoot, fx.evidenceRoot)
	}
	if vo.SubmittedClaim().EvidenceRoot != mustDigest(t, "totally-fake-root") {
		t.Fatal("submitted claim must keep the proposed (fake) root for audit")
	}
	if vo.Outcome().AssuranceProfile == "sealed_pinned_no_network" {
		t.Fatal("derived assurance must not echo the caller's inflated profile")
	}
	if vo.Outcome().AssuranceProfile != model.AssuranceKiwiMediatedAuthority.Name() {
		t.Fatalf("derived assurance = %q, want %q", vo.Outcome().AssuranceProfile, model.AssuranceKiwiMediatedAuthority.Name())
	}
	if !vo.ProvenPass() {
		t.Fatal("derived record over real evidence and covered checks must be a proven pass")
	}
}

// TestEvidenceVerifierDerivesExecIDsOverForgedClaim: a claimed execution id
// that no verified attestation binds never enters the derived authority — it
// is kept only as the proposal (Model A) and the derived set is exactly what
// the signatures bind.
func TestEvidenceVerifierDerivesExecIDsOverForgedClaim(t *testing.T) {
	fx := newSignedAttestationFixture(t)
	ob := provenanceFixtureObligation(t)
	v := baseOutcome(t, ob)
	v.EvidenceRoot = fx.evidenceRoot
	v.ProvenanceRefs = []string{"attestation-1"}
	v.ExecutionIDs = []string{fx.attemptID, "forged-exec"}

	verifier := fixtureVerifier(fx, "attestation-1")
	vo, err := verifier.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify forged execution id = %v (Model A keeps the proposal and derives truth)", err)
	}
	if len(vo.Outcome().ExecutionIDs) != 1 || vo.Outcome().ExecutionIDs[0] != fx.attemptID {
		t.Fatalf("derived execution ids = %v, want [%s]", vo.Outcome().ExecutionIDs, fx.attemptID)
	}
	if !equalStringSlices(vo.SubmittedClaim().ExecutionIDs, []string{fx.attemptID, "forged-exec"}) {
		t.Fatalf("submitted claim ids = %v, want the proposal preserved", vo.SubmittedClaim().ExecutionIDs)
	}
}

// TestEvidenceVerifierRefusesUnsignedOrTamperedEnvelope: no signature, or a
// tampered payload, never resolves to evidence.
func TestEvidenceVerifierRefusesUnsignedOrTamperedEnvelope(t *testing.T) {
	fx := newSignedAttestationFixture(t)
	ob := provenanceFixtureObligation(t)

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
		if _, err := verifier.Verify(context.Background(), ob, v); !errors.Is(err, ErrEvidence) {
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
		if _, err := verifier.Verify(context.Background(), ob, v); !errors.Is(err, ErrEvidence) {
			t.Fatalf("Verify under wrong key = %v, want ErrEvidence", err)
		}
		_ = otherPub
	})
}

// TestEvidenceVerifierRequiresRefs: an outcome citing no evidence can never
// resolve, so it can never become authoritative.
func TestEvidenceVerifierRequiresRefs(t *testing.T) {
	fx := newSignedAttestationFixture(t)
	ob := provenanceFixtureObligation(t)
	v := baseOutcome(t, ob)
	v.EvidenceRoot = fx.evidenceRoot
	v.ProvenanceRefs = nil

	verifier := fixtureVerifier(fx, "attestation-1")
	if _, err := verifier.Verify(context.Background(), ob, v); !errors.Is(err, ErrEvidence) {
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
		Status:            "success",
		Attested:          trustedWindow(),
		Checks:            passChecks("exec-1", "digest-match", "signature"),
	}
	f := &FuncEvidenceVerifier{
		Identity: "func-verifier/v1",
		Resolve:  func(context.Context, string) (ResolvedAttestation, error) { return ok, nil },
	}
	vo, err := f.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if !vo.ProvenPass() {
		t.Fatal("want proven pass")
	}

	noIdent := *f
	noIdent.Identity = ""
	if _, err := noIdent.Verify(context.Background(), ob, v); !errors.Is(err, ErrUnverified) {
		t.Fatalf("Verify without identity = %v, want ErrUnverified", err)
	}

	incomplete := ok
	incomplete.EvidenceRoot = ""
	f2 := &FuncEvidenceVerifier{
		Identity: "func-verifier/v1",
		Resolve:  func(context.Context, string) (ResolvedAttestation, error) { return incomplete, nil },
	}
	if _, err := f2.Verify(context.Background(), ob, v); !errors.Is(err, ErrEvidence) {
		t.Fatalf("Verify incomplete resolution = %v, want ErrEvidence", err)
	}
}

// TestRestoreVerifiedOutcomeRoundTrip: durable stores cannot serialize the
// unexported seal, so Accept + RestoreVerifiedOutcome rehydrates a previously
// sealed record through the MAC-checked acceptance path and ProvenPass
// survives the round trip. Incomplete or tampered evidence is refused instead
// of quietly losing the proven-pass bit.
func TestRestoreVerifiedOutcomeRoundTrip(t *testing.T) {
	ob := baseObligation(t)
	ob.RequiredChecks = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	ob.RequiredAssurance = "no_injected_credentials"
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
				Status:            string(model.StatusSuccess),
				Attested:          trustedWindow(),
				Facts:             &model.ExecutionFacts{FilesystemIsolated: true},
			}, nil
		},
	}
	sealed, err := f.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if !sealed.Sealed() || !sealed.ProvenPass() {
		t.Fatalf("want sealed proven pass before restore (outcome %q)", sealed.Outcome().Outcome)
	}

	key, err := NewHMACAcceptanceKey("acc-restore", []byte("restore-test-secret-32-bytes!"))
	if err != nil {
		t.Fatal(err)
	}
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
	restored, err := RestoreVerifiedOutcome(persisted, key)
	if err != nil {
		t.Fatalf("RestoreVerifiedOutcome = %v", err)
	}
	if !restored.Sealed() || !restored.ProvenPass() {
		t.Fatal("restored record must stay sealed and proven")
	}
	if restored.Evidence().VerifierIdentity != sealed.Evidence().VerifierIdentity {
		t.Fatalf("restored verifier identity = %q, want %q", restored.Evidence().VerifierIdentity, sealed.Evidence().VerifierIdentity)
	}

	// Tampered / truncated evidence must not restore as authoritative.
	bad := persisted
	bad.Evidence.AttestationDigests = nil
	if _, err := RestoreVerifiedOutcome(bad, key); err == nil {
		t.Fatal("restore without attestation digests must fail")
	}
	bad = persisted
	bad.Evidence.VerifierIdentity = ""
	if _, err := RestoreVerifiedOutcome(bad, key); err == nil {
		t.Fatal("restore without verifier identity must fail")
	}
	// A wrong acceptance key can never recreate authority.
	other, err := NewHMACAcceptanceKey("acc-other", []byte("another-secret-32-bytes-long!!"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreVerifiedOutcome(persisted, other); err == nil {
		t.Fatal("restore under a foreign acceptance key must fail")
	}
}

// ---------------------------------------------------------------------------
// P1-A adversarial: real evidence + caller Result=pass/assurance=high is
// never an authoritative pass when the job failed or the required checks are
// not bound by signed result evidence.
// ---------------------------------------------------------------------------

// adversarialSignedFixture builds a REAL signed execution attestation with
// the given job status and named test-report suites (the only two knobs the
// adversary does not control: the signature and evidence root are genuine).
// Each suite name is backed by a real stored report whose suite digest the
// attestation commits, so the verifier can resolve it and derive the check
// outcome from its cases.
func adversarialSignedFixture(t *testing.T, status string, suiteNames []string) signedAttestationFixture {
	t.Helper()
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	finish := start.Add(90 * time.Second)
	reports := make([]provenance.ExecutionAttestationReport, 0, len(suiteNames))
	stored := make(map[string]model.TestReport, len(suiteNames))
	for i, name := range suiteNames {
		rep, dig := passingReport(name)
		stored[dig] = rep
		reports = append(reports, provenance.ExecutionAttestationReport{
			Name:        name,
			SuiteDigest: dig,
			Generation:  int64(7 + i),
		})
	}
	evidenceRoot := provenance.ExecutionEvidenceRoot(provenance.ExecutionEvidenceGraph{
		Artifacts: []provenance.ExecutionEvidenceArtifact{
			{Name: "bin", SHA256: strings.Repeat("1", 64), Size: 42, Generation: 7, ProvenanceSHA256: strings.Repeat("2", 64)},
		},
		TestReports: reports,
	})
	st, err := provenance.ExecutionAttestationStatement(provenance.ExecutionAttestationInput{
		RunID:                  "run-adv",
		JobID:                  "job-adv",
		Generation:             7,
		Status:                 status,
		StartedAt:              &start,
		FinishedAt:             &finish,
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
		TestReports:     reports,
		ExternalEffects: model.EffectsKiwiMediated,
	})
	if err != nil {
		t.Fatalf("build adversarial attestation: %v", err)
	}
	pub, priv, err := provenance.NewProvenanceKey()
	if err != nil {
		t.Fatal(err)
	}
	env, err := provenance.Sign(st, "kid-adv", priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EvidenceEnvelopeJSON(env)
	if err != nil {
		t.Fatal(err)
	}
	return signedAttestationFixture{
		envelope:     raw,
		evidenceRoot: Digest(evidenceRoot),
		attemptID:    st.AttemptID,
		pub:          pub,
		reports:      stored,
	}
}

// TestAdversarialCallerPassHighWithFailedJobIsNotProvenPass: real signed
// evidence of a FAILED job, while the caller proposes Result=pass and
// assurance=sealed_pinned_no_network with every required check named. The
// derived record must not be a proven pass — authority follows the signed
// job status, not the proposal.
func TestAdversarialCallerPassHighWithFailedJobIsNotProvenPass(t *testing.T) {
	fx := adversarialSignedFixture(t, "failure", []string{"digest-match", "signature"})
	ob := provenanceFixtureObligation(t)
	v := baseOutcome(t, ob)
	v.EvidenceRoot = fx.evidenceRoot
	v.ProvenanceRefs = []string{"attestation-1"}
	v.ExecutionIDs = []string{fx.attemptID}
	// Caller inflation: claim a pass under a stronger profile than the facts
	// prove, with every required check named.
	v.Outcome = OutcomePass
	v.AssuranceProfile = "sealed_pinned_no_network"
	v.CompletedChecks = []string{"digest-match", "signature"}

	verifier := fixtureVerifier(fx, "attestation-1")
	vo, err := verifier.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if vo.ProvenPass() {
		t.Fatal("ProvenPass = true, want false: the signed job status is failure")
	}
	if vo.Outcome().Outcome != OutcomeFail {
		t.Fatalf("derived result = %q, want fail (signed job status is failure)", vo.Outcome().Outcome)
	}
	if vo.SubmittedClaim().Outcome != OutcomePass || vo.SubmittedClaim().AssuranceProfile != "sealed_pinned_no_network" {
		t.Fatal("the caller's pass/high proposal must be preserved on SubmittedClaim")
	}
	if vo.Outcome().AssuranceProfile == "sealed_pinned_no_network" {
		t.Fatal("derived assurance must not echo the caller's inflated profile")
	}
	if vo.Evidence().JobStatus != "failure" {
		t.Fatalf("derived job status = %q, want failure", vo.Evidence().JobStatus)
	}

	// Even if a caller tries to persist it, the record is not a proven pass.
	reg := NewRegistry(func() time.Time { return ob.IssuedAt.Add(30 * time.Second) })
	if err := reg.SubmitObligation(ob); err != nil {
		t.Fatal(err)
	}
	if err := reg.RecordVerifiedOutcome(vo); err != nil {
		t.Fatalf("RecordVerifiedOutcome = %v", err)
	}
	got, err := reg.QueryOutcome(v.VerificationID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProvenPass() {
		t.Fatal("QueryOutcome must not report a proven pass for a failed job")
	}
}

// TestAdversarialCallerPassWithUnboundChecksIsNotProvenPass: real signed
// evidence whose test reports do NOT bind the obligation's required check
// names. The caller lists those names on the claim and proposes Result=pass —
// the derived CompletedChecks contain only what IS bound, and the derived
// result is partial, never a proven pass. Caller strings are not authority.
func TestAdversarialCallerPassWithUnboundChecksIsNotProvenPass(t *testing.T) {
	// The signed evidence binds only the suite "other-suite" — none of the
	// obligation's required check names.
	fx := adversarialSignedFixture(t, "success", []string{"other-suite"})
	ob := provenanceFixtureObligation(t)
	v := baseOutcome(t, ob)
	v.EvidenceRoot = fx.evidenceRoot
	v.ProvenanceRefs = []string{"attestation-1"}
	v.ExecutionIDs = []string{fx.attemptID}
	v.Outcome = OutcomePass
	v.AssuranceProfile = "sealed_pinned_no_network"
	v.CompletedChecks = []string{"digest-match", "signature"} // caller strings: NOT authority

	verifier := fixtureVerifier(fx, "attestation-1")
	vo, err := verifier.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if vo.ProvenPass() {
		t.Fatal("ProvenPass = true, want false: required checks are not bound by signed result evidence")
	}
	if vo.Outcome().Outcome != OutcomePartial {
		t.Fatalf("derived result = %q, want partial (checks missing)", vo.Outcome().Outcome)
	}
	// Derived CompletedChecks contain only what the signatures bind.
	for _, c := range vo.Outcome().CompletedChecks {
		if c == "digest-match" || c == "signature" {
			t.Fatalf("derived completed checks %v must not contain caller-only names", vo.Outcome().CompletedChecks)
		}
	}
	if !equalStringSlices(vo.SubmittedClaim().CompletedChecks, []string{"digest-match", "signature"}) {
		t.Fatal("the caller's check-name proposal must be preserved on SubmittedClaim")
	}
	hasStructural := false
	for _, c := range vo.Outcome().CompletedChecks {
		if c == CheckJobStatusSuccess || c == CheckEvidenceRoot {
			hasStructural = true
		}
		if c == "other-suite" {
			hasStructural = true
		}
	}
	if !hasStructural {
		t.Fatalf("derived completed checks %v must contain the bound structural/named checks", vo.Outcome().CompletedChecks)
	}
	if vo.Outcome().AssuranceProfile == "sealed_pinned_no_network" {
		t.Fatal("derived assurance must not echo the caller's inflated profile")
	}
}

// TestAdversarialCallerPassMissingEvidenceChecksIsNotProvenPass: the bare
// structural derivation (status success + evidence root present) never
// satisfies an obligation that demands named checks the attestation cannot
// bind. Caller-named CompletedChecks are ignored entirely.
func TestAdversarialCallerPassMissingEvidenceChecksIsNotProvenPass(t *testing.T) {
	ob := baseObligation(t)
	v := baseOutcome(t, ob)
	v.EvidenceRoot = mustDigest(t, "adv-root")
	v.ProvenanceRefs = []string{"adv-1"}
	v.ExecutionIDs = []string{"exec-1"}
	v.Outcome = OutcomePass
	v.AssuranceProfile = "sealed_pinned_no_network"
	v.CompletedChecks = []string{"digest-match", "signature", "extra-claim"}

	// The attestation carries NO named check results at all.
	f := &FuncEvidenceVerifier{
		Identity: "adv-verifier/v1",
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      mustDigest(t, "adv-root"),
				AttestationDigest: mustDigest(t, "adv-att"),
				Status:            "success",
				Attested:          trustedWindow(),
			}, nil
		},
	}
	vo, err := f.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if vo.ProvenPass() {
		t.Fatal("ProvenPass = true, want false: named required checks are unbound")
	}
	if vo.Outcome().Outcome != OutcomePartial {
		t.Fatalf("derived result = %q, want partial", vo.Outcome().Outcome)
	}
	if !equalStringSlices(vo.Outcome().CompletedChecks, []string{CheckJobStatusSuccess, CheckEvidenceRoot}) {
		t.Fatalf("derived completed checks = %v, want only the bound structural pair", vo.Outcome().CompletedChecks)
	}
	if !equalStringSlices(vo.SubmittedClaim().CompletedChecks, []string{"digest-match", "signature", "extra-claim"}) {
		t.Fatal("the caller's check-name proposal must be preserved on SubmittedClaim")
	}
}

// TestDerivedVerifiedOutcomeWireShape pins the persisted JSON contract of a
// DerivedVerifiedOutcome: the wire names are unchanged (submitted_claim /
// outcome / evidence) and unmarshal never restores the seal — a decoded
// value is data, and only RestoreVerifiedOutcome mints authority again.
func TestDerivedVerifiedOutcomeWireShape(t *testing.T) {
	ob := baseObligation(t)
	v := baseOutcome(t, ob)
	v.EvidenceRoot = mustDigest(t, "wire-root")
	v.ProvenanceRefs = []string{"att-1"}
	v.ExecutionIDs = []string{"exec-1"}
	f := &FuncEvidenceVerifier{
		Identity: "wire-verifier/v1",
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      mustDigest(t, "wire-root"),
				AttestationDigest: mustDigest(t, "wire-att"),
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
	raw, err := json.Marshal(sealed)
	if err != nil {
		t.Fatalf("MarshalJSON = %v", err)
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(raw, &shape); err != nil {
		t.Fatalf("decode shape = %v", err)
	}
	for _, name := range []string{"submitted_claim", "outcome", "evidence"} {
		if _, ok := shape[name]; !ok {
			t.Fatalf("wire shape missing %q: %s", name, raw)
		}
	}
	var back DerivedVerifiedOutcome
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("UnmarshalJSON = %v", err)
	}
	if back.Sealed() {
		t.Fatal("json.Unmarshal must never restore the seal")
	}
	if back.ProvenPass() {
		t.Fatal("a decoded value must never be a proven pass")
	}
	// Content round-trips: the accessors see the same authority values.
	if back.Outcome().VerificationID != sealed.Outcome().VerificationID {
		t.Fatalf("round-trip verification id = %q, want %q", back.Outcome().VerificationID, sealed.Outcome().VerificationID)
	}
	if back.Outcome().Outcome != sealed.Outcome().Outcome {
		t.Fatalf("round-trip result = %q, want %q", back.Outcome().Outcome, sealed.Outcome().Outcome)
	}
	if back.Evidence().EvidenceRoot != mustDigest(t, "wire-root") {
		t.Fatalf("round-trip evidence root = %s", back.Evidence().EvidenceRoot)
	}
}
