package verifyapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// ---------------------------------------------------------------------------
// P0c — Service must re-bind verifier output.
// ---------------------------------------------------------------------------

// TestServiceRefusesHostileProviderForeignProof: a provider that returns a
// sealed record minted for ANOTHER obligation (tenant-B proof for a tenant-A
// request) is refused before anything is stored. The Service never trusts
// the provider to address its own output.
func TestServiceRefusesHostileProviderForeignProof(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()

	// Honest seal for tenant B — the "foreign proof" the hostile provider
	// will try to pass off as tenant A's discharge.
	obB := f.obligation(t, "ob-b", "tenant-b")
	claimB := f.claim(t, obB)
	foreign, err := f.verifier.Verify(ctx, obB, claimB)
	if err != nil {
		t.Fatalf("seal tenant-B: %v", err)
	}
	if !foreign.Sealed() {
		t.Fatal("tenant-B seal setup")
	}

	hostile := &stubProvider{
		kind: externalScannerKind,
		caps: externalScannerCapability(),
		verify: func(context.Context, VerificationObligation, VerificationOutcome) (DerivedVerifiedOutcome, error) {
			return foreign, nil
		},
	}
	reg := NewProviderRegistry()
	if err := reg.Register(hostile); err != nil {
		t.Fatal(err)
	}
	f.svc.Providers = reg

	obA := f.obligation(t, "ob-a", "tenant-a")
	obA.VerifierProviderKind = externalScannerKind
	if err := f.svc.SubmitObligation(ctx, f.tenantA, obA); err != nil {
		t.Fatalf("SubmitObligation: %v", err)
	}
	claimA := f.claim(t, obA)
	if err := f.svc.RecordClaim(ctx, f.tenantA, claimA); err != nil {
		t.Fatalf("RecordClaim: %v", err)
	}

	// The hostile return must be refused — not stored, not disclosed.
	if _, err := f.svc.VerifyAndRecord(ctx, f.tenantA, claimA); err == nil {
		t.Fatal("hostile provider returning tenant-B proof must be refused")
	}
	if _, err := f.svc.Store.QueryOutcome(ctx, claimA.VerificationID); err == nil {
		t.Fatal("nothing may be recorded from the hostile return")
	}
}

// TestServiceRefusesSwappedSubmittedClaim: a provider that returns a sealed
// record whose SubmittedClaim is not the supplied submission (post-seal
// mutation of the proposal) is refused by the independent re-bind.
func TestServiceRefusesSwappedSubmittedClaim(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	ob := f.obligation(t, "ob-swap", "tenant-a")
	claim := f.claim(t, ob)
	honest, err := f.verifier.Verify(ctx, ob, claim)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	swapped := honest // copy keeps the unexported seal bit
	swappedClaim := claim
	swappedClaim.VerificationID = "ver-forged"
	swapped.submittedClaim = swappedClaim

	hostile := &stubProvider{
		kind: externalScannerKind,
		caps: externalScannerCapability(),
		verify: func(context.Context, VerificationObligation, VerificationOutcome) (DerivedVerifiedOutcome, error) {
			return swapped, nil
		},
	}
	reg := NewProviderRegistry()
	if err := reg.Register(hostile); err != nil {
		t.Fatal(err)
	}
	f.svc.Providers = reg

	ob.VerifierProviderKind = externalScannerKind
	if err := f.svc.SubmitObligation(ctx, f.tenantA, ob); err != nil {
		t.Fatalf("SubmitObligation: %v", err)
	}
	if err := f.svc.RecordClaim(ctx, f.tenantA, claim); err != nil {
		t.Fatalf("RecordClaim: %v", err)
	}
	if _, err := f.svc.VerifyAndRecord(ctx, f.tenantA, claim); err == nil {
		t.Fatal("swapped submitted claim must be refused by re-bind")
	}
}

// TestServiceRefusesOutcomeForOtherObligation: a sealed record whose outcome
// names another obligation's candidate/snapshot/contract is refused even
// when the SubmittedClaim was copied from the real request.
func TestServiceRefusesOutcomeForOtherObligation(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	ob := f.obligation(t, "ob-ident", "tenant-a")
	claim := f.claim(t, ob)
	honest, err := f.verifier.Verify(ctx, ob, claim)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	// Forge the derived identity to another candidate while keeping the
	// caller's submitted claim intact.
	mutated := honest
	out := honest.outcome
	out.CandidateDigest = mustDigest(t, "other-candidate")
	mutated.outcome = out

	hostile := &stubProvider{
		kind: externalScannerKind,
		caps: externalScannerCapability(),
		verify: func(context.Context, VerificationObligation, VerificationOutcome) (DerivedVerifiedOutcome, error) {
			return mutated, nil
		},
	}
	reg := NewProviderRegistry()
	if err := reg.Register(hostile); err != nil {
		t.Fatal(err)
	}
	f.svc.Providers = reg

	ob.VerifierProviderKind = externalScannerKind
	if err := f.svc.SubmitObligation(ctx, f.tenantA, ob); err != nil {
		t.Fatalf("SubmitObligation: %v", err)
	}
	if err := f.svc.RecordClaim(ctx, f.tenantA, claim); err != nil {
		t.Fatalf("RecordClaim: %v", err)
	}
	if _, err := f.svc.VerifyAndRecord(ctx, f.tenantA, claim); err == nil {
		t.Fatal("outcome bound to another candidate must be refused by re-bind")
	}
}

// ---------------------------------------------------------------------------
// P1d — provider constraints in demand + acceptance MAC (V5).
// ---------------------------------------------------------------------------

// TestProviderConstraintsRideDemand: EffectiveVerificationDemand carries the
// five provider axes from the obligation, and two obligations that differ
// only in provider kind never share a demand (or obligation) digest.
func TestProviderConstraintsRideDemand(t *testing.T) {
	ob := baseObligation(t)
	ob.VerifierProviderKind = "prov-a"
	ob.VerifierContractVersion = "1"
	ob.VerifierClaimClass = "signed"
	ob.VerifierPlatform = "linux"
	ob.VerifierEvidenceTypes = []string{"execution-attestation"}

	d, err := ResolveEffectiveDemand(ob, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.VerifierProviderKind != "prov-a" || d.VerifierContractVersion != "1" ||
		d.VerifierClaimClass != "signed" || d.VerifierPlatform != "linux" ||
		len(d.VerifierEvidenceTypes) != 1 || d.VerifierEvidenceTypes[0] != "execution-attestation" {
		t.Fatalf("demand lost provider axes: %+v", d)
	}

	other := ob
	other.VerifierProviderKind = "prov-b"
	d1, err := EffectiveVerificationDemandDigest(ob, nil)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := EffectiveVerificationDemandDigest(other, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d2 {
		t.Fatal("obligations differing only in provider kind must not share a demand digest")
	}
	o1, err := obligationDigestV5(ob)
	if err != nil {
		t.Fatal(err)
	}
	o2, err := obligationDigestV5(other)
	if err != nil {
		t.Fatal(err)
	}
	if o1 == o2 {
		t.Fatal("obligations differing only in provider kind must not share an obligation digest")
	}
	// The v3 encoding (V3/V4 restore) deliberately does NOT bind the axes.
	v3a, err := obligationDigestV3(ob)
	if err != nil {
		t.Fatal(err)
	}
	v3b, err := obligationDigestV3(other)
	if err != nil {
		t.Fatal(err)
	}
	if v3a != v3b {
		t.Fatal("historical obligation/v3 encoding must not change with provider axes")
	}
}

// TestAcceptanceV5BindsProviderConstraints: a v5 acceptance record refuses to
// restore under an obligation whose provider kind was swapped on the row.
func TestAcceptanceV5BindsProviderConstraints(t *testing.T) {
	ob := baseObligation(t)
	ob.RequiredChecks = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	ob.VerifierProviderKind = "prov-a"
	v := baseOutcome(t, ob)
	v.EvidenceRoot = mustDigest(t, "p1d-root")
	v.ProvenanceRefs = []string{"att-1"}
	v.ExecutionIDs = []string{"exec-1"}

	f := &FuncEvidenceVerifier{
		Identity: "p1d-verifier/v1",
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      mustDigest(t, "p1d-root"),
				AttestationDigest: mustDigest(t, "p1d-att"),
				Status:            "success",
				Checks:            passChecks("exec-1", CheckJobStatusSuccess, CheckEvidenceRoot),
				Attested:          trustedWindow(),
			}, nil
		},
	}
	sealed, err := f.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	key := mustKey(t, "acc-p1d", "p1d-test-secret-32-bytes-long!!")
	rec, err := Accept(ob, sealed, key, time.Date(2026, 1, 2, 3, 6, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Accept = %v", err)
	}
	if rec.AcceptanceVersion != AcceptanceVersionV5 {
		t.Fatalf("AcceptanceVersion = %d, want %d", rec.AcceptanceVersion, AcceptanceVersionV5)
	}
	persisted := PersistedVerified{
		Obligation:     ob,
		SubmittedClaim: sealed.SubmittedClaim(),
		Outcome:        sealed.Outcome(),
		Evidence:       sealed.Evidence(),
		Acceptance:     rec,
	}
	if _, err := RestoreVerifiedOutcome(persisted, key); err != nil {
		t.Fatalf("intact v5 restore = %v", err)
	}

	// Swap the provider kind on the stored obligation: both the obligation
	// digest and the demand digest no longer match.
	tampered := persisted
	tampered.Obligation = persisted.Obligation
	tampered.Obligation.VerifierProviderKind = "prov-b"
	if _, err := RestoreVerifiedOutcome(tampered, key); !errors.Is(err, ErrAcceptance) {
		t.Fatalf("tampered provider kind = %v, want ErrAcceptance", err)
	}

	// Swap the claim class: same refusal.
	tampered2 := persisted
	tampered2.Obligation = persisted.Obligation
	tampered2.Obligation.VerifierClaimClass = "forged"
	if _, err := RestoreVerifiedOutcome(tampered2, key); !errors.Is(err, ErrAcceptance) {
		t.Fatalf("tampered claim class = %v, want ErrAcceptance", err)
	}
}

// TestV3V4RestoreStillWorks: historical records keep restoring under their
// own encodings (obligation/v3 + demand/v1), while v5 writes the new ones.
func TestV3V4RestoreStillWorks(t *testing.T) {
	ob := baseObligation(t)
	ob.RequiredChecks = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	v := baseOutcome(t, ob)
	v.EvidenceRoot = mustDigest(t, "hist-root")
	v.ProvenanceRefs = []string{"att-1"}
	v.ExecutionIDs = []string{"exec-1"}

	f := &FuncEvidenceVerifier{
		Identity: "hist-verifier/v1",
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      mustDigest(t, "hist-root"),
				AttestationDigest: mustDigest(t, "hist-att"),
				Status:            "success",
				Checks:            passChecks("exec-1", CheckJobStatusSuccess, CheckEvidenceRoot),
				Attested:          trustedWindow(),
			}, nil
		},
	}
	sealed, err := f.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	key := mustKey(t, "acc-hist", "hist-test-secret-32-bytes-long!!")
	at := time.Date(2026, 1, 2, 3, 6, 0, 0, time.UTC)

	obDig, err := obligationDigestV3(ob)
	if err != nil {
		t.Fatal(err)
	}
	claimDig, err := submittedClaimDigest(sealed.SubmittedClaim())
	if err != nil {
		t.Fatal(err)
	}
	outDig, err := outcomeDigestV2(sealed.Outcome())
	if err != nil {
		t.Fatal(err)
	}
	demandDig, err := effectiveVerificationDemandDigestV1(ob, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		version int
		evDig   Digest
		payload func(AcceptanceRecord) ([]byte, error)
	}{
		{
			name:    "v3",
			version: AcceptanceVersionV3,
			evDig:   mustDigest(t, "v3-ev"), // placeholder, replaced below
			payload: acceptancePayloadV3,
		},
		{
			name:    "v4",
			version: AcceptanceVersionV4,
			evDig:   mustDigest(t, "v4-ev"),
			payload: acceptancePayloadV4,
		},
	} {
		var evDig Digest
		if tc.version == AcceptanceVersionV3 {
			evDig, err = evidenceDigestV2(sealed.Evidence())
		} else {
			evDig, err = evidenceDigestV3(sealed.Evidence())
		}
		if err != nil {
			t.Fatalf("%s evidence digest: %v", tc.name, err)
		}
		rec := AcceptanceRecord{
			AcceptanceVersion:      tc.version,
			SchemaVersion:          SchemaVersion,
			ObligationDigest:       obDig,
			SubmittedClaimDigest:   claimDig,
			OutcomeDigest:          outDig,
			VerifiedEvidenceDigest: evDig,
			DemandDigest:           demandDig,
			Subject:                ob.Subject,
			Algorithm:              key.Algorithm(),
			VerifiedAt:             at,
			KeyID:                  key.KeyID(),
		}
		payload, err := tc.payload(rec)
		if err != nil {
			t.Fatalf("%s payload: %v", tc.name, err)
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
		if _, err := RestoreVerifiedOutcome(persisted, key); err != nil {
			t.Fatalf("%s restore = %v, want success", tc.name, err)
		}
	}
}

// ---------------------------------------------------------------------------
// P1e — provider constraints require a provider kind.
// ---------------------------------------------------------------------------

// TestObligationProviderAxesRequireKind: an auxiliary provider axis without
// VerifierProviderKind is unaddressable demand and is refused at Validate.
func TestObligationProviderAxesRequireKind(t *testing.T) {
	for name, mut := range map[string]func(*VerificationObligation){
		"contract version": func(o *VerificationObligation) { o.VerifierContractVersion = "1" },
		"claim class":      func(o *VerificationObligation) { o.VerifierClaimClass = "signed" },
		"platform":         func(o *VerificationObligation) { o.VerifierPlatform = "linux" },
		"evidence types":   func(o *VerificationObligation) { o.VerifierEvidenceTypes = []string{"execution-attestation"} },
	} {
		ob := baseObligation(t)
		mut(&ob)
		if err := ob.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s without provider kind = %v, want ErrInvalid", name, err)
		}
		// With a kind the same shape is sound.
		ob.VerifierProviderKind = "prov-a"
		if err := ob.Validate(); err != nil {
			t.Fatalf("%s with provider kind = %v, want success", name, err)
		}
	}
	// Empty / duplicate evidence types are also refused.
	ob := baseObligation(t)
	ob.VerifierProviderKind = "prov-a"
	bad := ob
	bad.VerifierEvidenceTypes = []string{""}
	if err := bad.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty evidence type = %v, want ErrInvalid", err)
	}
	bad2 := ob
	bad2.VerifierEvidenceTypes = []string{"a", "a"}
	if err := bad2.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate evidence type = %v, want ErrInvalid", err)
	}
}

// ---------------------------------------------------------------------------
// P1g — real V2 restore re-derives Window/Kinds.
// ---------------------------------------------------------------------------

// TestV2RestoreRederivesWindowKinds: a real frozen v2 acceptance fixture
// (obligation/v2 + evidence/v2 + acceptance v2 domain) restores, and the
// persisted Window / Kinds — which the v2 MAC does not cover — are re-derived
// from the MAC-verified primitives rather than trusted.
func TestV2RestoreRederivesWindowKinds(t *testing.T) {
	ob := baseObligation(t)
	ob.RequiredChecks = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	claim := baseOutcome(t, ob)
	claim.EvidenceRoot = mustDigest(t, "v2f-root")
	claim.ProvenanceRefs = []string{"att-1"}
	claim.ExecutionIDs = []string{"exec-1"}

	f := &FuncEvidenceVerifier{
		Identity: "v2f-verifier/v1",
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      mustDigest(t, "v2f-root"),
				AttestationDigest: mustDigest(t, "v2f-att"),
				Status:            "success",
				Checks:            passChecks("exec-1", CheckJobStatusSuccess, CheckEvidenceRoot),
				// No Attested window: re-derived source must be Unknown.
			}, nil
		},
	}
	sealed, err := f.Verify(context.Background(), ob, claim)
	if err != nil {
		t.Fatalf("seal = %v", err)
	}
	key := mustKey(t, "k-v2f", "v2f-secret-32-bytes-long-enough!!")
	at := time.Date(2026, 1, 2, 3, 6, 0, 0, time.UTC)

	// Hand-roll a REAL v2 record: v2 obligation digest, v2 evidence digest,
	// v2 MAC domain. The v2 evidence encoding binds neither Window nor Kinds.
	obDig, err := obligationDigestV2(ob)
	if err != nil {
		t.Fatal(err)
	}
	claimDig, err := submittedClaimDigest(sealed.SubmittedClaim())
	if err != nil {
		t.Fatal(err)
	}
	outDig, err := outcomeDigestV2(sealed.Outcome())
	if err != nil {
		t.Fatal(err)
	}
	evDig, err := evidenceDigestV2(sealed.Evidence())
	if err != nil {
		t.Fatal(err)
	}
	rec := AcceptanceRecord{
		AcceptanceVersion:      AcceptanceVersionV2,
		SchemaVersion:          SchemaVersion,
		ObligationDigest:       obDig,
		SubmittedClaimDigest:   claimDig,
		OutcomeDigest:          outDig,
		VerifiedEvidenceDigest: evDig,
		Subject:                ob.Subject,
		Algorithm:              key.Algorithm(),
		VerifiedAt:             at,
		KeyID:                  key.KeyID(),
	}
	payload, err := acceptancePayloadV2(rec)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := key.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	rec.MAC = mac

	// Forge an attested window source AND an injected evidence kind on the
	// persisted evidence. The v2 encoding covers neither, so the digests and
	// the MAC stay valid — the row is exactly what a database writer could
	// produce.
	forged := sealed.Evidence()
	forged.Window = ExecutionWindow{
		StartedAt:   sealed.Outcome().StartedAt,
		CompletedAt: sealed.Outcome().CompletedAt,
		Source:      WindowSourceAttested,
	}
	forged.Kinds = []string{EvidenceKindExecutionAttestation, EvidenceKindTestReport}

	persisted := PersistedVerified{
		Obligation:     ob,
		SubmittedClaim: sealed.SubmittedClaim(),
		Outcome:        sealed.Outcome(),
		Evidence:       forged,
		Acceptance:     rec,
	}
	restored, err := RestoreVerifiedOutcome(persisted, key)
	if err != nil {
		t.Fatalf("intact v2 restore = %v", err)
	}
	if restored.Evidence().Window.Source == WindowSourceAttested {
		t.Fatal("v2 restore trusted a forged attested window source")
	}
	if restored.Evidence().Window.Source != WindowSourceUnknown {
		t.Fatalf("re-derived window source = %q, want unknown", restored.Evidence().Window.Source)
	}
	for _, k := range restored.Evidence().Kinds {
		if k == EvidenceKindTestReport {
			t.Fatal("v2 restore trusted an injected test-report evidence kind")
		}
	}
	// Kinds must be re-derived from the primitives: only the attestation
	// kind is present (one resolved attestation, no suite-derived check).
	if len(restored.Evidence().Kinds) != 1 || restored.Evidence().Kinds[0] != EvidenceKindExecutionAttestation {
		t.Fatalf("re-derived kinds = %v, want [execution-attestation]", restored.Evidence().Kinds)
	}
}

// ---------------------------------------------------------------------------
// P1h — recipe lifecycle.
// ---------------------------------------------------------------------------

// TestRecipePublishWithdrawLifecycle: Publish + Withdraw(digest, at, reason)
// track liveness explicitly; a re-publish carrying a WithdrawnAt must not
// silently keep the old live state; a stored withdrawal is sticky.
func TestRecipePublishWithdrawLifecycle(t *testing.T) {
	reg := NewRecipeRegistry()
	r := testRecipe(t)
	d, err := reg.Publish(r)
	if err != nil {
		t.Fatalf("Publish = %v", err)
	}
	got, err := reg.ByDigest(d)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Live(time.Now().UTC()) {
		t.Fatal("freshly published recipe must be live")
	}

	// Withdraw with an audit reason.
	at := r.IssuedAt.Add(time.Hour)
	if err := reg.Withdraw(d, at, "superseded by v2"); err != nil {
		t.Fatalf("Withdraw = %v", err)
	}
	got, err = reg.ByDigest(d)
	if err != nil {
		t.Fatal(err)
	}
	if got.Live(at.Add(time.Second)) {
		t.Fatal("withdrawn recipe must not be live after the withdrawal instant")
	}
	if got.WithdrawnAt == nil || !got.WithdrawnAt.Equal(at) {
		t.Fatalf("WithdrawnAt = %v, want %v", got.WithdrawnAt, at)
	}
	if got.WithdrawalReason != "superseded by v2" {
		t.Fatalf("WithdrawalReason = %q", got.WithdrawalReason)
	}
	// Withdrawal is not identity: the digest is unchanged.
	again, err := RecipeDigest(got)
	if err != nil {
		t.Fatal(err)
	}
	if again != d {
		t.Fatal("withdrawal must not change recipe identity")
	}

	// Re-publishing the live shape must NOT resurrect a withdrawn recipe.
	if _, err := reg.Publish(r); err != nil {
		t.Fatalf("re-publish = %v", err)
	}
	got, _ = reg.ByDigest(d)
	if got.Live(at.Add(time.Second)) {
		t.Fatal("re-publish must not resurrect a withdrawn recipe")
	}
}

// TestRecipeRepublishWithdrawnNotSilentlyLive: registering the same content
// with a WithdrawnAt must apply the withdrawal rather than keep the old live
// state (the Register early-return used to).
func TestRecipeRepublishWithdrawnNotSilentlyLive(t *testing.T) {
	reg := NewRecipeRegistry()
	r := testRecipe(t)
	d, err := reg.Register(r)
	if err != nil {
		t.Fatal(err)
	}
	wAt := r.IssuedAt.Add(time.Hour)
	withdrawn := r
	withdrawn.WithdrawnAt = &wAt
	withdrawn.WithdrawalReason = "policy change"
	if _, err := reg.Register(withdrawn); err != nil {
		t.Fatalf("re-register with WithdrawnAt = %v", err)
	}
	got, err := reg.ByDigest(d)
	if err != nil {
		t.Fatal(err)
	}
	if got.Live(wAt.Add(time.Second)) {
		t.Fatal("re-register with WithdrawnAt must not silently keep the old live state")
	}
	if got.WithdrawalReason != "policy change" {
		t.Fatalf("WithdrawalReason = %q, want policy change", got.WithdrawalReason)
	}
}

// TestRecipeWithdrawFailClosed: unknown digest, zero time and pre-issuance
// withdrawal are refused; a second withdrawal at a different instant is
// refused so history cannot be rewritten.
func TestRecipeWithdrawFailClosed(t *testing.T) {
	reg := NewRecipeRegistry()
	r := testRecipe(t)
	d, err := reg.Publish(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Withdraw(mustDigest(t, "unknown"), r.IssuedAt.Add(time.Hour), "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown digest = %v, want ErrNotFound", err)
	}
	if err := reg.Withdraw(d, time.Time{}, "x"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero time = %v, want ErrInvalid", err)
	}
	if err := reg.Withdraw(d, r.IssuedAt.Add(-time.Hour), "x"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("pre-issuance = %v, want ErrInvalid", err)
	}
	at := r.IssuedAt.Add(time.Hour)
	if err := reg.Withdraw(d, at, "first"); err != nil {
		t.Fatal(err)
	}
	// Same instant is idempotent (reason refreshed).
	if err := reg.Withdraw(d, at, "first-again"); err != nil {
		t.Fatalf("idempotent re-withdraw = %v, want success", err)
	}
	// A different instant rewrites history and is refused.
	if err := reg.Withdraw(d, at.Add(time.Hour), "second"); !errors.Is(err, ErrExists) {
		t.Fatalf("re-withdraw at different time = %v, want ErrExists", err)
	}
}

// TestRecipeRegistryConcurrentAccess: the registry is safe for concurrent
// publish/withdraw/lookup (P1h).
func TestRecipeRegistryConcurrentAccess(t *testing.T) {
	reg := NewRecipeRegistry()
	base := testRecipe(t)
	d, err := reg.Publish(base)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			r := base
			r.Version = 100 + n
			if _, err := reg.Publish(r); err != nil {
				t.Errorf("concurrent publish: %v", err)
				return
			}
			if _, err := reg.ByDigest(d); err != nil {
				t.Errorf("concurrent lookup: %v", err)
			}
			_ = reg.Withdraw(d, base.IssuedAt.Add(time.Duration(n+1)*time.Minute), "concurrent")
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if _, err := reg.ByDigest(d); err != nil {
		t.Fatalf("post-concurrent lookup: %v", err)
	}
}

// ---------------------------------------------------------------------------
// P1f — MinAttestations counts distinct digests.
// ---------------------------------------------------------------------------

// TestEvidenceMinimumCountsDistinctAttestations: two references to one signed
// statement are one piece of evidence — the floor counts distinct digests.
func TestEvidenceMinimumCountsDistinctAttestations(t *testing.T) {
	one := mustDigest(t, "one")
	two := mustDigest(t, "two")
	m := EvidenceMinimum{MinAttestations: 2}

	// Two entries, one digest: does NOT meet a floor of two.
	dup := VerifiedEvidence{AttestationDigests: []Digest{one, one}}
	if err := m.Check(dup); err == nil {
		t.Fatal("duplicate attestation digests must not satisfy MinAttestations=2")
	}
	// Two distinct digests do.
	distinct := VerifiedEvidence{AttestationDigests: []Digest{one, two}}
	if err := m.Check(distinct); err != nil {
		t.Fatalf("distinct digests = %v, want success", err)
	}
}

// TestVerifierRefusesDuplicateAttestationDigests: the verifier refuses a
// claim whose evidence refs resolve to the same signed statement.
func TestVerifierRefusesDuplicateAttestationDigests(t *testing.T) {
	ob := baseObligation(t)
	claim := baseOutcome(t, ob)
	claim.EvidenceRoot = mustDigest(t, "dup-root")
	claim.ProvenanceRefs = []string{"ref-a", "ref-b"}
	claim.ExecutionIDs = []string{"exec-1"}

	f := &FuncEvidenceVerifier{
		Identity: "dup-verifier/v1",
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			// Both refs resolve to the SAME signed statement.
			return ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      mustDigest(t, "dup-root"),
				AttestationDigest: mustDigest(t, "dup-att"),
				Status:            "success",
				Checks:            passChecks("exec-1", CheckJobStatusSuccess, CheckEvidenceRoot),
				Attested:          trustedWindow(),
			}, nil
		},
	}
	if _, err := f.Verify(context.Background(), ob, claim); err == nil {
		t.Fatal("duplicate attestation digest must be refused during verification")
	}
}

// ---------------------------------------------------------------------------
// P2i — evidence floor is pass-only everywhere.
// ---------------------------------------------------------------------------

// TestEvidenceFloorIsPassOnly: the floor gates a pass claim only; a fail
// whose evidence is below the floor still records (the floor is what a
// recipe demands "before any pass can be claimed").
func TestEvidenceFloorIsPassOnly(t *testing.T) {
	reg := NewRecipeRegistry()
	r := testRecipe(t)
	r.Requirements = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	r.Assurance = "no_injected_credentials"
	r.EvidenceMin = EvidenceMinimum{MinAttestations: 3}
	d, err := reg.Publish(r)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	// Seal a FAIL (signed job status failure) with a single attestation
	// (below the floor of 3). The fail is verifier-derived, never a
	// post-seal edit: the seal re-derives the result from the primitives.
	ob, resigned := evidenceFloorFixtureStatus(t, r, d, 1, trustedWindow(), string(model.StatusFailure))
	if resigned.Outcome().Outcome != OutcomeFail {
		t.Fatalf("fixture result = %q, want fail", resigned.Outcome().Outcome)
	}

	key := mustKey(t, "k-pass-only", "pass-only-secret-32-bytes-xx")
	at := now.Add(time.Minute)

	// Accept: fail below the floor is recorded.
	if _, err := AcceptWithRecipe(ob, resigned, key, nil, &r, at); err != nil {
		t.Fatalf("Accept fail below floor = %v, want success (pass-only)", err)
	}

	// Registry: same rule.
	store := NewMemoryStore(clock).WithRecipes(reg)
	if err := store.SubmitObligation(context.Background(), ob); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordVerifiedOutcome(context.Background(), resigned); err != nil {
		t.Fatalf("RecordVerifiedOutcome fail below floor = %v, want success (pass-only)", err)
	}

	// A PASS below the floor is still refused.
	_, passSealed := evidenceFloorFixtureStatus(t, r, d, 1, trustedWindow(), string(model.StatusSuccess))
	if _, err := AcceptWithRecipe(ob, passSealed, key, nil, &r, at); !errors.Is(err, ErrEvidence) {
		t.Fatalf("Accept pass below floor = %v, want ErrEvidence", err)
	}
}

// ---------------------------------------------------------------------------
// P2j — verified comparison requires a shared base.
// ---------------------------------------------------------------------------

// TestCompareVerifiedCandidatesRequiresSharedBase: every source's
// Outcome.SnapshotDigest must equal the comparison's base; a candidate
// verified against a different source state is not comparable.
func TestCompareVerifiedCandidatesRequiresSharedBase(t *testing.T) {
	base := mustDigest(t, "shared-base")
	other := mustDigest(t, "other-base")

	mk := func(snap Digest) VerifiedCandidateSource {
		t.Helper()
		iv := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		v := VerificationOutcome{
			VerificationID:   "ver-base",
			ObligationID:     "ob-base",
			CandidateDigest:  mustDigest(t, "cand"),
			SnapshotDigest:   snap,
			ContractDigest:   mustDigest(t, "contract"),
			Outcome:          OutcomePass,
			AssuranceProfile: modelAssuranceUncontrolled,
			CompletedChecks:  []string{CheckJobStatusSuccess},
			ExecutionIDs:     []string{"exec-1"},
			EvidenceRoot:     mustDigest(t, "evidence"),
			Resources:        ResourceFacts{RunnerClass: "standard"},
			StartedAt:        iv,
			CompletedAt:      iv.Add(time.Second),
		}
		ev := VerifiedEvidence{
			ExecutionIDs:       []string{"exec-1"},
			EvidenceRoot:       mustDigest(t, "evidence"),
			AttestationDigests: []Digest{mustDigest(t, "att")},
			JobStatus:          "success",
			CompletedChecks:    []string{CheckJobStatusSuccess},
			Assurance:          model.AssuranceUncontrolled,
			VerifierIdentity:   "base-verifier/v1",
			VerifiedAt:         iv,
		}
		sealed, err := sealDerivedOutcome(v, v, ev)
		if err != nil {
			t.Fatal(err)
		}
		src, err := VerifiedFromDerived("c-base", sealed, 0)
		if err != nil {
			t.Fatal(err)
		}
		return src
	}

	// Matching base: accepted.
	if _, err := CompareVerifiedCandidates(base, []VerifiedCandidateSource{mk(base)}, nil); err != nil {
		t.Fatalf("matching base = %v, want success", err)
	}
	// Different base: refused.
	if _, err := CompareVerifiedCandidates(base, []VerifiedCandidateSource{mk(other)}, nil); !errors.Is(err, ErrGroupBinding) {
		t.Fatalf("mismatched base = %v, want ErrGroupBinding", err)
	}
	// Missing base: refused.
	if _, err := CompareVerifiedCandidates("", []VerifiedCandidateSource{mk(base)}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty base = %v, want ErrInvalid", err)
	}
}
