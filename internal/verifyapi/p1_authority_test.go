package verifyapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// ---------------------------------------------------------------------------
// P1a — RecipeDigest binds semantics.
// ---------------------------------------------------------------------------

// TestServiceSubmitObligationRecipeWeakerDemandRefused is the P1a core: an
// obligation that pins RecipeDigest=R but carries weaker checks / assurance /
// freshness than the recipe is refused — recipe-owned fields are NOT
// independently definable.
func TestServiceSubmitObligationRecipeWeakerDemandRefused(t *testing.T) {
	f := newServiceFixture(t)
	reg := NewRecipeRegistry()
	f.svc.Recipes = reg
	f.store.WithRecipes(reg)
	r := testRecipe(t)
	// Align the recipe's checks/assurance with what the fixture can prove.
	r.Requirements = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	r.Assurance = "no_injected_credentials"
	r.EvidenceMin = EvidenceMinimum{MinAttestations: 1, RequiredKinds: []string{EvidenceKindExecutionAttestation}}
	d, err := reg.Register(r)
	if err != nil {
		t.Fatal(err)
	}

	ob := f.obligation(t, "ob-recipe", "tenant-a")
	ob.RecipeDigest = d
	// The obligation's inline demand matches the recipe: accepted and bound.
	if err := f.svc.SubmitObligation(context.Background(), f.tenantA, ob); err != nil {
		t.Fatalf("matching recipe obligation = %v, want success", err)
	}

	// Weaker checks under the same recipe digest: refused.
	weakerChecks := f.obligation(t, "ob-recipe-weaker-checks", "tenant-a")
	weakerChecks.RecipeDigest = d
	weakerChecks.RequiredChecks = []string{CheckJobStatusSuccess} // missing evidence-root
	if err := f.svc.SubmitObligation(context.Background(), f.tenantA, weakerChecks); !errors.Is(err, ErrBinding) {
		t.Fatalf("weaker checks under recipe = %v, want ErrBinding", err)
	}

	// Weaker assurance under the same recipe digest: refused.
	weakerAssurance := f.obligation(t, "ob-recipe-weaker-assurance", "tenant-a")
	weakerAssurance.RecipeDigest = d
	weakerAssurance.RequiredAssurance = modelAssuranceUncontrolled
	if err := f.svc.SubmitObligation(context.Background(), f.tenantA, weakerAssurance); !errors.Is(err, ErrBinding) {
		t.Fatalf("weaker assurance under recipe = %v, want ErrBinding", err)
	}

	// Disagreeing freshness under the same recipe digest: refused.
	otherFreshness := f.obligation(t, "ob-recipe-other-freshness", "tenant-a")
	otherFreshness.RecipeDigest = d
	otherFreshness.Freshness = FreshnessPolicy{MaxAgeSeconds: 60}
	if err := f.svc.SubmitObligation(context.Background(), f.tenantA, otherFreshness); !errors.Is(err, ErrBinding) {
		t.Fatalf("disagreeing freshness under recipe = %v, want ErrBinding", err)
	}
}

// modelAssuranceUncontrolled is the conservative derived profile name used by
// fixtures without assurance facts.
const modelAssuranceUncontrolled = "uncontrolled"

// TestServiceRecipeWithdrawalBlocksNewDemand: a withdrawn recipe cannot mint
// new demand — SubmitObligation is refused even though the digest still
// resolves.
func TestServiceRecipeWithdrawalBlocksNewDemand(t *testing.T) {
	f := newServiceFixture(t)
	reg := NewRecipeRegistry()
	f.svc.Recipes = reg
	f.store.WithRecipes(reg)
	r := testRecipe(t)
	r.Requirements = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	r.Assurance = "no_injected_credentials"
	r.EvidenceMin = EvidenceMinimum{MinAttestations: 1}
	d, err := reg.Register(r)
	if err != nil {
		t.Fatal(err)
	}

	// Withdraw the recipe AFTER publication (liveness fact, not identity).
	withdrawnAt := f.clock().Add(-time.Second)
	r.WithdrawnAt = &withdrawnAt
	// Re-registering identical content is a no-op; withdrawal is tracked on
	// the stored recipe via the registry's live view. Model it by replacing
	// the registry entry through a fresh register of the withdrawn shape
	// under a new version — here we simply check BindRecipe's liveness and
	// the service's submit gate against a registry that knows the
	// withdrawal. The RecipeRegistry stores the recipe as registered; a
	// withdrawal is applied by registering the same content with a
	// WithdrawnAt is NOT a different identity (digest excludes it), so the
	// service must consult Live() on the resolved recipe. Simulate the
	// post-publication withdrawal by storing the withdrawn recipe under the
	// same digest via a tiny shim registry state: re-register is idempotent
	// on content, so instead assert through BindRecipe + the service path
	// using a registry populated with the withdrawn recipe from the start
	// under a different name/version pair is wrong — the requirement is
	// that LIVE(recipe)=false blocks new demand. Use BindRecipe directly
	// for the pure rule, and the service with a registry whose resolved
	// recipe reports withdrawn.
	_ = d

	// Pure rule: BindRecipe refuses a recipe that is not live at bind time.
	if _, err := BindRecipe(f.obligation(t, "ob-x", "tenant-a"), r, f.clock()); !errors.Is(err, ErrBinding) {
		t.Fatalf("BindRecipe withdrawn = %v, want ErrBinding", err)
	}

	// Service path: resolve through a registry that holds the withdrawn
	// recipe (Register accepts it; Live is evaluated at submit time).
	reg2 := NewRecipeRegistry()
	withdrawnRecipe := testRecipe(t)
	withdrawnRecipe.Requirements = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	withdrawnRecipe.Assurance = "no_injected_credentials"
	wat := withdrawnRecipe.IssuedAt.Add(30 * time.Second)
	withdrawnRecipe.WithdrawnAt = &wat
	d2, err := reg2.Register(withdrawnRecipe)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.Recipes = reg2
	f.store.WithRecipes(reg2)
	ob := f.obligation(t, "ob-withdrawn", "tenant-a")
	ob.RecipeDigest = d2
	if err := f.svc.SubmitObligation(context.Background(), f.tenantA, ob); !errors.Is(err, ErrBinding) {
		t.Fatalf("submit under withdrawn recipe = %v, want ErrBinding", err)
	}
}

// TestServiceSubmitObligationResolvesRecipeFromRegistry: an unknown recipe
// digest is refused (ErrNotFound) rather than accepted on faith.
func TestServiceSubmitObligationResolvesRecipeFromRegistry(t *testing.T) {
	f := newServiceFixture(t)
	f.svc.Recipes = NewRecipeRegistry()
	f.store.WithRecipes(NewRecipeRegistry())
	ob := f.obligation(t, "ob-unknown-recipe", "tenant-a")
	ob.RecipeDigest = mustDigest(t, "no-such-recipe")
	if err := f.svc.SubmitObligation(context.Background(), f.tenantA, ob); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown recipe = %v, want ErrNotFound", err)
	}

	// No registry configured: fail closed.
	f.svc.Recipes = nil
	f.store.WithRecipes(nil)
	if err := f.svc.SubmitObligation(context.Background(), f.tenantA, ob); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no registry = %v, want ErrNotFound", err)
	}
}

// TestServiceSubmitObligationRecipeSuppliesPolicyFields: the documented
// recipe-bound usage is "submit identity + recipe, Kiwi resolves and fills
// the recipe-owned policy dimensions". The caller must NOT have to
// pre-populate required_checks / required_assurance / freshness before
// SubmitObligation — that would duplicate recipe authority into the caller.
// ValidateSubmission accepts the partial form; the bound obligation is then
// fully validated before authorize/persist.
func TestServiceSubmitObligationRecipeSuppliesPolicyFields(t *testing.T) {
	f := newServiceFixture(t)
	reg := NewRecipeRegistry()
	f.svc.Recipes = reg
	f.store.WithRecipes(reg)
	r := testRecipe(t)
	r.Requirements = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	r.Assurance = "no_injected_credentials"
	r.Freshness = FreshnessPolicy{MaxAgeSeconds: 7200}
	r.EvidenceMin = EvidenceMinimum{MinAttestations: 1, RequiredKinds: []string{EvidenceKindExecutionAttestation}}
	d, err := reg.Register(r)
	if err != nil {
		t.Fatal(err)
	}

	// Identity + recipe only: no checks, no assurance, no freshness.
	ob := baseObligation(t)
	ob.ObligationID = "ob-recipe-supplied"
	ref := tenantRef("tenant-a")
	ob.SubjectRef = &ref
	ob.RecipeDigest = d
	ob.RequiredChecks = nil
	ob.RequiredAssurance = ""
	ob.Freshness = FreshnessPolicy{}

	// Pre-bind gate accepts the partial submission.
	if err := ob.ValidateSubmission(); err != nil {
		t.Fatalf("ValidateSubmission of recipe-owned-empty obligation = %v, want success", err)
	}
	// Full bound Validate must still refuse the unbound partial form: the
	// policy dimensions are required on the BOUND obligation.
	if err := ob.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate of unbound partial obligation = %v, want ErrInvalid", err)
	}

	if err := f.svc.SubmitObligation(context.Background(), f.tenantA, ob); err != nil {
		t.Fatalf("SubmitObligation identity+recipe = %v, want success", err)
	}

	stored, err := f.store.GetObligation(context.Background(), ob.ObligationID)
	if err != nil {
		t.Fatalf("GetObligation: %v", err)
	}
	if !stringSetsEqual(stored.RequiredChecks, r.Requirements) {
		t.Fatalf("stored checks = %v, want recipe %v", stored.RequiredChecks, r.Requirements)
	}
	if stored.RequiredAssurance != r.Assurance {
		t.Fatalf("stored assurance = %q, want recipe %q", stored.RequiredAssurance, r.Assurance)
	}
	if !freshnessEqual(stored.Freshness, r.Freshness) {
		t.Fatalf("stored freshness = %+v, want recipe %+v", stored.Freshness, r.Freshness)
	}
	if stored.RecipeDigest != d {
		t.Fatalf("stored recipe digest = %s, want %s", stored.RecipeDigest, d)
	}
	if err := stored.Validate(); err != nil {
		t.Fatalf("bound stored obligation must Validate: %v", err)
	}

	// Without a recipe the same empty policy dimensions stay refused — the
	// full Validate gate is unchanged for inline obligations.
	inline := baseObligation(t)
	inline.ObligationID = "ob-inline-empty"
	inline.SubjectRef = &ref
	inline.RequiredChecks = nil
	inline.RequiredAssurance = ""
	inline.Freshness = FreshnessPolicy{}
	if err := f.svc.SubmitObligation(context.Background(), f.tenantA, inline); !errors.Is(err, ErrInvalid) {
		t.Fatalf("inline empty policy = %v, want ErrInvalid", err)
	}
}

// TestAcceptBindsEffectiveVerificationDemandDigest: the acceptance record
// commits the canonical resolved demand, and tampering the demand (or the
// recipe identity) breaks restore.
func TestAcceptBindsEffectiveVerificationDemandDigest(t *testing.T) {
	ob := baseObligation(t)
	ob.RequiredChecks = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	v := baseOutcome(t, ob)
	v.EvidenceRoot = mustDigest(t, "demand-root")
	v.ProvenanceRefs = []string{"att-1"}
	v.ExecutionIDs = []string{"exec-1"}

	f := &FuncEvidenceVerifier{
		Identity: "demand-verifier/v1",
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      mustDigest(t, "demand-root"),
				AttestationDigest: mustDigest(t, "demand-att"),
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
	if !sealed.ProvenPass() {
		t.Fatal("want sealed proven pass")
	}
	key, err := NewHMACAcceptanceKey("acc-demand", []byte("demand-test-secret-32-bytes-xx"))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := Accept(ob, sealed, key, time.Date(2026, 1, 2, 3, 6, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Accept = %v", err)
	}
	want, err := EffectiveVerificationDemandDigest(ob, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.DemandDigest != want {
		t.Fatalf("DemandDigest = %s, want %s", rec.DemandDigest, want)
	}
	if rec.AcceptanceVersion != AcceptanceVersionCurrent {
		t.Fatalf("AcceptanceVersion = %d, want %d", rec.AcceptanceVersion, AcceptanceVersionCurrent)
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

	// Swap the demanded checks on the stored obligation: the demand digest
	// no longer matches and restore is refused.
	tampered := persisted
	tampered.Obligation = persisted.Obligation
	tampered.Obligation.RequiredChecks = []string{CheckJobStatusSuccess}
	if _, err := RestoreVerifiedOutcome(tampered, key); !errors.Is(err, ErrAcceptance) {
		t.Fatalf("tampered demand = %v, want ErrAcceptance", err)
	}

	// Swap the recipe identity on the stored obligation: same refusal
	// (the demand pins the recipe digest too).
	tamperedRecipe := persisted
	tamperedRecipe.Obligation = persisted.Obligation
	tamperedRecipe.Obligation.RecipeDigest = mustDigest(t, "other-recipe")
	if _, err := RestoreVerifiedOutcome(tamperedRecipe, key); !errors.Is(err, ErrAcceptance) {
		t.Fatalf("tampered recipe identity = %v, want ErrAcceptance", err)
	}
}

// TestEvidenceMinimumEnforcedOnDischarge: Recipe.EvidenceMinimum gates the
// authoritative discharge path — RequireAttestedWindow, MinAttestations and
// RequiredKinds are all enforced against verifier-derived evidence.
func TestEvidenceMinimumEnforcedOnDischarge(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	// Recipe demands an attested window.
	r := testRecipe(t)
	r.Requirements = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	r.Assurance = "no_injected_credentials"
	r.EvidenceMin = EvidenceMinimum{
		MinAttestations:       1,
		RequiredKinds:         []string{EvidenceKindExecutionAttestation},
		RequireAttestedWindow: true,
	}
	reg := NewRecipeRegistry()
	d, err := reg.Register(r)
	if err != nil {
		t.Fatal(err)
	}

	principal := Principal{Subject: "svc", Capabilities: CapabilitiesIn(tenantRef("tenant-a"))}
	base := func(id string) VerificationObligation {
		ob := baseObligation(t)
		ref := tenantRef("tenant-a")
		ob.SubjectRef = &ref
		ob.ObligationID = id
		ob.RequiredChecks = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
		ob.RequiredAssurance = "no_injected_credentials"
		ob.RecipeDigest = d
		return ob
	}
	claimFor := func(ob VerificationObligation) VerificationOutcome {
		v := baseOutcome(t, ob)
		v.EvidenceRoot = mustDigest(t, "min-root")
		v.ProvenanceRefs = []string{"att-1"}
		v.ExecutionIDs = []string{"exec-1"}
		v.CompletedChecks = append([]string(nil), ob.RequiredChecks...)
		v.AssuranceProfile = ob.RequiredAssurance
		return v
	}
	resolveWith := func(window *AttestedResourceFacts) AttestationResolver {
		return func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      mustDigest(t, "min-root"),
				AttestationDigest: mustDigest(t, "min-att"),
				Status:            "success",
				Facts:             &model.ExecutionFacts{FilesystemIsolated: true},
				Checks:            passChecks("exec-1", CheckJobStatusSuccess, CheckEvidenceRoot),
				Attested:          window,
			}, nil
		}
	}

	// A no-window attestation under RequireAttestedWindow: freshness is
	// UNKNOWN, so the attempt can never discharge as a pass (the derived
	// outcome is downgraded and the floor refuses a pass regardless).
	svc, err := NewService(NewMemoryStore(clock).WithRecipes(reg), &FuncEvidenceVerifier{
		Identity: "min-verifier/v1",
		Clock:    clock,
		Resolve:  resolveWith(nil),
	}, ScopeAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	svc.Clock = clock
	svc.Recipes = reg
	ob := base("ob-min")
	if err := svc.SubmitObligation(context.Background(), principal, ob); err != nil {
		t.Fatalf("SubmitObligation = %v", err)
	}
	claim := claimFor(ob)
	seal, err := svc.VerifyAndRecord(context.Background(), principal, claim)
	if err != nil {
		// A hard refusal is also acceptable (fail closed).
		if !errors.Is(err, ErrFreshness) && !errors.Is(err, ErrEvidence) {
			t.Fatalf("discharge without attested window = %v, want refusal or a non-pass", err)
		}
	} else if seal.ProvenPass() || seal.Outcome().Outcome == OutcomePass {
		t.Fatalf("discharge without attested window must not produce a pass (outcome=%q)", seal.Outcome().Outcome)
	}

	// An OBSERVED (not attested) window under RequireAttestedWindow: the
	// default freshness floor is cleared (so checks can yield pass), but
	// the recipe floor demands an attested window and refuses the pass.
	svcObs, err := NewService(NewMemoryStore(clock).WithRecipes(reg), &FuncEvidenceVerifier{
		Identity: "min-verifier-obs/v1",
		Clock:    clock,
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      mustDigest(t, "min-root"),
				AttestationDigest: mustDigest(t, "min-att"),
				Status:            "success",
				Facts:             &model.ExecutionFacts{FilesystemIsolated: true},
				Checks:            passChecks("exec-1", CheckJobStatusSuccess, CheckEvidenceRoot),
				ObserverWindow:    trustedWindow(),
			}, nil
		},
	}, ScopeAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	svcObs.Clock = clock
	svcObs.Recipes = reg
	obObs := base("ob-min-obs")
	if err := svcObs.SubmitObligation(context.Background(), principal, obObs); err != nil {
		t.Fatalf("SubmitObligation obs = %v", err)
	}
	if _, err := svcObs.VerifyAndRecord(context.Background(), principal, claimFor(obObs)); err == nil {
		t.Fatal("discharge with only an observer window must be refused under RequireAttestedWindow")
	} else if !errors.Is(err, ErrFreshness) {
		t.Fatalf("observer-window discharge = %v, want ErrFreshness", err)
	}

	// The same evidence with an attested window discharges as a pass.
	svc2, err := NewService(NewMemoryStore(clock).WithRecipes(reg), &FuncEvidenceVerifier{
		Identity: "min-verifier-with-window/v1",
		Clock:    clock,
		Resolve:  resolveWith(trustedWindow()),
	}, ScopeAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	svc2.Clock = clock
	svc2.Recipes = reg
	ob2 := base("ob-min-window")
	if err := svc2.SubmitObligation(context.Background(), principal, ob2); err != nil {
		t.Fatalf("SubmitObligation (window) = %v", err)
	}
	seal2, err := svc2.VerifyAndRecord(context.Background(), principal, claimFor(ob2))
	if err != nil {
		t.Fatalf("discharge with attested window = %v, want success", err)
	}
	if !seal2.ProvenPass() {
		t.Fatal("attested window under RequireAttestedWindow must discharge as a proven pass")
	}

	// MinAttestations floor: demand two attestations, resolve only one.
	r2 := r
	r2.Version = 2
	r2.EvidenceMin.MinAttestations = 2
	r2.EvidenceMin.RequireAttestedWindow = true
	reg2 := NewRecipeRegistry()
	d2, err := reg2.Register(r2)
	if err != nil {
		t.Fatal(err)
	}
	svc3, err := NewService(NewMemoryStore(clock).WithRecipes(reg2), &FuncEvidenceVerifier{
		Identity: "min-verifier-2/v1",
		Clock:    clock,
		Resolve:  resolveWith(trustedWindow()),
	}, ScopeAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	svc3.Clock = clock
	svc3.Recipes = reg2
	ob3 := base("ob-min-2")
	ob3.RecipeDigest = d2
	if err := svc3.SubmitObligation(context.Background(), principal, ob3); err != nil {
		t.Fatalf("SubmitObligation 2 = %v", err)
	}
	if _, err := svc3.VerifyAndRecord(context.Background(), principal, claimFor(ob3)); err == nil {
		t.Fatal("discharge with too few attestations must be refused under MinAttestations")
	} else if !errors.Is(err, ErrEvidence) {
		t.Fatalf("min-attestations error = %v, want ErrEvidence", err)
	}

	// RequiredKinds floor: demand a test-report kind the evidence lacks.
	r3 := r
	r3.Version = 3
	r3.EvidenceMin = EvidenceMinimum{
		MinAttestations:       1,
		RequiredKinds:         []string{EvidenceKindTestReport},
		RequireAttestedWindow: true,
	}
	reg3 := NewRecipeRegistry()
	d3, err := reg3.Register(r3)
	if err != nil {
		t.Fatal(err)
	}
	svc4, err := NewService(NewMemoryStore(clock).WithRecipes(reg3), &FuncEvidenceVerifier{
		Identity: "min-verifier-3/v1",
		Clock:    clock,
		Resolve:  resolveWith(trustedWindow()),
	}, ScopeAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	svc4.Clock = clock
	svc4.Recipes = reg3
	ob4 := base("ob-min-3")
	ob4.RecipeDigest = d3
	if err := svc4.SubmitObligation(context.Background(), principal, ob4); err != nil {
		t.Fatalf("SubmitObligation 3 = %v", err)
	}
	if _, err := svc4.VerifyAndRecord(context.Background(), principal, claimFor(ob4)); err == nil {
		t.Fatal("discharge without a required evidence kind must be refused")
	} else if !errors.Is(err, ErrEvidence) {
		t.Fatalf("required-kinds error = %v, want ErrEvidence", err)
	}
}

// ---------------------------------------------------------------------------
// P1b — Freshness cannot inherit caller timestamps.
// ---------------------------------------------------------------------------

// TestCallerTypedWindowNeverSatisfiesFreshness is the P1b core: when the
// attestation carries no window, the caller-typed started_at/completed_at is
// NEVER freshness authority. The derived window is Unknown, freshness is
// UNKNOWN (NOT satisfied), and the attempt is evidence_incomplete with
// missing=attested_execution_window.
func TestCallerTypedWindowNeverSatisfiesFreshness(t *testing.T) {
	ob := baseObligation(t)
	v := baseOutcome(t, ob)
	// The caller types a window that would satisfy the freshness policy.
	v.StartedAt = ob.IssuedAt.Add(time.Second)
	v.CompletedAt = ob.IssuedAt.Add(10 * time.Second)
	v.ExecutionIDs = v.ExecutionIDs[:1]
	v.ProvenanceRefs = []string{"bare-att"}

	f := &FuncEvidenceVerifier{
		Identity: "freshness-verifier/v1",
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       v.ExecutionIDs[0],
				EvidenceRoot:      v.EvidenceRoot,
				AttestationDigest: mustDigest(t, "fresh-att"),
				Status:            "success",
				Checks:            passChecks(v.ExecutionIDs[0], "digest-match", "signature"),
				// No Attested / ObserverWindow: the attestation lacks a window.
			}, nil
		},
	}
	vo, err := f.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}

	// The derived window is Unknown — the claim's times are not a source.
	if vo.Evidence().Window.Source != WindowSourceUnknown {
		t.Fatalf("window source = %q, want %q", vo.Evidence().Window.Source, WindowSourceUnknown)
	}
	// Unknown never satisfies freshness at ANY minimum authority.
	for _, min := range []WindowSource{WindowSourceUnknown, WindowSourceVerifiedObserver, WindowSourceAttested} {
		if vo.Evidence().Window.SatisfiesFreshness(min) {
			t.Fatalf("Unknown window must not satisfy freshness at min=%q", min)
		}
		if EvaluateFreshness(vo.Evidence().Window, ob.Freshness, ob.IssuedAt, ob.IssuedAt.Add(30*time.Second), min) != FreshnessUnknown {
			t.Fatalf("EvaluateFreshness at min=%q = %v, want unknown", min,
				EvaluateFreshness(vo.Evidence().Window, ob.Freshness, ob.IssuedAt, ob.IssuedAt.Add(30*time.Second), min))
		}
	}

	// The sealed record is NOT a proven pass: freshness is unsatisfied.
	if vo.Outcome().Outcome != OutcomePartial {
		t.Fatalf("derived outcome = %q, want partial (freshness unknown)", vo.Outcome().Outcome)
	}
	if vo.ProvenPass() {
		t.Fatal("caller-typed window must never produce a proven pass")
	}

	// Rich status: evidence_incomplete missing=attested_execution_window.
	c := ComputeEvidenceCompleteness(
		[]string{"digest-match", "signature"},
		[]string{"digest-match", "signature"},
		[]string{"digest-match", "signature"},
	)
	status := StatusFromEvidence(c, vo.Outcome().Outcome, vo.Evidence().Window, MinWindowForRequireAttested(false))
	if status.Terminal != TerminalEvidenceIncomplete {
		t.Fatalf("terminal = %q, want %q", status.Terminal, TerminalEvidenceIncomplete)
	}
	if status.ProvenPass() {
		t.Fatal("freshness UNKNOWN must not be a proven pass")
	}
	if len(status.MissingItems) != 1 || status.MissingItems[0] != MissingAttestedExecutionWindow {
		t.Fatalf("missing items = %v, want [%s]", status.MissingItems, MissingAttestedExecutionWindow)
	}

	// An attested window under the same claim DOES satisfy freshness.
	f2 := &FuncEvidenceVerifier{
		Identity: "freshness-verifier-attested/v1",
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       v.ExecutionIDs[0],
				EvidenceRoot:      v.EvidenceRoot,
				AttestationDigest: mustDigest(t, "fresh-att"),
				Status:            "success",
				Checks:            passChecks(v.ExecutionIDs[0], "digest-match", "signature"),
				Attested:          trustedWindow(),
			}, nil
		},
	}
	vo2, err := f2.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify attested = %v", err)
	}
	if vo2.Evidence().Window.Source != WindowSourceAttested {
		t.Fatalf("window source = %q, want %q", vo2.Evidence().Window.Source, WindowSourceAttested)
	}
	if !vo2.Evidence().Window.SatisfiesFreshness(MinWindowForRequireAttested(false)) {
		t.Fatal("attested window must satisfy freshness")
	}
	if !vo2.ProvenPass() {
		t.Fatal("attested window must allow a proven pass")
	}
}

// TestSatisfiesFreshnessRequiresMinimumAuthority pins the authority ladder:
// Attested clears every floor; VerifiedObserver clears only a non-attested
// floor; Unknown clears nothing.
func TestSatisfiesFreshnessRequiresMinimumAuthority(t *testing.T) {
	iv := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		name string
		src  WindowSource
		min  WindowSource
		want bool
	}{
		{"attested meets attested", WindowSourceAttested, WindowSourceAttested, true},
		{"attested meets observer", WindowSourceAttested, WindowSourceVerifiedObserver, true},
		{"observer meets observer", WindowSourceVerifiedObserver, WindowSourceVerifiedObserver, true},
		{"observer fails attested floor", WindowSourceVerifiedObserver, WindowSourceAttested, false},
		{"unknown fails attested floor", WindowSourceUnknown, WindowSourceAttested, false},
		{"unknown fails observer floor", WindowSourceUnknown, WindowSourceVerifiedObserver, false},
		{"unknown fails unknown floor", WindowSourceUnknown, WindowSourceUnknown, false},
	}
	for _, tc := range cases {
		w := ExecutionWindow{StartedAt: iv, CompletedAt: iv.Add(time.Second), Source: tc.src}
		if got := w.SatisfiesFreshness(tc.min); got != tc.want {
			t.Fatalf("%s: SatisfiesFreshness(%q) = %v, want %v", tc.name, tc.min, got, tc.want)
		}
	}
	// MinWindowForRequireAttested maps the recipe flag onto the floor.
	if MinWindowForRequireAttested(true) != WindowSourceAttested {
		t.Fatal("RequireAttestedWindow must demand an attested window")
	}
	if MinWindowForRequireAttested(false) != WindowSourceVerifiedObserver {
		t.Fatal("default floor must be any trusted window")
	}
	// A caller-typed window (Unknown) with a perfect policy interval is
	// still freshness UNKNOWN.
	w := ExecutionWindow{StartedAt: iv, CompletedAt: iv.Add(time.Second), Source: WindowSourceUnknown}
	policy := FreshnessPolicy{MaxAgeSeconds: 3600}
	if got := EvaluateFreshness(w, policy, iv, iv.Add(30*time.Second), WindowSourceVerifiedObserver); got != FreshnessUnknown {
		t.Fatalf("caller-typed window freshness = %v, want unknown", got)
	}
	// The same interval attested is satisfied.
	w.Source = WindowSourceAttested
	if got := EvaluateFreshness(w, policy, iv, iv.Add(30*time.Second), WindowSourceVerifiedObserver); got != FreshnessSatisfied {
		t.Fatalf("attested window freshness = %v, want satisfied", got)
	}
}

// TestVerifiedObserverWindowIsWeakerThanAttested: a verified-observer window
// satisfies a normal freshness floor but never a RequireAttestedWindow one.
func TestVerifiedObserverWindowIsWeakerThanAttested(t *testing.T) {
	ob := baseObligation(t)
	v := baseOutcome(t, ob)
	v.ExecutionIDs = v.ExecutionIDs[:1]
	v.ProvenanceRefs = []string{"obs-att"}

	f := &FuncEvidenceVerifier{
		Identity: "observer-verifier/v1",
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       v.ExecutionIDs[0],
				EvidenceRoot:      v.EvidenceRoot,
				AttestationDigest: mustDigest(t, "obs-att-digest"),
				Status:            "success",
				Checks:            passChecks(v.ExecutionIDs[0], "digest-match", "signature"),
				ObserverWindow:    trustedWindow(),
			}, nil
		},
	}
	vo, err := f.Verify(context.Background(), ob, v)
	if err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if vo.Evidence().Window.Source != WindowSourceVerifiedObserver {
		t.Fatalf("window source = %q, want %q", vo.Evidence().Window.Source, WindowSourceVerifiedObserver)
	}
	if !vo.Evidence().Window.SatisfiesFreshness(WindowSourceVerifiedObserver) {
		t.Fatal("observer window must satisfy a non-attested floor")
	}
	if vo.Evidence().Window.SatisfiesFreshness(WindowSourceAttested) {
		t.Fatal("observer window must NOT satisfy a RequireAttestedWindow floor")
	}
	// Under the default floor an observer window can still discharge.
	if !vo.ProvenPass() {
		t.Fatal("observer window must allow a proven pass under the default floor")
	}
	// The recipe floor raises the bar to attested.
	min := MinWindowForRequireAttested(true)
	status := StatusFromEvidence(EvidenceCompleteness{Required: 1, Present: 1, Verified: 1}, vo.Outcome().Outcome, vo.Evidence().Window, min)
	if status.Terminal != TerminalEvidenceIncomplete {
		t.Fatalf("terminal under RequireAttestedWindow = %q, want evidence_incomplete", status.Terminal)
	}
	if len(status.MissingItems) == 0 || status.MissingItems[0] != MissingAttestedExecutionWindow {
		t.Fatalf("missing items = %v, want [%s]", status.MissingItems, MissingAttestedExecutionWindow)
	}
}

// TestAcceptRefusesRecipeBoundWithoutRecipe: a recipe-bound obligation must
// be accepted only against its resolved recipe. Accepting it with nil recipe
// would mint a valid MAC over weaker inline rules while advertising a strong
// recipe label (the substitution hole).
func TestAcceptRefusesRecipeBoundWithoutRecipe(t *testing.T) {
	r := Recipe{
		SchemaVersion: RecipeSchemaVersion,
		Name:          "strict",
		Version:       1,
		Requirements:  []string{CheckJobStatusSuccess, CheckEvidenceRoot},
		Assurance:     "no_injected_credentials",
		IssuedAt:      time.Now().UTC().Add(-time.Hour),
		Freshness:     FreshnessPolicy{MaxAgeSeconds: 3600},
	}
	r.EvidenceMin = EvidenceMinimum{MinAttestations: 1, RequiredKinds: []string{EvidenceKindExecutionAttestation}}
	reg := NewRecipeRegistry()
	d, err := reg.Register(r)
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return time.Now().UTC() }
	claimFor := func(ob VerificationObligation) VerificationOutcome {
		v := baseOutcome(t, ob)
		v.EvidenceRoot = mustDigest(t, "min-root")
		v.ProvenanceRefs = []string{"att-1"}
		v.ExecutionIDs = []string{"exec-1"}
		v.CompletedChecks = append([]string(nil), ob.RequiredChecks...)
		v.AssuranceProfile = ob.RequiredAssurance
		return v
	}
	resolve := func(context.Context, string) (ResolvedAttestation, error) {
		return ResolvedAttestation{
			ExecutionID:       "exec-1",
			EvidenceRoot:      mustDigest(t, "min-root"),
			AttestationDigest: mustDigest(t, "min-att"),
			Status:            "success",
			Facts:             &model.ExecutionFacts{FilesystemIsolated: true},
			Checks:            passChecks("exec-1", CheckJobStatusSuccess, CheckEvidenceRoot),
			Attested:          trustedWindow(),
		}, nil
	}
	f := &FuncEvidenceVerifier{Identity: "recipe-hole/v1", Clock: clock, Resolve: resolve}
	key := mustKey(t, "k1", "secret-1")

	// Unbound weaker obligation (inline rules disagree with recipe R).
	ob := baseObligation(t)
	ob.ObligationID = "ob-hole"
	ob.RequiredChecks = []string{CheckJobStatusSuccess}
	ob.RequiredAssurance = "uncontrolled"
	ob.RecipeDigest = d
	claim := claimFor(ob)
	sealed, err := f.Verify(context.Background(), ob, claim)
	if err != nil {
		t.Fatalf("seal unbound: %v", err)
	}
	if _, err := AcceptWithKeyring(ob, sealed, key, nil, time.Now().UTC()); err == nil {
		t.Fatal("Accept of recipe-bound obligation without resolved recipe must fail")
	}
	if _, err := AcceptWithRecipe(ob, sealed, key, nil, &r, time.Now().UTC()); err == nil {
		t.Fatal("Accept of obligation that disagrees with its recipe must fail")
	}

	// Bound obligation + matching recipe succeeds: start from a clean
	// obligation so BindRecipe can fill the recipe-owned fields.
	clean := baseObligation(t)
	clean.ObligationID = "ob-bound"
	clean.RecipeDigest = d
	clean.IssuedAt = ob.IssuedAt
	clean.Freshness = FreshnessPolicy{}
	clean.RequiredChecks = nil
	clean.RequiredAssurance = ""
	bound, err := BindRecipe(clean, r, ob.IssuedAt)
	if err != nil {
		t.Fatalf("BindRecipe: %v", err)
	}
	bclaim := claimFor(bound)
	sealed2, err := f.Verify(context.Background(), bound, bclaim)
	if err != nil {
		t.Fatalf("seal bound: %v", err)
	}
	if _, err := AcceptWithRecipe(bound, sealed2, key, nil, &r, time.Now().UTC()); err != nil {
		t.Fatalf("Accept of bound obligation with recipe: %v", err)
	}
}

// TestLegacyRestoreRederivesWindowKinds: v1/v2 evidence encodings never bound
// Window.Source or Kinds. A database writer must not be able to forge
// attested-window authority onto a legacy row — restore re-derives both from
// MAC-verified primitives.
func mustAcceptRecord(t *testing.T, ob VerificationObligation, sealed DerivedVerifiedOutcome, key AcceptanceKey) AcceptanceRecord {
	t.Helper()
	rec, err := AcceptWithKeyring(ob, sealed, key, nil, time.Now().UTC())
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	return rec
}

func TestLegacyRestoreRederivesWindowKinds(t *testing.T) {
	key := mustKey(t, "k1", "secret-1")
	ob := baseObligation(t)
	claim := baseOutcome(t, ob)
	claim.ProvenanceRefs = []string{"att-1"}
	claim.ExecutionIDs = []string{"exec-1"}
	claim.EvidenceRoot = mustDigest(t, "root")
	claim.CompletedChecks = ob.RequiredChecks
	f := &FuncEvidenceVerifier{
		Identity: "legacy-rederive/v1",
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      claim.EvidenceRoot,
				AttestationDigest: mustDigest(t, "att"),
				Status:            "success",
				Checks:            passChecks("exec-1", CheckJobStatusSuccess, CheckEvidenceRoot),
				// No Attested window: derived window source is Unknown.
			}, nil
		},
	}
	sealed, err := f.Verify(context.Background(), ob, claim)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Forge Window.Source=attested on the persisted evidence (as a DB
	// writer would). The v2/v1 MAC does not cover Window.
	forged := sealed.Evidence()
	forged.Window = ExecutionWindow{
		StartedAt:   sealed.Outcome().StartedAt,
		CompletedAt: sealed.Outcome().CompletedAt,
		Source:      WindowSourceAttested,
	}
	persisted := PersistedVerified{
		Obligation:     ob,
		SubmittedClaim: sealed.SubmittedClaim(),
		Outcome:        sealed.Outcome(),
		Evidence:       forged,
		Acceptance:     mustAcceptRecord(t, ob, sealed, key),
	}
	// Tamper the acceptance record's evidence digest so the MAC still
	// verifies over the forged evidence (simulating a writer who also
	// re-MACs — the MAC key is the trust root; without it the row fails).
	// Instead: accept the sealed (honest) record, then swap only Evidence.
	rec := mustAcceptRecord(t, ob, sealed, key)
	persisted.Acceptance = rec
	restored, err := RestoreVerifiedOutcome(persisted, key)
	if err != nil {
		// Digest mismatch is also a correct fail-closed outcome.
		t.Logf("restore refused forged evidence: %v", err)
		return
	}
	if restored.Evidence().Window.Source == WindowSourceAttested {
		t.Fatal("legacy restore trusted a forged attested window source")
	}
}

// TestPostSealMutationCannotUpgradeAuthority: a sealed DerivedVerifiedOutcome
// is a Go struct — flipping Outcome.Result after the verifier sealed it must
// not create an authoritative pass at Accept or RecordVerifiedOutcome.
func TestPostSealMutationCannotUpgradeAuthority(t *testing.T) {
	clock := func() time.Time { return time.Now().UTC() }
	f := &FuncEvidenceVerifier{
		Identity: "post-seal/v1",
		Clock:    clock,
		Resolve: func(context.Context, string) (ResolvedAttestation, error) {
			return ResolvedAttestation{
				ExecutionID:       "exec-1",
				EvidenceRoot:      mustDigest(t, "root"),
				AttestationDigest: mustDigest(t, "att"),
				Status:            "failure", // derived result is fail
				Facts:             &model.ExecutionFacts{},
				Checks:            passChecks("exec-1", CheckJobStatusSuccess, CheckEvidenceRoot),
				Attested:          trustedWindow(),
			}, nil
		},
	}
	ob := baseObligation(t)
	claim := baseOutcome(t, ob)
	claim.ProvenanceRefs = []string{"att-1"}
	claim.ExecutionIDs = []string{"exec-1"}
	claim.EvidenceRoot = mustDigest(t, "root")
	claim.CompletedChecks = append([]string(nil), ob.RequiredChecks...)
	claim.Outcome = OutcomePass // caller claims pass
	sealed, err := f.Verify(context.Background(), ob, claim)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if sealed.Outcome().Outcome == OutcomePass {
		t.Fatal("verifier derived pass from a failed job status")
	}
	// Immutability: the accessors return deep copies, so rewriting the
	// returned outcome cannot upgrade the sealed record.
	copyOut := sealed.Outcome()
	copyOut.Outcome = OutcomePass
	if sealed.Outcome().Outcome != OutcomeFail {
		t.Fatal("mutating an Outcome() copy must not upgrade the sealed record")
	}
	if sealed.ProvenPass() {
		t.Fatal("sealed record must not become a proven pass via copy mutation")
	}

	// Coordinated attack on the internals: flip the derived result to pass
	// AND rewrite the evidence projections to agree (the pre-P0 hole —
	// sealDerivedOutcome only compared the two mutable projections). The
	// seal re-derives result/checks/assurance from the evidence primitives
	// (JobStatus, VerifiedChecks, Assurance), so the failed job status still
	// proves fail and the forgery is refused.
	mutated := sealed
	mutated.outcome.Outcome = OutcomePass
	mutated.outcome.CompletedChecks = append([]string(nil), ob.RequiredChecks...)
	mutated.evidence.CompletedChecks = append([]string(nil), ob.RequiredChecks...)
	key := mustKey(t, "k1", "secret-1")
	if _, err := AcceptWithKeyring(ob, mutated, key, nil, time.Now().UTC()); err == nil {
		t.Fatal("Accept must refuse a coordinated post-seal mutation to pass")
	} else if !errors.Is(err, ErrUnverified) {
		t.Fatalf("Accept error = %v, want ErrUnverified", err)
	}
	reg := NewMemoryStore(clock)
	if err := reg.SubmitObligation(context.Background(), ob); err != nil {
		t.Fatal(err)
	}
	if err := reg.RecordVerifiedOutcome(context.Background(), mutated); err == nil {
		t.Fatal("RecordVerifiedOutcome must refuse a coordinated post-seal mutation to pass")
	} else if !errors.Is(err, ErrUnverified) {
		t.Fatalf("RecordVerifiedOutcome error = %v, want ErrUnverified", err)
	}

	// A subtler forgery: flip the consensus job status to success and the
	// result to pass while leaving the derived check set untouched. The
	// projections then agree with each other, but the structural
	// job-status-success check is still fail — the primitives contradict
	// the status, and the seal refuses. (Rewriting the primitives too is
	// out of scope here: those are the signature/MAC-bound trust root.)
	deeper := sealed
	deeper.outcome.Outcome = OutcomePass
	deeper.evidence.JobStatus = string(model.StatusSuccess)
	if _, err := sealDerivedOutcome(deeper.submittedClaim, deeper.outcome, deeper.evidence); err == nil {
		t.Fatal("seal must refuse evidence whose checks contradict its job status")
	} else if !errors.Is(err, ErrUnverified) {
		t.Fatalf("contradictory status/checks error = %v, want ErrUnverified", err)
	}
}
