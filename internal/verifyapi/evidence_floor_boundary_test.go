package verifyapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// evidenceFloorRecipe builds a live recipe whose floor demands more than a
// single bare execution attestation: two attestations AND the attested window.
func evidenceFloorRecipe(t *testing.T, minAttestations int, requireWindow bool) (Recipe, Digest) {
	t.Helper()
	r := testRecipe(t)
	r.Requirements = []string{CheckJobStatusSuccess, CheckEvidenceRoot}
	r.Assurance = "no_injected_credentials"
	r.EvidenceMin = EvidenceMinimum{
		MinAttestations:       minAttestations,
		RequiredKinds:         []string{EvidenceKindExecutionAttestation},
		RequireAttestedWindow: requireWindow,
	}
	reg := NewRecipeRegistry()
	d, err := reg.Register(r)
	if err != nil {
		t.Fatal(err)
	}
	return r, d
}

// evidenceFloorFixture seals a real DerivedVerifiedOutcome against a
// recipe-bound obligation through FuncEvidenceVerifier, with exactly the
// given number of resolved attestations and an optional attested window.
func evidenceFloorFixture(t *testing.T, r Recipe, d Digest, attestedCount int, window *AttestedResourceFacts) (VerificationObligation, DerivedVerifiedOutcome) {
	t.Helper()
	now := time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	clean := baseObligation(t)
	clean.ObligationID = "ob-floor"
	clean.SubjectRef = nil
	clean.RecipeDigest = d
	clean.IssuedAt = now.Add(-time.Minute)
	clean.Freshness = FreshnessPolicy{}
	clean.RequiredChecks = nil
	clean.RequiredAssurance = ""
	ob, err := BindRecipe(clean, r, clean.IssuedAt)
	if err != nil {
		t.Fatalf("BindRecipe: %v", err)
	}
	claim := baseOutcome(t, ob)
	claim.EvidenceRoot = mustDigest(t, "floor-root")
	claim.ProvenanceRefs = []string{"att-1"}
	claim.ExecutionIDs = []string{"exec-1"}
	claim.CompletedChecks = append([]string(nil), ob.RequiredChecks...)
	claim.AssuranceProfile = ob.RequiredAssurance

	resolve := func(context.Context, string) (ResolvedAttestation, error) {
		return ResolvedAttestation{
			ExecutionID:       "exec-1",
			EvidenceRoot:      mustDigest(t, "floor-root"),
			AttestationDigest: mustDigest(t, "floor-att"),
			Status:            "success",
			Facts:             &model.ExecutionFacts{FilesystemIsolated: true},
			Checks:            passChecks("exec-1", CheckJobStatusSuccess, CheckEvidenceRoot),
			Attested:          window,
		}, nil
	}
	// FuncEvidenceVerifier resolves one attestation per ProvenanceRef; pad
	// the claim's provenance refs so the derived evidence carries exactly
	// attestedCount digests.
	if attestedCount < 1 {
		t.Fatalf("attestedCount must be >= 1, got %d", attestedCount)
	}
	claim.ProvenanceRefs = nil
	for i := 0; i < attestedCount; i++ {
		claim.ProvenanceRefs = append(claim.ProvenanceRefs, "att-"+string(rune('a'+i)))
	}
	f := &FuncEvidenceVerifier{Identity: "floor-verifier/v1", Clock: clock, Resolve: resolve}
	sealed, err := f.Verify(context.Background(), ob, claim)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return ob, sealed
}

// TestAcceptWithRecipeEnforcesEvidenceFloor: the recipe evidence floor is
// applied in the common acceptance boundary (AcceptWithRecipe) BEFORE an
// acceptance record is minted. A sealed outcome whose evidence does not meet
// the floor is refused here — so Service, Postgres and memory stores cannot
// diverge on the floor decision.
func TestAcceptWithRecipeEnforcesEvidenceFloor(t *testing.T) {
	key := mustKey(t, "k-floor", "floor-secret")
	at := time.Date(2026, 1, 2, 3, 6, 0, 0, time.UTC)

	// Recipe demands two attestations; the fixture seals only one.
	r, d := evidenceFloorRecipe(t, 2, true)
	ob, sealed := evidenceFloorFixture(t, r, d, 1, trustedWindow())
	if !sealed.Sealed() {
		t.Fatal("fixture must produce a sealed record")
	}
	if _, err := AcceptWithRecipe(ob, sealed, key, nil, &r, at); !errors.Is(err, ErrEvidence) {
		t.Fatalf("AcceptWithRecipe below MinAttestations floor = %v, want ErrEvidence", err)
	}

	// Recipe demands an attested window; seal without one.
	r2, d2 := evidenceFloorRecipe(t, 1, true)
	ob2, sealed2 := evidenceFloorFixture(t, r2, d2, 1, nil)
	if _, err := AcceptWithRecipe(ob2, sealed2, key, nil, &r2, at); !errors.Is(err, ErrEvidence) && !errors.Is(err, ErrFreshness) {
		t.Fatalf("AcceptWithRecipe without attested window = %v, want ErrEvidence/ErrFreshness", err)
	}

	// Meeting the floor mints the record.
	r3, d3 := evidenceFloorRecipe(t, 1, true)
	ob3, sealed3 := evidenceFloorFixture(t, r3, d3, 1, trustedWindow())
	if _, err := AcceptWithRecipe(ob3, sealed3, key, nil, &r3, at); err != nil {
		t.Fatalf("AcceptWithRecipe meeting the floor = %v, want success", err)
	}
}

// TestRegistryRecordVerifiedOutcomeEvidenceFloor: the in-memory Registry
// applies the SAME Recipe.EvidenceMinimum as PostgresStore (via the shared
// floor rule AcceptWithRecipe enforces). A direct Registry write that bypasses
// the Service cannot store a below-floor record as authority.
func TestRegistryRecordVerifiedOutcomeEvidenceFloor(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	r, d := evidenceFloorRecipe(t, 2, true)
	_, sealed := evidenceFloorFixture(t, r, d, 1, trustedWindow())

	reg := NewRegistry(clock)
	reg.SetRecipes(NewRecipeRegistry())
	// Register the recipe under the SAME registry the floor check resolves
	// through.
	recipes := NewRecipeRegistry()
	if _, err := recipes.Register(r); err != nil {
		t.Fatal(err)
	}
	reg.SetRecipes(recipes)

	// The obligation must be submitted before a verified record can bind it.
	ob, _ := evidenceFloorFixture(t, r, d, 1, trustedWindow())
	if err := reg.SubmitObligation(ob); err != nil {
		t.Fatalf("SubmitObligation: %v", err)
	}

	// Direct write below the floor: refused, even though the record is sealed.
	if err := reg.RecordVerifiedOutcome(sealed); !errors.Is(err, ErrEvidence) {
		t.Fatalf("Registry below-floor record = %v, want ErrEvidence", err)
	}

	// Meeting the floor stores as authority.
	_, okSealed := evidenceFloorFixture(t, r, d, 2, trustedWindow())
	if err := reg.RecordVerifiedOutcome(okSealed); err != nil {
		t.Fatalf("Registry meeting-the-floor record = %v, want success", err)
	}
}

// TestRegistryRecordVerifiedOutcomeRecipeFloorFailClosed: a recipe-bound
// record cannot be stored through a Registry that cannot resolve the recipe —
// no floor, no authority. This matches PostgresStore without WithRecipes.
func TestRegistryRecordVerifiedOutcomeRecipeFloorFailClosed(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	r, d := evidenceFloorRecipe(t, 1, true)
	ob, sealed := evidenceFloorFixture(t, r, d, 1, trustedWindow())

	reg := NewRegistry(clock)
	if err := reg.SubmitObligation(ob); err != nil {
		t.Fatalf("SubmitObligation: %v", err)
	}
	// No recipe registry configured: fail closed.
	if err := reg.RecordVerifiedOutcome(sealed); !errors.Is(err, ErrNotFound) {
		t.Fatalf("recipe-bound write without recipe registry = %v, want ErrNotFound", err)
	}

	// A recipe registry that does not know the digest is equally a refusal.
	reg.SetRecipes(NewRecipeRegistry())
	if err := reg.RecordVerifiedOutcome(sealed); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unresolvable recipe digest = %v, want ErrNotFound", err)
	}
}

// TestMemoryStoreRecipeFloorMatchesRegistry: MemoryStore.WithRecipes wires
// the same floor as the underlying Registry — a recipe-bound write through
// the store is held to Recipe.EvidenceMinimum.
func TestMemoryStoreRecipeFloorMatchesRegistry(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 5, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	r, d := evidenceFloorRecipe(t, 2, true)
	ob, sealed := evidenceFloorFixture(t, r, d, 1, trustedWindow())

	recipes := NewRecipeRegistry()
	if _, err := recipes.Register(r); err != nil {
		t.Fatal(err)
	}
	st := NewMemoryStore(clock).WithRecipes(recipes)
	if err := st.SubmitObligation(context.Background(), ob); err != nil {
		t.Fatalf("SubmitObligation: %v", err)
	}
	if err := st.RecordVerifiedOutcome(context.Background(), sealed); !errors.Is(err, ErrEvidence) {
		t.Fatalf("MemoryStore below-floor record = %v, want ErrEvidence", err)
	}
}
