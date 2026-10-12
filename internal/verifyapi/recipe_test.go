package verifyapi

import (
	"errors"
	"testing"
	"time"
)

func testRecipe(t *testing.T) Recipe {
	t.Helper()
	return Recipe{
		SchemaVersion: RecipeSchemaVersion,
		Name:          "release-signature",
		Version:       1,
		Requirements:  []string{"digest-match", "signature"},
		Assurance:     "uncontrolled",
		EvidenceMin: EvidenceMinimum{
			MinAttestations:       1,
			RequiredKinds:         []string{"execution-attestation"},
			RequireAttestedWindow: true,
		},
		Freshness: FreshnessPolicy{MaxAgeSeconds: 3600},
		IssuedAt:  time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

func TestRecipeDigestStableAndSensitive(t *testing.T) {
	r := testRecipe(t)
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate = %v", err)
	}
	d1, err := RecipeDigest(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDigest("recipe_digest", d1); err != nil {
		t.Fatal(err)
	}
	d2, err := RecipeDigest(r)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("digest unstable: %s vs %s", d1, d2)
	}

	// Requirement order is not identity.
	reordered := r
	reordered.Requirements = []string{"signature", "digest-match"}
	d3, err := RecipeDigest(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if d3 != d1 {
		t.Fatalf("requirement order changed the digest: %s vs %s", d3, d1)
	}

	// A UTC-shifted equal instant is the same recipe.
	loc := time.FixedZone("UTC+2", 2*3600)
	moved := r
	moved.IssuedAt = r.IssuedAt.In(loc)
	d4, err := RecipeDigest(moved)
	if err != nil {
		t.Fatal(err)
	}
	if d4 != d1 {
		t.Fatalf("equal instant in another location changed the digest")
	}

	// Withdrawal is not identity: the digest a proof cites stays stable.
	withdrawn := r
	at := r.IssuedAt.Add(time.Hour)
	withdrawn.WithdrawnAt = &at
	d5, err := RecipeDigest(withdrawn)
	if err != nil {
		t.Fatal(err)
	}
	if d5 != d1 {
		t.Fatalf("withdrawal changed the recipe digest: %s vs %s", d5, d1)
	}

	// Any rule change is a different digest.
	for name, mut := range map[string]func(*Recipe){
		"assurance":   func(c *Recipe) { c.Assurance = "attested-v1" },
		"version":     func(c *Recipe) { c.Version = 2 },
		"requirement": func(c *Recipe) { c.Requirements = []string{"digest-match"} },
		"evidence":    func(c *Recipe) { c.EvidenceMin.MinAttestations = 2 },
		"freshness":   func(c *Recipe) { c.Freshness.MaxAgeSeconds = 60 },
	} {
		other := r
		mut(&other)
		d, err := RecipeDigest(other)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d == d1 {
			t.Fatalf("%s change did not change the digest", name)
		}
	}
}

func TestRecipeValidateRefuses(t *testing.T) {
	base := testRecipe(t)
	for name, mut := range map[string]func(*Recipe){
		"bad schema":   func(c *Recipe) { c.SchemaVersion = 99 },
		"empty name":   func(c *Recipe) { c.Name = "" },
		"padded name":  func(c *Recipe) { c.Name = " x" },
		"zero version": func(c *Recipe) { c.Version = 0 },
		"no checks":    func(c *Recipe) { c.Requirements = nil },
		"dup checks":   func(c *Recipe) { c.Requirements = []string{"a", "a"} },
		"empty check":  func(c *Recipe) { c.Requirements = []string{""} },
		"no assurance": func(c *Recipe) { c.Assurance = "" },
		"no issued_at": func(c *Recipe) { c.IssuedAt = time.Time{} },
		"no freshness": func(c *Recipe) { c.Freshness = FreshnessPolicy{} },
		"neg min att":  func(c *Recipe) { c.EvidenceMin.MinAttestations = -1 },
		"dup kinds":    func(c *Recipe) { c.EvidenceMin.RequiredKinds = []string{"k", "k"} },
		"withdraw first": func(c *Recipe) {
			t := c.IssuedAt.Add(-time.Second)
			c.WithdrawnAt = &t
		},
	} {
		bad := base
		mut(&bad)
		if err := bad.Validate(); err == nil {
			t.Fatalf("%s: Validate accepted a broken recipe", name)
		} else if !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: err = %v, want ErrInvalid", name, err)
		}
		if _, err := RecipeDigest(bad); err == nil {
			t.Fatalf("%s: RecipeDigest accepted a broken recipe", name)
		}
	}
}

func TestRecipeLiveAndBindRecipe(t *testing.T) {
	r := testRecipe(t)
	now := r.IssuedAt.Add(time.Minute)
	if !r.Live(now) {
		t.Fatal("live recipe must be Live")
	}
	withdrawn := r
	at := r.IssuedAt.Add(30 * time.Second)
	withdrawn.WithdrawnAt = &at
	if withdrawn.Live(now) {
		t.Fatal("withdrawn recipe must not be Live")
	}
	if !withdrawn.Live(r.IssuedAt) {
		t.Fatal("withdrawal is prospective only")
	}

	ob := VerificationObligation{
		ObligationID:               "ob-1",
		Subject:                    "svc",
		ImmutableCandidateDigest:   mustDigest(t, "candidate"),
		SourceSnapshotDigest:       mustDigest(t, "snapshot"),
		VerificationContractDigest: mustDigest(t, "contract"),
		IssuedAt:                   now,
	}
	bound, err := BindRecipe(ob, r, now)
	if err != nil {
		t.Fatalf("BindRecipe = %v", err)
	}
	if bound.RecipeDigest == "" {
		t.Fatal("BindRecipe must pin the recipe digest")
	}
	if err := bound.Validate(); err != nil {
		t.Fatalf("bound obligation invalid: %v", err)
	}
	// The recipe's dimensions fill the empty obligation.
	if len(bound.RequiredChecks) != 2 || bound.RequiredAssurance != "uncontrolled" {
		t.Fatalf("bound dimensions not inherited: %+v", bound)
	}
	if bound.Freshness.MaxAgeSeconds != 3600 {
		t.Fatalf("bound freshness not inherited: %+v", bound.Freshness)
	}
	// Caller-set dimensions are preserved.
	pinned := ob
	pinned.RequiredChecks = []string{"custom"}
	pinned.RequiredAssurance = "attested-v1"
	pinned.Freshness = FreshnessPolicy{MaxAgeSeconds: 60}
	bound2, err := BindRecipe(pinned, r, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(bound2.RequiredChecks) != 1 || bound2.RequiredChecks[0] != "custom" {
		t.Fatalf("caller checks overwritten: %+v", bound2.RequiredChecks)
	}

	// A withdrawn recipe cannot mint new demand.
	if _, err := BindRecipe(ob, withdrawn, now); !errors.Is(err, ErrBinding) {
		t.Fatalf("BindRecipe withdrawn = %v, want ErrBinding", err)
	}
}

func TestRecipeRegistryImmutable(t *testing.T) {
	reg := NewRecipeRegistry()
	r := testRecipe(t)
	d, err := reg.Register(r)
	if err != nil {
		t.Fatalf("Register = %v", err)
	}
	// Idempotent on identical content.
	d2, err := reg.Register(r)
	if err != nil || d2 != d {
		t.Fatalf("idempotent Register = %v, %v", d2, err)
	}
	// Same (name, version), different content: refused.
	conflict := r
	conflict.Assurance = "attested-v1"
	if _, err := reg.Register(conflict); !errors.Is(err, ErrExists) {
		t.Fatalf("conflicting Register = %v, want ErrExists", err)
	}
	// A new version of the same name is a different recipe.
	next := r
	next.Version = 2
	dNext, err := reg.Register(next)
	if err != nil {
		t.Fatalf("Register v2 = %v", err)
	}
	if dNext == d {
		t.Fatal("different versions must have different digests")
	}

	got, err := reg.ByDigest(d)
	if err != nil || got.Name != r.Name {
		t.Fatalf("ByDigest = %+v, %v", got, err)
	}
	got2, err := reg.ByNameVersion(r.Name, 2)
	if err != nil || MustRecipeDigest(got2) != dNext {
		t.Fatalf("ByNameVersion = %+v, %v", got2, err)
	}
	if _, err := reg.ByDigest("0000000000000000000000000000000000000000000000000000000000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown ByDigest = %v, want ErrNotFound", err)
	}
	if _, err := reg.ByNameVersion("nope", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown ByNameVersion = %v, want ErrNotFound", err)
	}
}

func TestObligationRecipeDigestBinding(t *testing.T) {
	r := testRecipe(t)
	d := MustRecipeDigest(r)
	ob := VerificationObligation{
		ObligationID:               "ob-1",
		Subject:                    "svc",
		ImmutableCandidateDigest:   mustDigest(t, "candidate"),
		SourceSnapshotDigest:       mustDigest(t, "snapshot"),
		VerificationContractDigest: mustDigest(t, "contract"),
		RecipeDigest:               d,
		RequiredChecks:             []string{"digest-match", "signature"},
		RequiredAssurance:          "uncontrolled",
		Freshness:                  FreshnessPolicy{MaxAgeSeconds: 3600},
		IssuedAt:                   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	if err := ob.Validate(); err != nil {
		t.Fatalf("obligation with recipe digest invalid: %v", err)
	}
	// RecipeDigest participates in the canonical obligation digest.
	d1, err := CanonicalObligationDigest(ob)
	if err != nil {
		t.Fatal(err)
	}
	other := ob
	other.RecipeDigest = mustDigest(t, "other-recipe")
	d2, err := CanonicalObligationDigest(other)
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d2 {
		t.Fatal("recipe digest must participate in the obligation digest")
	}
	// A malformed recipe digest is refused.
	bad := ob
	bad.RecipeDigest = "nope"
	if err := bad.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad recipe digest = %v, want ErrInvalid", err)
	}
}
