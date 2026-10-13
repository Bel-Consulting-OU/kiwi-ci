package verifyapi

import (
	"fmt"
	"sort"
	"time"
)

// Effective verification demand (P1a).
//
// When an obligation binds a recipe, the recipe owns the demand: the checks,
// assurance, freshness and evidence floor are resolved from the Recipe
// Registry and are NOT independently definable on the obligation. The
// effective demand is that resolved rule set, and its canonical digest is
// what acceptance records and proofs bind — so a discharge is pinned to the
// exact rules it was measured against, not to whatever the obligation
// happened to carry inline.

// EffectiveVerificationDemandSchemaVersion is the demand document schema
// version. Any change to the canonical digest input must bump it.
const EffectiveVerificationDemandSchemaVersion = 1

// demandDomain separates demand digests from every other digest in the
// package. This is the v1 domain: the pre-provider-axes field set, retained
// so AcceptanceVersionV3/V4 records keep restoring.
const demandDomain = "kiwi-ci/verify-demand/v1"

// demandDomainV2 is the v2 demand domain. v2 additionally binds the
// verifier provider constraints (kind, contract version, claim class,
// platform, evidence types); the domain bump keeps a v1 demand digest from
// ever colliding with a v2 one.
const demandDomainV2 = "kiwi-ci/verify-demand/v2"

// EffectiveVerificationDemand is the canonical resolved verification demand
// one discharge is measured against. When the obligation binds a recipe, the
// demand is the recipe's rules (resolved from the RecipeRegistry at submit
// time); when it does not, the demand is the obligation's inline rules.
// Recipe-owned fields on an obligation are always exactly the recipe's after
// BindRecipe — the demand is the single statement of what was required.
type EffectiveVerificationDemand struct {
	// SchemaVersion is the demand document version.
	SchemaVersion int `json:"schema_version"`
	// RecipeDigest pins the recipe the demand was resolved from. Empty
	// when the obligation pinned its rules inline (no recipe).
	RecipeDigest Digest `json:"recipe_digest,omitempty"`
	// Requirements is the check set a pass must cover.
	Requirements []string `json:"requirements"`
	// Assurance is the assurance profile a pass must achieve.
	Assurance string `json:"assurance"`
	// EvidenceMin is the evidence floor for any claim under this demand.
	EvidenceMin EvidenceMinimum `json:"evidence_min"`
	// Freshness is the freshness policy the demand enforces.
	Freshness FreshnessPolicy `json:"freshness"`
	// IssuedAt anchors the freshness clock: ALWAYS the obligation's
	// issuance time. A recipe is a reusable policy template — a recipe
	// published six months ago must not make a newly issued obligation
	// six months old. The recipe contributes the freshness RULE
	// (MaxAgeSeconds / NotAfter), not the clock start.
	IssuedAt time.Time `json:"issued_at"`
	// VerifierProviderKind, when non-empty, names the VerifierProvider.Kind()
	// that must discharge this demand. Empty selects the service default
	// EvidenceVerifier. P1d: these five provider axes ride the demand (and
	// therefore DemandDigest) so an acceptance MAC pins WHICH verifier must
	// discharge the obligation, not just what it must prove.
	VerifierProviderKind string `json:"verifier_provider_kind,omitempty"`
	// VerifierContractVersion, when non-empty, pins the provider capability
	// schema version required to discharge this demand.
	VerifierContractVersion string `json:"verifier_contract_version,omitempty"`
	// VerifierClaimClass, when non-empty, pins the claim class the
	// discharging provider must cover.
	VerifierClaimClass string `json:"verifier_claim_class,omitempty"`
	// VerifierPlatform, when non-empty, pins the execution platform the
	// discharging provider must cover.
	VerifierPlatform string `json:"verifier_platform,omitempty"`
	// VerifierEvidenceTypes, when non-empty, pins every evidence encoding
	// the discharging provider must resolve. Each entry is a hard
	// requirement (see VerifierCapability.Covers).
	VerifierEvidenceTypes []string `json:"verifier_evidence_types,omitempty"`
}

// ResolveEffectiveDemand derives the effective demand of one obligation. A
// recipe-bound obligation resolves its rules from the recipe (the obligation
// fields are then already the recipe's, see BindRecipe); when only the
// obligation is available its fields are the demand and its RecipeDigest
// (when set) pins the recipe identity. An unbound obligation's inline rules
// are the demand.
func ResolveEffectiveDemand(o VerificationObligation, recipe *Recipe) (EffectiveVerificationDemand, error) {
	// Provider constraints are obligation-owned (a recipe is a reusable
	// rule template and carries no provider axes): both resolution paths
	// pin them from the obligation so DemandDigest binds WHO must verify.
	providerAxes := EffectiveVerificationDemand{
		VerifierProviderKind:    o.VerifierProviderKind,
		VerifierContractVersion: o.VerifierContractVersion,
		VerifierClaimClass:      o.VerifierClaimClass,
		VerifierPlatform:        o.VerifierPlatform,
		VerifierEvidenceTypes:   append([]string(nil), o.VerifierEvidenceTypes...),
	}
	if recipe != nil {
		if err := recipe.Validate(); err != nil {
			return EffectiveVerificationDemand{}, err
		}
		d, err := RecipeDigest(*recipe)
		if err != nil {
			return EffectiveVerificationDemand{}, err
		}
		return EffectiveVerificationDemand{
			SchemaVersion: EffectiveVerificationDemandSchemaVersion,
			RecipeDigest:  d,
			Requirements:  append([]string(nil), recipe.Requirements...),
			Assurance:     recipe.Assurance,
			EvidenceMin:   recipe.EvidenceMin,
			Freshness:     utcFreshnessPolicy(recipe.Freshness),
			// Freshness clock starts at the obligation, not the recipe.
			IssuedAt: o.IssuedAt.UTC(),

			VerifierProviderKind:    providerAxes.VerifierProviderKind,
			VerifierContractVersion: providerAxes.VerifierContractVersion,
			VerifierClaimClass:      providerAxes.VerifierClaimClass,
			VerifierPlatform:        providerAxes.VerifierPlatform,
			VerifierEvidenceTypes:   providerAxes.VerifierEvidenceTypes,
		}, nil
	}
	return EffectiveVerificationDemand{
		SchemaVersion: EffectiveVerificationDemandSchemaVersion,
		RecipeDigest:  o.RecipeDigest,
		Requirements:  append([]string(nil), o.RequiredChecks...),
		Assurance:     o.RequiredAssurance,
		Freshness:     utcFreshnessPolicy(o.Freshness),
		IssuedAt:      o.IssuedAt.UTC(),

		VerifierProviderKind:    providerAxes.VerifierProviderKind,
		VerifierContractVersion: providerAxes.VerifierContractVersion,
		VerifierClaimClass:      providerAxes.VerifierClaimClass,
		VerifierPlatform:        providerAxes.VerifierPlatform,
		VerifierEvidenceTypes:   providerAxes.VerifierEvidenceTypes,
	}, nil
}

// Validate reports whether the demand is structurally sound.
func (d EffectiveVerificationDemand) Validate() error {
	if d.SchemaVersion != EffectiveVerificationDemandSchemaVersion {
		return fmt.Errorf("%w: demand schema_version %d (want %d)", ErrInvalid, d.SchemaVersion, EffectiveVerificationDemandSchemaVersion)
	}
	if d.RecipeDigest != "" {
		if err := validateDigest("demand recipe_digest", d.RecipeDigest); err != nil {
			return err
		}
	}
	if len(d.Requirements) == 0 {
		return fmt.Errorf("%w: demand requirements must be non-empty", ErrInvalid)
	}
	seen := make(map[string]bool, len(d.Requirements))
	for i, c := range d.Requirements {
		if c == "" {
			return fmt.Errorf("%w: demand requirements[%d] is empty", ErrInvalid, i)
		}
		if seen[c] {
			return fmt.Errorf("%w: demand requirements contains duplicate %q", ErrInvalid, c)
		}
		seen[c] = true
	}
	if d.Assurance == "" {
		return fmt.Errorf("%w: demand assurance is required", ErrInvalid)
	}
	if err := d.EvidenceMin.Validate(); err != nil {
		return err
	}
	seenET := make(map[string]bool, len(d.VerifierEvidenceTypes))
	for i, et := range d.VerifierEvidenceTypes {
		if et == "" {
			return fmt.Errorf("%w: demand verifier_evidence_types[%d] is empty", ErrInvalid, i)
		}
		if seenET[et] {
			return fmt.Errorf("%w: demand verifier_evidence_types contains duplicate %q", ErrInvalid, et)
		}
		seenET[et] = true
	}
	if d.IssuedAt.IsZero() {
		return fmt.Errorf("%w: demand issued_at is required", ErrInvalid)
	}
	if err := d.Freshness.validate(d.IssuedAt); err != nil {
		return err
	}
	return nil
}

// CanonicalDigest is the stable content digest of the resolved demand: a
// lowercase hex SHA-256 over the FROZEN domain-separated canonical encoding
// (see encodeDemandFrozenV2) with the requirement, kind and evidence-type
// lists sorted and timestamps UTC-normalized. Two demands digest equal
// exactly when they demand the same rules from the same verifier family —
// this is the value acceptance records and proofs bind as DemandDigest.
func (d EffectiveVerificationDemand) CanonicalDigest() (Digest, error) {
	n := d
	if err := n.Validate(); err != nil {
		return "", err
	}
	n.Requirements = append([]string(nil), n.Requirements...)
	n.EvidenceMin.RequiredKinds = append([]string(nil), n.EvidenceMin.RequiredKinds...)
	n.VerifierEvidenceTypes = append([]string(nil), n.VerifierEvidenceTypes...)
	sort.Strings(n.Requirements)
	sort.Strings(n.EvidenceMin.RequiredKinds)
	sort.Strings(n.VerifierEvidenceTypes)
	n.Freshness = utcFreshnessPolicy(n.Freshness)
	n.IssuedAt = n.IssuedAt.UTC()
	return encodeDemandFrozenV2(n).frozenHash("demand")
}

// canonicalDigestV1 is the pre-provider-fields demand digest (the v1 frozen
// field set under the v1 demand domain). Retained verbatim so historical
// AcceptanceVersionV3/V4 acceptance records keep restoring: their DemandDigest
// was minted before the provider axes existed and must keep hashing equal.
func (d EffectiveVerificationDemand) canonicalDigestV1() (Digest, error) {
	n := d
	if err := n.Validate(); err != nil {
		return "", err
	}
	n.Requirements = append([]string(nil), n.Requirements...)
	n.EvidenceMin.RequiredKinds = append([]string(nil), n.EvidenceMin.RequiredKinds...)
	sort.Strings(n.Requirements)
	sort.Strings(n.EvidenceMin.RequiredKinds)
	n.Freshness = utcFreshnessPolicy(n.Freshness)
	n.IssuedAt = n.IssuedAt.UTC()
	return encodeDemandFrozen(n).frozenHash("demand")
}

// EffectiveVerificationDemandDigest is the canonical resolved-demand digest
// of one obligation. Pass the recipe the obligation was resolved against
// (nil for an inline obligation). This is the digest acceptance and proof
// bind as DemandDigest.
func EffectiveVerificationDemandDigest(o VerificationObligation, recipe *Recipe) (Digest, error) {
	d, err := ResolveEffectiveDemand(o, recipe)
	if err != nil {
		return "", err
	}
	return d.CanonicalDigest()
}

// effectiveVerificationDemandDigestV1 is the historical demand digest rule
// (v1 frozen field set), used only when restoring AcceptanceVersionV3/V4
// records whose DemandDigest predates the provider axes.
func effectiveVerificationDemandDigestV1(o VerificationObligation, recipe *Recipe) (Digest, error) {
	d, err := ResolveEffectiveDemand(o, recipe)
	if err != nil {
		return "", err
	}
	return d.canonicalDigestV1()
}
