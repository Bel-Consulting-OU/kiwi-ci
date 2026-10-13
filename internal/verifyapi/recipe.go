package verifyapi

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Verification recipes (P12).
//
// A Recipe is a versioned, immutable verification demand: the name and
// version identify it, and its content (requirements, assurance, evidence
// minimum, freshness) never changes after publication. A new demand is a new
// version, never an edit. Obligations bind a recipe by digest
// (VerificationObligation.RecipeDigest), so the exact rules an obligation
// was issued under are pinned forever and a withdrawn recipe can be detected
// later without rewriting history (see PolicyEvaluation).

// RecipeSchemaVersion is the recipe document schema version. Any change to
// the canonical digest input must bump it.
const RecipeSchemaVersion = 1

// recipeDomain separates recipe digests from every other digest in the
// package.
const recipeDomain = "kiwi-ci/verify-recipe/v1"

// EvidenceMinimum is the evidence floor a recipe demands before any pass can
// be claimed. Counts are minimums; empty kind lists mean "no kind constraint".
type EvidenceMinimum struct {
	// MinAttestations is the minimum number of distinct verified
	// attestations required. Zero means "no count floor" (discouraged:
	// recipes should name one).
	MinAttestations int `json:"min_attestations,omitempty"`
	// RequiredKinds lists evidence kinds that must appear (for example
	// "execution-attestation", "test-report"). Empty means no kind floor.
	RequiredKinds []string `json:"required_kinds,omitempty"`
	// RequireAttestedWindow demands that the attested job window be
	// present on every attestation (so freshness cannot be satisfied by a
	// caller-typed interval).
	RequireAttestedWindow bool `json:"require_attested_window,omitempty"`
}

// Validate reports whether the evidence floor is structurally sound.
func (m EvidenceMinimum) Validate() error {
	if m.MinAttestations < 0 {
		return fmt.Errorf("%w: evidence minimum min_attestations must be >= 0", ErrInvalid)
	}
	seen := make(map[string]bool, len(m.RequiredKinds))
	for i, k := range m.RequiredKinds {
		if k == "" {
			return fmt.Errorf("%w: evidence minimum required_kinds[%d] is empty", ErrInvalid, i)
		}
		if seen[k] {
			return fmt.Errorf("%w: evidence minimum required_kinds contains duplicate %q", ErrInvalid, k)
		}
		seen[k] = true
	}
	return nil
}

// Evidence kind vocabulary (P1a). Kinds name the classes of evidence a
// recipe may demand; VerifiedEvidence.Kinds is the verifier-derived set of
// kinds actually present.
const (
	// EvidenceKindExecutionAttestation: at least one cryptographically
	// resolved execution attestation.
	EvidenceKindExecutionAttestation = "execution-attestation"
	// EvidenceKindTestReport: at least one check derived from a signed
	// test report.
	EvidenceKindTestReport = "test-report"
)

// Check enforces this evidence floor against verifier-derived evidence. It
// is applied on the authoritative discharge path only: a pass claim whose
// evidence does not meet the floor is refused. RequireAttestedWindow demands
// an attested (not observer, not caller-typed) execution window.
func (m EvidenceMinimum) Check(e VerifiedEvidence) error {
	if m.MinAttestations > 0 && len(e.AttestationDigests) < m.MinAttestations {
		return fmt.Errorf("%w: evidence minimum requires %d attestations, got %d", ErrEvidence, m.MinAttestations, len(e.AttestationDigests))
	}
	if len(m.RequiredKinds) > 0 {
		present := make(map[string]bool, len(e.Kinds))
		for _, k := range e.Kinds {
			present[k] = true
		}
		for _, need := range m.RequiredKinds {
			if !present[need] {
				return fmt.Errorf("%w: evidence minimum requires kind %q, which is absent", ErrEvidence, need)
			}
		}
	}
	if m.RequireAttestedWindow && !e.Window.SatisfiesFreshness(WindowSourceAttested) {
		return errWindowAuthority(WindowSourceAttested, e.Window.Source)
	}
	return nil
}

// Recipe is one immutable, versioned verification demand. The zero value is
// not a recipe; construct one, Validate it, and bind obligations to its
// digest. A Recipe is never mutated after publication: changing any rule is
// a new (Name, Version) pair with a new digest.
type Recipe struct {
	// SchemaVersion is the recipe document version (RecipeSchemaVersion).
	SchemaVersion int `json:"schema_version"`
	// Name is the stable recipe identity across versions (e.g.
	// "release-signature"). Non-empty.
	Name string `json:"name"`
	// Version is the monotonically increasing version of this name. A
	// published (Name, Version) pair is immutable; a changed rule set is a
	// higher version.
	Version int `json:"version"`
	// Requirements is the non-empty set of check identities a pass must
	// cover (same vocabulary as VerificationObligation.RequiredChecks).
	Requirements []string `json:"requirements"`
	// Assurance is the assurance profile a pass must achieve.
	Assurance string `json:"assurance"`
	// EvidenceMin is the evidence floor for any claim under this recipe.
	EvidenceMin EvidenceMinimum `json:"evidence_min"`
	// Freshness is the freshness policy obligations under this recipe
	// inherit. At least one dimension must be set (the obligation rule).
	Freshness FreshnessPolicy `json:"freshness"`
	// IssuedAt is when this recipe version was published. It anchors the
	// recipe's own freshness policy.
	IssuedAt time.Time `json:"issued_at"`
	// WithdrawnAt, when set, marks the recipe as withdrawn at that
	// instant. Withdrawal does not rewrite history: proofs minted under
	// the recipe stay historically valid, but a PolicyEvaluation run after
	// the withdrawal refuses them (see proof.go). Zero means live.
	WithdrawnAt *time.Time `json:"withdrawn_at,omitempty"`
}

// Validate reports whether the recipe is structurally sound and internally
// consistent. It enforces the immutability invariants a published recipe
// must satisfy: non-empty name, positive version, non-empty requirements
// without duplicates, non-empty assurance, a valid evidence floor, and a
// freshness policy that is legal relative to the recipe's IssuedAt.
func (r Recipe) Validate() error {
	if r.SchemaVersion != RecipeSchemaVersion {
		return fmt.Errorf("%w: recipe schema_version %d (want %d)", ErrInvalid, r.SchemaVersion, RecipeSchemaVersion)
	}
	if strings.TrimSpace(r.Name) != r.Name || r.Name == "" {
		return fmt.Errorf("%w: recipe name is required and must not have surrounding whitespace", ErrInvalid)
	}
	if r.Version < 1 {
		return fmt.Errorf("%w: recipe version must be >= 1", ErrInvalid)
	}
	if len(r.Requirements) == 0 {
		return fmt.Errorf("%w: recipe requirements must be non-empty", ErrInvalid)
	}
	seen := make(map[string]bool, len(r.Requirements))
	for i, c := range r.Requirements {
		if c == "" {
			return fmt.Errorf("%w: recipe requirements[%d] is empty", ErrInvalid, i)
		}
		if seen[c] {
			return fmt.Errorf("%w: recipe requirements contains duplicate %q", ErrInvalid, c)
		}
		seen[c] = true
	}
	if r.Assurance == "" {
		return fmt.Errorf("%w: recipe assurance is required", ErrInvalid)
	}
	if err := r.EvidenceMin.Validate(); err != nil {
		return err
	}
	if r.IssuedAt.IsZero() {
		return fmt.Errorf("%w: recipe issued_at is required", ErrInvalid)
	}
	if err := r.Freshness.validate(r.IssuedAt.UTC()); err != nil {
		return err
	}
	if r.WithdrawnAt != nil && r.WithdrawnAt.Before(r.IssuedAt) {
		return fmt.Errorf("%w: recipe withdrawn_at precedes issued_at", ErrInvalid)
	}
	return nil
}

// Live reports whether the recipe is still live at the given instant (not
// withdrawn, or withdrawn only after now).
func (r Recipe) Live(now time.Time) bool {
	if r.WithdrawnAt == nil {
		return true
	}
	return now.Before(r.WithdrawnAt.UTC())
}

// Normalize returns a copy of the recipe with timestamps in UTC and the
// requirement / kind slices copied and left in caller order (order is not
// identity here: the digest sorts them, see RecipeDigest).
func (r Recipe) Normalize() Recipe {
	n := r
	n.IssuedAt = n.IssuedAt.UTC()
	if n.WithdrawnAt != nil {
		t := n.WithdrawnAt.UTC()
		n.WithdrawnAt = &t
	}
	n.Freshness = utcFreshnessPolicy(n.Freshness)
	n.Requirements = append([]string(nil), r.Requirements...)
	n.EvidenceMin.RequiredKinds = append([]string(nil), r.EvidenceMin.RequiredKinds...)
	return n
}

// RecipeDigest is the stable content digest of one recipe version. It is a
// lowercase hex SHA-256 over the FROZEN domain-separated canonical encoding
// of the recipe (see encodeRecipeFrozen) with requirement and kind lists
// sorted, timestamps UTC-normalized, and WithdrawnAt excluded (withdrawal is
// a liveness fact, not recipe identity: a withdrawn recipe keeps the digest
// its proofs cite). Equal recipes therefore digest equal across processes and
// storage round trips; any rule change is a different digest.
func RecipeDigest(r Recipe) (Digest, error) {
	n := r.Normalize()
	if err := n.Validate(); err != nil {
		return "", err
	}
	// Identity excludes withdrawal (a withdrawn recipe keeps the digest its
	// proofs cite) and sorts the unordered lists so caller order is not
	// identity.
	n.WithdrawnAt = nil
	sort.Strings(n.Requirements)
	sort.Strings(n.EvidenceMin.RequiredKinds)
	return encodeRecipeFrozen(n).frozenHash("recipe")
}

// MustRecipeDigest is RecipeDigest for values already known to validate; it
// panics on error and exists for tests and static fixtures only.
func MustRecipeDigest(r Recipe) Digest {
	d, err := RecipeDigest(r)
	if err != nil {
		panic(err)
	}
	return d
}

// BindRecipe returns a copy of o pinned to recipe: RecipeDigest is set to
// the recipe's stable digest, and the obligation's requirement, assurance
// and freshness dimensions are set to the recipe's. Recipe-owned fields are
// NOT independently definable: an obligation that already carries different
// checks, assurance or freshness disagrees with the recipe and is refused
// (ErrBinding) — the recipe binds the semantics, so a weaker inline demand
// can never ride along under a strong recipe digest. Empty fields are filled
// from the recipe. The obligation id and subject stay the caller's. A recipe
// that is not live at bind time is refused so a withdrawn recipe cannot mint
// new demand. Historical restores must not consult liveness at all: use
// bindRecipe there so a proof accepted under a since-withdrawn recipe keeps
// restoring (withdrawal is live policy, not a rewrite of history).
func BindRecipe(o VerificationObligation, r Recipe, now time.Time) (VerificationObligation, error) {
	if err := r.Validate(); err != nil {
		return VerificationObligation{}, err
	}
	if !r.Live(now) {
		return VerificationObligation{}, fmt.Errorf("%w: recipe %s@%d is withdrawn", ErrBinding, r.Name, r.Version)
	}
	return bindRecipe(o, r)
}

// bindRecipe pins recipe-owned fields without any liveness check. It is the
// historical binding used at restore time: the recipe identity must already
// match the obligation's pin (a mismatched recipe is a different demand and
// is refused), and recipe-owned fields are filled or verified exactly as
// BindRecipe does. Withdrawal is deliberately NOT consulted — a withdrawn
// recipe keeps the semantics its accepted proofs were measured against.
func bindRecipe(o VerificationObligation, r Recipe) (VerificationObligation, error) {
	if err := r.Validate(); err != nil {
		return VerificationObligation{}, err
	}
	d, err := RecipeDigest(r)
	if err != nil {
		return VerificationObligation{}, err
	}
	out := o
	if out.RecipeDigest != "" && out.RecipeDigest != d {
		return VerificationObligation{}, fmt.Errorf("%w: obligation recipe digest %s disagrees with supplied recipe %s@%d (%s)",
			ErrBinding, out.RecipeDigest, r.Name, r.Version, d)
	}
	out.RecipeDigest = d
	if len(out.RequiredChecks) == 0 {
		out.RequiredChecks = append([]string(nil), r.Requirements...)
	} else if !stringSetsEqual(out.RequiredChecks, r.Requirements) {
		return VerificationObligation{}, fmt.Errorf("%w: obligation checks %v disagree with recipe %s@%d requirements %v",
			ErrBinding, out.RequiredChecks, r.Name, r.Version, r.Requirements)
	} else {
		out.RequiredChecks = append([]string(nil), r.Requirements...)
	}
	if out.RequiredAssurance == "" {
		out.RequiredAssurance = r.Assurance
	} else if out.RequiredAssurance != r.Assurance {
		return VerificationObligation{}, fmt.Errorf("%w: obligation assurance %q disagrees with recipe %s@%d assurance %q",
			ErrBinding, out.RequiredAssurance, r.Name, r.Version, r.Assurance)
	}
	if out.Freshness == (FreshnessPolicy{}) {
		out.Freshness = r.Freshness
	} else if !freshnessEqual(out.Freshness, r.Freshness) {
		return VerificationObligation{}, fmt.Errorf("%w: obligation freshness %+v disagrees with recipe %s@%d freshness %+v",
			ErrBinding, out.Freshness, r.Name, r.Version, r.Freshness)
	} else {
		out.Freshness = utcFreshnessPolicy(r.Freshness)
	}
	return out, nil
}

// stringSetsEqual reports whether two check lists hold the same identities
// (order-insensitive; duplicates already rejected by Validate).
func stringSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	return true
}

// freshnessEqual reports whether two freshness policies constrain the same
// dimensions to the same instants (pointer times compared by value).
func freshnessEqual(a, b FreshnessPolicy) bool {
	if a.MaxAgeSeconds != b.MaxAgeSeconds {
		return false
	}
	if (a.NotBefore == nil) != (b.NotBefore == nil) {
		return false
	}
	if a.NotBefore != nil && !a.NotBefore.Equal(*b.NotBefore) {
		return false
	}
	if (a.NotAfter == nil) != (b.NotAfter == nil) {
		return false
	}
	if a.NotAfter != nil && !a.NotAfter.Equal(*b.NotAfter) {
		return false
	}
	return true
}

// RecipeRegistry holds published recipe versions keyed by digest. Recipes
// are immutable: Register is idempotent on an identical digest and refuses
// any different content under the same (name, version) with ErrExists.
type RecipeRegistry struct {
	byDigest map[string]Recipe
	byName   map[string]map[int]Digest
}

// NewRecipeRegistry returns an empty recipe registry.
func NewRecipeRegistry() *RecipeRegistry {
	return &RecipeRegistry{
		byDigest: make(map[string]Recipe),
		byName:   make(map[string]map[int]Digest),
	}
}

// Register publishes a recipe version. The recipe must validate. Registering
// the identical recipe again is a no-op success; the same (name, version)
// with different content is ErrExists (a published version is immutable).
func (reg *RecipeRegistry) Register(r Recipe) (Digest, error) {
	if reg == nil {
		return "", fmt.Errorf("%w: nil recipe registry", ErrInvalid)
	}
	if err := r.Validate(); err != nil {
		return "", err
	}
	d, err := RecipeDigest(r)
	if err != nil {
		return "", err
	}
	stored := reg.byDigest[string(d)]
	if stored.Name != "" {
		return d, nil
	}
	versions, ok := reg.byName[r.Name]
	if !ok {
		versions = make(map[int]Digest)
		reg.byName[r.Name] = versions
	}
	if existing, taken := versions[r.Version]; taken {
		return "", fmt.Errorf("%w: recipe %s@%d already published as %s", ErrExists, r.Name, r.Version, existing)
	}
	reg.byDigest[string(d)] = r.Normalize()
	versions[r.Version] = d
	return d, nil
}

// ByDigest fetches a published recipe by its stable digest.
func (reg *RecipeRegistry) ByDigest(d Digest) (Recipe, error) {
	if reg == nil {
		return Recipe{}, fmt.Errorf("%w: nil recipe registry", ErrNotFound)
	}
	r, ok := reg.byDigest[string(d)]
	if !ok {
		return Recipe{}, fmt.Errorf("%w: recipe %s", ErrNotFound, d)
	}
	return r, nil
}

// ByNameVersion fetches a published recipe by name and version.
func (reg *RecipeRegistry) ByNameVersion(name string, version int) (Recipe, error) {
	if reg == nil {
		return Recipe{}, fmt.Errorf("%w: nil recipe registry", ErrNotFound)
	}
	d, ok := reg.byName[name][version]
	if !ok {
		return Recipe{}, fmt.Errorf("%w: recipe %s@%d", ErrNotFound, name, version)
	}
	return reg.ByDigest(d)
}

// utcFreshnessPolicy normalizes the optional freshness timestamps to UTC.
func utcFreshnessPolicy(p FreshnessPolicy) FreshnessPolicy {
	if p.NotBefore != nil {
		t := p.NotBefore.UTC()
		p.NotBefore = &t
	}
	if p.NotAfter != nil {
		t := p.NotAfter.UTC()
		p.NotAfter = &t
	}
	return p
}
