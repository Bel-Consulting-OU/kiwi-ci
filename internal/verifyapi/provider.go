package verifyapi

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// External verifier SPI.
//
// A VerifierProvider is a pluggable evidence verifier that advertises its
// Kind and Capabilities and can discharge obligations routed to it. The
// substrate stays product-neutral: Kind and every capability dimension are
// opaque strings defined by the verification contract ecosystem, never by
// this package. The Service's default EvidenceVerifier remains the
// acceptance boundary for obligations that name no provider; a named kind
// is fail closed — unknown kind or a capability mismatch refuses the
// verification before any record is stored.

// VerifierProvider is one external evidence verifier. Verify has the same
// contract as EvidenceVerifier: it returns a server-created sealed
// DerivedVerifiedOutcome (every authority-bearing value derived from the
// signed evidence) or an error, never a caller-shaped record. A provider
// that returns an unsealed record is refused by the Service.
type VerifierProvider interface {
	// Kind names this provider family (e.g. "external-scanner"). Opaque,
	// stable, and the dispatch key an obligation names.
	Kind() string
	// Capabilities advertises what this provider can actually check. The
	// Kind field of the capability must equal Kind().
	Capabilities() VerifierCapability
	// Verify discharges one obligation against one submitted claim.
	Verify(ctx context.Context, obligation VerificationObligation, submittedClaim VerificationOutcome) (DerivedVerifiedOutcome, error)
}

// ProviderRegistry is the in-process catalog of registered
// VerifierProviders, keyed by Kind(). It is safe for concurrent use. The
// registry never invents providers: a kind is known only after an explicit
// Register, and an unknown kind is a refusal (fail closed), not a fallback
// to the default verifier.
type ProviderRegistry struct {
	mu        sync.RWMutex
	providers map[string]VerifierProvider
}

// NewProviderRegistry returns an empty provider catalog.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{providers: make(map[string]VerifierProvider)}
}

// Register validates and stores a provider. Duplicate kinds are refused
// rather than silently replaced, so a later registrant cannot shadow an
// established provider. The provider's advertised capability must be
// structurally sound and must name the same kind as Kind().
func (r *ProviderRegistry) Register(p VerifierProvider) error {
	if p == nil {
		return fmt.Errorf("%w: provider is required", ErrInvalid)
	}
	kind := p.Kind()
	if kind == "" {
		return fmt.Errorf("%w: provider kind is required", ErrInvalid)
	}
	caps := p.Capabilities()
	if err := caps.Validate(); err != nil {
		return err
	}
	if caps.Kind != kind {
		return fmt.Errorf("%w: provider kind %q advertises capability kind %q", ErrInvalid, kind, caps.Kind)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[kind]; exists {
		return fmt.Errorf("%w: provider %q", ErrExists, kind)
	}
	r.providers[kind] = p
	return nil
}

// Provider fetches a registered provider by kind. An unknown kind answers
// ErrNotFound — the caller must refuse rather than fall back.
func (r *ProviderRegistry) Provider(kind string) (VerifierProvider, error) {
	if kind == "" {
		return nil, fmt.Errorf("%w: provider kind is required", ErrInvalid)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[kind]
	if !ok {
		return nil, fmt.Errorf("%w: provider %q", ErrNotFound, kind)
	}
	return p, nil
}

// Providers returns every registered provider ordered by kind for
// deterministic iteration.
func (r *ProviderRegistry) Providers() []VerifierProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]VerifierProvider, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind() < out[j].Kind() })
	return out
}

// ResolvedDemand is the dispatch contract an obligation resolves to before a
// provider is admitted: which provider kind must discharge it, under which
// contract version, for which claim class, on which platform, over which
// evidence types, at which assurance. Empty demand dimensions mean "no demand
// on that axis" and are vacuously covered. Admission requires
// provider.capabilities ⊇ demand (VerifierCapability.Covers); the same check
// is re-run in the verifier path as defense in depth.
type ResolvedDemand struct {
	// ProviderKind names the VerifierProvider.Kind() that must discharge
	// the obligation. Empty means the service default verifier.
	ProviderKind string
	// ContractVersion, when set, demands a specific capability schema
	// version of that provider family.
	ContractVersion string
	// ClaimClass, when set, demands one claim class the provider can verify.
	ClaimClass string
	// Platform, when set, demands one execution platform the provider covers.
	Platform string
	// EvidenceTypes, when non-empty, demands every listed evidence encoding
	// the provider can resolve.
	EvidenceTypes []string
	// Assurance, when set, demands the assurance profile the provider can
	// confirm.
	Assurance string
}

// ResolveDemand resolves the dispatch demand of an obligation. Every axis
// the obligation carries is pinned: the provider kind, contract version,
// claim class, platform and evidence types come from the obligation's
// Verifier* fields when set, and the required assurance always comes from
// RequiredAssurance. An axis the obligation does not carry stays empty (no
// demand on it); an axis it does carry is a hard requirement the provider's
// capabilities must cover — absence in the capability set is unsupported,
// not universal (see VerifierCapability.Covers).
func ResolveDemand(obligation VerificationObligation) ResolvedDemand {
	return ResolvedDemand{
		ProviderKind:    obligation.VerifierProviderKind,
		ContractVersion: obligation.VerifierContractVersion,
		ClaimClass:      obligation.VerifierClaimClass,
		Platform:        obligation.VerifierPlatform,
		EvidenceTypes:   append([]string(nil), obligation.VerifierEvidenceTypes...),
		Assurance:       obligation.RequiredAssurance,
	}
}

// ResolveDemandFull pins every dimension of the dispatch demand explicitly,
// overriding whatever the obligation carries on the overridden axes.
func ResolveDemandFull(obligation VerificationObligation, contractVersion, claimClass, platform string, evidenceTypes []string) ResolvedDemand {
	d := ResolvedDemand{
		ProviderKind: obligation.VerifierProviderKind,
		Assurance:    obligation.RequiredAssurance,
	}
	d.ContractVersion = contractVersion
	d.ClaimClass = claimClass
	d.Platform = platform
	d.EvidenceTypes = append([]string(nil), evidenceTypes...)
	return d
}

// Covers reports whether the capability set is a superset of the demand
// (provider.capabilities ⊇ demand). Empty DEMAND dimensions are vacuously
// covered (no constraint on that axis). Empty CAPABILITY dimensions are NOT
// universal advertisers: an axis the capability never advertised is
// unsupported and any demand on it is refused. A verifier that means
// "everything on this axis" must say so explicitly with the AnyCapability
// wildcard ("*"). Fail closed on every mismatch.
func (c VerifierCapability) Covers(d ResolvedDemand) error {
	if d.ProviderKind != "" && c.Kind != d.ProviderKind {
		return fmt.Errorf("%w: demand requires provider kind %q, capability is %q", ErrBinding, d.ProviderKind, c.Kind)
	}
	if d.ContractVersion != "" && !versionCovers(c.Version, d.ContractVersion) {
		return fmt.Errorf("%w: demand requires contract version %q, capability is %q", ErrBinding, d.ContractVersion, c.Version)
	}
	if d.ClaimClass != "" && !capabilityCovers(c.ClaimClasses, d.ClaimClass) {
		return fmt.Errorf("%w: capability %s/%s does not cover claim class %q (has %v)", ErrBinding, c.Kind, c.Version, d.ClaimClass, c.ClaimClasses)
	}
	if d.Platform != "" && !capabilityCovers(c.Platforms, d.Platform) {
		return fmt.Errorf("%w: capability %s/%s does not cover platform %q (has %v)", ErrBinding, c.Kind, c.Version, d.Platform, c.Platforms)
	}
	for _, et := range d.EvidenceTypes {
		if !capabilityCovers(c.EvidenceTypes, et) {
			return fmt.Errorf("%w: capability %s/%s does not cover evidence type %q (has %v)", ErrBinding, c.Kind, c.Version, et, c.EvidenceTypes)
		}
	}
	if d.Assurance != "" && !capabilityCovers(c.AssuranceLevels, d.Assurance) {
		return fmt.Errorf("%w: provider %q does not advertise assurance %q (has %v)", ErrBinding, c.Kind, d.Assurance, c.AssuranceLevels)
	}
	return nil
}

// providerServes reports whether p's advertised capabilities cover the
// obligation's resolved demand, and that the obligation is addressed to p's
// kind. Fail closed:
//
//   - a kind mismatch is a routing error (the caller named a different
//     provider than the one it is about to invoke);
//   - any demand dimension the provider does not advertise is a capability
//     mismatch and is refused even when the kind matches.
//
// This is the admission gate. Service.VerifyAndRecord re-checks the same
// demand after the provider's Verify returns (defense in depth against a
// provider that registered one capability set and verified outside it).
func providerServes(p VerifierProvider, obligation VerificationObligation) error {
	if p == nil {
		return fmt.Errorf("%w: provider is required", ErrInvalid)
	}
	kind := p.Kind()
	if obligation.VerifierProviderKind != kind {
		return fmt.Errorf("%w: obligation names provider %q, invoking %q", ErrBinding, obligation.VerifierProviderKind, kind)
	}
	caps := p.Capabilities()
	if caps.Kind != kind {
		return fmt.Errorf("%w: provider %q advertises capability kind %q", ErrInvalid, kind, caps.Kind)
	}
	return caps.Covers(ResolveDemand(obligation))
}

// recheckProviderDemand re-runs the capability-coverage check against the
// demand after verification. It is the verifier-side re-check: the provider's
// advertised capabilities must still cover the obligation's resolved demand
// once Verify returns, so a registration-time fit cannot be silently drifted
// away from. A sealed result that claims pass under an assurance the demand
// does not name is also refused.
func recheckProviderDemand(p VerifierProvider, obligation VerificationObligation, derived DerivedVerifiedOutcome) error {
	if err := providerServes(p, obligation); err != nil {
		return err
	}
	demand := ResolveDemand(obligation)
	if demand.Assurance != "" && derived.Sealed() && derived.outcome.Outcome == OutcomePass &&
		derived.outcome.AssuranceProfile != demand.Assurance {
		return fmt.Errorf("%w: derived pass assurance %q does not meet demand %q", ErrBinding, derived.outcome.AssuranceProfile, demand.Assurance)
	}
	return nil
}
