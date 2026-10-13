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

// providerServes reports whether p's advertised capabilities cover the
// obligation, and that the obligation is addressed to p's kind. Fail closed:
//
//   - a kind mismatch is a routing error (the caller named a different
//     provider than the one it is about to invoke);
//   - a required assurance the provider does not advertise is a capability
//     mismatch and is refused even when the kind matches.
//
// ClaimClasses / Platforms / EvidenceTypes are discovery dimensions for
// callers choosing a provider; the acceptance boundary stays the provider's
// own Verify. Assurance is the one dimension the substrate itself refuses
// on: an obligation that demands an assurance profile the provider never
// advertised must not be discharged by it.
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
	if len(caps.AssuranceLevels) > 0 {
		ok := false
		for _, level := range caps.AssuranceLevels {
			if level == obligation.RequiredAssurance {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%w: provider %q does not advertise assurance %q (has %v)", ErrBinding, kind, obligation.RequiredAssurance, caps.AssuranceLevels)
		}
	}
	return nil
}
