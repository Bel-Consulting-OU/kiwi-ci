package verifyapi

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// VerifiedOutcome is the compatibility spelling of DerivedVerifiedOutcome
// used by the durable store contract. Prefer DerivedVerifiedOutcome in new
// code; the alias keeps the two surfaces interchangeable.
type VerifiedOutcome = DerivedVerifiedOutcome

// Service-level authorization errors. Callers must treat these as refusals
// (fail closed): no write is recorded and no outcome is disclosed.
var (
	// ErrUnauthorized is returned when the Authorizer refuses the principal
	// for the action on the addressed subject. The Service never falls back
	// to "allow" — a missing Authorizer denies everything.
	ErrUnauthorized = errors.New("verifyapi: unauthorized")
)

// Action names the Service operations an Authorizer mediates. The spelling
// is the capability vocabulary: each action is a grant a principal may hold
// on an authority scope (see Capability).
type Action string

const (
	// ActionObligationCreate: create an obligation under a subject.
	ActionObligationCreate Action = "verification.obligation.create"
	// ActionClaimSubmit: record a CLAIM outcome. Claims are never
	// authoritative and never authorize merge/deploy.
	ActionClaimSubmit Action = "verification.claim.submit"
	// ActionProofVerify: run the evidence verifier and record the
	// sealed authoritative outcome.
	ActionProofVerify Action = "verification.proof.verify"
	// ActionProofRead: read the sealed authoritative record.
	ActionProofRead Action = "verification.proof.read"
	// ActionGroupCompare: read a speculative-group resource comparison.
	ActionGroupCompare Action = "verification.group.compare"
	// ActionVerificationAdmin is the action carried by the
	// GlobalVerificationAdmin capability. It is never granted on a scope —
	// only as the explicit global break-glass.
	ActionVerificationAdmin Action = "verification.admin"
)

// Capability is one explicit authorization grant: an Action within an
// authority Scope (a strict SubjectRef hierarchy, trailing wildcards only),
// or the global break-glass. Scopes are never inferred: a zero SubjectRef
// grants nothing, and global authority is only GlobalVerificationAdmin.
type Capability struct {
	// Action is the granted operation (capability vocabulary).
	Action Action
	// Scope is the authority hierarchy the grant applies in. Must pass
	// SubjectRef.ValidateHierarchy. Ignored when Global is set.
	Scope SubjectRef
	// Global marks the GlobalVerificationAdmin grant: every action on
	// every subject. The empty SubjectRef is NOT a global wildcard — this
	// explicit flag on the named admin capability is the only break-glass.
	Global bool
}

// GlobalVerificationAdmin is the explicit break-glass capability: every
// verification action on every subject in every namespace. It is a named,
// security-significant grant — never a zero SubjectRef (the empty struct
// covers nothing). Authorizers must still audit its use. Sentinel value:
// copy it into a principal's capability list; do not mutate it.
var GlobalVerificationAdmin = Capability{Action: ActionVerificationAdmin, Global: true}

// CapabilitiesIn returns the standard per-action capability set covering
// the given scope hierarchy: every non-admin verification action, each
// scoped to the same authority subject. The scope must be a valid strict
// prefix hierarchy (SubjectRef.ValidateHierarchy); a malformed or zero
// scope yields no capabilities (fail closed).
func CapabilitiesIn(scope SubjectRef) []Capability {
	if err := scope.ValidateHierarchy(); err != nil {
		return nil
	}
	return []Capability{
		{Action: ActionObligationCreate, Scope: scope},
		{Action: ActionClaimSubmit, Scope: scope},
		{Action: ActionProofVerify, Scope: scope},
		{Action: ActionProofRead, Scope: scope},
		{Action: ActionGroupCompare, Scope: scope},
	}
}

// Principal is the authenticated caller identity the Service authorizes.
// Authority is ONLY the explicit capability list: there is no Admin bool
// and a zero SubjectRef never grants anything (global authority is the
// named GlobalVerificationAdmin capability). The type is deliberately local
// so verifyapi stays free of the HTTP auth package: the mounting server
// adapts its own principal onto this shape.
type Principal struct {
	// Subject names the caller (token subject / service identity).
	Subject string
	// Capabilities are the explicit grants the caller holds. Every act of
	// authority flows through these; an empty list holds no authority.
	Capabilities []Capability
}

// Validate reports whether every capability is well formed. A global grant
// must be the admin action (GlobalVerificationAdmin's shape); a scoped
// grant must name an action and carry a valid strict-prefix hierarchy.
// Principal construction MUST call this so a malformed partial scope can
// never ride along on a principal.
func (p Principal) Validate() error {
	for i, c := range p.Capabilities {
		if c.Global {
			if c.Action != ActionVerificationAdmin {
				return fmt.Errorf("%w: capability[%d]: global grant must be %s, got %q", ErrInvalid, i, ActionVerificationAdmin, c.Action)
			}
			continue
		}
		if c.Action == "" {
			return fmt.Errorf("%w: capability[%d]: action is required", ErrInvalid, i)
		}
		if err := c.Scope.ValidateHierarchy(); err != nil {
			return fmt.Errorf("%w: capability[%d] (%s): %v", ErrInvalid, i, c.Action, err)
		}
	}
	return nil
}

// Allows reports whether p holds a capability granting action on subject.
// GlobalVerificationAdmin grants every action on every subject; otherwise
// the capability's action must match and its scope must cover the subject
// (SubjectRef.Includes, which itself refuses malformed hierarchies and the
// zero ref).
func (p Principal) Allows(action Action, subject SubjectRef) bool {
	for _, c := range p.Capabilities {
		if c.Global {
			return true
		}
		if c.Action != action {
			continue
		}
		if c.Scope.Includes(subject) {
			return true
		}
	}
	return false
}

// Authorizer decides whether a principal may perform an action on a subject.
// Implementations must fail closed: an unknown principal, a malformed
// principal, a zero subject where a named subject is required, or any error
// is a refusal. A nil Authorizer on the Service denies every call.
type Authorizer interface {
	Authorize(ctx context.Context, p Principal, action Action, subject SubjectRef) error
}

// AuthorizerFunc adapts a function to Authorizer.
type AuthorizerFunc func(ctx context.Context, p Principal, action Action, subject SubjectRef) error

// Authorize implements Authorizer.
func (f AuthorizerFunc) Authorize(ctx context.Context, p Principal, action Action, subject SubjectRef) error {
	return f(ctx, p, action, subject)
}

// ScopeAuthorizer is the reference Authorizer: a principal may act on a
// subject when its capabilities grant the action on a scope that covers the
// subject (Principal.Allows), or when it holds the explicit
// GlobalVerificationAdmin break-glass. A malformed principal, a zero
// subject and an empty capability list are all refusals — the zero
// SubjectRef is never a wildcard.
type ScopeAuthorizer struct{}

// Authorize implements Authorizer.
func (ScopeAuthorizer) Authorize(_ context.Context, p Principal, action Action, subject SubjectRef) error {
	if err := p.Validate(); err != nil {
		return fmt.Errorf("%w: principal %q is malformed: %v", ErrUnauthorized, p.Subject, err)
	}
	if !p.Allows(action, subject) {
		return fmt.Errorf("%w: principal %q holds no capability for %s on %s", ErrUnauthorized, p.Subject, action, subject)
	}
	return nil
}

// DenyAllAuthorizer refuses every call. It is the fail-closed default.
type DenyAllAuthorizer struct{}

// Authorize implements Authorizer.
func (DenyAllAuthorizer) Authorize(_ context.Context, p Principal, action Action, subject SubjectRef) error {
	return fmt.Errorf("%w: principal %q denied %s", ErrUnauthorized, p.Subject, action)
}

// Service is the production verification service: the one entry point that
// combines the durable VerificationStore, the EvidenceVerifier acceptance
// boundary and the Authorizer. It is the surface merge/deploy gates and
// controllers call — never the raw store and never a posted claim.
//
// Acceptance boundary (unchanged from the registry contract):
//
//   - RecordClaim stores a CLAIM. Claims are never authoritative. A posted
//     result with outcome=pass MUST NOT authorize merge or deploy.
//   - VerifyAndRecord runs the EvidenceVerifier and stores ONLY the sealed
//     VerifiedOutcome (transactionally in the durable store). That sealed
//     record is the single discharge path.
//   - QueryOutcome returns sealed authoritative records only (claims answer
//     ErrUnverified). Merge/deploy must use QueryOutcome / ProvenPass.
//
// Authorization is fail closed: Store, Verifier and Authz are all required;
// a nil Authz denies every call. Every method authorizes against the
// STORED obligation's SubjectRef — never against a caller-claimed subject —
// so two byte-identical candidates under tenant A and tenant B never share
// authorization.
type Service struct {
	// Store is the durable verification substrate (MemoryStore in tests,
	// PostgresStore in production).
	Store VerificationStore
	// Verifier is the evidence acceptance boundary. It is the only way a
	// VerifiedOutcome is minted for obligations that name no provider kind.
	Verifier EvidenceVerifier
	// Providers is the optional external verifier SPI catalog (see
	// provider.go). An obligation whose VerifierProviderKind is set is
	// dispatched to the matching registered provider instead of Verifier;
	// unknown kind or a capability mismatch is a refusal. Nil means no
	// external providers — a named kind is then fail closed.
	Providers *ProviderRegistry
	// Authz mediates every method. Nil denies everything.
	Authz Authorizer
	// Clock reads wall time for service-side stamps. Nil selects time.Now.
	Clock func() time.Time
}

// NewService builds a Service and fails closed on missing seams: a nil
// store, verifier or authorizer is refused at construction rather than at
// first use.
func NewService(store VerificationStore, verifier EvidenceVerifier, authz Authorizer) (*Service, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: service requires a VerificationStore", ErrInvalid)
	}
	if verifier == nil {
		return nil, fmt.Errorf("%w: service requires an EvidenceVerifier", ErrInvalid)
	}
	if authz == nil {
		return nil, fmt.Errorf("%w: service requires an Authorizer", ErrInvalid)
	}
	return &Service{Store: store, Verifier: verifier, Authz: authz}, nil
}

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now()
}

// authorize is the single fail-closed gate. A nil service or nil Authz
// denies; the Authorizer's error is returned as-is (usually ErrUnauthorized).
// The subject must be structurally sound, and a named subject must also be a
// valid strict-prefix hierarchy (defense in depth before Includes). The zero
// subject is allowed through as "no subject" (group registration / empty
// comparisons): only GlobalVerificationAdmin ever covers it.
func (s *Service) authorize(ctx context.Context, p Principal, action Action, subject SubjectRef) error {
	if s == nil || s.Authz == nil {
		return fmt.Errorf("%w: %s denied (no authorizer)", ErrUnauthorized, action)
	}
	if err := subject.Validate(); err != nil {
		return err
	}
	if !subject.IsZero() {
		if err := subject.ValidateHierarchy(); err != nil {
			return err
		}
	}
	return s.Authz.Authorize(ctx, p, action, subject)
}

// subjectOf loads the stored obligation's authority subject. Fail closed:
// an unknown obligation refuses the call (ErrNotFound) — a caller can never
// invent a subject by skipping the store.
func (s *Service) subjectOf(ctx context.Context, obligationID string) (VerificationObligation, error) {
	ob, err := s.Store.GetObligation(ctx, obligationID)
	if err != nil {
		return VerificationObligation{}, err
	}
	return ob, nil
}

// SubmitObligation records a new claim obligation under its SubjectRef.
// The caller must be authorized for THAT subject: the obligation names its
// own authority, so a tenant can never submit into a sibling's scope.
// ObligationID is the store idempotency key (identical resubmit is a no-op).
func (s *Service) SubmitObligation(ctx context.Context, p Principal, o VerificationObligation) error {
	if err := o.Validate(); err != nil {
		return err
	}
	if err := s.authorize(ctx, p, ActionObligationCreate, o.SubjectReference()); err != nil {
		return err
	}
	return s.Store.SubmitObligation(ctx, o)
}

// RecordClaim records a submitted outcome as a CLAIM. The claim is bound
// and freshness-checked by the store, but it is NEVER authoritative: a
// claim must not authorize merge or deploy. Use VerifyAndRecord for the
// sealed discharge path.
//
// Authorization runs against the STORED obligation's SubjectRef (the claim
// payload cannot name its own authority).
func (s *Service) RecordClaim(ctx context.Context, p Principal, v VerificationOutcome) error {
	if err := v.Validate(); err != nil {
		return err
	}
	ob, err := s.subjectOf(ctx, v.ObligationID)
	if err != nil {
		return err
	}
	if err := s.authorize(ctx, p, ActionClaimSubmit, ob.SubjectReference()); err != nil {
		return err
	}
	return s.Store.RecordOutcome(ctx, v)
}

// VerifyAndRecord runs the EvidenceVerifier over the submitted outcome and
// records the sealed VerifiedOutcome as the authoritative result. The
// verifier is the acceptance boundary: a forged evidence_root or an
// unbound execution id is refused before anything is stored. Persistence is
// the store's transactional RecordVerifiedOutcome (PostgresStore commits the
// claim upgrade and the verified row in one transaction).
//
// The returned record is sealed; only sealed records discharge obligations.
// Authorization runs against the STORED obligation's SubjectRef.
//
// Provider dispatch is fail closed: an obligation whose
// VerifierProviderKind is set is routed to that registered provider
// (refused when the kind is unknown or the provider's advertised
// capabilities do not cover the required assurance). An obligation that
// names no kind uses the default Verifier.
func (s *Service) VerifyAndRecord(ctx context.Context, p Principal, v VerificationOutcome) (VerifiedOutcome, error) {
	if err := v.Validate(); err != nil {
		return VerifiedOutcome{}, err
	}
	ob, err := s.subjectOf(ctx, v.ObligationID)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if err := s.authorize(ctx, p, ActionProofVerify, ob.SubjectReference()); err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	// Choose the acceptance boundary: the default Verifier, or the
	// obligation's named external provider.
	verifier := s.Verifier
	if ob.VerifierProviderKind != "" {
		if s.Providers == nil {
			return DerivedVerifiedOutcome{}, fmt.Errorf("%w: obligation names provider %q but no providers are registered", ErrNotFound, ob.VerifierProviderKind)
		}
		prov, perr := s.Providers.Provider(ob.VerifierProviderKind)
		if perr != nil {
			return DerivedVerifiedOutcome{}, perr
		}
		if err := providerServes(prov, ob); err != nil {
			return DerivedVerifiedOutcome{}, err
		}
		verifier = prov
	}
	// The verifier derives every authority-bearing value from signed
	// evidence; the submitted claim is a proposal only.
	seal, err := verifier.Verify(ctx, ob, v)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if !seal.Sealed() {
		// Defense in depth: an EvidenceVerifier that returns an unsealed
		// record is refused here rather than stored as authority.
		return DerivedVerifiedOutcome{}, fmt.Errorf("%w: verifier returned an unsealed record", ErrUnverified)
	}
	if err := s.Store.RecordVerifiedOutcome(ctx, seal); err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	return seal, nil
}

// QueryOutcome returns the sealed authoritative record for a verification
// id. This is the ONLY read merge/deploy may trust: a claim-only id answers
// ErrUnverified and an unknown id answers ErrNotFound. Authorization runs
// against the STORED obligation's SubjectRef, so a tenant A principal can
// never read tenant B's outcome even when the candidate digests are
// byte-identical.
func (s *Service) QueryOutcome(ctx context.Context, p Principal, id string) (DerivedVerifiedOutcome, error) {
	vo, err := s.Store.QueryOutcome(ctx, id)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	ob, err := s.subjectOf(ctx, vo.Outcome.ObligationID)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if err := s.authorize(ctx, p, ActionProofRead, ob.SubjectReference()); err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	return vo, nil
}

// CompareGroup lines up the resource facts of a speculative group. The
// caller must be authorized for EVERY obligation subject the group's
// recorded outcomes reference (a comparison that spans tenants is refused
// unless the caller covers them all). An empty group authorizes against the
// zero subject (admin only under ScopeAuthorizer).
func (s *Service) CompareGroup(ctx context.Context, p Principal, groupID string) (GroupComparison, error) {
	cmp, err := s.Store.CompareGroup(ctx, groupID)
	if err != nil {
		return GroupComparison{}, err
	}
	seen := make(map[SubjectRef]bool)
	for _, row := range cmp.Candidates {
		if row.VerificationID == "" {
			continue
		}
		out, err := s.Store.GetOutcome(ctx, row.VerificationID)
		if err != nil {
			return GroupComparison{}, err
		}
		ob, err := s.subjectOf(ctx, out.ObligationID)
		if err != nil {
			return GroupComparison{}, err
		}
		subj := ob.SubjectReference()
		if seen[subj] {
			continue
		}
		seen[subj] = true
		if err := s.authorize(ctx, p, ActionGroupCompare, subj); err != nil {
			return GroupComparison{}, err
		}
	}
	if len(seen) == 0 {
		if err := s.authorize(ctx, p, ActionGroupCompare, SubjectRef{}); err != nil {
			return GroupComparison{}, err
		}
	}
	return cmp, nil
}

// ProvenPass is the single merge/deploy discharge predicate over a service
// read: the record must be sealed AND claim pass. A POSTed claim never
// satisfies it. Callers gate merge/deploy on QueryOutcome + ProvenPass and
// never on GetOutcome / RecordClaim results.
func ProvenPass(v VerifiedOutcome) bool { return v.ProvenPass() }
