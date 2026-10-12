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

// Action names the Service operations an Authorizer mediates.
type Action string

const (
	// ActionSubmitObligation: create an obligation under a subject.
	ActionSubmitObligation Action = "submit_obligation"
	// ActionRecordClaim: record a CLAIM outcome. Claims are never
	// authoritative and never authorize merge/deploy.
	ActionRecordClaim Action = "record_claim"
	// ActionVerifyAndRecord: run the evidence verifier and record the
	// sealed authoritative outcome.
	ActionVerifyAndRecord Action = "verify_and_record"
	// ActionQueryOutcome: read the sealed authoritative record.
	ActionQueryOutcome Action = "query_outcome"
	// ActionCompareGroup: read a speculative-group resource comparison.
	ActionCompareGroup Action = "compare_group"
)

// Principal is the authenticated caller identity the Service authorizes.
// Scope is the authority SubjectRef the caller may act in; Admin is the
// break-glass override (still audited by the Authorizer implementation).
// The type is deliberately local so verifyapi stays free of the HTTP auth
// package: the mounting server adapts its own principal onto this shape.
type Principal struct {
	// Subject names the caller (token subject / service identity).
	Subject string
	// Scope is the authority subject the caller holds. A zero scope is
	// never authority over a named subject (fail closed).
	Scope SubjectRef
	// Admin grants cross-subject access. Authorizers must still log it.
	Admin bool
}

// Authorizer decides whether a principal may perform an action on a subject.
// Implementations must fail closed: an unknown principal, a zero subject
// where a named subject is required, or any error is a refusal. A nil
// Authorizer on the Service denies every call.
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
// subject when it is admin, or when its Scope covers the subject (see
// SubjectRef.Includes). A zero principal scope covers only the zero subject
// and only for admin. Anything else is ErrUnauthorized.
type ScopeAuthorizer struct{}

// Authorize implements Authorizer.
func (ScopeAuthorizer) Authorize(_ context.Context, p Principal, action Action, subject SubjectRef) error {
	if p.Admin {
		return nil
	}
	if p.Scope.IsZero() {
		return fmt.Errorf("%w: principal %q holds no authority subject for %s on %s", ErrUnauthorized, p.Subject, action, subject)
	}
	if !p.Scope.Includes(subject) {
		return fmt.Errorf("%w: principal %q scope %s does not cover %s for %s", ErrUnauthorized, p.Subject, p.Scope, subject, action)
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
	// VerifiedOutcome is minted.
	Verifier EvidenceVerifier
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
func (s *Service) authorize(ctx context.Context, p Principal, action Action, subject SubjectRef) error {
	if s == nil || s.Authz == nil {
		return fmt.Errorf("%w: %s denied (no authorizer)", ErrUnauthorized, action)
	}
	if err := subject.Validate(); err != nil {
		return err
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
	if err := s.authorize(ctx, p, ActionSubmitObligation, o.SubjectReference()); err != nil {
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
	if err := s.authorize(ctx, p, ActionRecordClaim, ob.SubjectReference()); err != nil {
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
func (s *Service) VerifyAndRecord(ctx context.Context, p Principal, v VerificationOutcome) (VerifiedOutcome, error) {
	if err := v.Validate(); err != nil {
		return VerifiedOutcome{}, err
	}
	ob, err := s.subjectOf(ctx, v.ObligationID)
	if err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	if err := s.authorize(ctx, p, ActionVerifyAndRecord, ob.SubjectReference()); err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	// The verifier derives every authority-bearing value from signed
	// evidence; the submitted claim is a proposal only.
	seal, err := s.Verifier.Verify(ctx, ob, v)
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
	if err := s.authorize(ctx, p, ActionQueryOutcome, ob.SubjectReference()); err != nil {
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
		if err := s.authorize(ctx, p, ActionCompareGroup, subj); err != nil {
			return GroupComparison{}, err
		}
	}
	if len(seen) == 0 {
		if err := s.authorize(ctx, p, ActionCompareGroup, SubjectRef{}); err != nil {
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
