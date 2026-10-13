package verifyapi

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"
)

// VerificationStore is the durable verification substrate contract. It is
// the persistence-shaped view of the same domain operations the in-process
// Registry exposes: submit obligations, record claims and authoritative
// verified outcomes, read them back, and compare speculative groups.
//
// Idempotency: ObligationID is the idempotency key of SubmitObligation.
// Resubmitting an identical obligation is a no-op success (the claim was
// already accepted under that key); resubmitting different content under the
// same key is refused with ErrExists. RecordOutcome / RecordVerifiedOutcome
// are idempotent on VerificationID the same way, so retries after a lost
// ack never fork the durable record.
//
// Implementations:
//
//   - MemoryStore (this package) is the in-process reference implementation
//     and the one the unit tests pin the contract against.
//   - PostgresStore (internal/storage/verifystore) is the PRODUCTION
//     durable implementation. It is deliberately not defined in this
//     package: the verification contract stays free of database drivers and
//     migrations, and the storage layer owns the SQL schema, transactions
//     and HA behavior. Host applications that need durability construct a
//     PostgresStore there and depend on this interface here.
//
// Every method takes a context for cancellation and for store-side deadlines
// (a database round trip may be slow; the in-memory store only observes
// cancellation).
type VerificationStore interface {
	// SubmitObligation records a new claim obligation. Idempotent on
	// ObligationID.
	SubmitObligation(ctx context.Context, o VerificationObligation) error
	// RecordOutcome records a submitted outcome as a CLAIM. Claims are never
	// authoritative; only RecordVerifiedOutcome discharges an obligation.
	// Idempotent on VerificationID.
	RecordOutcome(ctx context.Context, v VerificationOutcome) error
	// RecordVerifiedOutcome records a verifier-produced DerivedVerifiedOutcome
	// as the authoritative result. Idempotent on VerificationID.
	RecordVerifiedOutcome(ctx context.Context, v DerivedVerifiedOutcome) error
	// GetObligation fetches a stored obligation by id.
	GetObligation(ctx context.Context, id string) (VerificationObligation, error)
	// GetOutcome fetches any stored outcome (claim or verified) by id. It is
	// not proof of verification.
	GetOutcome(ctx context.Context, id string) (VerificationOutcome, error)
	// QueryOutcome fetches the authoritative verified record. Claims never
	// satisfy it as a proven pass (ErrUnverified).
	QueryOutcome(ctx context.Context, id string) (DerivedVerifiedOutcome, error)
	// OutcomesForObligation lists every recorded outcome answering the
	// obligation, ordered by verification id.
	OutcomesForObligation(ctx context.Context, obligationID string) ([]VerificationOutcome, error)
	// RegisterGroup records a speculative group. Idempotent on
	// VerificationGroupID when the candidate set is identical.
	RegisterGroup(ctx context.Context, g SpeculativeGroup) error
	// GetGroup fetches a stored speculative group by id.
	GetGroup(ctx context.Context, id string) (SpeculativeGroup, error)
	// CompareGroup lines up the resource facts of a speculative group.
	CompareGroup(ctx context.Context, groupID string) (GroupComparison, error)
}

// MemoryStore is the in-memory VerificationStore. It wraps Registry (the
// in-process authoritative API) and adds the store contract's idempotent
// submit semantics and context plumbing. It is safe for concurrent use and
// is the reference implementation of the durable contract; see the
// VerificationStore doc for the production PostgresStore.
type MemoryStore struct {
	mu sync.Mutex
	r  *Registry
}

// NewMemoryStore returns an empty in-memory store reading wall time from the
// given clock (nil selects time.Now).
func NewMemoryStore(clock func() time.Time) *MemoryStore {
	return &MemoryStore{r: NewRegistry(clock)}
}

// compile-time proof that MemoryStore satisfies the durable contract.
var _ VerificationStore = (*MemoryStore)(nil)

// Registry exposes the underlying in-process registry (capabilities, direct
// accessors). Callers should prefer the VerificationStore methods.
func (m *MemoryStore) Registry() *Registry { return m.r }

// WithRecipes installs the recipe registry used to resolve recipe-bound
// records' evidence floors, mirroring PostgresStore.WithRecipes. A
// recipe-bound RecordVerifiedOutcome without one is refused (fail closed).
func (m *MemoryStore) WithRecipes(r *RecipeRegistry) *MemoryStore {
	m.r.SetRecipes(r)
	return m
}

// SubmitObligation records an obligation; ObligationID is the idempotency
// key.
func (m *MemoryStore) SubmitObligation(ctx context.Context, o VerificationObligation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.r.SubmitObligation(o)
	if errors.Is(err, ErrExists) {
		existing, gerr := m.r.Obligation(o.ObligationID)
		if gerr == nil && reflect.DeepEqual(existing, o) {
			return nil
		}
	}
	return err
}

// RecordOutcome records a claim; VerificationID is the idempotency key.
func (m *MemoryStore) RecordOutcome(ctx context.Context, v VerificationOutcome) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.r.RecordOutcome(v)
	if errors.Is(err, ErrExists) {
		existing, gerr := m.r.Outcome(v.VerificationID)
		if gerr == nil && claimEquivalent(existing, v) {
			return nil
		}
	}
	return err
}

// RecordVerifiedOutcome records an authoritative result; VerificationID is
// the idempotency key.
func (m *MemoryStore) RecordVerifiedOutcome(ctx context.Context, v DerivedVerifiedOutcome) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.r.RecordVerifiedOutcome(v)
	if errors.Is(err, ErrExists) {
		existing, gerr := m.r.QueryOutcome(v.outcome.VerificationID)
		if gerr == nil && claimEquivalent(existing.outcome, v.outcome) {
			return nil
		}
	}
	return err
}

// GetObligation fetches an obligation by id.
func (m *MemoryStore) GetObligation(ctx context.Context, id string) (VerificationObligation, error) {
	if err := ctx.Err(); err != nil {
		return VerificationObligation{}, err
	}
	return m.r.Obligation(id)
}

// GetOutcome fetches any stored outcome (claim or verified) by id.
func (m *MemoryStore) GetOutcome(ctx context.Context, id string) (VerificationOutcome, error) {
	if err := ctx.Err(); err != nil {
		return VerificationOutcome{}, err
	}
	return m.r.Outcome(id)
}

// QueryOutcome fetches the authoritative verified record.
func (m *MemoryStore) QueryOutcome(ctx context.Context, id string) (DerivedVerifiedOutcome, error) {
	if err := ctx.Err(); err != nil {
		return DerivedVerifiedOutcome{}, err
	}
	return m.r.QueryOutcome(id)
}

// OutcomesForObligation lists the outcomes answering an obligation.
func (m *MemoryStore) OutcomesForObligation(ctx context.Context, obligationID string) ([]VerificationOutcome, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.r.OutcomesForObligation(obligationID), nil
}

// RegisterGroup records a speculative group; VerificationGroupID is the
// idempotency key (an identical resubmit is a no-op success).
func (m *MemoryStore) RegisterGroup(ctx context.Context, g SpeculativeGroup) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.r.RegisterGroup(g)
	if errors.Is(err, ErrExists) {
		existing, gerr := m.r.Group(g.VerificationGroupID)
		if gerr == nil && reflect.DeepEqual(existing, g) {
			return nil
		}
	}
	return err
}

// GetGroup fetches a speculative group by id.
func (m *MemoryStore) GetGroup(ctx context.Context, id string) (SpeculativeGroup, error) {
	if err := ctx.Err(); err != nil {
		return SpeculativeGroup{}, err
	}
	return m.r.Group(id)
}

// CompareGroup lines up the resource facts of a speculative group.
func (m *MemoryStore) CompareGroup(ctx context.Context, groupID string) (GroupComparison, error) {
	if err := ctx.Err(); err != nil {
		return GroupComparison{}, err
	}
	return m.r.CompareGroup(groupID)
}

// RegisterCapability records a verifier capability (see Registry).
func (m *MemoryStore) RegisterCapability(c VerifierCapability) error {
	return m.r.RegisterCapability(c)
}

// QueryCapabilities lists registered verifier capabilities (see Registry).
func (m *MemoryStore) QueryCapabilities(q CapabilityQuery) []VerifierCapability {
	return m.r.QueryCapabilities(q)
}
