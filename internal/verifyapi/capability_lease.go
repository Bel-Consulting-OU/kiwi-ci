package verifyapi

import (
	"fmt"
	"sync"
	"time"
)

// Capability cluster semantics.
//
// VerifierCapability rows come in two flavors:
//
//   - STATIC: version-pinned advertising registered once at startup from
//     configuration (RegisterCapability on the Registry). The (kind,
//     version) identity is immutable; a duplicate is refused. Static rows
//     never expire — they describe the binary's built-in verifier surface.
//
//   - DYNAMIC (leased): a verifier process registers what it can check and
//     holds a lease. A lease that is not renewed expires: the capability
//     disappears from discovery instead of advertising a verifier that is no
//     longer running. This is the cluster-safe form — a crashed verifier
//     must not keep attracting work forever.
//
// Capability advertising is never enforcement: the binding rule and the
// EvidenceVerifier remain the only acceptance boundary.

// CapabilityLease is one dynamic capability registration bound to a holder
// identity with an expiry. The lease is the liveness claim of the
// registrant: while it is live the capability is discoverable; once
// ExpiresAt passes without a renewal the row is dead and Query skips it.
type CapabilityLease struct {
	// Capability is the advertised verifier surface.
	Capability VerifierCapability `json:"capability"`
	// Holder names the registrant (verifier instance / pod identity).
	// Renewals must present the same holder so one registrant cannot
	// hijack another's lease.
	Holder string `json:"holder"`
	// ExpiresAt is the lease deadline (absolute time on the registry
	// clock). A row is live iff now < ExpiresAt.
	ExpiresAt time.Time `json:"expires_at"`
}

// Live reports whether the lease is still inside its window at now.
func (l CapabilityLease) Live(now time.Time) bool {
	return now.Before(l.ExpiresAt)
}

// LeaseRegistry is the dynamic capability cluster: leased registrations
// with expiry and renewal. Static capabilities stay on Registry; this type
// only manages the leased (dynamic) half. It is safe for concurrent use.
type LeaseRegistry struct {
	mu     sync.Mutex
	clock  func() time.Time
	leases map[string]CapabilityLease
}

// NewLeaseRegistry returns an empty lease registry reading wall time from
// the given clock (nil selects time.Now).
func NewLeaseRegistry(clock func() time.Time) *LeaseRegistry {
	if clock == nil {
		clock = time.Now
	}
	return &LeaseRegistry{clock: clock, leases: make(map[string]CapabilityLease)}
}

// leaseKey is the cluster identity of a leased capability row.
func leaseKey(c VerifierCapability) string { return capabilityKey(c) }

// Register records or renews a leased capability for holder with the given
// TTL. The rules are fail closed:
//
//   - the capability must be structurally valid and the holder non-empty;
//   - TTL must be positive (a zero/negative lease would be dead on arrival);
//   - an existing LIVE lease for the same (kind, version) held by a
//     different holder is refused (ErrExists) — a competitor cannot steal
//     the registration;
//   - an existing lease from the SAME holder is renewed in place;
//   - an EXPIRED lease (any holder) is replaced: a dead registration never
//     blocks a new one.
func (l *LeaseRegistry) Register(c VerifierCapability, holder string, ttl time.Duration) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if holder == "" {
		return fmt.Errorf("%w: capability lease holder is required", ErrInvalid)
	}
	if ttl <= 0 {
		return fmt.Errorf("%w: capability lease ttl must be positive", ErrInvalid)
	}
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	key := leaseKey(c)
	if prev, ok := l.leases[key]; ok {
		if prev.Live(now) && prev.Holder != holder {
			return fmt.Errorf("%w: capability %s/%s leased to %q", ErrExists, c.Kind, c.Version, prev.Holder)
		}
	}
	l.leases[key] = CapabilityLease{
		Capability: cloneCapability(c),
		Holder:     holder,
		ExpiresAt:  now.Add(ttl),
	}
	return nil
}

// Renew extends a live lease held by holder. An expired lease, an unknown
// capability or a foreign holder is refused: renewal is proof of liveness,
// not a takeover.
func (l *LeaseRegistry) Renew(c VerifierCapability, holder string, ttl time.Duration) error {
	if holder == "" {
		return fmt.Errorf("%w: capability lease holder is required", ErrInvalid)
	}
	if ttl <= 0 {
		return fmt.Errorf("%w: capability lease ttl must be positive", ErrInvalid)
	}
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	key := leaseKey(c)
	prev, ok := l.leases[key]
	if !ok || !prev.Live(now) {
		return fmt.Errorf("%w: capability %s/%s has no live lease", ErrNotFound, c.Kind, c.Version)
	}
	if prev.Holder != holder {
		return fmt.Errorf("%w: capability %s/%s leased to %q", ErrUnauthorized, c.Kind, c.Version, prev.Holder)
	}
	prev.ExpiresAt = now.Add(ttl)
	l.leases[key] = prev
	return nil
}

// Revoke drops a live lease held by holder (graceful deregistration).
func (l *LeaseRegistry) Revoke(c VerifierCapability, holder string) error {
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	key := leaseKey(c)
	prev, ok := l.leases[key]
	if !ok || !prev.Live(now) {
		return fmt.Errorf("%w: capability %s/%s has no live lease", ErrNotFound, c.Kind, c.Version)
	}
	if prev.Holder != holder {
		return fmt.Errorf("%w: capability %s/%s leased to %q", ErrUnauthorized, c.Kind, c.Version, prev.Holder)
	}
	delete(l.leases, key)
	return nil
}

// Query returns the LIVE leased capabilities matching every non-empty query
// dimension, ordered by (kind, version). Expired rows are never returned and
// are pruned opportunistically.
func (l *LeaseRegistry) Query(q CapabilityQuery) []VerifierCapability {
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]VerifierCapability, 0, len(l.leases))
	for key, lease := range l.leases {
		if !lease.Live(now) {
			delete(l.leases, key)
			continue
		}
		if q.matches(lease.Capability) {
			out = append(out, cloneCapability(lease.Capability))
		}
	}
	sortCapabilities(out)
	return out
}

// Expire drops every dead lease and returns how many were removed. It is
// the explicit sweep for operators; Query prunes opportunistically.
func (l *LeaseRegistry) Expire() int {
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for key, lease := range l.leases {
		if !lease.Live(now) {
			delete(l.leases, key)
			n++
		}
	}
	return n
}

// Live reports whether the (kind, version) capability currently has a live
// lease.
func (l *LeaseRegistry) Live(c VerifierCapability) bool {
	now := l.clock()
	l.mu.Lock()
	defer l.mu.Unlock()
	lease, ok := l.leases[leaseKey(c)]
	return ok && lease.Live(now)
}

func sortCapabilities(list []VerifierCapability) {
	// Insertion sort by (kind, version); the lists are tiny.
	for i := 1; i < len(list); i++ {
		for j := i; j > 0; j-- {
			a, b := list[j-1], list[j]
			if a.Kind < b.Kind || (a.Kind == b.Kind && a.Version < b.Version) {
				break
			}
			list[j-1], list[j] = list[j], list[j-1]
		}
	}
}
