package dogfood

import (
	"fmt"
	"sync"
)

// FaultPoint is a deterministic pause hook in the harness's simulated
// control-plane flow. Each point sits in a window the audit identified as
// crash- or race-sensitive: the window between two durable effects where a
// killed or interleaved process must still be recoverable and single-winner.
// The names are stable so scenarios can pin an interleaving by name and a
// failure report says exactly which window was exercised.
type FaultPoint string

const (
	// AfterStateMutationBeforeLedger: the control plane mutated in-memory
	// state but has not yet committed the crash-recovery/event ledger entry.
	// A crash here must leave no half-recorded effect.
	AfterStateMutationBeforeLedger FaultPoint = "after-state-mutation-before-ledger"
	// AfterObjectUploadBeforeFinalize: artifact bytes are in the object
	// store but the finalize/commit record is not written. A crash here must
	// not mint an artifact identity, and a retry must not double-publish.
	AfterObjectUploadBeforeFinalize FaultPoint = "after-object-upload-before-finalize"
	// AfterWinnerCAS: a speculative/competing effect installed its winner
	// via compare-and-swap but the loser has not yet observed defeat. The
	// single-winner rule must hold even if the loser completes afterwards.
	AfterWinnerCAS FaultPoint = "after-winner-CAS"
	// BeforeEvidenceSignature: the attestation block is assembled but not
	// yet signed. Nothing may be observable as evidence in this window, and
	// a crash must not emit a partially-signed envelope.
	BeforeEvidenceSignature FaultPoint = "before-evidence-signature"
	// AfterLeaseExpirationBeforeReclaim: the lease has expired but the
	// control plane has not yet reclaimed/reassigned it. A completion from
	// the expired holder racing this window must not win over the reclaim.
	AfterLeaseExpirationBeforeReclaim FaultPoint = "after-lease-expiration-before-reclaim"
)

// AllFaultPoints is the closed set of deterministic pause hooks. A scenario
// that names a point outside this set is refused, so a typo cannot silently
// run an un-faulted interleaving and report green.
var AllFaultPoints = []FaultPoint{
	AfterStateMutationBeforeLedger,
	AfterObjectUploadBeforeFinalize,
	AfterWinnerCAS,
	BeforeEvidenceSignature,
	AfterLeaseExpirationBeforeReclaim,
}

// FaultInjector holds the deterministic pause hooks of one harness
// invocation. Hooks are registered before the scenario runs and fire in
// registration order at their point. A Pause blocks the hitting goroutine
// until released: the scenario injects the competing action (a stale
// completion, a duplicate webhook) while the control plane is frozen inside
// the window, then releases and asserts the reconciliation.
//
// The injector is pure coordination: it never mutates system-under-test
// state. All mutation stays in the harness flow being interrupted.
type FaultInjector struct {
	mu     sync.Mutex
	hooks  map[FaultPoint][]func() error
	pauses map[FaultPoint][]chan struct{}
	hits   map[FaultPoint]int
}

// NewFaultInjector returns an empty injector with no hooks armed.
func NewFaultInjector() *FaultInjector {
	return &FaultInjector{
		hooks:  make(map[FaultPoint][]func() error),
		pauses: make(map[FaultPoint][]chan struct{}),
		hits:   make(map[FaultPoint]int),
	}
}

// On arms fn to run when the harness reaches point. The hook may return an
// error to abort the flow (the harness surfaces it as the scenario failure).
func (f *FaultInjector) On(point FaultPoint, fn func() error) error {
	if !knownPoint(point) {
		return fmt.Errorf("dogfood: unknown fault point %q", point)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hooks[point] = append(f.hooks[point], fn)
	return nil
}

// PauseAt arms a pause at point. The returned channel is closed when the
// hitting goroutine ARRIVES at the point (the scenario then knows the
// control plane is frozen inside the window). The returned release func
// unblocks that goroutine; calling it before arrival arms the pause to pass
// through. release is idempotent.
func (f *FaultInjector) PauseAt(point FaultPoint) (release func(), arrived <-chan struct{}, err error) {
	if !knownPoint(point) {
		return nil, nil, fmt.Errorf("dogfood: unknown fault point %q", point)
	}
	gate := make(chan struct{})
	arrivedCh := make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(gate) }) }
	f.mu.Lock()
	f.pauses[point] = append(f.pauses[point], gate)
	f.hooks[point] = append(f.hooks[point], func() error {
		close(arrivedCh)
		<-gate
		return nil
	})
	f.mu.Unlock()
	return release, arrivedCh, nil
}

// Hit runs the armed hooks and pauses for point. It is called by the harness
// flow at each window; with no hooks armed it is a no-op.
func (f *FaultInjector) Hit(point FaultPoint) error {
	f.mu.Lock()
	f.hits[point]++
	hooks := append([]func() error(nil), f.hooks[point]...)
	f.mu.Unlock()
	for _, fn := range hooks {
		if err := fn(); err != nil {
			return fmt.Errorf("dogfood: fault at %s: %w", point, err)
		}
	}
	return nil
}

// Hits reports how many times point was reached. A scenario that arms a
// fault but never hits it is miswired and must not report green on the
// strength of an un-exercised interleaving.
func (f *FaultInjector) Hits(point FaultPoint) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[point]
}

func knownPoint(p FaultPoint) bool {
	for _, k := range AllFaultPoints {
		if k == p {
			return true
		}
	}
	return false
}
