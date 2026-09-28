package cache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
)

// ErrCacheBudgetExceeded reports that an aggregate cache operation could not
// be admitted even after evicting every cold entry: the requested archive is
// larger than the whole configured budget (or every entry slot is reserved
// by concurrent operations). Callers treat it as a best-effort cache failure
// (a restore warning, a save warning), never as data loss.
var ErrCacheBudgetExceeded = errors.New("cache: aggregate cache budget exceeded")

// Manager is the RUNNER-WIDE aggregate cache capacity owner. A per-job
// Store cannot enforce an aggregate bound on its own: every job builds its
// own Store (with its own mutex) over the SAME directory, so independent
// Prune calls cannot serialize publication, eviction or reservation and
// remote restores would bypass inline pruning entirely. The Manager is
// shared by every job of one runner and serializes:
//
//   - reservations taken BEFORE a save or a remote restore writes bytes,
//   - eviction of cold entries to satisfy a reservation,
//   - explicit retention passes.
//
// The invariant is: retained bytes (measured from the directory itself on
// every reservation, so external deletions can never desynchronize a
// counter) + outstanding reservations <= policy.MaxBytes, with the same
// treatment for entry counts. A reservation is released once the operation
// published (or failed); retained bytes are then visible to the next scan,
// so a failed cleanup keeps occupying the budget.
type Manager struct {
	mu     sync.Mutex
	root   string
	policy RetentionPolicy

	inflight      int64
	inflightCount int
	// pendingTemps maps a temp file whose removal failed to the charge that
	// stays counted until a retry removes it.
	pendingTemps map[string]int64
}

// NewManager returns a manager for root with the given aggregate policy. A
// manager with an inactive policy is still usable: reservations become
// no-ops (there is no aggregate bound to enforce) and Prune does nothing.
func NewManager(root string, policy RetentionPolicy) *Manager {
	return &Manager{root: root, policy: policy, pendingTemps: map[string]int64{}}
}

// Root returns the manager's cache directory (restart validation compares
// it with the configured root).
func (m *Manager) Root() string {
	if m == nil {
		return ""
	}
	return m.root
}

// Policy returns the manager's aggregate retention policy (restart
// validation compares it with the configured policy).
func (m *Manager) Policy() RetentionPolicy {
	if m == nil {
		return RetentionPolicy{}
	}
	return m.policy
}

// Reservation states. A reservation is OPEN while its operation may still
// need the charge, PUBLISHED once Manager.Publish retired it because the
// bytes became visible to scans (retained, so the charge must NOT be
// returned again), or RELEASED when the operation aborted before publication.
const (
	reservationOpen = iota
	reservationPublished
	reservationReleased
	// reservationRetained means the operation aborted but its temp file
	// could not be removed: the charge stays counted against the budget as
	// cleanup debt until Manager.RetryTempCleanup removes the file.
	reservationRetained
)

// Reservation is one granted aggregate-cache charge. It is ended exactly
// once: Manager.Publish retires it on successful publication, Release
// returns the charge when the operation aborted before publication. Both are
// idempotent, and Release is a no-op on an already published or released
// reservation — a deferred Release after Publish must never subtract the
// charge a second time (that would drive inflight negative and let later
// reservations oversubscribe the physical budget).
type Reservation struct {
	m     *Manager
	n     int64
	state int
}

// retainLocked converts an OPEN reservation into cleanup debt for path. The
// charge itself is unchanged (the file still occupies disk), so later
// reservations keep seeing it; RetryTempCleanup returns it once the file is
// gone. Callers hold m.mu.
func (r *Reservation) retainLocked(path string) {
	if r == nil || r.state != reservationOpen {
		return
	}
	r.state = reservationRetained
	r.m.pendingTemps[path] = r.n
}

// Release returns an OPEN reservation's charge. Retained bytes are measured
// from the directory on the next scan, so an aborted operation stops
// occupying reservation capacity; a published reservation is already
// represented by those retained bytes and must not be released again.
func (r *Reservation) Release() {
	if r == nil || r.m == nil {
		return
	}
	m := r.m
	m.mu.Lock()
	if r.state == reservationOpen {
		m.inflight -= r.n
		m.inflightCount--
		r.state = reservationReleased
	}
	m.mu.Unlock()
}

// RetainTempCleanup records that path (a temp file created under an OPEN
// reservation) could not be removed. The charge stays counted against the
// budget and RetryTempCleanup retries the removal; the reservation can no
// longer be released or published. It reports whether the reservation was
// open and is now retained.
func (m *Manager) RetainTempCleanup(res *Reservation, path string) bool {
	if m == nil || res == nil || path == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if res.m != m || res.state != reservationOpen {
		return false
	}
	res.retainLocked(path)
	return true
}

// RetryTempCleanup retries every retained temp file's removal under the
// manager lock. Successfully removed files return their charge to the
// budget; failures stay pending for the next pass. The context is checked
// between files.
func (m *Manager) RetryTempCleanup(ctx context.Context) (int, error) {
	if m == nil || len(m.pendingTemps) == 0 {
		return 0, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	removed := 0
	var firstErr error
	for path, charge := range m.pendingTemps {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		if err := removeCacheTemp(path); err != nil && !os.IsNotExist(err) {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		delete(m.pendingTemps, path)
		m.inflight -= charge
		m.inflightCount--
		removed++
	}
	return removed, firstErr
}

// Publish runs publish while holding the manager lock and, on success,
// RETIRES the reservation: the published bytes are visible to scans (and
// therefore retained) before any concurrent reservation can run, so keeping
// the worst-case charge would double-count them and make a second
// reservation evict the entry that was just published. On failure the
// reservation stays held and the caller must Release it.
//
// The reservation must belong to this manager and be OPEN; anything else is
// a programming error and leaves the accounting untouched (the publish
// itself still runs).
func (m *Manager) Publish(res *Reservation, publish func() error) error {
	if m == nil {
		return publish()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := publish(); err != nil {
		return err
	}
	if res != nil && res.m == m && res.state == reservationOpen {
		m.inflight -= res.n
		m.inflightCount--
		res.state = reservationPublished
	}
	return nil
}

// Reserve grants a charge of expected bytes for one upcoming cache entry,
// evicting cold retained entries (oldest first) until the aggregate
// invariant holds. It returns ErrCacheBudgetExceeded when the request can
// never fit (for example an archive larger than the whole budget), and the
// context error when the caller's job ended while evicting.
func (m *Manager) Reserve(ctx context.Context, expected int64) (*Reservation, error) {
	if m == nil || !m.policy.Active() {
		return &Reservation{}, nil
	}
	if expected < 0 {
		expected = 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m.policy.MaxBytes > 0 && expected > m.policy.MaxBytes {
		return nil, fmt.Errorf("%w: request %d bytes exceeds the %d-byte aggregate budget", ErrCacheBudgetExceeded, expected, m.policy.MaxBytes)
	}
	if m.policy.MaxEntries > 0 && m.inflightCount+1 > m.policy.MaxEntries {
		return nil, fmt.Errorf("%w: every entry slot is reserved", ErrCacheBudgetExceeded)
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entries, err := listLocalEntriesAt(m.root)
		if err != nil {
			return nil, err
		}
		var used int64
		for _, e := range entries {
			used += e.size
		}
		overBytes := m.policy.MaxBytes > 0 && used+m.inflight+expected > m.policy.MaxBytes
		overEntries := m.policy.MaxEntries > 0 && len(entries)+m.inflightCount+1 > m.policy.MaxEntries
		if !overBytes && !overEntries {
			m.inflight += expected
			m.inflightCount++
			return &Reservation{m: m, n: expected}, nil
		}
		if !m.evictOldestLocked(entries) {
			return nil, fmt.Errorf("%w: no colder entry could be evicted", ErrCacheBudgetExceeded)
		}
	}
}

// managerEvictHook, when set (tests only), observes every manager-driven
// eviction by key. It exists so a concurrency test can report WHICH entry a
// reservation chose as its victim.
var managerEvictHook func(key string)

// evictOldestLocked evicts the oldest retained entry and reports whether one
// was removed. Entries that fail the freshness fence or the physical removal
// are skipped in favor of the next-oldest, so one undeletable file cannot
// wedge the whole cache. Callers hold m.mu.
func (m *Manager) evictOldestLocked(entries []localCacheEntry) bool {
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].modTime.Equal(entries[j].modTime) {
			return entries[i].modTime.Before(entries[j].modTime)
		}
		return entries[i].key < entries[j].key
	})
	var res PruneResult
	for _, e := range entries {
		if managerEvictHook != nil {
			managerEvictHook(e.key)
		}
		if evictLocalEntry(m.root, e, &res) {
			return true
		}
	}
	return false
}

// Prune runs one retention pass under the same lock as reservations, so it
// can never race a publication or evict an entry a concurrent reservation is
// about to replace. It is the manager-aware replacement for Store.Prune.
func (m *Manager) Prune(ctx context.Context) (PruneResult, error) {
	if m == nil {
		return PruneResult{}, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return pruneLocalDir(ctx, m.root, m.policy)
}
