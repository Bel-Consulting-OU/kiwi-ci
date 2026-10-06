// Package scheduler implements the PostgreSQL-backed control plane. It
// operates on the storage.Store contract: the durable SQL rows are the source
// of truth, while the server keeps its in-memory maps only for dev mode.
//
// Leader semantics: exactly one instance may lease jobs or recover expired
// leases. Leadership is a session-level Postgres advisory lock held by the
// store on a dedicated connection; TryAcquireLeadership renews the claim and
// reports ownership, so a standby can observe promotion by polling IsLeader.
// Because a cached renewal may briefly report true after the lock session
// died, leadership is enforced by a monotonic EPOCH (migration 0025), not by
// the check alone: the store publishes a new epoch on acquisition, retains it
// while it holds the claim, and every leader-only mutation re-validates it
// inside its own transaction. A replica whose cached claim outlived its
// session is rejected with storage.ErrStaleLeader and mutates nothing.
package scheduler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// ErrNotLeader is returned by leader-only operations when this instance does
// not hold the leadership advisory lock (a standby serving reads).
var ErrNotLeader = errors.New("scheduler: not leader")

// ErrNoJobs is returned by Lease when no job is currently available for the
// requesting runner.
var ErrNoJobs = errors.New("scheduler: no jobs available")

const (
	// DefaultLeaseDuration is the lease lifetime used when none is configured.
	DefaultLeaseDuration = 45 * time.Second
	// DefaultLeaderTTL is the soft renewal window for the leadership claim.
	DefaultLeaderTTL = 15 * time.Second
	// DefaultLeaderKey names the leadership lock slot shared by every
	// instance of the same control plane.
	DefaultLeaderKey = "kiwi-scheduler"
	// DefaultCandidatePageSize is the queued-candidate page size used when
	// none is configured.
	DefaultCandidatePageSize = 256
	// DefaultMaxCandidateRows bounds the queued candidates one lease attempt
	// materializes across all pages.
	DefaultMaxCandidateRows = 4096
	// MaxCandidateRowsCap is the hard upper bound SetLeaseScanLimits clamps
	// maxRows to, so a library caller cannot disable the bounded scan. It
	// mirrors config.MaxSchedulerMaxCandidateRows, the ceiling the config
	// validator applies to scheduler.max_candidate_rows.
	MaxCandidateRowsCap = 100000
	// queuedScanCursorTTL is how long a per-runner continuation cursor stays
	// usable: an unused cursor older than this is discarded so a queue that
	// changed shape underneath it is re-scanned from the head instead of
	// resuming at a stale position forever.
	queuedScanCursorTTL = 15 * time.Minute
	// DefaultReservationWait is the default reservation-head wait: zero makes
	// a resource-blocked candidate block starving backfill immediately.
	DefaultReservationWait = time.Duration(0)
)

// queuedScanState is one runner's continuation cursor: after names the last
// queued candidate the previous lease attempt actually evaluated, touched is
// when that attempt finished. It is request-local bookkeeping only; a claim
// race between two concurrent leases for the same runner is resolved by the
// store's atomic claim, never by this state.
type queuedScanState struct {
	after   storage.QueuedJobCursor
	touched time.Time
}

// Scheduler is the control-plane scheduling contract. Implementations operate
// on a storage.Store and must be safe for concurrent use.
type Scheduler interface {
	Enqueue(ctx context.Context, run model.Run, jobs map[string]model.Job, deps map[string][]string, cancelInProgress bool) error
	Lease(ctx context.Context, runnerID string, now time.Time) (*model.Job, string /*raw token*/, time.Time /*expires*/, error)
	Heartbeat(ctx context.Context, jobID, runnerID string, tokenHash []byte, generation int64, expiresAt time.Time) (bool /*cancelled*/, time.Time /*authoritative expiry*/, error)
	Complete(ctx context.Context, jobID string, generation int64, runnerID string, status model.Status, errMsg string, outputs map[string]string, resultHash string) error
	CancelRun(ctx context.Context, runID, reason string) error
	RecoverExpired(ctx context.Context, now time.Time) error
}

// DBScheduler schedules against a storage.Store. The token generator and
// hash are injectable so tests can assert exact token handling; production
// uses a crypto/rand hex token hashed with SHA-256 (the server layer HMACs it
// with its lease key before persisting).
type DBScheduler struct {
	Store         storage.Store
	LeaseDuration time.Duration
	NewToken      func() (string, error)
	HashToken     func(raw string) []byte

	// LeaderKey names the leadership advisory-lock slot shared by all
	// instances of this control plane.
	LeaderKey string
	// LeaderTTL is the soft renewal window for the leadership claim.
	LeaderTTL time.Duration

	// Quota limits (0 = unlimited) are enforced INSIDE the atomic lease's
	// queued->running transition, so a lease can never push the running
	// count past the configured concurrency. The server installs them
	// through SetQuotaLimits after wiring the store (config is applied
	// after SwitchToDB) and re-applies them on every lease.
	quotaMu         sync.Mutex
	repoConcurrency float64
	teamConcurrency float64

	// Lease scan bounds: the queued-candidate page size, the total candidate
	// rows one lease attempt may materialize, and the reservation-head wait
	// (see Lease). Installed through SetLeaseScanLimits, mutex-guarded like
	// the quota limits because Lease can run concurrently from runner poll
	// goroutines.
	leaseScanMu       sync.Mutex
	candidatePageSize int
	maxCandidateRows  int
	reservationWait   time.Duration

	// scanMu guards scan, the per-runner continuation position of the
	// bounded queued-candidate walk: when one lease attempt exhausts its
	// maxRows budget while the page store still has more candidates, the
	// last EVALUATED cursor is remembered here so the next poll for the
	// same runner resumes after it instead of re-materializing the same
	// incompatible prefix. A cursor older than queuedScanCursorTTL is
	// discarded. Correctness never depends on exclusive ownership: two
	// concurrent leases may scan from the same position, and their claim
	// race is resolved by the store's atomic lease.
	scanMu sync.Mutex
	scan   map[string]queuedScanState

	// leader is true while this instance holds the leadership claim.
	// Access is atomic: Lease and IsLeader can run concurrently from
	// runner poll goroutines.
	leader atomic.Bool
	// initErr records a leadership acquisition failure at construction.
	initErr error
}

// SetQuotaLimits installs the repo/team concurrency limits enforced by the
// atomic lease's conditional queued->running transition (0 = unlimited).
// Safe for concurrent use with Lease.
func (s *DBScheduler) SetQuotaLimits(repo, team float64) {
	s.quotaMu.Lock()
	s.repoConcurrency = repo
	s.teamConcurrency = team
	s.quotaMu.Unlock()
}

// quotaLimits returns the current repo/team concurrency limits.
func (s *DBScheduler) quotaLimits() (repo, team float64) {
	s.quotaMu.Lock()
	defer s.quotaMu.Unlock()
	return s.repoConcurrency, s.teamConcurrency
}

// SetLeaseScanLimits installs the lease candidate-scan bounds: the
// keyset-page size, the maximum candidate rows one Lease attempt may
// materialize across pages, and the reservation-head wait. Non-positive
// pageSize/maxRows select DefaultCandidatePageSize/DefaultMaxCandidateRows;
// maxRows above MaxCandidateRowsCap is clamped to it, so a library caller
// cannot disable the bounded scan. A negative reservationWait is clamped to
// zero (immediate head activation). Safe for concurrent use with Lease.
func (s *DBScheduler) SetLeaseScanLimits(pageSize, maxRows int, reservationWait time.Duration) {
	if pageSize <= 0 {
		pageSize = DefaultCandidatePageSize
	}
	if maxRows <= 0 {
		maxRows = DefaultMaxCandidateRows
	}
	if maxRows > MaxCandidateRowsCap {
		maxRows = MaxCandidateRowsCap
	}
	if reservationWait < 0 {
		reservationWait = 0
	}
	s.leaseScanMu.Lock()
	s.candidatePageSize = pageSize
	s.maxCandidateRows = maxRows
	s.reservationWait = reservationWait
	s.leaseScanMu.Unlock()
}

// leaseScanLimits returns the current lease candidate-scan bounds, applying
// the built-in defaults to a scheduler that was never configured.
func (s *DBScheduler) leaseScanLimits() (pageSize, maxRows int, reservationWait time.Duration) {
	s.leaseScanMu.Lock()
	pageSize, maxRows, reservationWait = s.candidatePageSize, s.maxCandidateRows, s.reservationWait
	s.leaseScanMu.Unlock()
	if pageSize <= 0 {
		pageSize = DefaultCandidatePageSize
	}
	if maxRows <= 0 {
		maxRows = DefaultMaxCandidateRows
	}
	// Defensive second clamp: the fields are unexported, but an in-package
	// caller can still install them directly, and the hard bound must hold
	// for every reader.
	if maxRows > MaxCandidateRowsCap {
		maxRows = MaxCandidateRowsCap
	}
	if reservationWait < 0 {
		reservationWait = 0
	}
	return pageSize, maxRows, reservationWait
}

// NewDB constructs a DBScheduler backed by store and attempts to acquire the
// leadership claim once. A hard store failure is recorded in InitErr; losing
// the claim to another live leader is not an error — the instance starts as a
// standby and can be promoted later (Server.Maintain polls IsLeader).
func NewDB(store storage.Store, leaseDur time.Duration, newToken func() (string, error), hashToken func(raw string) []byte) *DBScheduler {
	if leaseDur <= 0 {
		leaseDur = DefaultLeaseDuration
	}
	if newToken == nil {
		newToken = defaultToken
	}
	if hashToken == nil {
		hashToken = func(raw string) []byte {
			sum := sha256.Sum256([]byte(raw))
			return sum[:]
		}
	}
	s := &DBScheduler{
		Store:         store,
		LeaseDuration: leaseDur,
		NewToken:      newToken,
		HashToken:     hashToken,
		LeaderKey:     DefaultLeaderKey,
		LeaderTTL:     DefaultLeaderTTL,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := store.TryAcquireLeadership(ctx, s.LeaderKey, s.LeaderTTL)
	if err != nil {
		s.initErr = err
	} else {
		s.leader.Store(got)
	}
	return s
}

// InitErr reports a leadership acquisition failure at construction time.
// Callers should refuse to start on a hard store failure but may continue as
// a standby when the claim was simply lost to another live leader.
func (s *DBScheduler) InitErr() error { return s.initErr }

// IsLeader renews (or takes) the leadership claim and reports whether this
// instance currently holds it. A false result means another instance is the
// leader; a store error is logged and reported as not-leader.
//
// A true result can be served from the store's throttled cached proof (no
// round-trip), so it may briefly survive the loss of the advisory-lock
// session. That window is closed by the store's leadership EPOCH, not by this
// check: every leader-only mutation validates the epoch inside its own
// transaction and fails with storage.ErrStaleLeader when the claim is stale,
// so a cached true can hand out no work that mutates shared state.
func (s *DBScheduler) IsLeader(ctx context.Context) bool {
	if s.Store == nil {
		return false
	}
	got, err := s.Store.TryAcquireLeadership(ctx, s.LeaderKey, s.LeaderTTL)
	if err != nil {
		log.Printf("scheduler: leadership check failed: %v", err)
		return false
	}
	s.leader.Store(got)
	return got
}

// Enqueue inserts a run, its compiled jobs and their dependency edges
// through the store's ONE atomic enqueue transaction
// (storage.InsertCompiledRun): the run row, every job row, the dependency
// edges, the supersession cancellations and their dependent/run
// recomputation commit together or not at all.
//
// Supersession is NOT applied as a follow-up pass: when cancelInProgress is
// set the request carries an in-transaction storage.SupersedePolicy, so the
// store resolves the conflicting non-terminal runs of the same repository
// and concurrency group inside the transaction and cancels them — jobs
// terminal-cancelled with leases cleared, runner slots and quota released,
// dependents recomputed — in the same commit that publishes the new run.
// Concurrent superseding enqueues therefore serialize on the store's
// per-(repository, group) transaction lock: exactly one run survives
// non-terminal and no partial state is ever observable. A store without the
// atomic contract fails closed instead of falling back to the sequential
// run/job inserts.
//
// Queue deadlines are materialized here: a job whose QueueDeadline is unset
// but whose compiled payload declares a queue_timeout gets its deadline
// (CreatedAt + timeout) persisted with the insert, so the deadline is set at
// enqueue for every DB-mode job.
func (s *DBScheduler) Enqueue(ctx context.Context, run model.Run, jobs map[string]model.Job, deps map[string][]string, cancelInProgress bool) error {
	rs, ok := s.Store.(storage.RunEnqueueStore)
	if !ok {
		return errors.New("scheduler: store does not support the atomic enqueue transaction")
	}
	for id, j := range jobs {
		if j.QueueDeadline == nil {
			// The canonical helper derives CreatedAt + queue_timeout from the
			// compiled payload when the deadline field is unset.
			if dl := storage.QueueDeadlineFor(j); dl != nil {
				j.QueueDeadline = dl
			}
		}
		jobs[id] = j
	}
	req := storage.InsertCompiledRunRequest{
		Run:  run,
		Jobs: jobs,
		Deps: deps,
	}
	// The supersede policy carries the CANONICAL repository identity of the
	// run (stored RepoID, legacy URL + full-name fallback), not the clone
	// URL: HTTPS and SSH submissions of one repository must supersede, and
	// the SQL store's advisory lock and prior-run selection key on the same
	// canonical value.
	if cancelInProgress {
		if repoID := storage.RepoIDForRun(run); repoID != "" && run.ConcurrencyGroup != "" {
			req.Supersede = &storage.SupersedePolicy{RepoID: repoID, ConcurrencyGroup: run.ConcurrencyGroup}
		}
	}
	return rs.InsertCompiledRun(ctx, req)
}

// Lease claims the best available queued job for runnerID. It is leader-only.
// Candidate selection uses the ONE shared lease predicate
// (storage.LeasePredicate): admission state, labels, canonical repository
// ACL, runtime capability, the enforced-policy runtime grant, placement
// regions and environment concurrency. Dependency readiness and queue
// deadlines are evaluated on top, then priority (downstream depth) and age.
// The raw lease token is returned exactly once; only its hash is persisted.
//
// RESOURCE ADMISSION: a candidate whose TOTAL request (its own
// CPU/memory/disk/PIDs plus the aggregate service envelope,
// model.Job.ReservedResources) does not fit the runner's REMAINING resource
// capacity is skipped, so it waits (or is leased to another runner with room)
// instead of oversubscribing this one. The check here is a pre-filter over the
// live reservation sum; the authoritative check-and-reserve happens inside the
// claim transaction (storage.AcquireLeaseAtomic), which fails with
// storage.ErrResourceCapacity when a concurrent lease won the remaining
// capacity first — that error is treated exactly like a lost capacity race
// (try the next candidate). A runner without configured capacities (all
// dimensions zero, the documented default) admits every candidate: only the
// job-count capacity applies.
//
// BOUNDED CANDIDATE SCAN: one /next poll materializes at most
// maxCandidateRows queued candidates, requested in keyset pages of at most
// candidatePageSize from a store implementing storage.QueuedJobPageStore
// (the durable and in-memory stores do); a store without the contract falls
// back to the historical whole-queue ListQueuedJobs read. Pages are walked
// in the aged order (aged priority DESC, created_at ASC, id ASC — see
// orderQueuedJobs), the same order the page store returns, so bounding the
// scan never changes the fairness policy.
//
// The read carries the effective runner's coarse eligibility pushdown
// (storage.QueuedJobFilter: runtimes, labels, region, capacity and the
// job-scoped-cgroup envelope relaxation), so candidates the shared lease
// predicate would reject are skipped by the store instead of being
// materialized. Every lease attempt starts with a HEAD WINDOW page (newly
// enqueued/high-priority candidates are always seen), then resumes from a
// fresh per-runner continuation cursor when the previous attempt exhausted
// its maxRows budget mid-queue — so a long prefix of candidates that pass
// the coarse filter but fail the Go gates (deadlines, dependencies,
// environment/policy concurrency) cannot pin the scan to the same rows
// forever. Cursors older than queuedScanCursorTTL are discarded, and a claim
// or an exhausted queue clears the cursor.
//
// RESERVATION POLICY (anti-backfill): the first resource-blocked candidate
// in aged order that is still eligible on every other gate becomes the
// request's RESERVATION HEAD — the job that would run on this runner once
// its current reservations drain. A candidate above the runner's configured
// capacity (never satisfiable) can never become the head: an oversized job
// must not block backfill. While a head is active, a resource-fitting
// candidate is claimed only when the head would still fit after admitting it
// (reserved + candidate + head against the configured capacity, checked on
// the dimensions the candidate actually requests): a conflicting backfill
// that would occupy the head's starved dimension is skipped, while a
// non-conflicting one — e.g. a memory-only job alongside a CPU-blocked head —
// is admitted, so free capacity is not wasted and a stream of individually
// fitting backfills cannot re-accumulate into starvation. reservationWait
// delays head activation so a freshly queued large job grants a grace period
// to backfill already fitting the runner. The head is request-local and
// never persisted; a successful claim ends the walk.
//
// Deliberately NOT epoch-fenced, unlike the leader-only housekeeping
// mutations: the lease claim is itself a single atomic conditional
// transaction (AcquireLeaseAtomic / AcquireLease) whose mutual exclusion comes
// from the row state — the queued->running transition, the lease generation
// and the runner capacity/environment/quota predicates are checked under the
// job row lock, so a stale leader cannot double-lease or corrupt a claim; its
// worst case is handing out a job the current leader would also have handed
// out. Leadership orders this work, it is not the safety boundary for it.
//
// Every scheduling attribute is resolved LIVE: when the runner has a linked
// profile the profile's current labels/region/repo ACL/capacity/rates are
// used, not the registration snapshot, and the effective capability set is
// the profile ceiling intersected with the runner's reported hardware claim
// (never the profile alone — see storage.ResolveRunnerProfile).
func (s *DBScheduler) Lease(ctx context.Context, runnerID string, now time.Time) (*model.Job, string, time.Time, error) {
	if !s.IsLeader(ctx) {
		return nil, "", time.Time{}, ErrNotLeader
	}
	ri, err := s.Store.GetRunner(ctx, runnerID)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	// Profile semantics: capacity 0 means the runner takes no work (a
	// runner without a linked profile registers capacity 0). The legacy
	// clamp to 1 is gone — zero is meaningful now.
	eff := s.effectiveRunner(ctx, ri)
	if eff.Capacity <= 0 {
		return nil, "", time.Time{}, ErrNoJobs
	}
	if len(eff.ActiveJobs) >= eff.Capacity {
		return nil, "", time.Time{}, ErrNoJobs
	}
	// The runner's live resource reservations, read ONCE per lease attempt
	// (the pre-filter below evaluates every candidate against the same
	// snapshot; the claim transaction re-reads them under the runner row
	// lock). A store without the reservation contract reports zero, which
	// makes the pre-filter vacuous.
	reserved := s.reservedResources(ctx, runnerID)
	// One lease attempt materializes at most maxCandidateRows candidates in
	// keyset pages of at most candidatePageSize (see SetLeaseScanLimits).
	pageSize, maxRows, reservationWait := s.leaseScanLimits()
	repoConcurrency, teamConcurrency := s.quotaLimits()
	walk := &leaseCandidateWalk{
		s:               s,
		ctx:             ctx,
		now:             now,
		runnerID:        runnerID,
		ri:              ri,
		eff:             eff,
		reserved:        reserved,
		repoConcurrency: repoConcurrency,
		teamConcurrency: teamConcurrency,
		reservationWait: reservationWait,
		runJobs:         map[string]map[string]model.Job{},
		envJobs:         map[string][]model.Job{},
	}
	// The runner-coarse eligibility pushdown is built ONCE per attempt from
	// the effective runner and used by BOTH paths: the page store applies it
	// in SQL/memory, and the fallback applies the ONE shared matcher before
	// ordering. It is a conservative coarse prefilter only — the Go
	// predicate set (queue deadline, resource admission, environment,
	// enforced-policy, dependencies) still decides every candidate.
	filter := runnerQueuedJobFilter(eff)
	scanned := 0
	pageStore, hasPages := s.Store.(storage.QueuedJobPageStore)
	if hasPages {
		res, err := s.leasePaged(ctx, pageStore, filter, walk, runnerID, pageSize, maxRows, now)
		if err != nil {
			return nil, "", time.Time{}, err
		}
		if res.claimed {
			return res.job, res.raw, res.expires, nil
		}
	} else {
		// Historical fallback for stores without the paged candidate
		// contract: materialize the whole queue, apply the SAME coarse
		// matcher the page store applies, and walk it in the same aged
		// order, still bounded by maxCandidateRows. The per-runner
		// continuation cursor is not applied here: this path is a legacy
		// store contract, and the whole-queue read already bounds the
		// candidate set.
		queued, err := s.Store.ListQueuedJobs(ctx)
		if err != nil {
			return nil, "", time.Time{}, err
		}
		eligible := make([]model.Job, 0, len(queued))
		for _, j := range queued {
			if storage.QueuedJobMatchesFilter(j, filter) {
				eligible = append(eligible, j)
			}
		}
		orderQueuedJobs(eligible, now)
		for i := range eligible {
			if scanned >= maxRows {
				break
			}
			scanned++
			res := walk.consider(eligible[i])
			if res.err != nil {
				return nil, "", time.Time{}, res.err
			}
			if res.claimed {
				return res.job, res.raw, res.expires, nil
			}
		}
	}
	return nil, "", time.Time{}, ErrNoJobs
}

// leasePaged runs the bounded paged candidate walk of ONE lease attempt over
// a storage.QueuedJobPageStore:
//
//  1. HEAD WINDOW: one page at the head (after=nil) is fetched and walked
//     first, so newly enqueued or highest-aged candidates are always seen
//     promptly, even while the runner is resuming deeper in the queue.
//  2. CONTINUATION: while budget remains, pages are fetched from a FRESH
//     per-runner cursor when one exists, otherwise strictly after the head
//     window's Last. Every fetched page is walked in full, so the cursor
//     only ever advances past rows this attempt actually evaluated.
//  3. STATE: a claim clears the cursor; exhaustion (!HasMore) clears it; a
//     maxRows exhaustion with HasMore stores the last evaluated position so
//     the next poll for the same runner resumes instead of re-materializing
//     the same prefix. An interactive reservation head that leaves every
//     candidate unclaimed simply stores (or keeps) the position the same
//     way, so the next poll continues rather than restarting.
func (s *DBScheduler) leasePaged(ctx context.Context, pageStore storage.QueuedJobPageStore, filter storage.QueuedJobFilter, walk *leaseCandidateWalk, runnerID string, pageSize, maxRows int, now time.Time) (leaseWalkResult, error) {
	headLimit := pageSize
	if maxRows < headLimit {
		headLimit = maxRows
	}
	scanned := 0
	head, err := pageStore.ListQueuedJobsPage(ctx, filter, nil, headLimit, now)
	if err != nil {
		return leaseWalkResult{}, err
	}
	// The page store already returns the aged order; re-applying the local
	// ordering keeps the in-page decision identical to the historical
	// whole-queue walk even if a store returns a page in a looser order.
	orderQueuedJobs(head.Jobs, now)
	scanned += len(head.Jobs)
	if res := walk.walkPage(head.Jobs); res.claimed || res.err != nil {
		if res.claimed {
			s.clearScanCursor(runnerID)
		}
		return res, nil
	}
	last, hasMore := head.Last, head.HasMore
	if len(head.Jobs) == 0 {
		hasMore = false
	}
	after, hasAfter := head.Last, hasMore
	if stored, ok := s.loadScanCursor(runnerID, now); ok {
		after, hasAfter = stored, true
	}
	for hasAfter && scanned < maxRows {
		pageLimit := pageSize
		if remaining := maxRows - scanned; remaining < pageLimit {
			pageLimit = remaining
		}
		page, err := pageStore.ListQueuedJobsPage(ctx, filter, &after, pageLimit, now)
		if err != nil {
			return leaseWalkResult{}, err
		}
		if len(page.Jobs) == 0 {
			hasMore = false
			break
		}
		orderQueuedJobs(page.Jobs, now)
		scanned += len(page.Jobs)
		if res := walk.walkPage(page.Jobs); res.claimed || res.err != nil {
			if res.claimed {
				s.clearScanCursor(runnerID)
			}
			return res, nil
		}
		last, hasMore = page.Last, page.HasMore
		if !hasMore {
			break
		}
		after = page.Last
	}
	if hasMore && scanned >= maxRows {
		// Budget exhausted with candidates still unscanned: remember the
		// last position the walk actually evaluated, so the next poll
		// resumes behind it instead of re-scanning the same prefix.
		s.saveScanCursor(runnerID, last, now)
	} else {
		s.clearScanCursor(runnerID)
	}
	return leaseWalkResult{}, nil
}

// walkPage considers every candidate of one page in order, stopping at the
// first claim or fatal error. Every row of the page is evaluated before the
// page is considered walked, which is what lets the continuation cursor be
// saved at a page boundary without skipping an unevaluated row.
func (w *leaseCandidateWalk) walkPage(candidates []model.Job) leaseWalkResult {
	for _, candidate := range candidates {
		res := w.consider(candidate)
		if res.claimed || res.err != nil {
			return res
		}
	}
	return leaseWalkResult{}
}

// loadScanCursor returns the runner's fresh continuation cursor. A cursor at
// or past queuedScanCursorTTL is discarded, so a queue that changed shape
// underneath a stale position is re-scanned from the head.
func (s *DBScheduler) loadScanCursor(runnerID string, now time.Time) (storage.QueuedJobCursor, bool) {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	st, ok := s.scan[runnerID]
	if !ok {
		return storage.QueuedJobCursor{}, false
	}
	if now.Sub(st.touched) > queuedScanCursorTTL {
		delete(s.scan, runnerID)
		return storage.QueuedJobCursor{}, false
	}
	return st.after, true
}

// saveScanCursor records the runner's continuation position. Concurrent
// leases for one runner may overwrite each other; the last writer wins and
// the worst case is one redundant re-scan, never a skipped claim (the store's
// atomic claim is the race boundary).
func (s *DBScheduler) saveScanCursor(runnerID string, after storage.QueuedJobCursor, now time.Time) {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	if s.scan == nil {
		s.scan = map[string]queuedScanState{}
	}
	s.scan[runnerID] = queuedScanState{after: after, touched: now}
}

// clearScanCursor drops the runner's continuation position (a claim, an
// exhausted queue, or any state that would otherwise be re-scanned next
// poll).
func (s *DBScheduler) clearScanCursor(runnerID string) {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	delete(s.scan, runnerID)
}

// runnerQueuedJobFilter derives the storage.QueuedJobFilter for one effective
// runner, mirroring EXACTLY the coarse dimensions of the shared lease
// predicate:
//
//   - Runtimes is nil for the legacy-unrestricted case (not enforced and no
//     capabilities: every runtime is accepted), otherwise a non-nil copy of
//     the effective capability set — an ENFORCED empty set stays non-nil and
//     matches nothing, exactly like RuntimeAllowed;
//   - RunnerLabels is ALWAYS non-nil (an empty slice when the runner holds
//     none), because a label-less runner must exclude jobs with required
//     labels, and a nil slice would mean "unconstrained";
//   - RunnerRegion/ MaxRequested / IgnoreServiceEnvelope carry the runner's
//     placement region, configured resource capacity and job-scoped cgroup
//     capability, so the coarse capacity predicate evaluates the same
//     effective request (job request, plus envelope unless JobCgroup) the
//     scheduler and the claim reserve.
func runnerQueuedJobFilter(eff model.Runner) storage.QueuedJobFilter {
	filter := storage.QueuedJobFilter{
		RunnerRegion:          eff.Region,
		MaxRequested:          eff.ResourceCapacity,
		IgnoreServiceEnvelope: eff.JobCgroup,
	}
	if !eff.CapabilitiesEnforced && len(eff.Capabilities) == 0 {
		filter.Runtimes = nil
	} else {
		filter.Runtimes = append([]string{}, eff.Capabilities...)
	}
	labels := make([]string, 0, len(eff.Labels))
	labels = append(labels, eff.Labels...)
	sort.Strings(labels)
	filter.RunnerLabels = labels
	return filter
}

// leaseCandidateWalk is the request-local state of ONE Lease candidate scan:
// the effective runner, the live reservation snapshot, the memo caches and
// the reservation head (see Lease).
type leaseCandidateWalk struct {
	s               *DBScheduler
	ctx             context.Context
	now             time.Time
	runnerID        string
	ri              model.Runner
	eff             model.Runner
	reserved        model.ResourceCapacity
	repoConcurrency float64
	teamConcurrency float64
	reservationWait time.Duration
	runJobs         map[string]map[string]model.Job
	envJobs         map[string][]model.Job
	// head is the reservation head: the first resource-blocked but otherwise
	// eligible candidate in aged order. Nil while none was seen.
	head *model.Job
}

// leaseWalkResult is the outcome of considering one candidate: a successful
// claim, a fatal error, or "keep scanning" (every field zero).
type leaseWalkResult struct {
	job     *model.Job
	raw     string
	expires time.Time
	claimed bool
	err     error
}

// consider runs the per-candidate decision in the required order: queue
// deadline, resource admission, then (for a resource-blocked candidate that
// may become the reservation head, and for a resource-fitting candidate
// before claiming) environment concurrency, the shared lease predicate and
// dependency readiness. A blocked candidate is never claimed — it only
// records the reservation head; a fitting candidate that would starve an
// active head is skipped before any of its other gates are evaluated.
func (w *leaseCandidateWalk) consider(candidate model.Job) leaseWalkResult {
	// Queue-timeout expiry: a candidate whose queue deadline has passed is
	// never leased; RecoverExpired cancels it. Both the atomic-lease and the
	// plain-lease branches below share this gate.
	if dl := QueueDeadlineFor(candidate); dl != nil && !dl.After(w.now) {
		return leaseWalkResult{}
	}
	// Resource admission pre-filter: a candidate that cannot fit the
	// runner's remaining resource capacity waits for room on this runner
	// (or a lease on another one) instead of being claimed and rolling
	// back. The requested total is effectiveJobRequest: the job's OWN
	// request plus its aggregate service envelope, unless the runner
	// establishes a job-scoped parent cgroup (JobCgroup), in which case the
	// kernel bounds the aggregate and only the job request is charged — the
	// same total the claim transaction and the fs/dev path charge.
	adm := storage.ResourceAdmission{
		Capacity:  w.eff.ResourceCapacity,
		Reserved:  w.reserved,
		Requested: effectiveJobRequest(candidate, w.eff.JobCgroup),
	}
	if !adm.Allows() {
		if w.head != nil || !adm.EverSatisfiable() {
			return leaseWalkResult{}
		}
		// Reservation head candidate: evaluate the remaining gates so a job
		// that cannot run on this runner for a non-resource reason (labels,
		// runtime, region, environment, dependencies) never blocks backfill.
		_, eligible, err := w.eligible(candidate)
		if err != nil {
			return leaseWalkResult{err: err}
		}
		if !eligible {
			return leaseWalkResult{}
		}
		// Head activation wait: two-phase fairness, and zero (the default)
		// activates immediately.
		if w.reservationWait > 0 && w.now.Sub(candidate.CreatedAt) < w.reservationWait {
			return leaseWalkResult{}
		}
		head := candidate
		w.head = &head
		return leaseWalkResult{}
	}
	if w.head != nil && !w.headFitsAlongside(candidate) {
		// Claiming this candidate would consume capacity the head needs
		// once the runner's current reservations drain: skip it so a stream
		// of smaller backfill jobs cannot starve the head.
		return leaseWalkResult{}
	}
	jobs, eligible, err := w.eligible(candidate)
	if err != nil {
		return leaseWalkResult{err: err}
	}
	if !eligible {
		return leaseWalkResult{}
	}
	raw, err := w.s.NewToken()
	if err != nil {
		return leaseWalkResult{err: err}
	}
	expires := LeaseExpiry(w.now, w.s.LeaseDuration)
	generation := candidate.LeaseGeneration + 1
	claim := storage.LeaseClaim{
		JobID:      candidate.ID,
		RunnerID:   w.runnerID,
		TokenHash:  w.s.HashToken(raw),
		Generation: generation,
		ExpiresAt:  expires,
		// A DB-clock store derives the stored expiry from this TTL and
		// its own live clock, so cross-replica application-clock skew
		// cannot shorten or lengthen the real lease.
		TTL:                    w.s.LeaseDuration,
		RunnerCapacity:         w.eff.Capacity,
		Runtime:                storage.JobRuntime(candidate),
		CanonRepoID:            storage.RepoIDForJob(candidate),
		RepoFullName:           candidate.RepoFullName,
		RequiredLabels:         candidate.RequiredLabels,
		PlacementRegions:       candidate.PlacementRegions,
		Environment:            candidate.Environment,
		EnvironmentConcurrency: candidate.EnvironmentConcurrency,
		RepoConcurrency:        w.repoConcurrency,
		TeamConcurrency:        w.teamConcurrency,
		CPURequest:             candidate.CPURequest,
		MemoryRequest:          candidate.MemoryRequest,
		DiskRequest:            candidate.DiskRequest,
		PIDsRequest:            candidate.PIDsRequest,
		// The aggregate service envelope rides the claim so the claim
		// transaction reserves job request + envelope in the ONE
		// ledger row (LeaseClaim.RequestedResources).
		ServiceEnvelopeRequest: candidate.ServiceEnvelopeRequest,
		// A runner that can establish a job-scoped parent cgroup bounds the
		// main container and every service together at the kernel, so the
		// claim reserves only the job's own request (the SAME relaxation
		// the pre-filter and headFitsAlongside applied).
		IgnoreServiceEnvelope: w.eff.JobCgroup,
		// A quarantined candidate carries the durable identity flag, so
		// the SQL claim denies it independently of every allowlist just
		// as the in-memory predicate does (R1-6).
		Quarantined: candidate.RepoIdentityQuarantined,
	}
	// Capacity-atomic lease: the job claim, every predicate above, the
	// resource reservation and the runner's active-jobs append happen in
	// ONE transaction, so two concurrent leases can never exceed the
	// runner's capacity — count or resources — bypass a concurrent
	// disable/drain or overrun environment/quota limits.
	// The separate UpsertRunner afterwards is skipped because the store
	// already updated the runner row.
	clockStore, hasClock := w.s.Store.(storage.LeaseClockStore)
	atomicStore, hasAtomic := w.s.Store.(storage.AtomicLeaseStore)
	if hasClock || hasAtomic {
		var j model.Job
		var err error
		if hasClock {
			j, err = clockStore.AcquireLeaseWithTTL(w.ctx, claim)
		} else {
			j, err = atomicStore.AcquireLeaseAtomic(w.ctx, claim)
		}
		switch {
		case err == nil:
			j.NeedsOutputs = CollectNeedsOutputs(candidate, jobs)
			// Prefer the STORE-assigned expiry (a DB-clock store wrote
			// clock_timestamp()+TTL); the app-clock instant is only the
			// fallback for stores without a live clock.
			exp := expires
			if j.LeaseExpiresAt != nil {
				exp = *j.LeaseExpiresAt
			}
			return leaseWalkResult{job: &j, raw: raw, expires: exp, claimed: true}
		case errors.Is(err, storage.ErrLeaseConflict):
			return leaseWalkResult{}
		case errors.Is(err, storage.ErrNoCapacity),
			errors.Is(err, storage.ErrEnvConcurrency),
			errors.Is(err, storage.ErrResourceCapacity),
			errors.Is(err, storage.ErrQuotaExceeded):
			// A predicate lost a race (filled capacity slot, taken
			// environment slot, exhausted resource capacity or quota) or
			// this candidate is not eligible for this runner: try the
			// next candidate.
			return leaseWalkResult{}
		default:
			return leaseWalkResult{err: err}
		}
	}
	j, err := w.s.Store.AcquireLease(w.ctx, candidate.ID, w.runnerID, w.s.HashToken(raw), generation, expires)
	if errors.Is(err, storage.ErrLeaseConflict) {
		// Another leader raced us (or the row moved); try the next candidate.
		return leaseWalkResult{}
	}
	if err != nil {
		return leaseWalkResult{err: err}
	}
	// The plain-lease fallback persists no rates (its signature has no
	// rate source): freeze the live rates on the returned job and
	// persist them so completion accounting stays identical to the
	// atomic path.
	j.CostRate = w.eff.CostPerHour
	j.PowerWatts = w.eff.PowerWatts
	if j.StartedAt == nil {
		j.StartedAt = &w.now
	}
	j.NeedsOutputs = CollectNeedsOutputs(candidate, jobs)
	if err := w.s.Store.UpdateJob(w.ctx, j); err != nil {
		log.Printf("scheduler: persist frozen rates for %s: %v", j.ID, err)
	}
	ri := w.ri
	ri.ActiveJobs = appendUnique(ri.ActiveJobs, j.ID)
	ri.Busy = len(ri.ActiveJobs) >= ri.Capacity
	ri.CurrentJob = ""
	if len(ri.ActiveJobs) > 0 {
		ri.CurrentJob = ri.ActiveJobs[0]
	}
	if err := w.s.Store.UpsertRunner(w.ctx, ri); err != nil {
		// The lease is already durably held; a runner bookkeeping failure
		// must not strand the job.
		log.Printf("scheduler: update runner %s after lease: %v", w.runnerID, err)
	}
	// last_seen belongs to the narrow touch (the generic profile write
	// preserves the committed value), so advance it explicitly through
	// the capability when the store has it.
	if hs, ok := w.s.Store.(storage.RunnerHeartbeatStore); ok {
		_ = hs.TouchRunnerLastSeen(w.ctx, w.runnerID)
	}
	return leaseWalkResult{job: &j, raw: raw, expires: expires, claimed: true}
}

// eligible evaluates the non-resource gates for one candidate — environment
// concurrency, the shared lease predicate and dependency readiness — and
// returns the candidate run's job map on success (the claim's
// CollectNeedsOutputs input). The environment listing and the run's jobs are
// memoized per lease attempt, exactly as the historical walk did.
func (w *leaseCandidateWalk) eligible(candidate model.Job) (map[string]model.Job, bool, error) {
	// The shared predicate is the same decision the SQL claim and the
	// in-memory stores apply: admission state (disabled/draining,
	// capacity), labels, canonical repo ACL, runtime capability,
	// enforced-policy runtime grant, placement regions and environment
	// concurrency.
	envRunning := 0
	if candidate.Environment != "" && candidate.EnvironmentConcurrency > 0 {
		// The environment concurrency key is the CANONICAL repository
		// identity plus the environment name (LeaseClaim.EnvKey): the
		// same repository submitted via HTTPS and via SSH shares one
		// slot pool, and a same-named environment on another repository
		// never shares it.
		repoID := storage.RepoIDForJob(candidate)
		key := repoID + "\x00" + candidate.Environment
		active, ok := w.envJobs[key]
		if !ok {
			all, err := w.s.Store.ListJobsByEnvironment(w.ctx, repoID, candidate.Environment)
			if err != nil {
				return nil, false, err
			}
			w.envJobs[key] = all
			active = all
		}
		for _, other := range active {
			if other.ID != candidate.ID && other.Status == model.StatusRunning {
				envRunning++
			}
		}
	}
	policyRuntimes, policyEnforced := storage.LeasePolicyRuntimes(candidate)
	if !(storage.LeasePredicate{
		Runner:         w.eff,
		Job:            candidate,
		EnvRunning:     envRunning,
		PolicyEnforced: policyEnforced,
		PolicyRuntimes: policyRuntimes,
	}).Allows() {
		return nil, false, nil
	}
	jobs, ok := w.runJobs[candidate.RunID]
	if !ok {
		all, err := w.s.Store.ListJobsByRun(w.ctx, candidate.RunID)
		if err != nil {
			return nil, false, err
		}
		jobs = make(map[string]model.Job, len(all))
		for _, j := range all {
			jobs[j.ID] = j
		}
		w.runJobs[candidate.RunID] = jobs
	}
	ready, outcome := DependencyOutcome(candidate.Needs, nil, func(id string) (model.Status, bool) {
		d, ok := jobs[id]
		return d.Status, ok
	})
	if !ready || (outcome != model.StatusSuccess && !ConditionAllows(candidate.Condition, outcome)) {
		return nil, false, nil
	}
	return jobs, true, nil
}

// headFitsAlongside reports whether the reservation head would still fit the
// runner's configured capacity after candidate C is admitted alongside it.
// The check is dimension-scoped and cumulative:
//
//   - cumulative: the runner's CURRENT reservations are what the head is
//     waiting to drain, but admitting C adds a new occupant that only drains
//     later, so the comparison is reserved + C + head against the configured
//     capacity. A per-candidate-only comparison would let a stream of
//     individually-fitting backfills re-accumulate and starve the head again
//     (e.g. a 4-CPU head with a stream of 4-CPU jobs on an 8-CPU runner).
//   - dimension-scoped: only dimensions C actually requests can cause the
//     starvation, so a candidate with a zero request in the head's starved
//     dimension is admitted (a memory-only job alongside a CPU-blocked
//     head). Including a dimension C does not touch would waste free
//     capacity without protecting the head.
//
// A false result means admitting C could permanently occupy capacity the
// head needs; the candidate is skipped.
func (w *leaseCandidateWalk) headFitsAlongside(candidate model.Job) bool {
	// Both sides use the runner's effective request: on a JobCgroup runner
	// the kernel bounds the candidate and the head together by their own
	// declared requests, so their service envelopes are not charged here
	// (nor by the pre-filter, the filter or the claim).
	add := effectiveJobRequest(candidate, w.eff.JobCgroup)
	head := effectiveJobRequest(*w.head, w.eff.JobCgroup)
	capacity := w.eff.ResourceCapacity
	if capacity.CPU > 0 && add.CPU > 0 && w.reserved.CPU+add.CPU+head.CPU > capacity.CPU {
		return false
	}
	if capacity.Memory > 0 && add.Memory > 0 && w.reserved.Memory+add.Memory+head.Memory > capacity.Memory {
		return false
	}
	if capacity.Disk > 0 && add.Disk > 0 && w.reserved.Disk+add.Disk+head.Disk > capacity.Disk {
		return false
	}
	if capacity.PIDs > 0 && add.PIDs > 0 && w.reserved.PIDs+add.PIDs+head.PIDs > capacity.PIDs {
		return false
	}
	return true
}

// effectiveJobRequest returns the resources a lease on j reserves against a
// runner: the job's own declared request plus its aggregate service envelope
// (model.Job.ReservedResources). On a runner that can establish a job-scoped
// parent cgroup (ignoreEnvelope, from Runner.JobCgroup) the kernel bounds the
// main container and every service together by the job's declared envelope,
// so only the job's own request is charged — the SAME relaxation
// storage.LeaseClaim.IgnoreServiceEnvelope gives the claim transaction.
func effectiveJobRequest(j model.Job, ignoreEnvelope bool) model.ResourceCapacity {
	if ignoreEnvelope {
		return j.ResourceRequest()
	}
	return j.ReservedResources()
}

// effectiveRunner resolves the runner's LIVE scheduling view at lease time
// through the ONE shared live-profile precedence (storage.ResolveLiveProfileBinding):
// an explicit certificate-serial binding wins when the runner presents a
// registered serial, otherwise the runner-ID binding (runner_profile_links)
// applies, otherwise the registration snapshot is used unchanged. A profile
// edit therefore takes effect on the next lease for mTLS AND per-runner
// bearer identities.
//
// A dangling binding fails the lease closed ([LiveProfileResolution.
// DeniesLease]) and is presented here as a zero-capacity runner (the claim
// fails it closed with ErrNoCapacity), so the prefilter never proposes
// candidates the claim will reject. Stores without the resolver contract fall
// back to composing the same precedence from their profile read contracts
// (without dangling detection, since those report only found/not-found); the
// claim transaction remains the authoritative decision.
func (s *DBScheduler) effectiveRunner(ctx context.Context, ri model.Runner) model.Runner {
	eff, _ := s.effectiveRunnerChecked(ctx, ri)
	return eff
}

// effectiveRunnerChecked is effectiveRunner with an explicit resolution
// outcome: ok=false means the live-profile read failed and the returned
// runner is the registration snapshot. The scheduler's own prefilter/claim
// keeps the snapshot fallback (the claim re-reads inside its transaction and
// decides with its own error), while a caller that ADVERTISES a
// profile-derived capability to the runner — the /next task's job_cgroup
// flag — must treat a failed resolution conservatively and not advertise it.
func (s *DBScheduler) effectiveRunnerChecked(ctx context.Context, ri model.Runner) (model.Runner, bool) {
	if lr, ok := s.Store.(storage.LiveProfileResolver); ok {
		resolution, err := lr.ResolveLiveRunnerProfile(ctx, ri.ID, ri.CertSerial)
		if err != nil {
			// The prefilter is best-effort: a read failure falls back to the
			// snapshot and the claim (which re-reads inside its transaction)
			// decides with its own error.
			log.Printf("scheduler: resolve live profile for runner %s: %v", ri.ID, err)
			return ri, false
		}
		return applyLiveResolution(ri, resolution), true
	}
	var runnerLookup storage.ProfileBindingLookup
	if ls, ok := s.Store.(storage.RunnerProfileLinkStore); ok {
		runnerLookup = func() (model.RunnerProfile, bool, bool, error) {
			p, found, err := ls.ProfileForRunnerID(ctx, ri.ID)
			return p, found, found, err
		}
	}
	var certLookup storage.ProfileBindingLookup
	if ps, ok := s.Store.(storage.ProfileStore); ok {
		certLookup = func() (model.RunnerProfile, bool, bool, error) {
			p, found, err := ps.ProfileForSerial(ctx, ri.CertSerial)
			return p, found, found, err
		}
	}
	resolution, err := storage.ResolveLiveProfileBinding(ri.CertSerial, certLookup, runnerLookup)
	if err != nil {
		log.Printf("scheduler: resolve live profile for runner %s: %v", ri.ID, err)
		return ri, false
	}
	return applyLiveResolution(ri, resolution), true
}

// applyLiveResolution overlays one live-profile resolution on the runner's
// registration snapshot: a dangling binding presents the runner as
// zero-capacity (the claim fails it closed), a found profile replaces the
// snapshot attributes, and no binding keeps the snapshot unchanged. It is the
// ONE overlay body the per-runner and the batched entry points share, so the
// two paths cannot diverge.
func applyLiveResolution(ri model.Runner, resolution storage.LiveProfileResolution) model.Runner {
	switch {
	case resolution.DeniesLease():
		ri.Capacity = 0
		return ri
	case resolution.Applies():
		return storage.ResolveRunnerProfile(ri, resolution.Profile, true)
	default:
		return ri
	}
}

// EffectiveRunner exposes the LIVE scheduling view of one runner (profile
// overlay included) to the server's queue-reason explainer, so the reasons it
// reports use the same effective capacity the lease decision uses. Stores
// without a profile contract return the runner unchanged.
func (s *DBScheduler) EffectiveRunner(ctx context.Context, ri model.Runner) model.Runner {
	return s.effectiveRunner(ctx, ri)
}

// EffectiveRunnerChecked is EffectiveRunner with an explicit resolution
// outcome. ok=false means the live-profile read failed and the returned
// runner is the registration snapshot; the /next handler uses it to LEAVE
// the advertised job_cgroup capability false on a failed resolution, so a
// transient read error can never advertise an unenforced kernel bound.
func (s *DBScheduler) EffectiveRunnerChecked(ctx context.Context, ri model.Runner) (model.Runner, bool) {
	return s.effectiveRunnerChecked(ctx, ri)
}

// EffectiveRunnerBatch resolves the LIVE scheduling view of every runner in
// ONE set-based read when the store implements storage.FleetRunnerViewStore:
// the batched binding rows are resolved through the SAME shared precedence
// the per-runner path uses (storage.FleetRunnerBinding.Resolve ->
// ResolveLiveProfileBinding) and overlaid by the SAME body, so a batched view
// always equals EffectiveRunner's answer for the same runner.
//
// ok=false means the caller must use the per-runner entry point: the store
// has no batch contract, or the batch read failed (logged; the claim remains
// authoritative). Even on ok=true a runner the batch did not return (it
// raced the listing) is resolved per-runner, so the map is complete for every
// input runner.
func (s *DBScheduler) EffectiveRunnerBatch(ctx context.Context, runners []model.Runner) (map[string]model.Runner, bool) {
	vs, ok := s.Store.(storage.FleetRunnerViewStore)
	if !ok {
		return nil, false
	}
	bindings, err := vs.FleetRunnerProfileBindings(ctx)
	if err != nil {
		log.Printf("scheduler: batch resolve live profiles: %v", err)
		return nil, false
	}
	out := make(map[string]model.Runner, len(runners))
	for _, ri := range runners {
		binding, found := bindings[ri.ID]
		if !found {
			out[ri.ID] = s.effectiveRunner(ctx, ri)
			continue
		}
		out[ri.ID] = applyLiveResolution(ri, binding.Resolve(ri.CertSerial))
	}
	return out, true
}

// ReservedResources exposes the runner's live resource reservation sum to the
// queue-reason explainer. A store without the ledger contract reports zero,
// which makes the resource reasons vacuous.
func (s *DBScheduler) ReservedResources(ctx context.Context, runnerID string) model.ResourceCapacity {
	return s.reservedResources(ctx, runnerID)
}

// ReservedResourcesBatch returns every runner's live reservation sum from ONE
// GROUP BY runner_id read when the store implements
// storage.FleetRunnerViewStore, byte-for-byte the quantities the per-runner
// ReservedResources returns. ok=false means the caller falls back to the
// per-runner reads (the store has no batch contract, or the batch read failed
// and was logged).
func (s *DBScheduler) ReservedResourcesBatch(ctx context.Context) (map[string]model.ResourceCapacity, bool) {
	vs, ok := s.Store.(storage.FleetRunnerViewStore)
	if !ok {
		return nil, false
	}
	sums, err := vs.RunnerReservationSums(ctx)
	if err != nil {
		log.Printf("scheduler: batch read reserved resources: %v", err)
		return nil, false
	}
	return sums, true
}

// reservedResources reads the runner's live resource reservations when the
// store keeps the ledger. A store without the contract reports zero, which
// makes the resource pre-filter vacuous (the claim's own transaction still
// decides).
func (s *DBScheduler) reservedResources(ctx context.Context, runnerID string) model.ResourceCapacity {
	rs, ok := s.Store.(storage.ResourceReservationStore)
	if !ok {
		return model.ResourceCapacity{}
	}
	reserved, err := rs.RunnerReservedResources(ctx, runnerID)
	if err != nil {
		log.Printf("scheduler: read reserved resources for runner %s: %v", runnerID, err)
		return model.ResourceCapacity{}
	}
	return reserved
}

// Heartbeat extends the job's lease and reports whether the job was
// cancelled while running. The token hash is carried for contract symmetry;
// lease authorization (runner + generation) is enforced by the store.
//
// The returned instant is the expiry the store ACTUALLY persisted: a
// LeaseClockStore (DB mode) returns clock_timestamp()+TTL directly, so the
// caller never re-reads the job (and can never fall back to an application-
// clock estimate after a successful extension); legacy stores get their own
// expiresAt back.
func (s *DBScheduler) Heartbeat(ctx context.Context, jobID, runnerID string, tokenHash []byte, generation int64, expiresAt time.Time) (bool, time.Time, error) {
	_ = tokenHash
	j, err := s.Store.GetJob(ctx, jobID)
	if err != nil {
		return false, time.Time{}, err
	}
	if j.Status == model.StatusCancelled {
		return true, time.Time{}, nil
	}
	// The authoritative expiry is the value the store actually persisted: a
	// DB-clock store returns clock_timestamp()+TTL directly, so the caller
	// never has to re-read (and can never fall back to an app-clock estimate
	// after a successful extension).
	authoritative := expiresAt
	var hbErr error
	if lc, ok := s.Store.(storage.LeaseClockStore); ok {
		authoritative, hbErr = lc.HeartbeatLeaseWithTTL(ctx, jobID, runnerID, generation, s.LeaseDuration)
	} else {
		hbErr = s.Store.HeartbeatLease(ctx, jobID, runnerID, generation, expiresAt)
	}
	if err := hbErr; err != nil {
		if errors.Is(err, storage.ErrLeaseConflict) {
			// A conflict can mean a concurrent cancellation: surface it so the
			// runner stops instead of retrying the lease.
			if cur, gerr := s.Store.GetJob(ctx, jobID); gerr == nil && cur.Status == model.StatusCancelled {
				return true, time.Time{}, nil
			}
		}
		return false, time.Time{}, err
	}
	// Refresh the runner's advisory last-seen instant through the NARROW
	// RunnerHeartbeatStore capability. It deliberately does NOT fall back to
	// GetRunner -> UpsertRunner: UpsertRunner treats the caller as
	// authoritative for the runner's profile/admin fields, so a heartbeat
	// that read the runner before a concurrent disable/drain/profile edit
	// would write the stale snapshot back and silently undo the admin action.
	// A store without the capability skips the advisory refresh.
	if hs, ok := s.Store.(storage.RunnerHeartbeatStore); ok {
		_ = hs.TouchRunnerLastSeen(ctx, runnerID)
	}
	return false, authoritative, nil
}

// Complete applies a runner completion through the store's transactional
// CompleteJob, passing the canonical completion receipt for idempotent replay.
func (s *DBScheduler) Complete(ctx context.Context, jobID string, generation int64, runnerID string, status model.Status, errMsg string, outputs map[string]string, resultHash string) error {
	receipt := model.CompletionReceipt{JobID: jobID, Generation: generation, RunnerID: runnerID, ResultHash: resultHash}
	return s.Store.CompleteJob(ctx, jobID, generation, runnerID, status, errMsg, outputs, receipt)
}

// CancelRun cancels every non-terminal job of the run and the run itself via
// the store's transactional CancelRunJobs. The audit event is emitted by the
// server's audit funnel, which routes to the same store in DB mode.
func (s *DBScheduler) CancelRun(ctx context.Context, runID, reason string) error {
	if _, err := s.Store.CancelRunJobs(ctx, runID, reason); err != nil {
		return err
	}
	return nil
}

// recoveryPageSize bounds every recovery-discovery page. Candidate discovery
// is keyset-paged in job-id order, so this constant bounds memory and
// round-trip size per page, not how many candidates a sweep can reach: the
// loop keeps requesting the next page until a short page arrives, which means
// every expired/elapsed candidate is eventually visited regardless of how
// many newer runs exist. It is a var only so tests can shrink the page and
// prove paging determinism over a candidate set larger than one page.
var recoveryPageSize = 256

// RecoverExpired requeues or fails jobs whose leases expired and cancels
// queued jobs past their queue deadline, mirroring the in-memory
// recoverLeasesLocked (infrastructure retry budget respected). Every job
// transition is ONE transactional store operation that also releases the
// runner slot / quota reservation and recomputes dependents and the run, so
// no later best-effort pass can be lost to a crash. Leader-only, and every
// transition is EPOCH-FENCED inside the store transaction: a replica whose
// cached claim outlived its advisory-lock session gets
// storage.ErrStaleLeader, mutates nothing, and is demoted here immediately
// instead of sweeping on.
//
// Discovery is DIRECT and bounded: the store's id-paged candidate queries
// (storage.RecoveryScanStore) return lightweight candidates built from the
// authoritative relational columns (id, lease_generation, queue_deadline) for
// expired running leases and elapsed queue deadlines. ListRuns-style
// enumeration is deliberately gone: a newest-N window permanently orphans an
// old non-terminal job once N newer runs exist. Each page advances the id
// cursor past EVERY returned candidate, including candidates whose applier
// fails (logged, not fatal), so one bad row can never stall the candidates
// behind it; a later sweep revisits the failure from the start. Page query
// errors abort the sweep with an error, exactly as a ListRuns error did.
// Candidates are never decoded here, so a corrupt row is still swept: the
// fenced applier applies the forced recovery that releases its capacity.
func (s *DBScheduler) RecoverExpired(ctx context.Context, now time.Time) error {
	if !s.IsLeader(ctx) {
		return ErrNotLeader
	}
	scanner, ok := s.Store.(storage.RecoveryScanStore)
	if !ok {
		return fmt.Errorf("scheduler: store does not support paged recovery discovery")
	}
	// Expired running leases, in deterministic id order so the keyset cursor
	// is a total order.
	afterID := ""
	for {
		page, err := scanner.ListExpiredRunningJobs(ctx, now, afterID, recoveryPageSize)
		if err != nil {
			return fmt.Errorf("scheduler: list expired running jobs: %w", err)
		}
		for _, c := range page {
			// The expected generation makes the recovery idempotent and
			// race-safe: a lease replaced by a concurrent re-lease is left
			// untouched.
			if err := scanner.RecoverExpiredLease(ctx, c.ID, c.LeaseGeneration, now); err != nil {
				if errors.Is(err, storage.ErrStaleLeader) {
					return s.staleLeader("recover expired lease", err)
				}
				log.Printf("scheduler: recover job %s: %v", c.ID, err)
			}
			afterID = c.ID
		}
		if len(page) < recoveryPageSize {
			break
		}
	}
	// Queue-timeout expiry: a queued (or approval-waiting) job past its
	// queue deadline is cancelled terminally, independent of its attempt
	// count, and its reserved queued quota slot is released in the SAME
	// transaction. The candidate carries the persisted queue_deadline column
	// (zero for legacy payload-only rows); the applier re-derives the
	// effective deadline under its own row lock, so the query's superset
	// (legacy payload deadlines) is filtered inside the transaction.
	afterID = ""
	for {
		page, err := scanner.ListQueueTimedOutJobs(ctx, now, afterID, recoveryPageSize)
		if err != nil {
			return fmt.Errorf("scheduler: list queue-timed-out jobs: %w", err)
		}
		for _, c := range page {
			// The candidate carries the persisted queue_deadline column; a
			// nil deadline means the row is a legacy payload-only candidate,
			// signalled to the applier as the zero time.
			observed := time.Time{}
			if c.QueueDeadline != nil {
				observed = *c.QueueDeadline
			}
			if err := scanner.ExpireQueuedJob(ctx, c.ID, observed); err != nil {
				if errors.Is(err, storage.ErrStaleLeader) {
					return s.staleLeader("expire queue deadline", err)
				}
				log.Printf("scheduler: expire queue deadline for job %s: %v", c.ID, err)
			}
			afterID = c.ID
		}
		if len(page) < recoveryPageSize {
			break
		}
	}
	return nil
}

// staleLeader marks this scheduler not-leader after a store mutation rejected
// its leadership epoch and aborts the sweep. Every remaining candidate would
// be rejected the same way (the store already cleared its retained epoch), so
// continuing would be pure no-op work. The next IsLeader call either
// re-acquires (publishing a fresh epoch) or stays a standby.
func (s *DBScheduler) staleLeader(op string, err error) error {
	s.leader.Store(false)
	log.Printf("scheduler: %s rejected by the leadership fence; demoting to standby: %v", op, err)
	return fmt.Errorf("scheduler: %s: %w", op, err)
}

// jobRuntimeCapability extracts the job's runtime capability
// (container/tart/native) from the persisted compiled payload.
func jobRuntimeCapability(j model.Job) string {
	return storage.JobRuntime(j)
}

func appendUnique(in []string, v string) []string {
	for _, x := range in {
		if x == v {
			return in
		}
	}
	return append(in, v)
}

// defaultToken generates a 256-bit crypto/rand token, hex encoded.
func defaultToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// QueueDeadlineFor returns the job's queue deadline. It delegates to the
// canonical storage helper so the scheduler's lease gate, the recovery
// transaction and the server's in-memory mode all apply one queue-timeout
// rule (persisted QueueDeadline first, compiled-payload queue_timeout second).
func QueueDeadlineFor(j model.Job) *time.Time {
	return storage.QueueDeadlineFor(j)
}

// Scheduling fairness: a static priority order starves low-priority work
// forever when a continuous stream of fresh high-priority jobs is available,
// because age only breaks ties WITHIN a priority class. Waiting time now buys
// UNBOUNDED priority (one point per schedulerAgingInterval): static priority
// is downstream graph depth, which has no small maximum, so any fixed boost
// cap smaller than a valid priority difference would still admit starvation.
// With an uncapped boost every eligible job eventually outranks any finite
// static priority, and equal effective priorities are ordered oldest first.
// Downstream-depth priority is preserved as the primary signal for the
// common case.
const schedulerAgingInterval = 10 * time.Minute

// agedPriority is a job's scheduling priority including the unbounded
// wait-time boost.
func agedPriority(j model.Job, now time.Time) int {
	wait := now.Sub(j.CreatedAt)
	if wait <= 0 {
		return j.Priority
	}
	return j.Priority + int(wait/schedulerAgingInterval)
}

// orderQueuedJobs orders lease candidates by aged priority (descending) then
// age (oldest first). The lease claim walks this order, so the ordering IS the
// fairness policy.
func orderQueuedJobs(queued []model.Job, now time.Time) {
	sort.Slice(queued, func(i, j int) bool {
		pi, pj := agedPriority(queued[i], now), agedPriority(queued[j], now)
		if pi != pj {
			return pi > pj
		}
		return queued[i].CreatedAt.Before(queued[j].CreatedAt)
	})
}
