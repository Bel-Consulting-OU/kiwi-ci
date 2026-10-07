package scheduler

// Immutable-traversal lease tests (Round-11 finding A): the scheduler's
// continuation cursor must key on the immutable creation order, not on the
// mutable aged priority (priority + queue_boost). queue_boost changes
// asynchronously in PromoteQueuedJobBoosts, so an aged cursor can be crossed
// by a promoted row that then sorts BEFORE it and is skipped for an
// arbitrarily long time. These tests pin the two-mechanism design:
//
//   - the aged HEAD WINDOW (first page by priority+queue_boost) still sees
//     every newly promoted row that rises into it;
//   - the round-robin sweep over (created_at, id) reaches every other row in
//     creation order and wraps to the beginning when exhausted.
//
// Plus the bounded continuation-state map: TTL sweep, hard cardinality cap
// with oldest-eviction, and DropScanState.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestSchedulerCursorMutableOrderingCannotStarve is the audit's liveness
// regression: with a traversal-aware store, 300 dependency-blocked rows sit
// behind 10 high-priority decoy rows; a first poll forces a continuation
// cursor past the first 50 creation-order rows; then one blocked row is
// PROMOTED (its aged priority crosses the old mutable cursor boundary) and
// made runnable while still ranking outside the aged head window. The next
// polls must reach and lease it through the immutable traversal. An
// aged-priority continuation cursor would resume behind the promoted row and
// never see it (the head window holds only the decoys).
func TestSchedulerCursorMutableOrderingCannotStarve(t *testing.T) {
	ctx := context.Background()
	p := newPagedFakeStore()
	now := time.Now().UTC()
	base := now.Add(-2 * time.Hour)

	targetID := fmt.Sprintf("blocked-%03d", 250)
	jobs := make([]model.Job, 0, 310)
	// Ten decoys hold the aged head window (priority 100) and can never be
	// leased (dependency-blocked), so the promoted row stays outside it.
	for i := 0; i < 10; i++ {
		j := dependencyBlockedJob(fmt.Sprintf("decoy-%02d", i), base.Add(time.Duration(i)*time.Millisecond))
		j.Priority = 100
		jobs = append(jobs, j)
	}
	// 300 dependency-blocked rows in creation order, all priority 0.
	for i := 0; i < 300; i++ {
		jobs = append(jobs, dependencyBlockedJob(fmt.Sprintf("blocked-%03d", i), base.Add(time.Second+time.Duration(i)*time.Millisecond)))
	}
	runnerID := "runner-mutable-cursor"
	s := pagedLeaseStore(t, p, runnerID, now, jobs...)
	// Head window 10, budget 60: the first poll walks the 10 decoys plus the
	// first 50 creation-order rows (the decoys again, then blocked-000..039)
	// and saves a traversal cursor at blocked-039.
	s.SetLeaseScanLimits(10, 60, 0)
	if _, _, _, err := s.Lease(ctx, runnerID, now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("priming lease = %v, want ErrNoJobs", err)
	}
	if _, ok := scanCursorFor(s, runnerID); !ok {
		t.Fatal("priming lease did not save a traversal cursor")
	}

	// Promote blocked-250 across the old aged boundary (cursor row is aged
	// priority 0, the promoted row becomes priority 1) and make it runnable.
	// The priority-100 decoys keep it outside the 10-row head window.
	promoted, err := p.GetJob(ctx, targetID)
	if err != nil {
		t.Fatalf("load target: %v", err)
	}
	promoted.Priority = 1
	promoted.Needs = nil
	if err := p.UpdateJob(ctx, promoted); err != nil {
		t.Fatalf("promote target: %v", err)
	}

	var leased *model.Job
	for poll := 0; poll < 8; poll++ {
		j, _, _, err := s.Lease(ctx, runnerID, now)
		if err != nil {
			if errors.Is(err, ErrNoJobs) {
				continue
			}
			t.Fatalf("poll %d: %v", poll, err)
		}
		leased = j
		break
	}
	if leased == nil {
		t.Fatal("promoted row was never leased: the traversal cursor skipped a row that crossed the old aged boundary")
	}
	if leased.ID != targetID {
		t.Fatalf("leased %s, want the promoted %s", leased.ID, targetID)
	}
}

// TestSchedulerTraversalWraps drives the wrap: a budget-exhausted poll saves
// a traversal cursor; the row behind it is removed; a newly enqueued row
// whose creation instant is BEHIND the cursor (an older creation order, e.g.
// a compiled job whose insert was delayed) can then only be found by wrapping
// to the beginning when the traversal from the stored position is exhausted.
func TestSchedulerTraversalWraps(t *testing.T) {
	ctx := context.Background()
	p := newPagedFakeStore()
	now := time.Now().UTC()
	base := now.Add(-time.Hour)
	b0 := dependencyBlockedJob("blocked-0", base)
	b0.Priority = 10
	b1 := dependencyBlockedJob("blocked-1", base.Add(time.Second))
	runnerID := "runner-wrap"
	s := pagedLeaseStore(t, p, runnerID, now, b0, b1)
	s.SetLeaseScanLimits(1, 2, 0)

	// Poll 1: head window [blocked-0]; the traversal walks blocked-0 again
	// and saves the cursor after it (budget exhausted while blocked-1 is
	// still behind the cursor).
	if _, _, _, err := s.Lease(ctx, runnerID, now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("priming lease = %v, want ErrNoJobs", err)
	}
	if _, ok := scanCursorFor(s, runnerID); !ok {
		t.Fatal("priming lease did not save a traversal cursor")
	}

	// The only row behind the cursor leaves the queue, so the stored
	// position now points past the end of the live traversal.
	stored, err := p.GetJob(ctx, b1.ID)
	if err != nil {
		t.Fatalf("load blocked-1: %v", err)
	}
	stored.Status = model.StatusRunning
	if err := p.UpdateJob(ctx, stored); err != nil {
		t.Fatalf("retire blocked-1: %v", err)
	}

	// A "newly enqueued" row whose creation instant is behind the cursor.
	// The aged head window still shows blocked-0 first (page size 1), so the
	// row is only reachable after the sweep wraps to the beginning.
	target := model.Job{ID: "target-new", Key: "target-new", Status: model.StatusQueued, CreatedAt: base.Add(-time.Second)}
	if err := p.InsertJob(ctx, target); err != nil {
		t.Fatalf("insert target: %v", err)
	}

	s.SetLeaseScanLimits(1, 3, 0)
	j, _, _, err := s.Lease(ctx, runnerID, now)
	if err != nil {
		t.Fatalf("wrapped lease: %v", err)
	}
	if j.ID != target.ID {
		t.Fatalf("leased %s, want %s (found only after wrapping)", j.ID, target.ID)
	}
	if _, ok := scanCursorFor(s, runnerID); ok {
		t.Fatal("a successful claim must clear the traversal cursor")
	}
}

// TestSchedulerScanStateSweepAndCap pins the continuation-state bounds:
// inserting past the hard cap evicts the oldest-touched entry, the TTL sweep
// reclaims abandoned runner entries even though none of those runners ever
// returns (both when called directly and from the periodic Lease trigger),
// and DropScanState removes one runner immediately.
func TestSchedulerScanStateSweepAndCap(t *testing.T) {
	oldCap := queuedScanStateCap
	queuedScanStateCap = 8
	t.Cleanup(func() { queuedScanStateCap = oldCap })

	base := time.Now().UTC()
	s := &DBScheduler{}
	hasState := func(runnerID string) bool {
		s.scanMu.Lock()
		defer s.scanMu.Unlock()
		_, ok := s.scan[runnerID]
		return ok
	}
	for i := 0; i < queuedScanStateCap; i++ {
		s.saveScanCursor(fmt.Sprintf("runner-%02d", i),
			storage.QueuedJobTraversalCursor{ID: fmt.Sprintf("job-%02d", i)},
			base.Add(time.Duration(i)*time.Second))
	}
	if got := len(s.scan); got != queuedScanStateCap {
		t.Fatalf("state entries = %d, want the cap %d", got, queuedScanStateCap)
	}

	// A NEW runner at the cap evicts the oldest-touched entry.
	s.saveScanCursor("runner-new", storage.QueuedJobTraversalCursor{ID: "job-new"}, base.Add(time.Duration(queuedScanStateCap)*time.Second))
	if got := len(s.scan); got != queuedScanStateCap {
		t.Fatalf("state entries after cap insert = %d, want the cap %d", got, queuedScanStateCap)
	}
	if hasState("runner-00") {
		t.Fatal("oldest-touched entry was not evicted at the cap")
	}
	if !hasState("runner-new") {
		t.Fatal("the new runner's entry was not stored")
	}

	// Abandoned runners: entries touched far in the past, inserted directly
	// under the mutex so neither the cap eviction nor a mutating call has
	// swept them yet, then reclaimed by the independent sweep without any of
	// those runners returning.
	now := base.Add(time.Duration(queuedScanStateCap+1) * time.Second)
	abandonedAt := now.Add(-queuedScanCursorTTL - time.Minute)
	s.scanMu.Lock()
	for i := 0; i < 3; i++ {
		s.scan[fmt.Sprintf("abandoned-%d", i)] = queuedScanState{
			after:   storage.QueuedJobTraversalCursor{ID: fmt.Sprintf("old-%d", i)},
			touched: abandonedAt,
		}
	}
	s.scanMu.Unlock()
	if !hasState("abandoned-0") {
		t.Fatal("test setup: abandoned entry was not stored")
	}
	s.sweepScanState(now)
	for i := 0; i < 3; i++ {
		if hasState(fmt.Sprintf("abandoned-%d", i)) {
			t.Fatalf("abandoned-%d survived the TTL sweep", i)
		}
	}
	if !hasState("runner-new") {
		t.Fatal("a fresh entry was swept by the TTL sweep")
	}

	// DropScanState removes one runner immediately.
	s.DropScanState("runner-new")
	if hasState("runner-new") {
		t.Fatal("DropScanState did not remove the runner's entry")
	}

	// The periodic in-Lease sweep reclaims an abandoned entry with no
	// traffic from its runner at all.
	p := newPagedFakeStore()
	ctx := context.Background()
	leaseNow := time.Now().UTC()
	s2 := pagedLeaseStore(t, p, "runner-periodic", leaseNow)
	s2.saveScanCursor("runner-gone", storage.QueuedJobTraversalCursor{ID: "job-gone"},
		leaseNow.Add(-queuedScanCursorTTL-time.Hour))
	if !hasStateOf(s2, "runner-gone") {
		t.Fatal("test setup: periodic-sweep entry was not stored")
	}
	s2.scanCalls.Store(queuedScanSweepEvery - 1)
	if _, _, _, err := s2.Lease(ctx, "runner-periodic", leaseNow); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("periodic lease = %v, want ErrNoJobs", err)
	}
	if hasStateOf(s2, "runner-gone") {
		t.Fatal("the periodic Lease sweep did not reclaim the abandoned entry")
	}
}

// hasStateOf reports whether the scheduler's continuation map holds the
// runner, for tests that build their own scheduler.
func hasStateOf(s *DBScheduler, runnerID string) bool {
	s.scanMu.Lock()
	defer s.scanMu.Unlock()
	_, ok := s.scan[runnerID]
	return ok
}

// TestSchedulerTraversalFrontierAdvancesUnderPermanentHeadPrefix pins the
// head-vs-traversal budget contract. A permanently replenished high-priority
// dependency-blocked prefix keeps the aged head window full on every poll,
// and the scan budget is deliberately small relative to the page size
// (pageSize 8, maxRows 9 => minAdvance = max(1, 9/4) = 2), exactly the regime
// where the head window would otherwise consume all but one row of the
// traversal budget. The deep eligible row must be leased within
// ceil(depth/minAdvance)+2 polls, and every unsuccessful scan must have moved
// the immutable traversal frontier by at least the guaranteed minimum.
func TestSchedulerTraversalFrontierAdvancesUnderPermanentHeadPrefix(t *testing.T) {
	ctx := context.Background()
	p := newPagedFakeStore()
	now := time.Now().UTC()
	base := now.Add(-time.Hour)

	const depth = 40
	const pageSize, maxRows = 8, 9
	minAdvance := maxRows / 4
	if minAdvance > pageSize {
		minAdvance = pageSize
	}
	if minAdvance < 1 {
		minAdvance = 1
	}
	const replenish = 8
	maxPolls := (depth+minAdvance-1)/minAdvance + 2

	runnerID := "runner-frontier-guarantee"
	jobs := make([]model.Job, 0, depth+replenish+1)
	for i := 0; i < depth; i++ {
		jobs = append(jobs, dependencyBlockedJob(fmt.Sprintf("blocked-%03d", i), base.Add(time.Duration(i)*time.Millisecond)))
	}
	deep := model.Job{ID: "deep-eligible", Key: "deep-eligible", Status: model.StatusQueued,
		CreatedAt: base.Add(time.Duration(depth) * time.Millisecond)}
	jobs = append(jobs, deep)
	// The head-window blockers are created AFTER the deep row, so they can
	// never hide it from the creation-order traversal: they only occupy the
	// aged head with priority-1000 ineligible rows.
	creationOrder := make([]string, 0, depth+replenish+maxPolls)
	for i := 0; i < replenish; i++ {
		j := dependencyBlockedJob(fmt.Sprintf("head-%03d", i), base.Add(time.Duration(100+i)*time.Millisecond))
		j.Priority = 1000
		jobs = append(jobs, j)
	}
	for _, j := range jobs {
		creationOrder = append(creationOrder, j.ID)
	}
	s := pagedLeaseStore(t, p, runnerID, now, jobs...)
	s.SetLeaseScanLimits(pageSize, maxRows, 0)

	position := func(id string) int {
		for i, want := range creationOrder {
			if want == id {
				return i
			}
		}
		t.Fatalf("cursor names %s, which is not in the fixture creation order", id)
		return -1
	}

	previous := -1
	for poll := 1; poll <= maxPolls; poll++ {
		// Permanently replenish the head prefix: each new blocker outranks
		// every real candidate but is created after the deep row.
		extra := dependencyBlockedJob(fmt.Sprintf("head-live-%03d", poll), base.Add(time.Duration(200+poll)*time.Millisecond))
		extra.Priority = 1000
		extra.RunID = "run-" + runnerID
		if err := p.InsertJob(ctx, extra); err != nil {
			t.Fatalf("replenish poll %d: %v", poll, err)
		}
		creationOrder = append(creationOrder, extra.ID)

		j, _, _, err := s.Lease(ctx, runnerID, now)
		if err == nil {
			if j.ID != deep.ID {
				t.Fatalf("poll %d leased %s, want the deep eligible %s", poll, j.ID, deep.ID)
			}
			if _, ok := scanCursorFor(s, runnerID); ok {
				t.Fatal("a successful claim must clear the traversal frontier")
			}
			return
		}
		if !errors.Is(err, ErrNoJobs) {
			t.Fatalf("poll %d lease = %v, want ErrNoJobs or the deep claim", poll, err)
		}
		cursor, ok := scanCursorFor(s, runnerID)
		if !ok {
			t.Fatalf("poll %d: unsuccessful scan did not advance the traversal frontier", poll)
		}
		pos := position(cursor.ID)
		if advance := pos - previous; advance < minAdvance {
			t.Fatalf("poll %d: frontier advanced by %d rows, want at least minAdvance=%d (cursor %s at position %d)",
				poll, advance, minAdvance, cursor.ID, pos)
		}
		previous = pos
	}
	t.Fatalf("deep eligible row not leased within %d polls (depth=%d, minAdvance=%d)", maxPolls, depth, minAdvance)
}

// TestSchedulerHeadLatencyUnaffectedByTraversal pins the other half of the
// contract: the head window is read BEFORE the round-robin resumes, so a
// newly enqueued top-priority eligible job is claimed on the very next poll
// while a deep traversal frontier is pending — without fetching one further
// traversal page for it.
func TestSchedulerHeadLatencyUnaffectedByTraversal(t *testing.T) {
	ctx := context.Background()
	p := newPagedFakeStore()
	now := time.Now().UTC()
	base := now.Add(-time.Hour)
	jobs := make([]model.Job, 0, 1024)
	for i := 0; i < 1024; i++ {
		jobs = append(jobs, dependencyBlockedJob(fmt.Sprintf("old-%04d", i), base.Add(time.Duration(i)*time.Millisecond)))
	}
	runnerID := "runner-head-latency"
	s := pagedLeaseStore(t, p, runnerID, now, jobs...)
	s.SetLeaseScanLimits(32, 64, 0)

	// Prime a deep traversal frontier behind the ineligible prefix.
	if _, _, _, err := s.Lease(ctx, runnerID, now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("priming lease = %v, want ErrNoJobs", err)
	}
	if _, ok := scanCursorFor(s, runnerID); !ok {
		t.Fatal("priming lease did not record a traversal frontier")
	}
	p.mu.Lock()
	pagesBefore := p.traversalPages
	p.mu.Unlock()

	hot := model.Job{ID: "hot-new", RunID: "run-" + runnerID, Key: "hot-new",
		Status: model.StatusQueued, Priority: 1000, CreatedAt: now}
	if err := p.InsertJob(ctx, hot); err != nil {
		t.Fatalf("insert hot job: %v", err)
	}
	j, _, _, err := s.Lease(ctx, runnerID, now)
	if err != nil {
		t.Fatalf("head-window lease = %v, want the hot job on the next poll", err)
	}
	if j.ID != hot.ID {
		t.Fatalf("leased %s, want %s from the head window", j.ID, hot.ID)
	}
	p.mu.Lock()
	pagesAfter := p.traversalPages
	p.mu.Unlock()
	if pagesAfter != pagesBefore {
		t.Fatalf("head-window claim fetched %d traversal page(s); the pending frontier must not delay it", pagesAfter-pagesBefore)
	}
	if _, ok := scanCursorFor(s, runnerID); ok {
		t.Fatal("a successful claim must clear the traversal frontier")
	}
}

// TestSchedulerTraversalSmallBudgetGuaranteesOneTraversalPage pins the
// maxCandidateRows <= pageSize edge: the head window consumes the whole scan
// budget, and the request still walks one FULL traversal page so the
// round-robin frontier advances even though nothing else fits.
func TestSchedulerTraversalSmallBudgetGuaranteesOneTraversalPage(t *testing.T) {
	ctx := context.Background()
	p := newPagedFakeStore()
	now := time.Now().UTC()
	base := now.Add(-time.Hour)
	jobs := make([]model.Job, 0, 100)
	for i := 0; i < 100; i++ {
		jobs = append(jobs, dependencyBlockedJob(fmt.Sprintf("blocked-%03d", i), base.Add(time.Duration(i)*time.Millisecond)))
	}
	runnerID := "runner-small-budget"
	s := pagedLeaseStore(t, p, runnerID, now, jobs...)
	const pageSize, maxRows = 16, 4
	s.SetLeaseScanLimits(pageSize, maxRows, 0)

	if _, _, _, err := s.Lease(ctx, runnerID, now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("lease = %v, want ErrNoJobs", err)
	}
	p.mu.Lock()
	pages, returned := p.traversalPages, p.jobsReturned
	p.mu.Unlock()
	if pages != 1 {
		t.Fatalf("traversal pages = %d, want exactly one full traversal page", pages)
	}
	if returned != maxRows+pageSize {
		t.Fatalf("materialized rows = %d, want head %d + one traversal page %d", returned, maxRows, pageSize)
	}
	cursor, ok := scanCursorFor(s, runnerID)
	if !ok {
		t.Fatal("unsuccessful scan did not store a traversal frontier")
	}
	if cursor.ID != fmt.Sprintf("blocked-%03d", pageSize-1) {
		t.Fatalf("frontier = %s, want blocked-%03d (one full page past the head)", cursor.ID, pageSize-1)
	}
}
