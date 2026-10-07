package storage

// Unit tests for the immutable-creation-order traversal contract
// (QueuedJobTraversalStore) on the in-memory store and through the FaultyStore
// wrapper. The contract mirrors QueuedJobPageStore's filter/deadline
// predicates and keyset semantics, but orders by (created_at ASC, id ASC) —
// the immutable key that cannot be moved by PromoteQueuedJobBoosts.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func queuedJobsTraversalIDs(page QueuedJobTraversalPage) []string {
	ids := make([]string, 0, len(page.Jobs))
	for _, j := range page.Jobs {
		ids = append(ids, j.ID)
	}
	return ids
}

// TestQueuedJobsTraversalMemoryOrderingCursorAndLimits pins the memStore
// creation-order keyset contract: created_at ASC with the id tiebreak, strict
// keyset semantics with no duplicates or gaps, exact HasMore/Last, deadline
// and filter pushdown, and the materialized QueueBoost on returned copies.
func TestQueuedJobsTraversalMemoryOrderingCursorAndLimits(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 9, 10, 11, 12, 0, time.UTC)
	past := now.Add(-time.Minute)
	mk := func(id string, priority int, created time.Time) model.Job {
		return model.Job{ID: id, RunID: "run-1", Key: id, Status: model.StatusQueued, Priority: priority, CreatedAt: created}
	}
	m := queuedJobsPageMemoryStore(t,
		mk("e", 14, now),                     // newest, highest priority: aged head, LAST in creation order
		mk("a", 0, now.Add(-70*time.Minute)), // oldest
		mk("d", 7, now.Add(-2*time.Minute)),  // tie with c on created_at, larger id
		mk("c", 5, now.Add(-2*time.Minute)),  // tie with d on created_at, smaller id
		mk("b", 5, now.Add(-25*time.Minute)), //
		model.Job{ID: "past", RunID: "run-1", Key: "past", Status: model.StatusQueued, CreatedAt: now.Add(-time.Hour), QueueDeadline: &past},
		model.Job{ID: "running", RunID: "run-1", Key: "running", Status: model.StatusRunning, CreatedAt: now.Add(-80 * time.Minute)},
		mk("future", 0, now.Add(-80*time.Minute)), // oldest but not the oldest: running row sorts before it
	)
	// The running row is never a candidate and the elapsed persisted deadline
	// is pushed out; the rest are in creation order (id ASC within a tie).
	want := []string{"future", "a", "b", "c", "d", "e"}

	all, err := m.ListQueuedJobsByCreation(ctx, QueuedJobFilter{}, nil, 0, now)
	if err != nil {
		t.Fatalf("ListQueuedJobsByCreation(default): %v", err)
	}
	if got := strings.Join(queuedJobsTraversalIDs(all), ","); got != strings.Join(want, ",") {
		t.Fatalf("default traversal = %v, want %v", got, want)
	}
	if all.HasMore {
		t.Fatal("default traversal reported HasMore with the whole queue in it")
	}
	last := all.Jobs[len(all.Jobs)-1]
	if all.Last.ID != last.ID || !all.Last.CreatedAt.Equal(last.CreatedAt) {
		t.Fatalf("default traversal Last = %+v, want cursor of %s", all.Last, last.ID)
	}
	if !all.Jobs[0].BoostKnown {
		t.Fatal("traversal copies must carry the materialized QueueBoost")
	}

	var seen []string
	var after *QueuedJobTraversalCursor
	pages := 0
	for {
		page, err := m.ListQueuedJobsByCreation(ctx, QueuedJobFilter{}, after, 2, now)
		if err != nil {
			t.Fatalf("page %d: %v", pages+1, err)
		}
		pages++
		got := queuedJobsTraversalIDs(page)
		if page.HasMore && len(got) != 2 {
			t.Fatalf("page %d HasMore with %d jobs", pages, len(got))
		}
		seen = append(seen, got...)
		if !page.HasMore {
			break
		}
		pageLast := page.Jobs[len(page.Jobs)-1]
		if page.Last.ID != pageLast.ID || !page.Last.CreatedAt.Equal(pageLast.CreatedAt) {
			t.Fatalf("page %d Last = %+v, want cursor of %s", pages, page.Last, pageLast.ID)
		}
		cursor := page.Last
		after = &cursor
	}
	if pages != 3 {
		t.Fatalf("walk pages = %d, want 3", pages)
	}
	if got := strings.Join(seen, ","); got != strings.Join(want, ",") {
		t.Fatalf("walk = %v, want %v (no duplicates, no gaps)", got, want)
	}
}

// TestQueuedJobsTraversalMemoryFilter proves the traversal applies the SAME
// runner-coarse QueuedJobFilter as the aged page: a label-incompatible row is
// skipped by the store even though it is first in creation order, and the
// filtered page's Last still names the returned row.
func TestQueuedJobsTraversalMemoryFilter(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 9, 10, 11, 12, 0, time.UTC)
	m := queuedJobsPageMemoryStore(t,
		model.Job{ID: "blocked", RunID: "run-1", Key: "blocked", Status: model.StatusQueued,
			CreatedAt: now.Add(-time.Hour), RequiredLabels: []string{"macos"}},
		model.Job{ID: "eligible", RunID: "run-1", Key: "eligible", Status: model.StatusQueued, CreatedAt: now.Add(-time.Minute)},
	)
	page, err := m.ListQueuedJobsByCreation(ctx, QueuedJobFilter{RunnerLabels: []string{"linux"}}, nil, 10, now)
	if err != nil {
		t.Fatalf("ListQueuedJobsByCreation: %v", err)
	}
	got := queuedJobsTraversalIDs(page)
	if len(got) != 1 || got[0] != "eligible" {
		t.Fatalf("filtered traversal = %v, want [eligible]", got)
	}
}

// TestQueuedJobsTraversalFaultyStoreDelegation proves the wrapper delegates
// the read without consuming the mutation-fault counter and fails closed with
// a diagnosable error when the inner store lacks the capability.
func TestQueuedJobsTraversalFaultyStoreDelegation(t *testing.T) {
	now := time.Date(2026, 8, 9, 9, 10, 11, 0, time.UTC)
	m := queuedJobsPageMemoryStore(t,
		model.Job{ID: "a", RunID: "run-1", Key: "a", Status: model.StatusQueued, CreatedAt: now.Add(-time.Minute)},
		model.Job{ID: "b", RunID: "run-1", Key: "b", Status: model.StatusQueued, CreatedAt: now},
	)
	fault := &FaultyStore{Inner: m, FailAfter: 1, Err: ErrNotFound}
	ctx := context.Background()
	page, err := fault.ListQueuedJobsByCreation(ctx, QueuedJobFilter{}, nil, 1, now)
	if err != nil {
		t.Fatalf("ListQueuedJobsByCreation through FaultyStore: %v", err)
	}
	if ids := queuedJobsTraversalIDs(page); len(ids) != 1 || ids[0] != "a" || !page.HasMore {
		t.Fatalf("delegated traversal = %v (hasMore=%v)", ids, page.HasMore)
	}
	if fault.Mutations() != 0 {
		t.Fatalf("read consumed %d write fault(s)", fault.Mutations())
	}
	missing := &FaultyStore{Inner: storeOnlyInner{}}
	if _, err := missing.ListQueuedJobsByCreation(ctx, QueuedJobFilter{}, nil, 1, now); err == nil || !strings.Contains(err.Error(), "QueuedJobTraversalStore") {
		t.Fatalf("missing inner capability = %v, want QueuedJobTraversalStore error", err)
	}
}

// TestQueuedJobsTraversalQueryShape pins the generated SQL: the same
// status/deadline and filter predicates as the aged page, creation-order
// ordering with the pinned COLLATE "C" id tiebreak, and limit+1 for an exact
// HasMore.
func TestQueuedJobsTraversalQueryShape(t *testing.T) {
	limit := 32
	query, args := queuedJobsTraversalQuery(QueuedJobFilter{Runtimes: []string{"native"}}, &QueuedJobTraversalCursor{
		CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		ID:        "abc",
	}, limit, time.Now().UTC())
	for _, want := range []string{
		"status='queued'",
		"(queue_deadline IS NULL OR queue_deadline > $1::timestamptz)",
		`ORDER BY created_at ASC, id ASC`,
		`created_at > $`,
		`id > $`,
		`COLLATE "C"`,
		fmt.Sprintf("LIMIT $%d", len(args)),
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("traversal query is missing %q:\n%s", want, query)
		}
	}
	if got := args[len(args)-1]; got != limit+1 {
		t.Fatalf("final argument = %v, want limit+1 = %d", got, limit+1)
	}
}
