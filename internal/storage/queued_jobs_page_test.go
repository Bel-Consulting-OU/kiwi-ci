package storage

// Unit tests for the bounded queued-candidate page contract on the in-memory
// store (QueuedJobPageStore). They mirror the SQL page's contract: aged
// priority (priority + wait/10min) DESC, created_at ASC, id ASC; strict
// keyset semantics with no duplicates or gaps across pages; the persisted
// queue_deadline pushdown (a legacy payload-only deadline is NOT filtered,
// exactly like the SQL page — the scheduler applies QueueDeadlineFor in Go);
// and the bounded limit normalization.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func queuedJobsPageMemoryStore(t *testing.T, jobs ...model.Job) *memStore {
	t.Helper()
	m := newMemStore()
	for _, j := range jobs {
		if err := m.InsertJob(context.Background(), j); err != nil {
			t.Fatalf("seed job %s: %v", j.ID, err)
		}
	}
	return m
}

func queuedJobsPageIDs(page QueuedJobPage) []string {
	ids := make([]string, 0, len(page.Jobs))
	for _, j := range page.Jobs {
		ids = append(ids, j.ID)
	}
	return ids
}

// TestQueuedJobsPageMemoryOrderingCursorAndLimits pins the memStore keyset
// contract: the aged order with the created_at/id tiebreaks, strictly-after
// cursor semantics, exact HasMore/Last, and the bounded default.
func TestQueuedJobsPageMemoryOrderingCursorAndLimits(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	mk := func(id string, priority int, age time.Duration) model.Job {
		return model.Job{ID: id, RunID: "run-1", Key: id, Status: model.StatusQueued, Priority: priority, CreatedAt: now.Add(-age)}
	}
	m := queuedJobsPageMemoryStore(t,
		mk("a", 0, 25*time.Minute), // aged 0+2 = 2
		mk("b", 5, 5*time.Minute),  // aged 5+0 = 5
		mk("c", 5, 25*time.Minute), // aged 5+2 = 7
		mk("d", 7, 70*time.Minute), // aged 7+7 = 14, oldest of the 14s
		mk("e", 14, 0),             // aged 14
		mk("f", 14, time.Second),   // aged 14, created just before e
		mk("g", 3, 10*time.Minute), // aged 3+1 = 4
		model.Job{ID: "h", RunID: "run-1", Key: "h", Status: model.StatusRunning, Priority: 99, CreatedAt: now},
	)
	// Aged DESC, created_at ASC: d (14, -70m), f (14, -1s), e (14, 0), then
	// c (7), b (5), g (4), a (2). The running job is never a candidate.
	want := []string{"d", "f", "e", "c", "b", "g", "a"}

	// limit <= 0 selects the default: everything fits, no more data.
	all, err := m.ListQueuedJobsPage(ctx, QueuedJobFilter{}, nil, 0, now)
	if err != nil {
		t.Fatalf("ListQueuedJobsPage(default): %v", err)
	}
	if got := strings.Join(queuedJobsPageIDs(all), ","); got != strings.Join(want, ",") {
		t.Fatalf("default page = %v, want %v", got, want)
	}
	if all.HasMore {
		t.Fatal("default page reported HasMore with the whole queue in it")
	}
	last := all.Jobs[len(all.Jobs)-1]
	if all.Last.ID != last.ID || !all.Last.CreatedAt.Equal(last.CreatedAt) || all.Last.AgedPriority != queuedJobAgedPriority(last, now) {
		t.Fatalf("default page Last = %+v, want cursor of %s", all.Last, last.ID)
	}

	// Walk the whole queue with limit 3: no duplicates, no gaps, exact
	// HasMore/Last on every boundary.
	var seen []string
	var after *QueuedJobCursor
	pages := 0
	for {
		page, err := m.ListQueuedJobsPage(ctx, QueuedJobFilter{}, after, 3, now)
		if err != nil {
			t.Fatalf("page %d: %v", pages+1, err)
		}
		pages++
		got := queuedJobsPageIDs(page)
		seen = append(seen, got...)
		if page.HasMore {
			if len(page.Jobs) != 3 {
				t.Fatalf("page %d HasMore with %d jobs", pages, len(page.Jobs))
			}
			pageLast := page.Jobs[len(page.Jobs)-1]
			if page.Last.ID != pageLast.ID || page.Last.AgedPriority != queuedJobAgedPriority(pageLast, now) || !page.Last.CreatedAt.Equal(pageLast.CreatedAt) {
				t.Fatalf("page %d Last = %+v, want cursor of %s", pages, page.Last, pageLast.ID)
			}
			cursor := page.Last
			after = &cursor
			continue
		}
		if page.Jobs[len(page.Jobs)-1].ID != want[len(want)-1] {
			t.Fatalf("last page ends at %s, want %s", page.Jobs[len(page.Jobs)-1].ID, want[len(want)-1])
		}
		break
	}
	if pages != 3 {
		t.Fatalf("walk pages = %d, want 3", pages)
	}
	if got := strings.Join(seen, ","); got != strings.Join(want, ",") {
		t.Fatalf("walk = %v, want %v (no duplicates, no gaps)", got, want)
	}
}

// TestQueuedJobsPageNormalizeLimit pins the shared bound: non-positive maps
// to the default, above-cap clamps to the maximum.
func TestQueuedJobsPageNormalizeLimit(t *testing.T) {
	cases := []struct{ in, want int }{
		{-5, QueuedJobPageDefaultLimit},
		{0, QueuedJobPageDefaultLimit},
		{1, 1},
		{QueuedJobPageDefaultLimit, QueuedJobPageDefaultLimit},
		{QueuedJobPageMaxLimit, QueuedJobPageMaxLimit},
		{QueuedJobPageMaxLimit + 1, QueuedJobPageMaxLimit},
	}
	for _, tc := range cases {
		if got := NormalizeQueuedJobPageLimit(tc.in); got != tc.want {
			t.Fatalf("NormalizeQueuedJobPageLimit(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestQueuedJobsPageMemoryDeadlinePushdown proves the memStore page applies
// the same persisted-deadline filter as the SQL page: a row whose
// queue_deadline COLUMN elapsed is excluded while a future or absent column
// is included, and a legacy payload-only deadline (column NULL) is NOT
// filtered — the scheduler's Go gate handles that case.
func TestQueuedJobsPageMemoryDeadlinePushdown(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC)
	past := now.Add(-time.Minute)
	future := now.Add(time.Hour)
	payloadPast := model.Job{
		ID: "payload-past", RunID: "run-1", Key: "payload-past", Status: model.StatusQueued,
		CreatedAt: now.Add(-time.Hour),
		CompiledJobPayload: &model.CompiledJobPayload{
			SchemaVersion: 1,
			EffectiveJob:  []byte(`{"job":{"queue_timeout":"5m"}}`),
		},
	}
	m := queuedJobsPageMemoryStore(t,
		model.Job{ID: "past", RunID: "run-1", Key: "past", Status: model.StatusQueued, CreatedAt: now.Add(-3 * time.Minute), QueueDeadline: &past},
		model.Job{ID: "future", RunID: "run-1", Key: "future", Status: model.StatusQueued, CreatedAt: now.Add(-2 * time.Minute), QueueDeadline: &future},
		model.Job{ID: "none", RunID: "run-1", Key: "none", Status: model.StatusQueued, CreatedAt: now.Add(-time.Minute)},
		payloadPast,
	)
	page, err := m.ListQueuedJobsPage(ctx, QueuedJobFilter{}, nil, 10, now)
	if err != nil {
		t.Fatalf("ListQueuedJobsPage: %v", err)
	}
	got := queuedJobsPageIDs(page)
	seen := map[string]bool{}
	for _, id := range got {
		if seen[id] {
			t.Fatalf("duplicate %s in page %v", id, got)
		}
		seen[id] = true
	}
	if seen["past"] {
		t.Fatalf("page = %v, elapsed persisted deadline must be excluded", got)
	}
	if !seen["future"] || !seen["none"] || !seen["payload-past"] {
		t.Fatalf("page = %v, want future/none/payload-past", got)
	}
	if want := QueueDeadlineFor(payloadPast); want == nil || want.After(now) {
		t.Fatal("fixture bug: payload deadline must be elapsed")
	}
}

// TestQueuedJobsPageFaultyStoreDelegation proves the wrapper delegates the
// read without consuming the mutation-fault counter and fails closed with a
// diagnosable error when the inner store lacks the capability.
func TestQueuedJobsPageFaultyStoreDelegation(t *testing.T) {
	now := time.Date(2026, 7, 8, 9, 10, 11, 0, time.UTC)
	m := queuedJobsPageMemoryStore(t,
		model.Job{ID: "a", RunID: "run-1", Key: "a", Status: model.StatusQueued, CreatedAt: now},
		model.Job{ID: "b", RunID: "run-1", Key: "b", Status: model.StatusQueued, CreatedAt: now},
	)
	fault := &FaultyStore{Inner: m, FailAfter: 1, Err: ErrNotFound}
	ctx := context.Background()
	page, err := fault.ListQueuedJobsPage(ctx, QueuedJobFilter{}, nil, 1, now)
	if err != nil {
		t.Fatalf("ListQueuedJobsPage through FaultyStore: %v", err)
	}
	if ids := queuedJobsPageIDs(page); len(ids) != 1 || !page.HasMore {
		t.Fatalf("delegated page = %v (hasMore=%v)", ids, page.HasMore)
	}
	if fault.Mutations() != 0 {
		t.Fatalf("read consumed %d write fault(s)", fault.Mutations())
	}
	missing := &FaultyStore{Inner: storeOnlyInner{}}
	if _, err := missing.ListQueuedJobsPage(ctx, QueuedJobFilter{}, nil, 1, now); err == nil || !strings.Contains(err.Error(), "QueuedJobPageStore") {
		t.Fatalf("missing inner capability = %v, want QueuedJobPageStore error", err)
	}
}
