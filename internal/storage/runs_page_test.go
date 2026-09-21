package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// runsPageMemorySeed builds n runs whose ids and timestamps sort the same
// way: run i has created_at base+i*step and id run-<i>, so the newest-first
// order is run-(n-1) ... run-0.
func runsPageMemorySeed(n int, base time.Time, step time.Duration) []model.Run {
	runs := make([]model.Run, 0, n)
	for i := 0; i < n; i++ {
		runs = append(runs, model.Run{
			ID:        fmt.Sprintf("run-%04d", i),
			Status:    model.StatusSuccess,
			CreatedAt: base.Add(time.Duration(i) * step),
		})
	}
	return runs
}

func runsPageMemoryStore(t *testing.T, runs []model.Run) *memStore {
	t.Helper()
	m := newMemStore()
	for _, run := range runs {
		if err := m.InsertRun(context.Background(), run); err != nil {
			t.Fatalf("seed run %s: %v", run.ID, err)
		}
	}
	return m
}

func runsPageIDs(page RunPage) []string {
	ids := make([]string, 0, len(page.Runs))
	for _, run := range page.Runs {
		ids = append(ids, run.ID)
	}
	return ids
}

// TestRunsPageMemoryOrderingCursorAndLimits pins the memStore keyset
// contract: newest-first (created_at DESC, id DESC with the id tiebreak),
// strictly-older cursor semantics, exact HasMore/next position, and the
// bounded default.
func TestRunsPageMemoryOrderingCursorAndLimits(t *testing.T) {
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	runs := runsPageMemorySeed(7, base, time.Second)
	// Give runs 3 and 4 the same instant so the id tiebreak decides (4 first).
	runs[4].CreatedAt = runs[3].CreatedAt
	m := runsPageMemoryStore(t, runs)
	ctx := context.Background()

	// limit <= 0 selects the default (here: fewer rows than the limit).
	all, err := m.ListRunsPage(ctx, time.Time{}, "", 0)
	if err != nil {
		t.Fatalf("ListRunsPage(default): %v", err)
	}
	wantAll := []string{"run-0006", "run-0005", "run-0004", "run-0003", "run-0002", "run-0001", "run-0000"}
	if got := runsPageIDs(all); strings.Join(got, ",") != strings.Join(wantAll, ",") {
		t.Fatalf("default page = %v, want %v", got, wantAll)
	}
	if all.HasMore || all.NextID != "" || !all.NextCreatedAt.IsZero() {
		t.Fatalf("default page HasMore=%v next=(%v,%q), want terminal", all.HasMore, all.NextCreatedAt, all.NextID)
	}

	page1, err := m.ListRunsPage(ctx, time.Time{}, "", 3)
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if got := runsPageIDs(page1); strings.Join(got, ",") != "run-0006,run-0005,run-0004" {
		t.Fatalf("page1 = %v", got)
	}
	if !page1.HasMore || page1.NextID != "run-0004" || !page1.NextCreatedAt.Equal(runs[3].CreatedAt) {
		t.Fatalf("page1 boundary = HasMore %v next (%v,%q)", page1.HasMore, page1.NextCreatedAt, page1.NextID)
	}

	page2, err := m.ListRunsPage(ctx, page1.NextCreatedAt, page1.NextID, 3)
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if got := runsPageIDs(page2); strings.Join(got, ",") != "run-0003,run-0002,run-0001" {
		t.Fatalf("page2 = %v", got)
	}

	page3, err := m.ListRunsPage(ctx, page2.NextCreatedAt, page2.NextID, 3)
	if err != nil {
		t.Fatalf("page3: %v", err)
	}
	if got := runsPageIDs(page3); strings.Join(got, ",") != "run-0000" {
		t.Fatalf("page3 = %v", got)
	}
	if page3.HasMore || page3.NextID != "" {
		t.Fatalf("last page HasMore=%v next=%q, want terminal", page3.HasMore, page3.NextID)
	}

	// The keyset predicate is strict on both columns.
	tiebreak := runs[3] // run-0003, the id-tiebreak predecessor of run-0004
	if !RunOlderThan(tiebreak, page1.NextCreatedAt, page1.NextID) {
		t.Fatal("id-smaller run at the cursor instant must be older")
	}
	if RunOlderThan(runs[4], page1.NextCreatedAt, page1.NextID) {
		t.Fatal("the cursor row itself must not be returned again")
	}
}

// TestRunsPageMemoryInsertBetweenPages proves inserts between page reads can
// neither duplicate nor skip rows: a newer insert is simply not part of the
// ongoing walk (and starts a fresh first page), while an older insert shows
// up on a later page of the walk.
func TestRunsPageMemoryInsertBetweenPages(t *testing.T) {
	base := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	m := runsPageMemoryStore(t, runsPageMemorySeed(6, base, time.Second))
	ctx := context.Background()

	page1, err := m.ListRunsPage(ctx, time.Time{}, "", 2)
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if got := runsPageIDs(page1); strings.Join(got, ",") != "run-0005,run-0004" {
		t.Fatalf("page1 = %v", got)
	}

	newest := model.Run{ID: "run-9999", Status: model.StatusSuccess, CreatedAt: base.Add(time.Hour)}
	oldest := model.Run{ID: "run-old", Status: model.StatusSuccess, CreatedAt: base.Add(-time.Second)}
	for _, run := range []model.Run{newest, oldest} {
		if err := m.InsertRun(ctx, run); err != nil {
			t.Fatalf("insert %s: %v", run.ID, err)
		}
	}

	seen := append([]string{}, runsPageIDs(page1)...)
	page, cursorAt, cursorID := page1, page1.NextCreatedAt, page1.NextID
	for page.HasMore {
		page, err = m.ListRunsPage(ctx, cursorAt, cursorID, 2)
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
		seen = append(seen, runsPageIDs(page)...)
		cursorAt, cursorID = page.NextCreatedAt, page.NextID
	}
	want := []string{"run-0005", "run-0004", "run-0003", "run-0002", "run-0001", "run-0000", "run-old"}
	if strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Fatalf("walk = %v, want %v", seen, want)
	}

	// A fresh first page starts at the newest insert: keyset stability is
	// about the ongoing walk, never about hiding new data.
	fresh, err := m.ListRunsPage(ctx, time.Time{}, "", 1)
	if err != nil {
		t.Fatalf("fresh page: %v", err)
	}
	if got := runsPageIDs(fresh); len(got) != 1 || got[0] != "run-9999" {
		t.Fatalf("fresh first page = %v, want run-9999", got)
	}
}

// TestRunsPageNormalizeLimit pins the shared bound used by the store and the
// HTTP handler.
func TestRunsPageNormalizeLimit(t *testing.T) {
	cases := []struct{ in, want int }{
		{-5, DefaultRunsPageLimit},
		{0, DefaultRunsPageLimit},
		{1, 1},
		{DefaultRunsPageLimit, DefaultRunsPageLimit},
		{MaxRunsPageLimit, MaxRunsPageLimit},
		{MaxRunsPageLimit + 1, MaxRunsPageLimit},
	}
	for _, tc := range cases {
		if got := NormalizeRunsPageLimit(tc.in); got != tc.want {
			t.Fatalf("NormalizeRunsPageLimit(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestRunsPageFaultyStoreDelegation proves the wrapper delegates the read
// (without consuming the mutation-fault counter) when Inner supports the
// capability, and fails closed with a diagnosable error when it does not.
func TestRunsPageFaultyStoreDelegation(t *testing.T) {
	base := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	m := runsPageMemoryStore(t, runsPageMemorySeed(4, base, time.Second))
	fault := &FaultyStore{Inner: m, FailAfter: 1, Err: errors.New("write fault")}
	ctx := context.Background()

	page, err := fault.ListRunsPage(ctx, time.Time{}, "", 2)
	if err != nil {
		t.Fatalf("ListRunsPage through FaultyStore: %v", err)
	}
	if got := runsPageIDs(page); strings.Join(got, ",") != "run-0003,run-0002" || !page.HasMore {
		t.Fatalf("delegated page = %v (hasMore=%v)", got, page.HasMore)
	}
	if fault.Mutations() != 0 {
		t.Fatalf("read consumed %d write fault(s)", fault.Mutations())
	}
	if err := fault.InsertRun(ctx, model.Run{ID: "run-new"}); err == nil || !strings.Contains(err.Error(), "write fault") {
		t.Fatalf("armed fault did not fire on the next write: %v", err)
	}

	missing := &FaultyStore{Inner: storeOnlyInner{}}
	if _, err := missing.ListRunsPage(ctx, time.Time{}, "", 2); err == nil || !strings.Contains(err.Error(), "RunPageStore") {
		t.Fatalf("missing inner capability = %v, want RunPageStore error", err)
	}
}
