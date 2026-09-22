package storage

// Real-PostgreSQL integration tests for the single-record snapshot lookup and
// the keyset-paginated per-run snapshot collection. Gated on
// KIWI_TEST_POSTGRES_URL exactly like the other storage integration tests
// (each test owns a throwaway schema).

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITSnapshotRecord builds one snapshot record with a manifest entry, a
// microsecond-truncated instant (the SQL column precision) and a stable id.
func pgITSnapshotRecord(t *testing.T, runID string, id string, at time.Time) model.SnapshotRecord {
	t.Helper()
	digest := strings.Repeat("a", 64)
	return model.SnapshotRecord{
		ID:         id,
		RunID:      runID,
		JobID:      pgITNewID(t),
		JobKey:     "build",
		Path:       "cas:" + digest,
		Size:       42,
		SHA256:     digest,
		Version:    1,
		RootSHA256: strings.Repeat("b", 64),
		Entries: []model.SnapshotEntry{
			{Path: "private/service-account.json", Mode: 0o600, Size: 42, SHA256: strings.Repeat("c", 64)},
		},
		CreatedAt: at,
	}
}

func pgITSnapshotInsert(t *testing.T, st *PostgresStore, recs ...model.SnapshotRecord) {
	t.Helper()
	for _, rec := range recs {
		if err := st.InsertSnapshotRecord(context.Background(), rec); err != nil {
			t.Fatalf("InsertSnapshotRecord(%s): %v", rec.ID, err)
		}
	}
}

// TestIntegrationSnapshotGetSnapshotPointLookup drives the new
// SnapshotStore.GetSnapshot contract against a live database: the exact
// (run_id, id) pair resolves with its manifest, a missing id and a record of
// another run are reported missing, and a malformed id is a not-found (the
// historical 404 for the download route) rather than an internal error.
func TestIntegrationSnapshotGetSnapshotPointLookup(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Microsecond)
	runA, runB := pgITNewID(t), pgITNewID(t)
	recA1 := pgITSnapshotRecord(t, runA, pgITNewID(t), base)
	recA2 := pgITSnapshotRecord(t, runA, pgITNewID(t), base.Add(time.Second))
	recB1 := pgITSnapshotRecord(t, runB, pgITNewID(t), base)
	pgITSnapshotInsert(t, st, recA1, recA2, recB1)

	got, ok, err := st.GetSnapshot(ctx, runA, recA1.ID)
	if err != nil || !ok {
		t.Fatalf("GetSnapshot(%s, %s) = %+v ok=%v err=%v", runA, recA1.ID, got, ok, err)
	}
	if got.ID != recA1.ID || got.RunID != runA || got.JobKey != "build" || got.Size != recA1.Size ||
		got.SHA256 != recA1.SHA256 || got.RootSHA256 != recA1.RootSHA256 || len(got.Entries) != 1 ||
		got.Entries[0].Path != "private/service-account.json" {
		t.Fatalf("GetSnapshot decoded %+v, want %+v", got, recA1)
	}

	if _, ok, err := st.GetSnapshot(ctx, runA, pgITNewID(t)); err != nil || ok {
		t.Fatalf("unknown id ok=%v err=%v, want missing", ok, err)
	}
	// The lookup is scoped by run_id: another run's record never resolves.
	if _, ok, err := st.GetSnapshot(ctx, runA, recB1.ID); err != nil || ok {
		t.Fatalf("cross-run id ok=%v err=%v, want missing", ok, err)
	}
	if _, ok, err := st.GetSnapshot(ctx, runB, recB1.ID); err != nil || !ok {
		t.Fatalf("other run's own record ok=%v err=%v, want found", ok, err)
	}
	// A malformed id can never match a row; it must be a missing record, not
	// an error the download would surface as 500.
	if _, ok, err := st.GetSnapshot(ctx, runA, "not-an-id"); err != nil || ok {
		t.Fatalf("malformed id ok=%v err=%v, want missing without error", ok, err)
	}
}

// TestIntegrationSnapshotPageKeysetWalk drives ListSnapshotsPage against a
// live database: bounded pages in exact (created_at, id) order with no
// duplicate and no omission across the page boundaries, an exact HasMore,
// run scoping and the limit clamp.
func TestIntegrationSnapshotPageKeysetWalk(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Microsecond)
	runA, runB := pgITNewID(t), pgITNewID(t)

	// The expected key order is derived from the same (created_at, id) sort
	// the store must apply, including two created_at ties broken by id.
	type seed struct {
		id string
		at time.Time
	}
	const total = 25
	seeds := make([]seed, 0, total+2)
	for i := 0; i < total; i++ {
		seeds = append(seeds, seed{fmt.Sprintf("%032x", i+1), base.Add(time.Duration(i) * time.Second)})
	}
	seeds = append(seeds, seed{fmt.Sprintf("%032x", 0), base})                          // ties with id 1
	seeds = append(seeds, seed{fmt.Sprintf("%032x", 0xff), base.Add(10 * time.Second)}) // ties with id 11
	sort.Slice(seeds, func(i, j int) bool {
		if !seeds[i].at.Equal(seeds[j].at) {
			return seeds[i].at.Before(seeds[j].at)
		}
		return seeds[i].id < seeds[j].id
	})
	want := make([]string, 0, len(seeds))
	recs := make([]model.SnapshotRecord, 0, len(seeds))
	for _, s := range seeds {
		want = append(want, s.id)
		recs = append(recs, pgITSnapshotRecord(t, runA, s.id, s.at))
	}
	pgITSnapshotInsert(t, st, recs...)
	// Another run's record must never appear in runA's pages.
	pgITSnapshotInsert(t, st, pgITSnapshotRecord(t, runB, pgITNewID(t), base))

	const pageSize = 7
	var walk []string
	var cursor SnapshotPage
	pages := 0
	for {
		pages++
		if pages > 10 {
			t.Fatalf("page walk did not terminate")
		}
		page, err := st.ListSnapshotsPage(ctx, runA, cursor.NextCreatedAt, cursor.NextID, pageSize)
		if err != nil {
			t.Fatalf("ListSnapshotsPage page %d: %v", pages, err)
		}
		if len(page.Snapshots) > pageSize {
			t.Fatalf("page %d returned %d records, over the limit %d", pages, len(page.Snapshots), pageSize)
		}
		for _, rec := range page.Snapshots {
			if rec.RunID != runA {
				t.Fatalf("page leaked run %s", rec.RunID)
			}
			walk = append(walk, rec.ID)
		}
		if !page.HasMore {
			break
		}
		cursor = page
	}
	if len(walk) != len(want) {
		t.Fatalf("walk covered %d records, want %d", len(walk), len(want))
	}
	seen := map[string]bool{}
	for i, id := range walk {
		if id != want[i] {
			t.Fatalf("walk[%d] = %s, want %s", i, id, want[i])
		}
		if seen[id] {
			t.Fatalf("duplicate %s in the walk", id)
		}
		seen[id] = true
	}

	// A single oversized page is clamped to the hard cap.
	clamped, err := st.ListSnapshotsPage(ctx, runA, time.Time{}, "", MaxSnapshotPageLimit+1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(clamped.Snapshots) != len(want) || clamped.HasMore {
		t.Fatalf("clamped page = %d records hasMore=%v, want %d/false", len(clamped.Snapshots), clamped.HasMore, len(want))
	}

	// A run with no records is a terminal empty page.
	empty, err := st.ListSnapshotsPage(ctx, pgITNewID(t), time.Time{}, "", pageSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.Snapshots) != 0 || empty.HasMore {
		t.Fatalf("empty run page = %+v", empty)
	}
}

// TestIntegrationSnapshotPageCursorRoundTrip proves the page records carry
// the stored created_at column value, so feeding the last record back as the
// cursor neither repeats nor skips it even when the payload instant has
// sub-microsecond precision.
func TestIntegrationSnapshotPageCursorRoundTrip(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	base := time.Now().UTC().Add(-time.Minute) // nonzero, sub-microsecond component
	recs := []model.SnapshotRecord{
		pgITSnapshotRecord(t, runID, fmt.Sprintf("%032x", 1), base),
		pgITSnapshotRecord(t, runID, fmt.Sprintf("%032x", 2), base.Add(time.Millisecond)),
	}
	pgITSnapshotInsert(t, st, recs...)

	page, err := st.ListSnapshotsPage(ctx, runID, time.Time{}, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Snapshots) != 1 || !page.HasMore {
		t.Fatalf("first page = %+v", page)
	}
	next, err := st.ListSnapshotsPage(ctx, runID, page.NextCreatedAt, page.NextID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Snapshots) != 1 || next.Snapshots[0].ID != fmt.Sprintf("%032x", 2) || next.HasMore {
		t.Fatalf("continuation page = %+v", next.Snapshots)
	}
}
