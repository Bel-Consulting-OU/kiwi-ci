package storage

// Unit tests for the single-record snapshot lookup and the keyset page
// contract (postgres_snapshot_get.go): the in-memory mirror's GetSnapshot and
// ListSnapshotsPage, plus the shared PageSnapshots definition every
// implementation (memory, SQL and test doubles) must agree on. The live
// PostgreSQL counterparts live in postgres_snapshot_get_it_test.go.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const (
	snapGetRunID = "11111111111111111111111111111111"
	snapGetOther = "22222222222222222222222222222222"
)

// snapGetID returns the i-th 32-hex snapshot id.
func snapGetID(i int) string { return fmt.Sprintf("%032x", i+1) }

// snapGetRecord builds one record of runID with a stable id and instant.
func snapGetRecord(runID string, i int, base time.Time) model.SnapshotRecord {
	return model.SnapshotRecord{
		ID:         snapGetID(i),
		RunID:      runID,
		JobID:      snapGetID(i),
		Size:       int64(i + 1),
		SHA256:     fmt.Sprintf("%064d", i),
		RootSHA256: fmt.Sprintf("root-%d", i),
		Version:    1,
		Entries: []model.SnapshotEntry{
			{Path: fmt.Sprintf("private/file-%d", i), Mode: 0o600, Size: int64(i), SHA256: fmt.Sprintf("%064d", i)},
		},
		CreatedAt: base.Add(time.Duration(i) * time.Second),
	}
}

// TestMemStoreGetSnapshotPointLookup pins the in-memory SnapshotStore
// contract: the exact (run_id, id) pair resolves, and a missing id or a
// record of another run is reported as missing.
func TestMemStoreGetSnapshotPointLookup(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Microsecond)
	rec := snapGetRecord(snapGetRunID, 0, base)
	if err := m.InsertSnapshotRecord(ctx, rec); err != nil {
		t.Fatal(err)
	}
	other := snapGetRecord(snapGetOther, 1, base)
	if err := m.InsertSnapshotRecord(ctx, other); err != nil {
		t.Fatal(err)
	}

	got, ok, err := m.GetSnapshot(ctx, snapGetRunID, rec.ID)
	if err != nil || !ok {
		t.Fatalf("GetSnapshot = %+v ok=%v err=%v", got, ok, err)
	}
	if got.ID != rec.ID || got.RunID != snapGetRunID || len(got.Entries) != 1 {
		t.Fatalf("GetSnapshot returned %+v", got)
	}
	if _, ok, err := m.GetSnapshot(ctx, snapGetRunID, snapGetID(9)); err != nil || ok {
		t.Fatalf("unknown id ok=%v err=%v, want missing", ok, err)
	}
	// A cross-run id must never resolve: the lookup is scoped by run_id.
	if _, ok, err := m.GetSnapshot(ctx, snapGetRunID, other.ID); err != nil || ok {
		t.Fatalf("cross-run id ok=%v err=%v, want missing", ok, err)
	}
}

// TestMemStoreListSnapshotsPageKeyset pins the in-memory paged read against
// the shared keyset contract: bounded pages, exact HasMore, run scoping and
// the zero-cursor start.
func TestMemStoreListSnapshotsPageKeyset(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Microsecond)
	const total = 5
	for i := 0; i < total; i++ {
		if err := m.InsertSnapshotRecord(ctx, snapGetRecord(snapGetRunID, i, base)); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.InsertSnapshotRecord(ctx, snapGetRecord(snapGetOther, 0, base)); err != nil {
		t.Fatal(err)
	}

	page, err := m.ListSnapshotsPage(ctx, snapGetRunID, time.Time{}, "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Snapshots) != 2 || !page.HasMore || page.NextID != snapGetID(1) || !page.NextCreatedAt.Equal(base.Add(time.Second)) {
		t.Fatalf("first page = %+v", page)
	}
	if page.Snapshots[0].ID != snapGetID(0) || page.Snapshots[1].ID != snapGetID(1) {
		t.Fatalf("first page order = %+v", page.Snapshots)
	}
	next, err := m.ListSnapshotsPage(ctx, snapGetRunID, page.NextCreatedAt, page.NextID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Snapshots) != total-2 || next.HasMore {
		t.Fatalf("second page = %+v", next)
	}
	for i, rec := range next.Snapshots {
		if rec.ID != snapGetID(i+2) {
			t.Fatalf("second page[%d] = %s, want %s", i, rec.ID, snapGetID(i+2))
		}
	}
	other, err := m.ListSnapshotsPage(ctx, snapGetOther, time.Time{}, "", 10)
	if err != nil || other.HasMore || len(other.Snapshots) != 1 || other.Snapshots[0].RunID != snapGetOther {
		t.Fatalf("other run page = %+v err=%v", other, err)
	}
}

// TestPageSnapshotsContract pins the shared keyset definition: the zero
// cursor starts at the oldest record, the cursor excludes everything at or
// before it, the limit is clamped, and records of other runs are dropped.
func TestPageSnapshotsContract(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Microsecond)
	recs := []model.SnapshotRecord{
		snapGetRecord(snapGetRunID, 3, base),
		snapGetRecord(snapGetOther, 0, base),
		snapGetRecord(snapGetRunID, 0, base),
		snapGetRecord(snapGetRunID, 2, base),
		snapGetRecord(snapGetRunID, 1, base),
	}

	page := PageSnapshots(recs, snapGetRunID, time.Time{}, "", 0)
	if len(page.Snapshots) != 4 || page.HasMore {
		t.Fatalf("zero-cursor page = %d records hasMore=%v", len(page.Snapshots), page.HasMore)
	}
	for i, rec := range page.Snapshots {
		if rec.ID != snapGetID(i) {
			t.Fatalf("page[%d] = %s, want %s (oldest first)", i, rec.ID, snapGetID(i))
		}
	}

	clamped := PageSnapshots(recs, snapGetRunID, time.Time{}, "", MaxSnapshotPageLimit+1)
	if len(clamped.Snapshots) != 4 || clamped.HasMore {
		t.Fatalf("clamped page = %d records hasMore=%v", len(clamped.Snapshots), clamped.HasMore)
	}

	mid := PageSnapshots(recs, snapGetRunID, base.Add(time.Second), snapGetID(1), 10)
	if len(mid.Snapshots) != 2 || mid.Snapshots[0].ID != snapGetID(2) {
		t.Fatalf("cursor page = %+v", mid.Snapshots)
	}

	first := PageSnapshots(recs, snapGetRunID, time.Time{}, "", 2)
	if len(first.Snapshots) != 2 || !first.HasMore || first.NextID != snapGetID(1) {
		t.Fatalf("first page = %+v", first)
	}
}

// TestSnapshotAfterCursorOrder proves the cursor comparison is the exact
// in-memory equivalent of the SQL row-value predicate, including the
// created_at tie broken by id (byte order).
func TestSnapshotAfterCursorOrder(t *testing.T) {
	instant := time.Now().UTC()
	cursor := model.SnapshotRecord{ID: "b", CreatedAt: instant}
	cases := []struct {
		rec  model.SnapshotRecord
		want bool
	}{
		{model.SnapshotRecord{ID: "a", CreatedAt: instant.Add(-time.Second)}, false},
		{model.SnapshotRecord{ID: "a", CreatedAt: instant}, false},
		{model.SnapshotRecord{ID: "b", CreatedAt: instant}, false},
		{model.SnapshotRecord{ID: "c", CreatedAt: instant}, true},
		{model.SnapshotRecord{ID: "a", CreatedAt: instant.Add(time.Second)}, true},
	}
	for _, tc := range cases {
		if got := SnapshotAfterCursor(tc.rec, cursor.CreatedAt, cursor.ID); got != tc.want {
			t.Fatalf("SnapshotAfterCursor(%+v) = %v, want %v", tc.rec, got, tc.want)
		}
	}
	if !SnapshotAfterCursor(model.SnapshotRecord{ID: "x"}, time.Time{}, "") {
		t.Fatal("the zero cursor must match every record")
	}
}
