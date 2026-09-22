package storage

// Single-record lookup and keyset pagination for the workspace snapshot
// record collection.
//
// The archive DOWNLOAD used to resolve one snapshot by listing every record
// of the run (ListSnapshotsByRun) and scanning the slice for the id: O(records
// per run) rows read and decoded for a request that needs exactly one. The
// per-run LISTING used to return every record -- manifests included -- in one
// unbounded response. This file owns the two bounded contracts that replace
// them:
//
//   - GetSnapshot (part of SnapshotStore) resolves one record through a
//     (run_id, id) lookup: the workspace_snapshots primary key on id is the
//     point of access, and the run_id predicate keeps the record scoped to
//     the addressed run, so a cross-run id can never be served.
//
//   - SnapshotPageStore is the optional paged-read capability, mirroring
//     RunPageStore: a store that wants to serve the collection asserts it,
//     and a caller that needs paging fails closed without it (see the
//     server's listSnapshots) instead of silently truncating the walk.
//
// Ordering (both implementations): created_at ASC, id ASC -- exactly the
// order PostgresStore.ListSnapshotsByRun has always returned, so a first page
// without a cursor is the same oldest-first window as before. id breaks
// created_at ties, making the order total and stable; the SQL side pins id to
// COLLATE "C" so its comparison is Go's byte order (see ListSnapshotsPage).
//
// Cursor semantics: afterCreatedAt/afterID identify the LAST record of the
// previous page, and a page contains only rows strictly after that position,
// i.e. WHERE (created_at, id) > (afterCreatedAt, afterID). The zero cursor
// starts at the oldest record. SnapshotPage.HasMore reports whether any row
// exists past the page, and NextCreatedAt/NextID carry the last returned
// record's position, so a caller emits a next cursor exactly while more data
// exists and omits it on the last page.
//
// limit is bounded: limit <= 0 selects DefaultSnapshotPageLimit, and
// anything above MaxSnapshotPageLimit is clamped to it. Implementations
// fetch limit+1 rows internally so HasMore is exact.

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const (
	// DefaultSnapshotPageLimit is the page size used when a caller passes
	// no limit. Snapshot archives are per-run and small in number, so the
	// default page is deliberately modest.
	DefaultSnapshotPageLimit = 100
	// MaxSnapshotPageLimit is the hard upper bound on one page of snapshot
	// records: a response can never carry more than this many manifests.
	MaxSnapshotPageLimit = 1000
)

// SnapshotPage is one keyset page of snapshot records. Snapshots is ordered
// oldest-first (created_at ASC, id ASC) and is never nil. HasMore reports
// whether at least one record exists strictly after the last returned
// record; NextCreatedAt/NextID are that last record's (created_at, id)
// position and are valid exactly when HasMore is true, so a caller can emit
// the next cursor without re-reading the page slice.
type SnapshotPage struct {
	Snapshots     []model.SnapshotRecord
	NextCreatedAt time.Time
	NextID        string
	HasMore       bool
}

// SnapshotPageStore is the optional paged-read capability of a store. It is
// deliberately separate from SnapshotStore so minimal read-only wrappers and
// test doubles keep compiling; callers that need pagination assert this
// interface and fail closed when it is missing (see the server's
// listSnapshots): an unbounded ListSnapshotsByRun window cannot honor an
// older cursor, so it is never a fallback.
type SnapshotPageStore interface {
	// ListSnapshotsPage returns the page of records of runID strictly after
	// the cursor position, oldest-first. See the file comment for the full
	// cursor, ordering and limit contract.
	ListSnapshotsPage(ctx context.Context, runID string, afterCreatedAt time.Time, afterID string, limit int) (SnapshotPage, error)
}

// NormalizeSnapshotPageLimit applies the shared bound to a requested page
// size: non-positive selects DefaultSnapshotPageLimit, above-cap clamps to
// MaxSnapshotPageLimit.
func NormalizeSnapshotPageLimit(limit int) int {
	if limit <= 0 {
		return DefaultSnapshotPageLimit
	}
	if limit > MaxSnapshotPageLimit {
		return MaxSnapshotPageLimit
	}
	return limit
}

// SnapshotAfterCursor reports whether rec sorts strictly after the cursor
// position in the (created_at ASC, id ASC) keyset order: the in-memory
// equivalent of SQL's (created_at, id) > ($1, $2). The zero cursor matches
// every record.
func SnapshotAfterCursor(rec model.SnapshotRecord, afterCreatedAt time.Time, afterID string) bool {
	if afterCreatedAt.IsZero() && afterID == "" {
		return true
	}
	if rec.CreatedAt.After(afterCreatedAt) {
		return true
	}
	if rec.CreatedAt.Before(afterCreatedAt) {
		return false
	}
	return rec.ID > afterID
}

// SortSnapshotsOldestFirst orders records by created_at ASC, id ASC: the
// total order every SnapshotPageStore implementation returns.
func SortSnapshotsOldestFirst(recs []model.SnapshotRecord) {
	sort.Slice(recs, func(i, j int) bool {
		if !recs[i].CreatedAt.Equal(recs[j].CreatedAt) {
			return recs[i].CreatedAt.Before(recs[j].CreatedAt)
		}
		return recs[i].ID < recs[j].ID
	})
}

// PageSnapshots applies the keyset contract to an unordered in-memory record
// set: it keeps only the records of runID, drops every row at or before the
// cursor, sorts the rest oldest-first, and returns at most limit rows plus
// the exact HasMore and next position. It is the memory half of the contract,
// used by the server's memory mode (Server.listSnapshots) and by
// memStore.ListSnapshotsPage (the in-package in-memory SnapshotStore), plus
// package test doubles, so the memory and SQL pages share one definition.
func PageSnapshots(recs []model.SnapshotRecord, runID string, afterCreatedAt time.Time, afterID string, limit int) SnapshotPage {
	limit = NormalizeSnapshotPageLimit(limit)
	eligible := make([]model.SnapshotRecord, 0, len(recs))
	for _, rec := range recs {
		if rec.RunID != runID {
			continue
		}
		if SnapshotAfterCursor(rec, afterCreatedAt, afterID) {
			eligible = append(eligible, rec)
		}
	}
	SortSnapshotsOldestFirst(eligible)
	page := SnapshotPage{Snapshots: eligible}
	if len(eligible) > limit {
		page.Snapshots = eligible[:limit]
		page.HasMore = true
	}
	if page.HasMore {
		last := page.Snapshots[len(page.Snapshots)-1]
		page.NextCreatedAt = last.CreatedAt
		page.NextID = last.ID
	}
	return page
}

// GetSnapshot implements the single-record half of SnapshotStore for the
// durable store. One point read through the workspace_snapshots primary key,
// scoped by run_id: a record of another run is reported as not-found rather
// than returned, exactly like the previous list-and-scan contract, but
// without reading or decoding the run's other records. A malformed snapshot
// id can never match a stored row (ValidateID rejects it before SQL), so it
// is reported as not-found instead of an internal error, preserving the
// historical 404 for /runs/{id}/snapshots/{sid}.
func (s *PostgresStore) GetSnapshot(ctx context.Context, runID, snapshotID string) (model.SnapshotRecord, bool, error) {
	if err := ValidateRunID(runID); err != nil {
		return model.SnapshotRecord{}, false, err
	}
	if err := ValidateID(snapshotID); err != nil {
		return model.SnapshotRecord{}, false, nil
	}
	var payload []byte
	err := s.pool.QueryRow(ctx, `SELECT payload FROM workspace_snapshots WHERE run_id=$1 AND id=$2`, runID, snapshotID).Scan(&payload)
	if err == pgx.ErrNoRows {
		return model.SnapshotRecord{}, false, nil
	}
	if err != nil {
		return model.SnapshotRecord{}, false, err
	}
	var rec model.SnapshotRecord
	if err := json.Unmarshal(payload, &rec); err != nil {
		return model.SnapshotRecord{}, false, err
	}
	return rec, true, nil
}

// ListSnapshotsPage implements SnapshotPageStore for the durable store. One
// index-backed keyset read: ORDER BY created_at ASC, id COLLATE "C" ASC with
// the row-value cursor predicate and LIMIT limit+1 so HasMore is exact. The
// record payload is decoded through the same helper GetSnapshot uses, so a
// paged record decodes identically to a point-read one.
//
// Each returned record's CreatedAt is normalized to the stored created_at
// COLUMN value, not the payload's copy of it. timestamptz stores
// microseconds while the payload keeps the original Go instant: feeding a
// sub-microsecond payload timestamp back as a cursor would compare against
// the rounded column value and could duplicate or skip the boundary record.
// The column is the ordering key, so the column value is the record's
// position.
//
// id is compared with COLLATE "C" in both the ORDER BY and the cursor
// predicate: the byte order Go's string comparison uses in SnapshotAfterCursor,
// so the SQL and memory pages are identical regardless of the database's
// default collation (a text id can only be compared consistently across the
// two implementations when the collation is pinned).
func (s *PostgresStore) ListSnapshotsPage(ctx context.Context, runID string, afterCreatedAt time.Time, afterID string, limit int) (SnapshotPage, error) {
	if err := ValidateRunID(runID); err != nil {
		return SnapshotPage{}, err
	}
	limit = NormalizeSnapshotPageLimit(limit)
	args := []any{runID}
	where := ` WHERE run_id=$1`
	if !afterCreatedAt.IsZero() || afterID != "" {
		where += ` AND (created_at, id COLLATE "C") > ($2::timestamptz, $3::text COLLATE "C")`
		args = append(args, afterCreatedAt, afterID)
	}
	args = append(args, limit+1)
	rows, err := s.pool.Query(ctx,
		`SELECT created_at, payload FROM workspace_snapshots`+where+
			` ORDER BY created_at ASC, id COLLATE "C" ASC LIMIT $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return SnapshotPage{}, err
	}
	defer rows.Close()
	out := []model.SnapshotRecord{}
	for rows.Next() {
		var (
			createdAt time.Time
			payload   []byte
			rec       model.SnapshotRecord
		)
		if err := rows.Scan(&createdAt, &payload); err != nil {
			return SnapshotPage{}, err
		}
		if err := json.Unmarshal(payload, &rec); err != nil {
			return SnapshotPage{}, err
		}
		rec.CreatedAt = createdAt
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return SnapshotPage{}, err
	}
	page := SnapshotPage{Snapshots: out}
	if len(out) > limit {
		page.Snapshots = out[:limit]
		page.HasMore = true
	}
	if page.HasMore {
		last := page.Snapshots[len(page.Snapshots)-1]
		page.NextCreatedAt = last.CreatedAt
		page.NextID = last.ID
	}
	return page, nil
}

var _ SnapshotPageStore = (*PostgresStore)(nil)
var _ SnapshotStore = (*PostgresStore)(nil)
