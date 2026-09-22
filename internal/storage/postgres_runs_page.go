package storage

// Keyset pagination for the runs collection.
//
// GET /api/v1/runs used to be one ListRuns(1000) call with no pagination
// signal: with more than a page of runs, every older run silently vanished
// from the collection API and the UI. RunPageStore is the bounded,
// deterministic page contract that makes the whole collection reachable.
//
// Ordering (both implementations): created_at DESC, id DESC — exactly the
// order PostgresStore.ListRuns has always returned, so a first page without
// a cursor is the same newest-first window as before. id (runs.id, TEXT
// PRIMARY KEY) breaks created_at ties, making the order total and stable
// even for runs created in the same instant; the SQL side pins id to
// COLLATE "C" so its comparison is Go's byte order (see ListRunsPage).
//
// Cursor semantics: afterCreatedAt/afterID identify the LAST run of the
// previous page, and a page contains only rows strictly older in that order,
// i.e. WHERE (created_at, id) < (afterCreatedAt, afterID). The zero cursor
// (zero time, empty id) starts at the newest run. RunPage.HasMore reports
// whether any row exists past the page, and RunPage.NextCreatedAt/NextID
// carry the last returned run's position, so a caller emits a next cursor
// exactly while more data exists and omits it on the last page.
//
// Keyset — not OFFSET — means concurrent INSERTs can never shift a page
// boundary: a run created between two page reads is newer than the cursor
// and therefore simply not part of the remaining walk, and no row is ever
// returned twice or skipped.
//
// limit is bounded: limit <= 0 selects DefaultRunsPageLimit, and anything
// above MaxRunsPageLimit is clamped to it. Implementations fetch limit+1
// rows internally so HasMore is exact rather than inferred from a full page.

import (
	"context"
	"sort"
	"strconv"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const (
	// DefaultRunsPageLimit is the page size used when a caller passes no
	// limit. It preserves the collection's historical newest-1000 window.
	DefaultRunsPageLimit = 1000
	// MaxRunsPageLimit is the hard upper bound on one page: the same 10000
	// ceiling PostgresStore.ListRuns has always enforced.
	MaxRunsPageLimit = 10000
)

// RunPage is one keyset page of runs. Runs is ordered newest-first
// (created_at DESC, id DESC) and is never nil. HasMore reports whether at
// least one run exists strictly older than the last returned run;
// NextCreatedAt/NextID are that last run's (created_at, id) position and are
// valid exactly when HasMore is true, so a caller can emit the next cursor
// without re-reading the page slice.
type RunPage struct {
	Runs          []model.Run
	NextCreatedAt time.Time
	NextID        string
	HasMore       bool
}

// RunPageStore is the optional paged-read capability of a store. It is
// deliberately separate from Store so minimal read-only wrappers and test
// doubles keep compiling; callers that need pagination assert this interface
// and fail closed when it is missing (see listRunsPageFromStore): an
// unpaged ListRuns window cannot honor an older cursor, so it is never a
// fallback.
type RunPageStore interface {
	// ListRunsPage returns the page of runs strictly older than the cursor
	// position, newest-first. See the file comment for the full cursor,
	// ordering and limit contract.
	ListRunsPage(ctx context.Context, afterCreatedAt time.Time, afterID string, limit int) (RunPage, error)
}

// NormalizeRunsPageLimit applies the shared bound to a requested page size:
// non-positive selects DefaultRunsPageLimit, above-cap clamps to
// MaxRunsPageLimit.
func NormalizeRunsPageLimit(limit int) int {
	if limit <= 0 {
		return DefaultRunsPageLimit
	}
	if limit > MaxRunsPageLimit {
		return MaxRunsPageLimit
	}
	return limit
}

// RunOlderThan reports whether run sorts strictly after the cursor position
// in the (created_at DESC, id DESC) keyset order: the in-memory equivalent
// of SQL's (created_at, id) < ($1, $2). The zero cursor matches every run.
func RunOlderThan(run model.Run, afterCreatedAt time.Time, afterID string) bool {
	if afterCreatedAt.IsZero() && afterID == "" {
		return true
	}
	if run.CreatedAt.Before(afterCreatedAt) {
		return true
	}
	if run.CreatedAt.After(afterCreatedAt) {
		return false
	}
	return run.ID < afterID
}

// SortRunsNewestFirst orders runs by created_at DESC, id DESC: the total
// order every RunPageStore implementation returns.
func SortRunsNewestFirst(runs []model.Run) {
	sort.Slice(runs, func(i, j int) bool {
		if !runs[i].CreatedAt.Equal(runs[j].CreatedAt) {
			return runs[i].CreatedAt.After(runs[j].CreatedAt)
		}
		return runs[i].ID > runs[j].ID
	})
}

// PageRuns applies the keyset contract to an unordered in-memory run
// snapshot: it drops every row at or above the cursor, sorts the rest
// newest-first, and returns at most limit rows plus the exact HasMore and
// next position. It is the memory half of the contract, used by the server's
// memory mode (Server.listRuns) and by memStore.ListRunsPage (the in-package
// in-memory Store), plus package test doubles, so the memory and SQL pages
// share one definition. It is NOT a fallback for stores without
// RunPageStore: paged reads require that capability and fail closed without
// it, because an unpaged ListRuns window cannot honor an older cursor.
func PageRuns(runs []model.Run, afterCreatedAt time.Time, afterID string, limit int) RunPage {
	limit = NormalizeRunsPageLimit(limit)
	eligible := make([]model.Run, 0, len(runs))
	for _, run := range runs {
		if RunOlderThan(run, afterCreatedAt, afterID) {
			eligible = append(eligible, run)
		}
	}
	SortRunsNewestFirst(eligible)
	page := RunPage{Runs: eligible}
	if len(eligible) > limit {
		page.Runs = eligible[:limit]
		page.HasMore = true
	}
	if page.HasMore {
		last := page.Runs[len(page.Runs)-1]
		page.NextCreatedAt = last.CreatedAt
		page.NextID = last.ID
	}
	return page
}

// ListRunsPage implements RunPageStore for the durable store. One
// index-backed keyset read: ORDER BY created_at DESC, id DESC with the
// row-value cursor predicate and LIMIT limit+1 so HasMore is exact. runCols
// and scanRun are shared with ListRuns, so a paged run decodes identically
// to a non-paged one (no second payload-decoding path).
//
// id is compared with COLLATE "C" in both the ORDER BY and the cursor
// predicate: the byte order Go's string comparison uses in RunOlderThan, so
// the SQL and memory pages are identical regardless of the database's
// default collation (a text id can only be compared consistently across the
// two implementations when the collation is pinned).
func (s *PostgresStore) ListRunsPage(ctx context.Context, afterCreatedAt time.Time, afterID string, limit int) (RunPage, error) {
	limit = NormalizeRunsPageLimit(limit)
	args := []any{}
	where := ""
	if !afterCreatedAt.IsZero() || afterID != "" {
		where = ` WHERE (created_at, id COLLATE "C") < ($1::timestamptz, $2::text COLLATE "C")`
		args = append(args, afterCreatedAt, afterID)
	}
	args = append(args, limit+1)
	rows, err := s.pool.Query(ctx,
		`SELECT `+runCols+` FROM runs`+where+
			` ORDER BY created_at DESC, id COLLATE "C" DESC LIMIT $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return RunPage{}, err
	}
	defer rows.Close()
	out := []model.Run{}
	for rows.Next() {
		run, err := scanRun(rows)
		if err != nil {
			return RunPage{}, err
		}
		out = append(out, run)
	}
	if err := rows.Err(); err != nil {
		return RunPage{}, err
	}
	page := RunPage{Runs: out}
	if len(out) > limit {
		page.Runs = out[:limit]
		page.HasMore = true
	}
	if page.HasMore {
		last := page.Runs[len(page.Runs)-1]
		page.NextCreatedAt = last.CreatedAt
		page.NextID = last.ID
	}
	return page, nil
}

var _ RunPageStore = (*PostgresStore)(nil)
