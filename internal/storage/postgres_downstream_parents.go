package storage

// Downstream parent re-aggregation lookup: the reverse index from a child run
// to the parent runs that wait on it. This is the bounded, index-backed
// replacement for the old run-enumeration scan (ListRuns capped at the 10,000
// newest runs), which could never see an old parent on a busy installation —
// the parent stayed permanently stale when its child finished.

import (
	"context"
	"fmt"
)

// DownstreamParentRunStore resolves the parent runs that wait on one child
// run through the durable downstream_links reverse index
// (downstream_links_child_run_idx) instead of enumerating runs. The server's
// child-completion aggregation (refreshDownstreamParentsDB) requires this
// contract in DB mode and FAILS CLOSED without it: falling back to the
// bounded ListRuns window would silently strand old wait=true parents.
//
// Implementations must return each parent run ID exactly once (DISTINCT),
// ordered by run ID, and must not apply any window/limit.
type DownstreamParentRunStore interface {
	// ParentRunIDsForChild returns the distinct IDs of the runs owning the
	// parent jobs whose downstream link was launched as childRunID, ordered
	// by run ID. An unknown child returns an empty result, not an error.
	ParentRunIDsForChild(ctx context.Context, childRunID string) ([]string, error)
}

var _ DownstreamParentRunStore = (*PostgresStore)(nil)

// parentRunIDsForChildSQL is the reverse lookup executed by
// ParentRunIDsForChild. It is a package constant so integration tests can
// EXPLAIN the exact production statement and prove it rides the existing
// downstream_links_child_run_idx index.
const parentRunIDsForChildSQL = `SELECT DISTINCT j.run_id FROM downstream_links dl JOIN jobs j ON j.id = dl.parent_job_id WHERE dl.child_run_id = $1 ORDER BY j.run_id`

// ParentRunIDsForChild returns the distinct parent run IDs waiting on
// childRunID via the downstream_links child-run index. Unlike a ListRuns
// window scan this is complete for every child, regardless of how many newer
// runs exist, so an old wait=true parent is always re-aggregated when its
// child finishes.
func (s *PostgresStore) ParentRunIDsForChild(ctx context.Context, childRunID string) ([]string, error) {
	if childRunID == "" {
		return nil, fmt.Errorf("storage: empty child run id")
	}
	rows, err := s.pool.Query(ctx, parentRunIDsForChildSQL, childRunID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var runID string
		if err := rows.Scan(&runID); err != nil {
			return nil, err
		}
		out = append(out, runID)
	}
	return out, rows.Err()
}
