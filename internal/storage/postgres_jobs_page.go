package storage

// Bounded keyset pagination for queued lease candidates.
//
// The scheduler's lease walk used to materialize the ENTIRE queued set from
// Postgres (ListQueuedJobs) and sort it in Go on every /next poll, so under a
// backlog one poll's work grew with the backlog it was draining (O(R×Q) at
// R runners). QueuedJobPageStore is the optional bounded candidate-selection
// contract: the store returns the next page of queued jobs in the SAME aged
// scheduling order the scheduler's orderQueuedJobs defines — aged priority
// (priority + wait/10min, wait clamped at zero) DESC, created_at ASC, id ASC
// — with a keyset cursor naming the last returned job, so a caller can scan
// the queue in fixed-size pages instead of materializing it whole. Stores
// that do not implement it keep the historical ListQueuedJobs fallback.
//
// The ordering mirrors the Go policy exactly: EXTRACT(EPOCH FROM now -
// created_at)/600 truncated toward zero for a positive wait and clamped to
// zero otherwise, i.e. FLOOR for the positive domain with GREATEST(0, ...)
// covering clock skew and the exact-zero boundary. id is pinned to
// COLLATE "C" in the cursor comparison (see PostgresStore.ListQueuedJobsPage)
// so the SQL walk matches Go's byte-order id tiebreak; job ids are ASCII
// hex, so the ORDER BY under the database collation agrees in practice and
// the pinned comparison keeps the boundary deterministic.
//
// The page also pushes the definitely-expired queue deadline into SQL
// (`queue_deadline IS NULL OR queue_deadline > now`): a row past its
// persisted deadline is never a lease candidate. The scheduler still applies
// QueueDeadlineFor in Go, because a legacy row can carry its deadline only in
// the compiled payload.

import (
	"context"
	"sort"
	"strconv"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// QueuedJobCursor names the last candidate of a previous page in the aged
// scheduling order (aged priority DESC, created_at ASC, id ASC).
type QueuedJobCursor struct {
	AgedPriority int
	CreatedAt    time.Time
	ID           string
}

// QueuedJobPage is one bounded page of queued lease candidates.
type QueuedJobPage struct {
	Jobs    []model.Job
	HasMore bool
	Last    QueuedJobCursor
}

// QueuedJobPageStore is the optional bounded candidate-selection contract.
// Stores that implement it let the scheduler scan the queue in bounded
// keyset pages instead of materializing it whole; stores that do not keep
// the historical ListQueuedJobs fallback.
type QueuedJobPageStore interface {
	// ListQueuedJobsPage returns at most limit queued candidates strictly
	// after the cursor position, in the aged scheduling order. after == nil
	// starts at the first candidate. now is the scheduling clock the aged
	// priority is computed with (the same instant the caller's own ordering
	// uses). Jobs is never nil; Last names the last RETURNED candidate (zero
	// on an empty page); HasMore reports whether a candidate exists past the
	// page.
	ListQueuedJobsPage(ctx context.Context, after *QueuedJobCursor, limit int, now time.Time) (QueuedJobPage, error)
}

// Queued candidate page bounds: the scheduler's own defaults are 256/4096,
// so the store default stays well below its per-request row cap.
const (
	// QueuedJobPageDefaultLimit is the page size used when a caller passes
	// no limit.
	QueuedJobPageDefaultLimit = 256
	// QueuedJobPageMaxLimit is the hard upper bound on one page.
	QueuedJobPageMaxLimit = 1000
)

// NormalizeQueuedJobPageLimit applies the shared bound to a requested page
// size: non-positive selects QueuedJobPageDefaultLimit, above-cap clamps to
// QueuedJobPageMaxLimit.
func NormalizeQueuedJobPageLimit(limit int) int {
	if limit <= 0 {
		return QueuedJobPageDefaultLimit
	}
	if limit > QueuedJobPageMaxLimit {
		return QueuedJobPageMaxLimit
	}
	return limit
}

// queuedJobAgedPriority is the SQL aged-priority expression in Go: static
// priority plus one point per full 10-minute wait, with a non-positive wait
// (fresh or clock-skewed) contributing nothing.
func queuedJobAgedPriority(j model.Job, now time.Time) int {
	wait := now.Sub(j.CreatedAt)
	if wait <= 0 {
		return j.Priority
	}
	return j.Priority + int(wait/(10*time.Minute))
}

// queuedJobAfterCursor reports whether j sorts strictly after the cursor in
// the aged order (aged DESC, created_at ASC, id ASC): the in-memory
// equivalent of the SQL keyset predicate.
func queuedJobAfterCursor(j model.Job, c QueuedJobCursor, now time.Time) bool {
	ap := queuedJobAgedPriority(j, now)
	if ap != c.AgedPriority {
		return ap < c.AgedPriority
	}
	if !j.CreatedAt.Equal(c.CreatedAt) {
		return j.CreatedAt.After(c.CreatedAt)
	}
	return j.ID > c.ID
}

// sortQueuedJobsAged orders candidates by aged priority DESC, created_at
// ASC, id ASC — the total order every QueuedJobPageStore returns.
func sortQueuedJobsAged(jobs []model.Job, now time.Time) {
	sort.Slice(jobs, func(i, j int) bool {
		pi, pj := queuedJobAgedPriority(jobs[i], now), queuedJobAgedPriority(jobs[j], now)
		if pi != pj {
			return pi > pj
		}
		if !jobs[i].CreatedAt.Equal(jobs[j].CreatedAt) {
			return jobs[i].CreatedAt.Before(jobs[j].CreatedAt)
		}
		return jobs[i].ID < jobs[j].ID
	})
}

// ListQueuedJobsPage implements QueuedJobPageStore for the durable store.
// One index-backed keyset read: the aged ORDER BY with the row-value cursor
// predicate and LIMIT limit+1 so HasMore is exact. jobCols is shared with
// ListQueuedJobs, so a paged candidate decodes identically to a non-paged
// one (no second payload-decoding path).
//
// The deadline pushdown and the cursor id COLLATE "C" are documented in the
// file comment.
func (s *PostgresStore) ListQueuedJobsPage(ctx context.Context, after *QueuedJobCursor, limit int, now time.Time) (QueuedJobPage, error) {
	limit = NormalizeQueuedJobPageLimit(limit)
	aged := `(priority + GREATEST(0, FLOOR(EXTRACT(EPOCH FROM ($1::timestamptz - created_at)) / 600))::int)`
	args := []any{now}
	where := ` WHERE status='queued' AND (queue_deadline IS NULL OR queue_deadline > $1::timestamptz)`
	if after != nil {
		where += ` AND (` + aged + ` < $2::int OR (` + aged +
			` = $2::int AND (created_at > $3::timestamptz OR (created_at = $3::timestamptz AND id > $4::text COLLATE "C"))))`
		args = append(args, after.AgedPriority, after.CreatedAt, after.ID)
	}
	args = append(args, limit+1)
	rows, err := s.pool.Query(ctx,
		`SELECT `+jobCols+` FROM jobs`+where+
			` ORDER BY `+aged+` DESC, created_at ASC, id ASC LIMIT $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return QueuedJobPage{}, err
	}
	defer rows.Close()
	out := []model.Job{}
	for rows.Next() {
		js := jobScanner{}
		if err := rows.Scan(jobTargets(&js)...); err != nil {
			return QueuedJobPage{}, err
		}
		j, err := js.job()
		if err != nil {
			return QueuedJobPage{}, err
		}
		out = append(out, j)
	}
	if err := rows.Err(); err != nil {
		return QueuedJobPage{}, err
	}
	page := QueuedJobPage{Jobs: out}
	if len(out) > limit {
		page.Jobs = out[:limit]
		page.HasMore = true
	}
	if len(page.Jobs) > 0 {
		last := page.Jobs[len(page.Jobs)-1]
		page.Last = QueuedJobCursor{
			AgedPriority: queuedJobAgedPriority(last, now),
			CreatedAt:    last.CreatedAt,
			ID:           last.ID,
		}
	}
	return page, nil
}

var _ QueuedJobPageStore = (*PostgresStore)(nil)
var _ QueuedJobPageStore = (*memStore)(nil)
