package storage

import (
	"context"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// MetricsAggregateStore is the bounded aggregate contract behind the
// DB-mode state gauges (kiwi_runs, kiwi_jobs, kiwi_jobs_queue_reason and the
// runner slot gauges kiwi_runners / kiwi_runner_slots / kiwi_runner_slots_busy).
//
// Every method is ONE store-side aggregate. A metrics scrape must never
// enumerate runs: the previous DB path called ListRuns(ctx, 100), so
// kiwi_runs counted at most the newest 100 runs and skipped every job of a
// terminal run, while memory mode counted the full state — the same metric
// changed meaning with the backend. The aggregates below count EVERY row of
// their table (jobs included, whatever their run's status) and never decode
// a full payload to count a status.
//
// Error contract: an aggregate that cannot be read returns an error, NEVER a
// partial or empty count. Callers skip the affected metric family on error;
// a zero map would be rendered as a wrong zero sample. A cancelled context is
// an error like any other.
type MetricsAggregateStore interface {
	// RunStatusCounts counts every run by status:
	// SELECT status, COUNT(*) FROM runs GROUP BY status.
	RunStatusCounts(ctx context.Context) (map[model.Status]int, error)
	// JobStatusCounts counts every job by status, including jobs belonging
	// to terminal runs: SELECT status, COUNT(*) FROM jobs GROUP BY status.
	JobStatusCounts(ctx context.Context) (map[model.Status]int, error)
	// QueuedJobQueueReasonCounts counts the queued (and approval-waiting)
	// jobs that carry a non-empty queue reason, keyed by reason. Jobs in
	// other statuses and jobs without a reason are not counted, mirroring
	// the in-memory gauge.
	QueuedJobQueueReasonCounts(ctx context.Context) (map[string]int, error)
	// RunnerSlotTotals returns the runner count, the total effective slots
	// and the busy slots. It reads only the relational runner columns
	// (capacity, active_jobs) and never the runner payload.
	RunnerSlotTotals(ctx context.Context) (RunnerSlotTotals, error)
}

// RunnerSlotTotals is one runner-capacity aggregate. Capacity sums each
// runner's effective slots (a capacity < 1 counts as 1, exactly like the
// in-memory gauge); Busy sums each runner's active jobs; Runners counts the
// registered runner rows.
type RunnerSlotTotals struct {
	Runners  int
	Capacity int
	Busy     int
}

var _ MetricsAggregateStore = (*PostgresStore)(nil)

// RunStatusCounts implements MetricsAggregateStore. One GROUP BY aggregate;
// the runs_status_idx index covers it without touching any payload.
func (s *PostgresStore) RunStatusCounts(ctx context.Context) (map[model.Status]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT status, COUNT(*) FROM runs GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[model.Status]int{}
	for rows.Next() {
		var (
			status string
			n      int
		)
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		out[model.Status(status)] = n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// JobStatusCounts implements MetricsAggregateStore. One GROUP BY aggregate
// over the whole jobs table: jobs_run_id_idx/status index support it and no
// run join is needed, so jobs of terminal runs are counted like any other
// (the family is "jobs by status", not "jobs of active runs").
func (s *PostgresStore) JobStatusCounts(ctx context.Context) (map[model.Status]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT status, COUNT(*) FROM jobs GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[model.Status]int{}
	for rows.Next() {
		var (
			status string
			n      int
		)
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		out[model.Status(status)] = n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// QueuedJobQueueReasonCounts implements MetricsAggregateStore. The reason
// lives in the job payload (jsonb), so the aggregate reads the single
// 'queue_reason' key instead of decoding payloads; the status filter matches
// the in-memory gauge (queued and approval-waiting jobs only, non-empty
// reasons only).
func (s *PostgresStore) QueuedJobQueueReasonCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT payload->>'queue_reason', COUNT(*) FROM jobs WHERE status = ANY($1::text[]) AND COALESCE(payload->>'queue_reason', '') <> '' GROUP BY 1`,
		[]string{string(model.StatusQueued), string(model.StatusWaitingApproval)})
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var (
			reason string
			n      int
		)
		if err := rows.Scan(&reason, &n); err != nil {
			return nil, err
		}
		out[reason] = n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// RunnerSlotTotals implements MetricsAggregateStore. One aggregate over the
// runners table's relational columns: COUNT(*) is the runner gauge, the
// capacity sum clamps each row at one slot exactly like the in-memory gauge,
// and the busy sum counts active_jobs entries via jsonb_array_length. The
// runner payload is never read.
func (s *PostgresStore) RunnerSlotTotals(ctx context.Context) (RunnerSlotTotals, error) {
	var out RunnerSlotTotals
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*), COALESCE(SUM(GREATEST(capacity, 1)), 0), COALESCE(SUM(jsonb_array_length(COALESCE(active_jobs, '[]'::jsonb))), 0) FROM runners`).
		Scan(&out.Runners, &out.Capacity, &out.Busy)
	if err != nil {
		return RunnerSlotTotals{}, err
	}
	return out, nil
}
