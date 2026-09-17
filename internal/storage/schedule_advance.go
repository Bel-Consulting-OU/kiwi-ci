package storage

import (
	"context"
	"fmt"
	"time"
)

// AdvanceScheduleLastRun is the SQL implementation of the monotonic durable
// schedule advance: last_run = GREATEST(existing, nominal). A stale replica
// that still believes an older last_run can therefore never move the marker
// backwards and make an already-settled occurrence due again; advancing an
// occurrence that another replica already passed is a no-op. An unknown
// schedule reports ErrNotFound.
//
// It lives beside the rest of the package's durable-advance contract rather
// than in postgres.go so the monotonic semantics stay in one auditable
// place; postgres.go holds the remaining ScheduleStore methods.
func (s *PostgresStore) AdvanceScheduleLastRun(ctx context.Context, id string, nominal time.Time) error {
	if id == "" {
		return fmt.Errorf("storage: empty schedule id")
	}
	ct, err := s.pool.Exec(ctx,
		`UPDATE schedules SET last_run = GREATEST(COALESCE(last_run, 'epoch'::timestamptz), $2) WHERE id=$1`,
		id, nominal.UTC())
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
