package storage

import (
	"context"
)

// UsageOnceStore is the exactly-once usage accounting contract. The store is
// the arbiter of whether a job's completion usage has already been recorded;
// callers MUST move process-local metrics (cost/energy counters, the trailing
// budget window) only when won is true, so an at-least-once completion
// effect (outbox retry, receipt replay, a second replica) can never
// double-account.
//
// Semantics:
//   - won=true: this call transitioned the job from "usage not recorded" to
//     "usage recorded" and persisted cost/energyWh in the SAME atomic
//     write. The caller now owns the accounting.
//   - won=false: the job already recorded usage. The caller skips metric
//     movement entirely; a retry after a failed first attempt converges on
//     exactly one winner.
//   - err!=nil: nothing was recorded; the caller fails the effect closed and
//     retries later.
//
// A jobID that is empty or not a 32-character lowercase-hex ID (the server's
// job ID format) is rejected with an error and records nothing. generation is
// the lease generation (attempt identity) of the completion the usage
// belongs to; it is persisted alongside the amounts so the durable record
// names the exact attempt that incurred the cost.
type UsageOnceStore interface {
	RecordUsageOnce(ctx context.Context, jobID string, generation int64, cost, energyWh float64) (won bool, err error)
}

var _ UsageOnceStore = (*PostgresStore)(nil)

// RecordUsageOnce atomically records a job's completion usage exactly once.
// The conditional UPDATE matches only rows whose payload has not yet been
// marked usage_recorded, so exactly one caller (per job) can win regardless
// of how many replicas reconcile the same completion. The same statement
// writes cost, energy_wh (the fields RecentUsage sums) and the attempt's
// lease generation into the payload, so marker, amounts and attempt identity
// can never diverge.
func (s *PostgresStore) RecordUsageOnce(ctx context.Context, jobID string, generation int64, cost, energyWh float64) (bool, error) {
	if err := ValidateJobID(jobID); err != nil {
		return false, err
	}
	ct, err := s.execSchemaFenced(ctx, `UPDATE jobs
		SET payload = payload || jsonb_build_object('usage_recorded', true, 'cost', $3::double precision, 'energy_wh', $4::double precision, 'usage_lease_generation', $2::bigint)
		WHERE id=$1 AND COALESCE(payload->>'usage_recorded', 'false') <> 'true'`,
		jobID, generation, cost, energyWh)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() == 1, nil
}
