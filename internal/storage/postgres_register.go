package storage

// Atomic registration swap for PostgresStore.
//
// Re-registering a stable runner ID mints a new incarnation, but before this
// transaction the predecessor's running leases stayed live: its capacity
// slots and reservations were held for the rest of the lease TTL and the
// superseded process could still reach the durable-write endpoints
// (OIDC/secret/artifact/snapshot/cache) that authenticate the lease token
// alone. RegisterRunnerAndRevokeLeases performs the incarnation swap and the
// complete runner-scoped lease revocation in ONE schema-fenced transaction.

import (
	"context"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

var _ RunnerRegistrationStore = (*PostgresStore)(nil)

// RegisterRunnerAndRevokeLeases writes the new registration row and revokes
// every running lease the runner held under its PREVIOUS incarnation inside a
// single schema-fenced transaction (see RunnerRegistrationStore). The
// revocation is the existing revokeRunnerLeasesTx transition: each lease
// requeues while the infrastructure-retry budget allows it (otherwise it is
// terminal-cancelled with reason), resource reservations and quota counters
// are released, the runner's active set and failure counter move, dependent
// jobs and affected runs are recomputed, and one audit event per job is
// written. All of that commits together with the new profile row, so a crash
// can never leave a newly registered runner whose predecessor still holds
// capacity.
//
// Lock order: the revocation runs FIRST and takes job locks before the runner
// row lock (revokeRunnerLeasesTx phases 1-2), the same jobs -> runner order
// AcquireLeaseAtomic/CompleteJob/RecoverExpiredLease use. Writing the profile
// row first would take the runner lock before the job locks and could
// deadlock against a concurrent claim. The guarded profile write afterwards
// re-locks the already-held runner row and preserves the lease-owned fields
// and counters the revocation just moved.
func (s *PostgresStore) RegisterRunnerAndRevokeLeases(ctx context.Context, runner model.Runner, reason string) ([]string, error) {
	if err := ValidateRunnerID(runner.ID); err != nil {
		return nil, err
	}
	tx, err := s.beginSchemaCompatibleTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	now := time.Now().UTC()
	revoked, _, err := s.revokeRunnerLeasesTx(ctx, tx, runner.ID, reason, now)
	if err != nil {
		return nil, err
	}
	if err := s.writeRunnerProfileTx(ctx, tx, runner, false); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return revoked, nil
}
