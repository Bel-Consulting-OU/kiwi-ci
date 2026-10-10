package storage

// Migration identity integration: recorded digests must match the binary and
// the recorded compatibility floor must be observable. Gated on
// KIWI_TEST_POSTGRES_URL like the rest of the integration lane.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// TestPostgresIntegrationMigrationDigestMismatchRefused: editing an applied
// migration's content (or tampering with the recorded digest) is schema
// history divergence and must abort Migrate; restoring the true digest makes
// the same database migrate cleanly again.
func TestPostgresIntegrationMigrationDigestMismatchRefused(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	all, err := migrations.All()
	if err != nil || len(all) == 0 {
		t.Fatalf("migrations: %v", err)
	}
	first := all[0]
	if _, err := st.pool.Exec(ctx, `UPDATE schema_migrations SET sha256='deadbeef' WHERE version=$1`, first.Version); err != nil {
		t.Fatal(err)
	}
	err = st.Migrate(ctx)
	if err == nil || !strings.Contains(err.Error(), "divergence") {
		t.Fatalf("Migrate with a tampered digest = %v, want divergence", err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE schema_migrations SET sha256=$2 WHERE version=$1`, first.Version, first.Digest); err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate after restoring the digest: %v", err)
	}
}

// TestPostgresIntegrationSchemaCompatibilityFloor: every migration defaults
// its floor to its own version, so a fully migrated database reports the
// binary's max version; a newer floor recorded by a later release is reported
// verbatim (the readiness gate turns it into a 503).
func TestPostgresIntegrationSchemaCompatibilityFloor(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	floor, err := st.SchemaCompatibilityFloor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if floor != maxV {
		t.Fatalf("floor = %d, want %d", floor, maxV)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE schema_migrations SET compatible_from=$1 WHERE version=$2`, maxV+5, maxV); err != nil {
		t.Fatal(err)
	}
	floor, err = st.SchemaCompatibilityFloor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if floor != maxV+5 {
		t.Fatalf("floor = %d, want %d", floor, maxV+5)
	}
}

// TestPostgresIntegrationLeaseFenceRejectsIncompatibleFloor: the
// compatibility assertion lives INSIDE the lease transaction, so a floor
// that advanced after an old replica's check still refuses the claim — no
// check/claim race window.
func TestPostgresIntegrationLeaseFenceRejectsIncompatibleFloor(t *testing.T) {
	st := pgITStore(t)
	st.EnableSchemaFence()
	ctx := context.Background()
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	runnerID := pgITNewID(t)
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 1,
		ReportedCapabilities: []string{"native"}, Capabilities: []string{"native"}, CapabilitiesEnforced: true}); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)

	// Sanity: the claim leases while compatible.
	claim := LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1,
		Runtime: "native", ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if _, err := st.AcquireLeaseAtomic(ctx, claim); err != nil {
		t.Fatalf("compatible claim: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET status='queued', lease_token_hash=NULL, lease_runner_id=NULL WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}

	// A newer replica commits a migration whose floor is above this binary.
	if _, err := st.pool.Exec(ctx, `UPDATE schema_migrations SET compatible_from=$1 WHERE version=$2`, maxV+1, maxV); err != nil {
		t.Fatal(err)
	}
	_, err = st.AcquireLeaseAtomic(ctx, claim)
	if !errors.Is(err, ErrSchemaIncompatible) {
		t.Fatalf("claim under an incompatible floor = %v, want ErrSchemaIncompatible", err)
	}
	var status string
	if err := st.pool.QueryRow(ctx, `SELECT status FROM jobs WHERE id=$1`, jobID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "queued" {
		t.Fatalf("job status = %q, want queued (no lease issued)", status)
	}
}

// schemaLockKey is the advisory-lock namespace migrations and the lease
// fence share.
const schemaLockKeySQL = `hashtext('kiwi_schema_migrations')`

// TestIntegrationLeaseSchemaFloorFenceSerializesAgainstMigration is a REAL two-
// transaction interleaving test, not a sequential one: while a migration
// transaction holds the exclusive schema lock (uncommitted), a lease claim
// must BLOCK on the shared lock; committing the migration first makes the
// claim observe the new incompatible floor and refuse without touching the
// job row.
func TestIntegrationLeaseSchemaFloorFenceSerializesAgainstMigration(t *testing.T) {
	st := pgITStore(t)
	st.EnableSchemaFence()
	ctx := context.Background()
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	runnerID := pgITNewID(t)
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 1,
		ReportedCapabilities: []string{"native"}, Capabilities: []string{"native"}, CapabilitiesEnforced: true}); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	claim := LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1,
		Runtime: "native", ExpiresAt: time.Now().UTC().Add(time.Hour)}

	// The migration transaction: exclusive lock + floor advance, NOT committed.
	migConn, err := st.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer migConn.Release()
	migTx, err := migConn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer migTx.Rollback(ctx)
	if _, err := migTx.Exec(ctx, `SELECT pg_advisory_xact_lock(`+schemaLockKeySQL+`)`); err != nil {
		t.Fatal(err)
	}
	if _, err := migTx.Exec(ctx, `UPDATE schema_migrations SET compatible_from=$1 WHERE version=$2`, maxV+1, maxV); err != nil {
		t.Fatal(err)
	}

	// The lease claim must block: it cannot acquire the shared lock while
	// the exclusive migration lock is held.
	type res struct {
		job model.Job
		err error
	}
	done := make(chan res, 1)
	go func() {
		j, err := st.AcquireLeaseAtomic(ctx, claim)
		done <- res{j, err}
	}()
	select {
	case r := <-done:
		t.Fatalf("lease did not serialize against the migration: got (%v, %v)", r.job.ID, r.err)
	case <-time.After(1200 * time.Millisecond):
	}
	// Commit the migration: the claim unblocks and must observe the new
	// incompatible floor.
	if err := migTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if !errors.Is(r.err, ErrSchemaIncompatible) {
			t.Fatalf("claim after the migration committed = %v, want ErrSchemaIncompatible", r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("claim never returned after the migration committed")
	}
	var status string
	if err := st.pool.QueryRow(ctx, `SELECT status FROM jobs WHERE id=$1`, jobID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "queued" {
		t.Fatalf("job status = %q, want queued (no lease committed)", status)
	}
}

// TestIntegrationMigrationWaitsForLeaseSharedLock is the inverse ordering: a lease
// transaction holding the shared lock keeps a migration's exclusive lock
// waiting until the lease commits.
func TestIntegrationMigrationWaitsForLeaseSharedLock(t *testing.T) {
	st := pgITStore(t)
	st.EnableSchemaFence()
	ctx := context.Background()
	holder, err := st.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Release()
	holderTx, err := holder.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holderTx.Rollback(ctx)
	if _, err := holderTx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(`+schemaLockKeySQL+`)`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		mig, err := st.pool.Acquire(ctx)
		if err != nil {
			done <- err
			return
		}
		defer mig.Release()
		tx, err := mig.Begin(ctx)
		if err != nil {
			done <- err
			return
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(`+schemaLockKeySQL+`)`); err != nil {
			done <- err
			return
		}
		done <- tx.Commit(ctx)
	}()
	select {
	case err := <-done:
		t.Fatalf("migration did not wait for the shared schema lock: %v", err)
	case <-time.After(1200 * time.Millisecond):
	}
	if err := holderTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("migration after the lease released: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("migration never proceeded after the lease committed")
	}
}

// TestPostgresIntegrationNonLeaseMutationFencedAgainstMigration: a terminal
// COMPLETION (the audit's named non-lease mutation surface) participates in
// the migration lock protocol, so a floor that advanced while the replica
// was between its middleware check and the write still refuses the write.
func TestPostgresIntegrationNonLeaseMutationFencedAgainstMigration(t *testing.T) {
	st := pgITStore(t)
	st.EnableSchemaFence()
	ctx := context.Background()
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	runnerID := pgITNewID(t)
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 1,
		ReportedCapabilities: []string{"native"}, Capabilities: []string{"native"}, CapabilitiesEnforced: true}); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	token := []byte("fence-token")
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: token, Generation: 1,
		Runtime: "native", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatalf("lease: %v", err)
	}

	// Exclusive migration lock held, floor advanced, not committed.
	conn, err := st.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(`+schemaLockKeySQL+`)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE schema_migrations SET compatible_from=$1 WHERE version=$2`, maxV+1, maxV); err != nil {
		t.Fatal(err)
	}

	receipt := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID}
	done := make(chan error, 1)
	go func() {
		done <- st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, receipt, nil)
	}()
	select {
	case err := <-done:
		t.Fatalf("completion did not serialize against the migration: %v", err)
	case <-time.After(1200 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrSchemaIncompatible) {
			t.Fatalf("completion after the migration committed = %v, want ErrSchemaIncompatible", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("completion never returned")
	}
	var status string
	if err := st.pool.QueryRow(ctx, `SELECT status FROM jobs WHERE id=$1`, jobID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "running" {
		t.Fatalf("job status = %q, want running (the incompatible completion wrote nothing)", status)
	}
}

// TestIntegrationHeartbeatCannotCrossIncompatibleMigration: after a newer replica
// commits an incompatible floor, both heartbeat paths refuse and the stored
// expiry is untouched (the floor read and the mutation are one statement).
func TestIntegrationHeartbeatCannotCrossIncompatibleMigration(t *testing.T) {
	st := pgITStore(t)
	st.EnableSchemaFence()
	ctx := context.Background()
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	runnerID := pgITNewID(t)
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 1,
		ReportedCapabilities: []string{"native"}, Capabilities: []string{"native"}, CapabilitiesEnforced: true}); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1,
		Runtime: "native", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatalf("lease: %v", err)
	}
	var before time.Time
	if err := st.pool.QueryRow(ctx, `SELECT lease_expires_at FROM jobs WHERE id=$1`, jobID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	// A newer replica commits an incompatible floor.
	if _, err := st.pool.Exec(ctx, `UPDATE schema_migrations SET compatible_from=$1 WHERE version=$2`, maxV+1, maxV); err != nil {
		t.Fatal(err)
	}
	if err := st.HeartbeatLease(ctx, jobID, runnerID, 1, time.Now().UTC().Add(2*time.Hour)); !errors.Is(err, ErrSchemaIncompatible) {
		t.Fatalf("legacy heartbeat under an incompatible floor = %v, want ErrSchemaIncompatible", err)
	}
	if _, err := st.HeartbeatLeaseWithTTL(ctx, jobID, runnerID, 1, time.Hour); !errors.Is(err, ErrSchemaIncompatible) {
		t.Fatalf("TTL heartbeat under an incompatible floor = %v, want ErrSchemaIncompatible", err)
	}
	var after time.Time
	if err := st.pool.QueryRow(ctx, `SELECT lease_expires_at FROM jobs WHERE id=$1`, jobID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !after.Equal(before) {
		t.Fatalf("heartbeat mutated the lease expiry across an incompatible migration: %v -> %v", before, after)
	}
}

// TestIntegrationInsertCompiledRunCannotCrossIncompatibleMigration: the compiled-run
// enqueue transaction (the production enqueue path, also used by schedules
// and internal enqueue) refuses and writes nothing once a newer replica has
// committed an incompatible floor.
func TestIntegrationInsertCompiledRunCannotCrossIncompatibleMigration(t *testing.T) {
	st := pgITStore(t)
	st.EnableSchemaFence()
	ctx := context.Background()
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE schema_migrations SET compatible_from=$1 WHERE version=$2`, maxV+1, maxV); err != nil {
		t.Fatal(err)
	}
	runID, jobID := pgITNewID(t), pgITNewID(t)
	req := InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{jobID: pgITJob(runID, jobID, pgITRepo)},
	}
	if err := st.InsertCompiledRun(ctx, req); !errors.Is(err, ErrSchemaIncompatible) {
		t.Fatalf("enqueue under an incompatible floor = %v, want ErrSchemaIncompatible", err)
	}
	var runs, jobs bool
	if err := st.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM runs WHERE id=$1)`, runID).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if err := st.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM jobs WHERE id=$1)`, jobID).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if runs || jobs {
		t.Fatalf("incompatible enqueue wrote rows: run=%v job=%v", runs, jobs)
	}
}

// TestIntegrationHeartbeatSchemaFenceSerializesAgainstMigration is the true
// two-connection interleaving: a migration holds the exclusive schema lock
// (uncommitted floor change) while a heartbeat runs; the heartbeat must
// BLOCK on the shared lock, and after the migration commits it must observe
// the new floor and refuse without touching the lease.
func TestIntegrationHeartbeatSchemaFenceSerializesAgainstMigration(t *testing.T) {
	st := pgITStore(t)
	st.EnableSchemaFence()
	ctx := context.Background()
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	runnerID := pgITNewID(t)
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 1,
		ReportedCapabilities: []string{"native"}, Capabilities: []string{"native"}, CapabilitiesEnforced: true}); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1,
		Runtime: "native", ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatalf("lease: %v", err)
	}
	var before time.Time
	if err := st.pool.QueryRow(ctx, `SELECT lease_expires_at FROM jobs WHERE id=$1`, jobID).Scan(&before); err != nil {
		t.Fatal(err)
	}

	conn, err := st.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	migTx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer migTx.Rollback(ctx)
	if _, err := migTx.Exec(ctx, `SELECT pg_advisory_xact_lock(`+schemaLockKeySQL+`)`); err != nil {
		t.Fatal(err)
	}
	if _, err := migTx.Exec(ctx, `UPDATE schema_migrations SET compatible_from=$1 WHERE version=$2`, maxV+1, maxV); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, herr := st.HeartbeatLeaseWithTTL(ctx, jobID, runnerID, 1, time.Hour)
		done <- herr
	}()
	select {
	case herr := <-done:
		t.Fatalf("heartbeat did not serialize against the migration: %v", herr)
	case <-time.After(1200 * time.Millisecond):
	}
	if err := migTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case herr := <-done:
		if !errors.Is(herr, ErrSchemaIncompatible) {
			t.Fatalf("heartbeat after the migration committed = %v, want ErrSchemaIncompatible", herr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("heartbeat never returned")
	}
	var after time.Time
	if err := st.pool.QueryRow(ctx, `SELECT lease_expires_at FROM jobs WHERE id=$1`, jobID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !after.Equal(before) {
		t.Fatalf("heartbeat committed despite the migration: %v -> %v", before, after)
	}
}

// pgITSchemaFenceBarrier proves that one mutation serializes against a real
// exclusive migration lock: call is started while a background transaction
// holds pg_advisory_xact_lock(hashtext('kiwi_schema_migrations')) and has
// advanced the recorded floor above this binary (uncommitted), it must BLOCK
// (no result within the observation window), and after the migration commits
// it must return ErrSchemaIncompatible. The caller asserts separately that
// the method wrote nothing.
func pgITSchemaFenceBarrier(t *testing.T, st *PostgresStore, call func(context.Context) error) {
	t.Helper()
	st.EnableSchemaFence()
	ctx := context.Background()
	maxV, err := migrations.MaxVersion()
	if err != nil {
		t.Fatal(err)
	}
	// The migration transaction: exclusive lock + floor advance, NOT
	// committed (verbatim from TestIntegrationLeaseSchemaFloorFenceSerializesAgainstMigration).
	migConn, err := st.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer migConn.Release()
	migTx, err := migConn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer migTx.Rollback(ctx)
	if _, err := migTx.Exec(ctx, `SELECT pg_advisory_xact_lock(`+schemaLockKeySQL+`)`); err != nil {
		t.Fatal(err)
	}
	if _, err := migTx.Exec(ctx, `UPDATE schema_migrations SET compatible_from=$1 WHERE version=$2`, maxV+1, maxV); err != nil {
		t.Fatal(err)
	}

	// The mutation must block: it cannot acquire the shared schema lock
	// while the exclusive migration lock is held.
	done := make(chan error, 1)
	go func() { done <- call(ctx) }()
	select {
	case err := <-done:
		t.Fatalf("mutation did not serialize against the migration: got %v", err)
	case <-time.After(1200 * time.Millisecond):
	}
	// Commit the migration: the mutation unblocks and must observe the new
	// incompatible floor and commit nothing.
	if err := migTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrSchemaIncompatible) {
			t.Fatalf("mutation after the migration committed = %v, want ErrSchemaIncompatible", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("mutation never returned after the migration committed")
	}
}

// TestPostgresIntegrationOutboxAppendSchemaFenceBarrier: OutboxAppend was a
// raw single-statement pool write before the fence conversion; it must now
// block on the migration lock and refuse after an incompatible floor.
func TestPostgresIntegrationOutboxAppendSchemaFenceBarrier(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	id := pgITNewID(t)
	pgITSchemaFenceBarrier(t, st, func(ctx context.Context) error {
		return st.OutboxAppend(ctx, OutboxItem{ID: id, Kind: "test.fence", CreatedAt: time.Now().UTC()})
	})
	var n int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE id=$1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("OutboxAppend wrote %d row(s) across an incompatible migration floor", n)
	}
}

// TestPostgresIntegrationUpsertScheduleSchemaFenceBarrier: UpsertSchedule was
// a plain pool transaction before the fence conversion; it must now block on
// the migration lock and refuse after an incompatible floor.
func TestPostgresIntegrationUpsertScheduleSchemaFenceBarrier(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	id := pgITNewID(t)
	pgITSchemaFenceBarrier(t, st, func(ctx context.Context) error {
		return st.UpsertSchedule(ctx, Schedule{ID: id, Repository: pgITRepo, RepoURL: pgITRepo, Spec: "version: 1", CreatedAt: time.Now().UTC()})
	})
	var n int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM schedules WHERE id=$1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("UpsertSchedule wrote %d row(s) across an incompatible migration floor", n)
	}
}

// TestPostgresIntegrationCommitSecretIssuanceSchemaFenceBarrier:
// CommitSecretIssuance was a plain pool transaction before the fence
// conversion; it must now block on the migration lock and refuse after an
// incompatible floor (before it can even read the job row).
func TestPostgresIntegrationCommitSecretIssuanceSchemaFenceBarrier(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	jobID := pgITNewID(t)
	pgITSchemaFenceBarrier(t, st, func(ctx context.Context) error {
		_, _, err := st.CommitSecretIssuance(ctx, SecretIssuance{
			JobID:           jobID,
			RunnerID:        pgITNewID(t),
			LeaseGeneration: 1,
			LeaseTokenHash:  []byte("fence-token"),
			SecretName:      "DEPLOY_TOKEN",
			IssuedAt:        time.Now().UTC(),
		})
		return err
	})
	var n int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM secret_claims WHERE job_id=$1`, jobID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("CommitSecretIssuance wrote %d claim row(s) across an incompatible migration floor", n)
	}
}

// TestPostgresIntegrationClaimOutboxSchemaFenceBarrier: ClaimOutbox runs in a
// beginFencedTx transaction (leadership epoch + schema floor). An armed
// replica must still block on the migration lock and refuse after an
// incompatible floor, claiming nothing.
func TestPostgresIntegrationClaimOutboxSchemaFenceBarrier(t *testing.T) {
	st := pgITStore(t) // pgITStore arms the durable leadership epoch.
	ctx := context.Background()
	st.EnableSchemaFence()
	id := pgITNewID(t)
	if err := st.OutboxAppend(ctx, OutboxItem{ID: id, Kind: "test.fence", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("seed outbox row: %v", err)
	}
	pgITSchemaFenceBarrier(t, st, func(ctx context.Context) error {
		_, err := st.ClaimOutbox(ctx, "schema-fence-barrier", 10)
		return err
	})
	var claimed bool
	if err := st.pool.QueryRow(ctx, `SELECT claimed_at IS NOT NULL FROM outbox WHERE id=$1`, id).Scan(&claimed); err != nil {
		t.Fatal(err)
	}
	if claimed {
		t.Fatal("ClaimOutbox claimed a row across an incompatible migration floor")
	}
}
