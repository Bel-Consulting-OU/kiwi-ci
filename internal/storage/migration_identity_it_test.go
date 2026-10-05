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

// TestLeaseSchemaFloorFenceSerializesAgainstMigration is a REAL two-
// transaction interleaving test, not a sequential one: while a migration
// transaction holds the exclusive schema lock (uncommitted), a lease claim
// must BLOCK on the shared lock; committing the migration first makes the
// claim observe the new incompatible floor and refuse without touching the
// job row.
func TestLeaseSchemaFloorFenceSerializesAgainstMigration(t *testing.T) {
	st := pgITStore(t)
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

// TestMigrationWaitsForLeaseSharedLock is the inverse ordering: a lease
// transaction holding the shared lock keeps a migration's exclusive lock
// waiting until the lease commits.
func TestMigrationWaitsForLeaseSharedLock(t *testing.T) {
	st := pgITStore(t)
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
