package storage

// Real-PostgreSQL integration tests for the database-clock-authoritative
// lease lifetime (T3 time authority). Gated on KIWI_TEST_POSTGRES_URL like
// the other storage integration tests.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// leaseClockITSetup registers a native runner and enqueues one queued job,
// returning their ids.
func leaseClockITSetup(t *testing.T, st *PostgresStore) (runID, jobID, runnerID string) {
	t.Helper()
	runnerID = leaseClockITRunner(t, st)
	runID = pgITNewID(t)
	jobID = pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	return runID, jobID, runnerID
}

// leaseClockITSetupKeyed is leaseClockITSetup with an explicit run-scoped job
// Key. Since (run_id, key) uniqueness is per run, two keyed setups in
// different runs can deliberately share one Key (one repository test-history
// suite across two jobs).
func leaseClockITSetupKeyed(t *testing.T, st *PostgresStore, key string) (runID, jobID, runnerID string) {
	t.Helper()
	runnerID = leaseClockITRunner(t, st)
	runID = pgITNewID(t)
	jobID = pgITNewID(t)
	pgITEnqueueOneKeyed(t, st, runID, jobID, pgITRepo, key)
	return runID, jobID, runnerID
}

// leaseClockITRunner registers a native runner used by the lease-clock tests.
func leaseClockITRunner(t *testing.T, st *PostgresStore) string {
	t.Helper()
	runnerID := pgITNewID(t)
	if err := st.UpsertRunner(context.Background(), model.Runner{
		ID: runnerID, Name: runnerID, Capacity: 2,
		ReportedCapabilities: []string{"native"}, Capabilities: []string{"native"}, CapabilitiesEnforced: true,
	}); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	return runnerID
}

func leaseClockITClaim(jobID, runnerID string, ttl time.Duration) LeaseClaim {
	return LeaseClaim{
		JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1,
		Runtime: "native", TTL: ttl,
		// A wildly skewed absolute instant must be IGNORED by the DB-clock
		// claim; this is the epoch, the most extreme app-clock lie possible.
		ExpiresAt: time.Unix(0, 0).UTC(),
	}
}

func leaseClockITDBNow(t *testing.T, st *PostgresStore) time.Time {
	t.Helper()
	var now time.Time
	if err := st.pool.QueryRow(context.Background(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	return now.UTC()
}

// TestIntegrationLeaseClaimUsesDatabaseClock pins the claim: the stored
// expiry is clock_timestamp() + TTL inside the claim transaction, and the
// caller's absolute instant (here the epoch) is ignored entirely.
func TestIntegrationLeaseClaimUsesDatabaseClock(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, runnerID := leaseClockITSetup(t, st)

	before := leaseClockITDBNow(t, st)
	j, err := st.AcquireLeaseWithTTL(ctx, leaseClockITClaim(jobID, runnerID, 90*time.Second))
	if err != nil {
		t.Fatalf("AcquireLeaseWithTTL: %v", err)
	}
	after := leaseClockITDBNow(t, st)
	if j.LeaseExpiresAt == nil {
		t.Fatal("claim returned no lease expiry")
	}
	exp := j.LeaseExpiresAt.UTC()
	lo := before.Add(90 * time.Second)
	hi := after.Add(90*time.Second + time.Second)
	if exp.Before(lo) || exp.After(hi) {
		t.Fatalf("stored expiry %s outside [%s, %s]: not database-clock + TTL", exp, lo, hi)
	}
}

// TestIntegrationHeartbeatExtensionUsesDatabaseClock pins the renewal: a
// successful heartbeat moves the stored expiry to clock_timestamp() + TTL.
func TestIntegrationHeartbeatExtensionUsesDatabaseClock(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, runnerID := leaseClockITSetup(t, st)
	if _, err := st.AcquireLeaseWithTTL(ctx, leaseClockITClaim(jobID, runnerID, 30*time.Second)); err != nil {
		t.Fatal(err)
	}
	before := leaseClockITDBNow(t, st)
	exp, err := st.HeartbeatLeaseWithTTL(ctx, jobID, runnerID, 1, 120*time.Second)
	if err != nil {
		t.Fatalf("HeartbeatLeaseWithTTL: %v", err)
	}
	after := leaseClockITDBNow(t, st)
	lo := before.Add(120 * time.Second)
	hi := after.Add(120*time.Second + time.Second)
	if exp.UTC().Before(lo) || exp.UTC().After(hi) {
		t.Fatalf("heartbeat expiry %s outside [%s, %s]: not database-clock + TTL", exp.UTC(), lo, hi)
	}
}

// TestIntegrationHeartbeatRejectsExpiredLease pins the TOCTOU rule: a lease
// that already expired at the database clock can never be renewed (neither by
// the TTL path nor by the legacy absolute path), so a delayed heartbeat
// cannot resurrect a recoverable lease.
func TestIntegrationHeartbeatRejectsExpiredLease(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, runnerID := leaseClockITSetup(t, st)
	if _, err := st.AcquireLeaseWithTTL(ctx, leaseClockITClaim(jobID, runnerID, 60*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.HeartbeatLeaseWithTTL(ctx, jobID, runnerID, 1, 60*time.Second); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("TTL heartbeat on an expired lease = %v, want ErrLeaseConflict", err)
	}
	if err := st.HeartbeatLease(ctx, jobID, runnerID, 1, time.Now().UTC().Add(time.Hour)); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("legacy heartbeat on an expired lease = %v, want ErrLeaseConflict", err)
	}
	job, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatal(err)
	}
	if job.LeaseExpiresAt == nil || job.LeaseExpiresAt.After(time.Now().Add(time.Minute)) {
		t.Fatalf("expired lease was resurrected: %v", job.LeaseExpiresAt)
	}
}

// TestIntegrationAppClockSkewCannotPrematurelyRecoverLease pins recovery
// authority: a recovery replica whose application clock is hours ahead must
// not recover a lease the DATABASE still considers live, and one whose clock
// is hours behind must still recover an actually expired lease.
func TestIntegrationAppClockSkewCannotPrematurelyRecoverLease(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, runnerID := leaseClockITSetup(t, st)
	if _, err := st.AcquireLeaseWithTTL(ctx, leaseClockITClaim(jobID, runnerID, 60*time.Second)); err != nil {
		t.Fatal(err)
	}
	// Clock 2h AHEAD: must not recover a DB-live lease.
	if err := st.RecoverExpiredLease(ctx, jobID, 1, time.Now().UTC().Add(2*time.Hour)); err != nil {
		t.Fatalf("skewed-ahead recovery: %v", err)
	}
	job, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != model.StatusRunning || job.LeaseExpiresAt == nil {
		t.Fatalf("DB-live lease was recovered by a skewed-ahead replica: %+v", job.Status)
	}
	// Clock 2h BEHIND: an actually expired lease must still be recovered.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	if err := st.RecoverExpiredLease(ctx, jobID, 1, time.Now().UTC().Add(-2*time.Hour)); err != nil {
		t.Fatalf("skewed-behind recovery: %v", err)
	}
	job, err = st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status == model.StatusRunning || job.LeaseExpiresAt != nil {
		t.Fatalf("expired lease not recovered by a skewed-behind replica: %+v", job.Status)
	}
}

// TestIntegrationRecoveryUsesDatabaseClock pins discovery and application
// both judge expiry at the database clock, ignoring the caller's now in both
// directions.
func TestIntegrationRecoveryUsesDatabaseClock(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, runnerID := leaseClockITSetup(t, st)
	if _, err := st.AcquireLeaseWithTTL(ctx, leaseClockITClaim(jobID, runnerID, 60*time.Second)); err != nil {
		t.Fatal(err)
	}
	// Discovery with a far-future caller clock must not list the live lease.
	cands, err := st.ListExpiredRunningJobs(ctx, time.Now().UTC().Add(2*time.Hour), "", 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cands {
		if c.ID == jobID {
			t.Fatal("discovery listed a DB-live lease because the caller clock was ahead")
		}
	}
	// Discovery with a far-past caller clock still lists an expired lease.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	cands, err = st.ListExpiredRunningJobs(ctx, time.Now().UTC().Add(-2*time.Hour), "", 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range cands {
		if c.ID == jobID {
			found = true
		}
	}
	if !found {
		t.Fatal("discovery missed an expired lease because the caller clock was behind")
	}
}

// TestIntegrationAppClockSkewCannotPrematurelyRejectLease pins the mirror
// direction: the store-level TTL heartbeat succeeds for a DB-live lease (no
// application instant participates) and fails only once the database clock
// shows it expired.
func TestIntegrationAppClockSkewCannotPrematurelyRejectLease(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, runnerID := leaseClockITSetup(t, st)
	if _, err := st.AcquireLeaseWithTTL(ctx, leaseClockITClaim(jobID, runnerID, 60*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.HeartbeatLeaseWithTTL(ctx, jobID, runnerID, 1, 60*time.Second); err != nil {
		t.Fatalf("DB-live lease rejected by a heartbeat: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id=$1`, jobID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.HeartbeatLeaseWithTTL(ctx, jobID, runnerID, 1, 60*time.Second); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("DB-expired lease accepted by a heartbeat: %v", err)
	}
}

// TestIntegrationCompletionRejectsLeaseExpiredWhileWaitingForLock pins the
// completion-time authority: completion is a lifecycle transition judged
// against the live database clock AFTER the row lock. A lease that expires
// while the completion waits on another transaction's row lock is refused
// with ErrLeaseConflict, so the first writer after expiry (here the old
// runner) cannot decide the outcome ahead of recovery.
func TestIntegrationCompletionRejectsLeaseExpiredWhileWaitingForLock(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	_, jobID, runnerID := leaseClockITSetup(t, st)
	if _, err := st.AcquireLeaseWithTTL(ctx, leaseClockITClaim(jobID, runnerID, 800*time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	tx, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT 1 FROM jobs WHERE id=$1 FOR UPDATE`, jobID); err != nil {
		t.Fatalf("lock job row: %v", err)
	}
	receipt := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "h"}
	done := make(chan error, 1)
	go func() {
		done <- st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, receipt, nil)
	}()
	select {
	case err := <-done:
		t.Fatalf("completion returned before the row lock was released: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	// Wait past the lease expiry, then release the row WITHOUT touching it.
	time.Sleep(900 * time.Millisecond)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit unchanged row: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrLeaseConflict) {
			t.Fatalf("completion after the lease expired while blocked = %v, want ErrLeaseConflict", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("completion did not finish")
	}
	job, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != model.StatusRunning {
		t.Fatalf("expired completion transitioned the job: %s", job.Status)
	}
	var receipts int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM completion_receipts WHERE job_id=$1`, jobID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 0 {
		t.Fatalf("expired completion persisted %d receipts", receipts)
	}
	var effects int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE payload->>'job_id'=$1`, jobID).Scan(&effects); err != nil {
		t.Fatal(err)
	}
	if effects != 0 {
		t.Fatalf("expired completion persisted %d completion effect intents", effects)
	}
}
