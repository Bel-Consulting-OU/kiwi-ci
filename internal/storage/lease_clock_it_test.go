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
	ctx := context.Background()
	runnerID = pgITNewID(t)
	if err := st.UpsertRunner(ctx, model.Runner{
		ID: runnerID, Name: runnerID, Capacity: 2,
		ReportedCapabilities: []string{"native"}, Capabilities: []string{"native"}, CapabilitiesEnforced: true,
	}); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	runID = pgITNewID(t)
	jobID = pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	return runID, jobID, runnerID
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
