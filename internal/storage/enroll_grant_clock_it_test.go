package storage

// Real-PostgreSQL integration tests for enrollment-grant clock authority:
// creation derives the expiry from the database clock (TTL input, never an
// absolute instant), the gate evaluates liveness in that clock domain, and
// consumption re-evaluates expiry at UPDATE time so a row-lock wait cannot
// outlive the grant.

import (
	"context"
	"errors"
	"testing"
	"time"
)

func enrollGrantDigest(t *testing.T) string {
	t.Helper()
	return "digest-" + pgITNewID(t)
}

// TestIntegrationEnrollGrantTTLUsesDatabaseClock pins creation: the returned
// expiry and the stored column are clock_timestamp()+TTL at the database,
// with no application-clock input anywhere in the API.
func TestIntegrationEnrollGrantTTLUsesDatabaseClock(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	digest := enrollGrantDigest(t)
	before := leaseClockITDBNow(t, st)
	expires, err := st.PutEnrollGrantWithTTL(ctx, digest, 10*time.Minute, []string{"linux"})
	if err != nil {
		t.Fatalf("PutEnrollGrantWithTTL: %v", err)
	}
	after := leaseClockITDBNow(t, st)
	wantMin, wantMax := before.Add(10*time.Minute-time.Second), after.Add(10*time.Minute+time.Second)
	if expires.Before(wantMin) || expires.After(wantMax) {
		t.Fatalf("expiry %v outside the database window [%v, %v]", expires, wantMin, wantMax)
	}
	var col time.Time
	if err := st.pool.QueryRow(ctx, `SELECT expires_at FROM enrollment_grants WHERE digest=$1`, digest).Scan(&col); err != nil {
		t.Fatal(err)
	}
	if !col.UTC().Equal(expires) {
		t.Fatalf("stored expires_at %v != returned %v", col.UTC(), expires)
	}
}

// TestIntegrationEnrollGrantReplicaAheadCannotExtendLifetime pins the
// ahead-skew case structurally: the API takes a duration, so there is no
// absolute instant a fast replica could inflate; the lifetime is exactly the
// TTL from the database commit clock.
func TestIntegrationEnrollGrantReplicaAheadCannotExtendLifetime(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	digest := enrollGrantDigest(t)
	before := leaseClockITDBNow(t, st)
	expires, err := st.PutEnrollGrantWithTTL(ctx, digest, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Even a replica claiming to be arbitrarily ahead cannot make the grant
	// outlive DB-now+TTL: that is the only input path.
	if expires.After(before.Add(time.Minute + time.Second)) {
		t.Fatalf("grant expiry %v exceeds DB now+TTL (%v)", expires, before.Add(time.Minute))
	}
}

// TestIntegrationEnrollGrantReplicaBehindCannotPreExpireGrant pins the
// behind-skew case: the database clock decides the grant is live, so a slow
// replica's application time can neither reject it at the gate nor prevent
// consumption.
func TestIntegrationEnrollGrantReplicaBehindCannotPreExpireGrant(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	digest := enrollGrantDigest(t)
	if _, err := st.PutEnrollGrantWithTTL(ctx, digest, time.Minute, nil); err != nil {
		t.Fatal(err)
	}
	if live, err := st.EnrollGrantLive(ctx, digest); err != nil || !live {
		t.Fatalf("EnrollGrantLive = %v err=%v, want live", live, err)
	}
	if _, err := st.ConsumeEnrollGrant(ctx, digest, "runner-1"); err != nil {
		t.Fatalf("ConsumeEnrollGrant: %v", err)
	}
}

// TestIntegrationEnrollGrantExpiresWhileConsumeWaitsForRowLock pins the
// post-lock clock rule: a consumer that begins before expiry but waits on the
// grant row past it loses, because the UPDATE re-evaluates
// expires_at > clock_timestamp() when it finally runs. Nothing is consumed.
func TestIntegrationEnrollGrantExpiresWhileConsumeWaitsForRowLock(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	digest := enrollGrantDigest(t)
	if _, err := st.PutEnrollGrantWithTTL(ctx, digest, 800*time.Millisecond, nil); err != nil {
		t.Fatal(err)
	}

	tx, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT 1 FROM enrollment_grants WHERE digest=$1 FOR UPDATE`, digest); err != nil {
		t.Fatalf("lock grant row: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := st.ConsumeEnrollGrant(ctx, digest, "runner-1")
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("consume returned before the row lock was released: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	time.Sleep(900 * time.Millisecond)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit unchanged grant row: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrGrantExpired) {
			t.Fatalf("consume after waiting past expiry = %v, want ErrGrantExpired", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("consume did not finish")
	}
	var consumedAt *time.Time
	if err := st.pool.QueryRow(ctx, `SELECT consumed_at FROM enrollment_grants WHERE digest=$1`, digest).Scan(&consumedAt); err != nil {
		t.Fatal(err)
	}
	if consumedAt != nil {
		t.Fatal("expired grant was marked consumed after the lock wait")
	}
}

// TestIntegrationEnrollGrantConsumedAtUsesCommitClock pins consumption: the
// consumed_at column is the database clock at UPDATE time, so the audit
// instant of a single-use credential is not a replica's wall time.
func TestIntegrationEnrollGrantConsumedAtUsesCommitClock(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	digest := enrollGrantDigest(t)
	if _, err := st.PutEnrollGrantWithTTL(ctx, digest, time.Minute, nil); err != nil {
		t.Fatal(err)
	}
	before := leaseClockITDBNow(t, st)
	if _, err := st.ConsumeEnrollGrant(ctx, digest, "runner-1"); err != nil {
		t.Fatal(err)
	}
	after := leaseClockITDBNow(t, st)
	var consumedAt time.Time
	var consumedBy string
	if err := st.pool.QueryRow(ctx, `SELECT consumed_at, consumed_by FROM enrollment_grants WHERE digest=$1`, digest).Scan(&consumedAt, &consumedBy); err != nil {
		t.Fatal(err)
	}
	if consumedAt.UTC().Before(before.Add(-time.Second)) || consumedAt.UTC().After(after.Add(time.Second)) {
		t.Fatalf("consumed_at %v outside the database window [%v, %v]", consumedAt, before, after)
	}
	if consumedBy != "runner-1" {
		t.Fatalf("consumed_by = %q", consumedBy)
	}
}
