package storage

// Real-PostgreSQL integration tests for outbox claim-lease clock authority:
// the due predicate, the claim-lease cutoff and the claimed_at stamp all come
// from the database clock, so no application replica's skew can steal a live
// claim or strand a dead owner's claim.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// setOutboxClaimAge rewrites one row's claim age relative to the DATABASE
// clock, modelling the passage of time without sleeping.
func setOutboxClaimAge(t *testing.T, st *PostgresStore, id string, age time.Duration) {
	t.Helper()
	if _, err := st.pool.Exec(context.Background(), `UPDATE outbox SET claimed_at = clock_timestamp() - make_interval(secs => $2::double precision) WHERE id=$1`, id, age.Seconds()); err != nil {
		t.Fatal(err)
	}
}

// TestIntegrationOutboxClaimTTLUsesDatabaseClock pins the claim lease: a
// claim younger than OutboxClaimTTL is not reclaimable, one older than the
// TTL is — both decided by the database clock.
func TestIntegrationOutboxClaimTTLUsesDatabaseClock(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	id := "claim-clock-" + pgITNewID(t)
	if err := st.OutboxAppend(ctx, OutboxItem{ID: id, Kind: "test"}); err != nil {
		t.Fatal(err)
	}
	claimed, err := st.ClaimOutbox(ctx, "flusher-a", 1)
	if err != nil || len(claimed) != 1 || claimed[0].ID != id {
		t.Fatalf("initial claim = %+v err=%v", claimed, err)
	}

	// Half the TTL old: still this claimer's.
	setOutboxClaimAge(t, st, id, OutboxClaimTTL/2)
	if got, err := st.ClaimOutbox(ctx, "flusher-b", 1); err != nil || len(got) != 0 {
		t.Fatalf("live claim was stolen: %+v err=%v", got, err)
	}

	// Older than the TTL: reclaimable.
	setOutboxClaimAge(t, st, id, OutboxClaimTTL+time.Second)
	got, err := st.ClaimOutbox(ctx, "flusher-b", 1)
	if err != nil || len(got) != 1 || got[0].ID != id {
		t.Fatalf("expired claim was not reclaimed: %+v err=%v", got, err)
	}
	// The reclaim stamped a fresh database claim time.
	var behind bool
	if err := st.pool.QueryRow(ctx, `SELECT claimed_at < clock_timestamp() - interval '5 seconds' FROM outbox WHERE id=$1`, id).Scan(&behind); err != nil {
		t.Fatal(err)
	}
	if behind {
		t.Fatal("reclaim did not stamp a fresh database claim time")
	}
}

// TestIntegrationOutboxClaimTimestampIsPostWaitClock pins that claimed_at is
// the live database clock at UPDATE time: after an artificial age reset, a
// claim stamps now, not the transaction start.
func TestIntegrationOutboxClaimTimestampIsPostWaitClock(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	id := "claim-stamp-" + pgITNewID(t)
	if err := st.OutboxAppend(ctx, OutboxItem{ID: id, Kind: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ClaimOutbox(ctx, "flusher-a", 1); err != nil {
		t.Fatal(err)
	}
	setOutboxClaimAge(t, st, id, OutboxClaimTTL+time.Minute)
	before := leaseClockITDBNow(t, st)
	if _, err := st.ClaimOutbox(ctx, "flusher-b", 1); err != nil {
		t.Fatal(err)
	}
	after := leaseClockITDBNow(t, st)
	var claimedAt time.Time
	if err := st.pool.QueryRow(ctx, `SELECT claimed_at FROM outbox WHERE id=$1`, id).Scan(&claimedAt); err != nil {
		t.Fatal(err)
	}
	if claimedAt.UTC().Before(before.Add(-time.Second)) || claimedAt.UTC().After(after.Add(time.Second)) {
		t.Fatalf("claimed_at %v outside the database claim window [%v, %v]", claimedAt, before, after)
	}
}

// TestIntegrationOutboxConcurrentClaimersExactlyOneBeforeTTL races two
// flushers for one fresh row: exactly one claims it, and the durable claim
// records that winner.
func TestIntegrationOutboxConcurrentClaimersExactlyOneBeforeTTL(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	id := "claim-race-" + pgITNewID(t)
	if err := st.OutboxAppend(ctx, OutboxItem{ID: id, Kind: "test"}); err != nil {
		t.Fatal(err)
	}
	const workers = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners []string
		errs    []error
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			claimer := "flusher-" + string(rune('a'+i))
			items, err := st.ClaimOutbox(ctx, claimer, 1)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			for _, it := range items {
				if it.ID == id {
					winners = append(winners, claimer)
				}
			}
		}(i)
	}
	wg.Wait()
	if len(errs) != 0 {
		t.Fatalf("claim errors: %v", errs)
	}
	if len(winners) != 1 {
		t.Fatalf("winners = %v, want exactly one", winners)
	}
	var claimer *string
	if err := st.pool.QueryRow(ctx, `SELECT claimed_by FROM outbox WHERE id=$1`, id).Scan(&claimer); err != nil {
		t.Fatal(err)
	}
	if claimer == nil || *claimer != winners[0] {
		t.Fatalf("durable claimer = %v, want %s", claimer, winners[0])
	}
}

// TestPostgresOutboxClaimStatementUsesDatabaseClock is the source contract for
// the claim clock domain: the due predicate, cutoff and stamp must all be
// clock_timestamp() (with the TTL passed as an interval), and the Go-side
// cutoff must not reappear. Mutation-testing this contract is deleting the
// SQL clock expressions; this test then fails.
func TestPostgresOutboxClaimStatementUsesDatabaseClock(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	src, err := os.ReadFile(filepath.Join(filepath.Dir(file), "postgres.go"))
	if err != nil {
		t.Fatal(err)
	}
	code := string(src)
	for _, needle := range []string{
		"claimed_at = clock_timestamp(), claimed_by = $1",
		"next_attempt_at <= clock_timestamp()",
		"claimed_at < clock_timestamp() - make_interval(secs => $3::double precision)",
	} {
		if !strings.Contains(code, needle) {
			t.Fatalf("outbox claim lost its database-clock expression %q", needle)
		}
	}
	if strings.Contains(code, "time.Now().UTC().Add(-OutboxClaimTTL)") {
		t.Fatal("outbox claim reintroduced an application-clock cutoff")
	}
}

// TestIntegrationClockStoreNowUsesDatabaseClock pins the shared clock
// capability: Now returns the live database clock within the round-trip
// window, so DB-mode policy decisions (schedule due evaluation) share one
// clock domain across replicas.
func TestIntegrationClockStoreNowUsesDatabaseClock(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	before := leaseClockITDBNow(t, st)
	got, err := st.Now(ctx)
	if err != nil {
		t.Fatalf("Now: %v", err)
	}
	after := leaseClockITDBNow(t, st)
	if got.Before(before.Add(-time.Second)) || got.After(after.Add(time.Second)) {
		t.Fatalf("Now = %v outside the database window [%v, %v]", got, before, after)
	}
}
