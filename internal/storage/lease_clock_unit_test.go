package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestPostgresLeaseClockTTLValidation pins the DB-clock capability's input
// contract: a missing/zero TTL is refused before any statement runs (there is
// no application instant to fall back to on this path).
func TestPostgresLeaseClockTTLValidation(t *testing.T) {
	st := &PostgresStore{}
	if _, err := st.AcquireLeaseWithTTL(context.Background(), LeaseClaim{TTL: 0}); err == nil {
		t.Fatal("zero-TTL claim accepted")
	}
	if _, err := st.HeartbeatLeaseWithTTL(context.Background(), "0123456789abcdef0123456789abcdef", "runner", 1, 0); err == nil {
		t.Fatal("zero-TTL heartbeat accepted")
	}
}

// leaseClockMem adapts the in-memory store (single-process application
// clock) to the DB-clock capability interface so the fault wrapper's
// forwarding branches can be exercised without PostgreSQL.
type leaseClockMem struct{ *memStore }

func (l leaseClockMem) AcquireLeaseWithTTL(ctx context.Context, claim LeaseClaim) (model.Job, error) {
	return l.memStore.AcquireLeaseAtomic(ctx, claim)
}

func (l leaseClockMem) HeartbeatLeaseWithTTL(ctx context.Context, jobID, runnerID string, generation int64, ttl time.Duration) (time.Time, error) {
	exp := time.Now().UTC().Add(ttl)
	return exp, l.memStore.HeartbeatLease(ctx, jobID, runnerID, generation, exp)
}

// TestFaultyStoreLeaseClockForwarding pins the fault-injection wrapper for the
// new DB-clock capability: a missing inner store and an armed fault both fail
// before the call reaches a backing store.
func TestFaultyStoreLeaseClockForwarding(t *testing.T) {
	ctx := context.Background()
	f := &FaultyStore{}
	if _, err := f.AcquireLeaseWithTTL(ctx, LeaseClaim{TTL: time.Second}); err == nil {
		t.Fatal("missing-inner AcquireLeaseWithTTL succeeded")
	}
	if _, err := f.HeartbeatLeaseWithTTL(ctx, "0123456789abcdef0123456789abcdef", "runner", 1, time.Second); err == nil {
		t.Fatal("missing-inner HeartbeatLeaseWithTTL succeeded")
	}
	if _, err := f.PruneCacheManifests(ctx, CacheManifestPrunePolicy{PerRepoMaxEntries: 1}); err == nil {
		t.Fatal("missing-inner PruneCacheManifests succeeded")
	}

	armed := errors.New("injected fault")
	newArmed := func() *FaultyStore {
		return &FaultyStore{Inner: leaseClockMem{newMemStore()}, FailAfter: 1, Err: armed}
	}
	if _, err := newArmed().AcquireLeaseWithTTL(ctx, LeaseClaim{TTL: time.Second}); !errors.Is(err, armed) {
		t.Fatalf("armed AcquireLeaseWithTTL = %v, want the injected fault", err)
	}
	if _, err := newArmed().HeartbeatLeaseWithTTL(ctx, "0123456789abcdef0123456789abcdef", "runner", 1, time.Second); !errors.Is(err, armed) {
		t.Fatalf("armed HeartbeatLeaseWithTTL = %v, want the injected fault", err)
	}
	if _, err := newArmed().PruneCacheManifests(ctx, CacheManifestPrunePolicy{PerRepoMaxEntries: 1}); !errors.Is(err, armed) {
		t.Fatalf("armed PruneCacheManifests = %v, want the injected fault", err)
	}

	// Healthy forwarding reaches the backing store (the calls themselves
	// fail naturally on empty state, but the capability assertion and the
	// inner call lines are executed).
	healthy := &FaultyStore{Inner: leaseClockMem{newMemStore()}}
	if _, err := healthy.AcquireLeaseWithTTL(ctx, LeaseClaim{JobID: "0123456789abcdef0123456789abcdef", RunnerID: "runner", TTL: time.Second}); err == nil {
		t.Fatal("claim against an empty in-memory store succeeded")
	}
	if _, err := healthy.HeartbeatLeaseWithTTL(ctx, "0123456789abcdef0123456789abcdef", "runner", 1, time.Second); err == nil {
		t.Fatal("heartbeat against an empty in-memory store succeeded")
	}
	if _, err := healthy.PruneCacheManifests(ctx, CacheManifestPrunePolicy{PerRepoMaxEntries: 1}); err != nil {
		t.Fatalf("healthy PruneCacheManifests = %v", err)
	}
}
