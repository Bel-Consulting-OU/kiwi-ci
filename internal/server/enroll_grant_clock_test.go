package server

// Unit regressions for DB-mode enrollment grant clock authority: the durable
// store's clock decides creation expiry and gate liveness, never the serving
// replica's application clock.

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestEnrollGrantDBGateDoesNotUseApplicationClock pins the DB-mode gate: the
// store's clock decides liveness, so a skewed serving replica can neither
// admit a grant the database considers expired nor reject one it still
// considers live.
func TestEnrollGrantDBGateDoesNotUseApplicationClock(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	s.DB = f
	wall := time.Now().UTC()

	// Store clock two hours AHEAD: a grant seeded at wall+1h is expired by
	// the database even though the replica's wall clock says live.
	dbExpired := auth.TokenDigest("db-expired")
	f.mu.Lock()
	f.grants[dbExpired] = storage.EnrollGrantRecord{ExpiresAt: wall.Add(time.Hour)}
	f.leaseNow = func() time.Time { return wall.Add(2 * time.Hour) }
	f.mu.Unlock()
	if s.enrollGrantOK(context.Background(), "db-expired") {
		t.Fatal("gate admitted a database-expired grant: the application clock was used")
	}
	// The atomic claim must refuse it for the same reason.
	if err := s.consumeEnrollGrant(context.Background(), "db-expired", nil); err == nil {
		t.Fatal("consume admitted a database-expired grant")
	}

	// Store clock two hours BEHIND: a grant seeded at wall-1h is live by the
	// database even though wall time says expired.
	dbLive := auth.TokenDigest("db-live")
	f.mu.Lock()
	f.grants[dbLive] = storage.EnrollGrantRecord{ExpiresAt: wall.Add(-time.Hour)}
	f.leaseNow = func() time.Time { return wall.Add(-2 * time.Hour) }
	f.mu.Unlock()
	if !s.enrollGrantOK(context.Background(), "db-live") {
		t.Fatal("gate rejected a database-live grant: the application clock was used")
	}
	if err := s.consumeEnrollGrant(context.Background(), "db-live", nil); err != nil {
		t.Fatalf("consume rejected a database-live grant: %v", err)
	}
}

// TestCreateEnrollGrantUsesStoreClock pins DB-mode creation: the expiry is
// the store clock + TTL, never the serving replica's wall time.
func TestCreateEnrollGrantUsesStoreClock(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	s.DB = f
	dbNow := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	f.mu.Lock()
	f.leaseNow = func() time.Time { return dbNow }
	f.mu.Unlock()
	token, err := s.CreateEnrollGrant(context.Background(), 10*time.Minute, nil)
	if err != nil {
		t.Fatalf("CreateEnrollGrant: %v", err)
	}
	f.mu.Lock()
	rec := f.grants[auth.TokenDigest(token)]
	f.mu.Unlock()
	if !rec.ExpiresAt.Equal(dbNow.Add(10 * time.Minute)) {
		t.Fatalf("grant expiry %v, want the store clock + TTL %v", rec.ExpiresAt, dbNow.Add(10*time.Minute))
	}
}
