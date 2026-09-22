package storage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestMemStoreProfilesAndTokens exercises the migration-0006 interfaces on
// the in-memory store: profile CRUD, cert binding, per-runner tokens and
// revocations.
func TestMemStoreProfilesAndTokens(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	p := model.RunnerProfile{ID: "builders", Labels: []string{"container"}, Region: "east", Capabilities: []string{"container"}, MaxCapacity: 3, CostPerHour: 1.5, PowerWatts: 100}
	if err := m.UpsertProfile(ctx, p); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetProfile(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing profile: %v", err)
	}
	if err := m.BindCertProfile(ctx, "0cafe", "builders"); err != nil {
		t.Fatal(err)
	}
	got, ok, err := m.ProfileForSerial(ctx, "0cafe")
	if err != nil || !ok || got.ID != "builders" || got.MaxCapacity != 3 {
		t.Fatalf("ProfileForSerial: %+v ok=%v err=%v", got, ok, err)
	}
	if _, ok, err := m.ProfileForSerial(ctx, "unknown"); err != nil || ok {
		t.Fatalf("unbound serial: ok=%v err=%v", ok, err)
	}

	// Runner IDs are validated 32-hex identifiers; the revocation below goes
	// through the production disable transaction, which enforces that.
	const runnerA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := m.UpsertRunnerToken(ctx, runnerA, "digest-a"); err != nil {
		t.Fatal(err)
	}
	if id, ok, err := m.RunnerIDForToken(ctx, "digest-a"); err != nil || !ok || id != runnerA {
		t.Fatalf("token lookup: %q %v %v", id, ok, err)
	}
	if has, err := m.HasRunnerTokens(ctx); err != nil || !has {
		t.Fatalf("HasRunnerTokens: %v %v", has, err)
	}

	if err := m.UpsertRunner(ctx, model.Runner{ID: runnerA, Name: runnerA, Capacity: 1, CertSerial: "0cafe"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.DisableRunnerAndRevokeCert(ctx, runnerA, "0cafe", "admin"); err != nil {
		t.Fatal(err)
	}
	if revoked, err := m.CertRevoked(ctx, "0cafe"); err != nil || !revoked {
		t.Fatalf("CertRevoked: %v %v", revoked, err)
	}
}

// TestMemStoreConcurrentGrantConsumeOneWinner: the memStore's conditional
// consume yields exactly one winner among concurrent consumers.
func TestMemStoreConcurrentGrantConsumeOneWinner(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	if err := m.PutEnrollGrant(ctx, "digest", time.Now().Add(time.Hour), []string{"a"}); err != nil {
		t.Fatal(err)
	}
	const n = 16
	var wins int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.ConsumeEnrollGrant(ctx, "digest", "runner-x")
			if err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			} else if !errors.Is(err, ErrGrantConsumed) {
				t.Errorf("unexpected consume error: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("winners = %d, want exactly 1", wins)
	}
	if _, err := m.ConsumeEnrollGrant(ctx, "missing", "runner-x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown digest: %v", err)
	}
	if err := m.PutEnrollGrant(ctx, "expired", time.Now().Add(-time.Minute), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ConsumeEnrollGrant(ctx, "expired", "runner-x"); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("expired grant: %v", err)
	}
}
