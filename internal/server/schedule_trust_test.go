package server

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestTrustedScheduleRevokedCreatorSkipsOccurrence proves trusted schedules
// are a revocable delegation: when the creator principal loses trusted_run
// (or disappears), automatic firing skips the occurrence with an audit line
// instead of producing a trusted run.
func TestTrustedScheduleRevokedCreatorSkipsOccurrence(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := auth.NewTokenStore()
	creator := auth.Principal{
		Subject: "alice",
		Roles:   []auth.Role{auth.RolePolicyManage, auth.RoleTrustedRun},
	}
	if err := store.AddToken("alice-token", creator); err != nil {
		t.Fatal(err)
	}
	s.AuthStore = store

	sc := storage.Schedule{
		ID: "sched1", Repository: "acme/app", RepoID: "github.com/acme/app",
		RepoURL: "https://github.com/acme/app.git", Forge: "github",
		Trusted: true, Enabled: true, CreatedBy: "alice",
		Spec: "version: 1\non:\n  schedule:\n    cron: \"* * * * *\"\njobs:\n  build:\n    runtime: container\n    image: alpine\n    steps:\n      - run: echo hi\n",
	}
	ctx := context.Background()
	nominal := time.Now().UTC().Truncate(time.Minute)

	// Creator still authorized: the occurrence fires.
	if _, fired, err := s.fireSchedule(ctx, sc, nominal); err != nil || !fired {
		t.Fatalf("authorized fire: fired=%v err=%v", fired, err)
	}

	// Revoke: replace the store with one that no longer grants trusted_run.
	revoked := auth.NewTokenStore()
	if err := revoked.AddToken("alice-token", auth.Principal{Subject: "alice", Roles: []auth.Role{auth.RolePolicyManage}}); err != nil {
		t.Fatal(err)
	}
	s.AuthStore = revoked
	nominal2 := nominal.Add(time.Minute)
	if _, fired, err := s.fireSchedule(ctx, sc, nominal2); err == nil || fired {
		t.Fatalf("revoked fire must be skipped with an error sentinel: fired=%v err=%v", fired, err)
	}

	// Creator missing while OTHER principals exist: skipped (fail closed).
	other := auth.NewTokenStore()
	if err := other.AddToken("bob-token", auth.Principal{Subject: "bob", Roles: []auth.Role{auth.RolePolicyManage}}); err != nil {
		t.Fatal(err)
	}
	s.AuthStore = other
	if _, fired, err := s.fireSchedule(ctx, sc, nominal.Add(2*time.Minute)); err == nil || fired {
		t.Fatalf("missing creator must skip: fired=%v err=%v", fired, err)
	}

	// Open mode (nil or empty store) preserves historical behavior.
	s.AuthStore = nil
	if _, fired, err := s.fireSchedule(ctx, sc, nominal.Add(3*time.Minute)); err != nil || !fired {
		t.Fatalf("legacy open mode must fire: fired=%v err=%v", fired, err)
	}
}
