package server

// Durability/phase tests for OIDC key rotation against the shared cluster key
// store described by the fsutil typed-error contract:
//
//   - a post-rename (directory-fsync) failure means the new ring IS visible in
//     the store, so the rotation retains it in memory and arms the shared
//     degraded readiness marker until a later successful persist;
//   - a pre-rename failure means the material was definitely not published, so
//     the current ring stays active with no degraded marker;
//   - the cross-replica fence still produces exactly one rotation even when
//     the winner's persist is published-but-uncertain.

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/fsutil"
)

// rotationStoreServer builds a server whose OIDC signer persists through the
// supplied cluster store.
func rotationStoreServer(store ClusterKeyStore) *Server {
	s := New("shared-dev-tok")
	signer := newOIDCSigner()
	signer.cluster = store
	s.oidc = signer
	return s
}

// TestRotateOIDCDirSyncFailureRetainsPublishedRingAndDegrades: a directory
// fsync failure runs AFTER the rename, so the store already serves the new
// ring. The rotation must retain it in memory, arm the degraded marker, and a
// later successful persist must clear the marker.
func TestRotateOIDCDirSyncFailureRetainsPublishedRingAndDegrades(t *testing.T) {
	store := &FSClusterKeyStore{Dir: t.TempDir()}
	s := rotationStoreServer(store)
	old := s.oidc
	oldKID := old.KID
	if s.stateDegraded.Load() {
		t.Fatal("test setup: readiness unexpectedly degraded")
	}

	restore := fsutil.SetHooks(fsutil.Hooks{DirSync: func(string) error {
		return errors.New("injected directory fsync failure")
	}})
	s.rotateOIDCKeyLocked(time.Now().UTC())
	restore()

	if s.oidc == nil || s.oidc == old {
		t.Fatal("published-but-uncertain rotation must install the new ring in memory")
	}
	if s.oidc.KID == oldKID {
		t.Fatal("published-but-uncertain rotation kept the old active key")
	}
	if len(s.oidc.Previous) != 1 || s.oidc.Previous[0].KID != oldKID {
		t.Fatalf("retired ring = %+v, want the previous active key %q", s.oidc.Previous, oldKID)
	}
	if !s.stateDegraded.Load() {
		t.Fatal("published-but-uncertain rotation did not arm degraded readiness")
	}
	// The store's reads now return the retained ring, which is exactly why
	// retaining it (instead of rolling back) is the correct recovery.
	raw, found, err := store.Lookup(clusterKindOIDC)
	if err != nil || !found {
		t.Fatalf("published ring lookup: found=%v err=%v", found, err)
	}
	published, err := oidcSignerFromRing(raw)
	if err != nil {
		t.Fatalf("published ring parse: %v", err)
	}
	if published.KID != s.oidc.KID {
		t.Fatalf("retained ring kid %q != published ring kid %q", s.oidc.KID, published.KID)
	}

	// A subsequent successful persist reconciles the uncertainty.
	s.rotateOIDCKeyLocked(time.Now().UTC())
	if s.stateDegraded.Load() {
		t.Fatal("successful persist did not clear the degraded marker")
	}
}

// TestRotateOIDCPreRenameFailureKeepsOldRingCleanly: a failure before the
// rename means the material was definitely not published. The current ring
// stays active and readiness is untouched.
func TestRotateOIDCPreRenameFailureKeepsOldRingCleanly(t *testing.T) {
	faults := []struct {
		name  string
		hooks fsutil.Hooks
	}{
		{"file sync", fsutil.Hooks{FileSync: func(*os.File) error { return errors.New("injected file fsync failure") }}},
		{"close", fsutil.Hooks{FileClose: func(f *os.File) error {
			_ = fsutil.RealFileClose(f)
			return errors.New("injected close failure")
		}}},
		{"rename", fsutil.Hooks{Rename: func(string, string) error { return errors.New("injected rename failure") }}},
	}
	for _, fault := range faults {
		t.Run(fault.name, func(t *testing.T) {
			store := &FSClusterKeyStore{Dir: t.TempDir()}
			s := rotationStoreServer(store)
			old := s.oidc
			restore := fsutil.SetHooks(fault.hooks)
			s.rotateOIDCKeyLocked(time.Now().UTC())
			restore()
			if s.oidc != old {
				t.Fatal("definitely-not-published rotation must keep the current ring active")
			}
			if s.stateDegraded.Load() {
				t.Fatal("definitely-not-published rotation must not degrade readiness")
			}
		})
	}
}

// uncertainFencedStore publishes the bytes like the real store but reports a
// post-rename (dir-sync) failure, modeling a rename that is visible with
// uncertified crash durability.
type uncertainFencedStore struct {
	*fencedClusterStore
}

func (u *uncertainFencedStore) Store(kind string, data []byte) error {
	if err := u.fencedClusterStore.Store(kind, data); err != nil {
		return err
	}
	return &fsutil.AtomicWriteError{
		Path:    "oidc-keyring.json",
		Phase:   fsutil.PhaseDirSync,
		Renamed: true,
		Err:     errors.New("injected directory fsync failure"),
	}
}

// TestOIDCRotationPublishedUncertainSingleWinner: the fence still yields
// exactly one rotation when the winner's persist is published-but-uncertain.
// The loser re-reads the published ring inside the fence, sees it is no longer
// due, and adopts the winner's key instead of rotating again.
func TestOIDCRotationPublishedUncertainSingleWinner(t *testing.T) {
	oldMax := oidcActiveKeyMaxAge
	oidcActiveKeyMaxAge = time.Hour
	defer func() { oidcActiveKeyMaxAge = oldMax }()

	store := &uncertainFencedStore{newFencedClusterStore()}
	s1, err := NewPersistentWithCluster("t", "t", t.TempDir(), store)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := NewPersistentWithCluster("t", "t", t.TempDir(), store)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	makeOIDCDue(s1, now)
	makeOIDCDue(s2, now)

	var wg sync.WaitGroup
	kids := make([]string, 2)
	for i, s := range []*Server{s1, s2} {
		wg.Add(1)
		go func(i int, s *Server) {
			defer wg.Done()
			signer := s.ensureOIDCSigner(context.Background(), time.Now().UTC())
			if signer == nil {
				t.Error("ensureOIDCSigner returned nil")
				return
			}
			kids[i] = signer.KID
		}(i, s)
	}
	wg.Wait()

	if kids[0] == "" || kids[0] != kids[1] {
		t.Fatalf("replicas disagree on the winning key: %q vs %q", kids[0], kids[1])
	}
	if store.stores != 1 {
		t.Fatalf("rotation writes = %d, want exactly 1 (single winner)", store.stores)
	}
	stored := store.storedOIDC(t)
	if stored.KID != kids[0] {
		t.Fatalf("published ring active kid = %q, replicas issue under %q", stored.KID, kids[0])
	}
	// The winner surfaced the published-but-uncertain outcome, so readiness
	// must be degraded while the ring is retained.
	if !s1.stateDegraded.Load() && !s2.stateDegraded.Load() {
		t.Fatal("published-but-uncertain winner did not arm degraded readiness on either replica")
	}
}
