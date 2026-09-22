package server

// Branch coverage for the OIDC ring's failure paths: a rotation whose ring
// cannot be persisted must keep the CURRENT active key everywhere (never a
// ring only this replica can verify), and a key store that supports neither
// the context-aware nor the plain lookup surface contributes nothing.

import (
	"testing"
	"time"
)

// TestRotateOIDCKeyKeepsRingOnPersistFailure: when the shared key store
// cannot write, the rotation aborts before activation, so issued tokens stay
// verifiable and peers keep serving the same active key.
func TestRotateOIDCKeyKeepsRingOnPersistFailure(t *testing.T) {
	s := New("shared-dev-tok")
	signer := newOIDCSigner()
	// A cluster store that cannot write (only LoadOrCreate): the persist
	// step must refuse rather than activate the new ring.
	signer.cluster = failingClusterStore{}
	s.oidc = signer
	before := s.oidc
	beforeKID := s.oidc.KID
	beforePublic := string(s.oidc.Public)

	s.rotateOIDCKeyLocked(time.Now().UTC())

	if s.oidc != before {
		t.Fatal("rotation swapped the ring despite a failed persist")
	}
	if s.oidc.KID != beforeKID || string(s.oidc.Public) != beforePublic {
		t.Fatalf("active key changed: kid=%q", s.oidc.KID)
	}
	if len(s.oidc.Previous) != 0 {
		t.Fatalf("failed rotation retired a key: %d previous entries", len(s.oidc.Previous))
	}

	// With a writable store the same call rotates (proving the guard above
	// is what stopped it).
	s2 := New("shared-dev-tok")
	store := &StaticClusterKeyStore{Keys: map[string][]byte{}}
	signer2 := newOIDCSigner()
	signer2.cluster = store
	s2.oidc = signer2
	s2.rotateOIDCKeyLocked(time.Now().UTC())
	if s2.oidc == signer2 || s2.oidc.KID == signer2.KID {
		t.Fatal("writable store did not publish a fresh ring")
	}
	if len(s2.oidc.Previous) != 1 {
		t.Fatalf("previous ring entries = %d, want the retired key", len(s2.oidc.Previous))
	}
}

// TestLookupOIDCRingBytesWithoutLookupSurface: a store that implements only
// the load-or-create contract has no ring to refresh, so the lookup reports
// "nothing found" without error and the caller keeps its current signer.
func TestLookupOIDCRingBytesWithoutLookupSurface(t *testing.T) {
	s := New("shared-dev-tok")
	b, found, err := s.lookupOIDCRingBytes(t.Context(), failingClusterStore{err: errSeamEntropy})
	if err != nil || found || b != nil {
		t.Fatalf("store-less lookup = (%d bytes, %v, %v), want not found", len(b), found, err)
	}
	// A store with the plain lookup surface is still consulted (and a
	// cancelable context is not required for it).
	fixed := fixedLookupStore{b: []byte("ring"), found: true}
	b, found, err = s.lookupOIDCRingBytes(t.Context(), fixed)
	if err != nil || !found || string(b) != "ring" {
		t.Fatalf("plain lookup = (%q, %v, %v)", b, found, err)
	}
}
