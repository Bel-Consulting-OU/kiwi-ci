package portableproof

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

// Offline-root signed discovery with anti-rollback: a replayed older
// document must never hide a later revocation.

func TestSignedDiscoveryAntiRollback(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	proofPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := PublishDoc("pk-1", proofPub, KeyActive, now, "genesis")
	if err != nil {
		t.Fatal(err)
	}

	d1 := NewDiscovery(now)
	d1.Sequence = 1
	d1.ExpiresAt = now.Add(24 * time.Hour)
	d1.Keys = []PublicKeyDoc{doc}
	s1, err := SignDiscovery(d1, "root-1", rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	st1, err := VerifySignedDiscovery(s1, rootPub, DiscoveryState{}, now)
	if err != nil {
		t.Fatalf("genesis discovery = %v", err)
	}
	if st1.Sequence != 1 {
		t.Fatalf("state sequence = %d", st1.Sequence)
	}

	// Revocation publication at sequence 2.
	d2 := NewDiscovery(now.Add(time.Hour))
	d2.Sequence = 2
	d2.ExpiresAt = now.Add(48 * time.Hour)
	d2.PredecessorHash = st1.PredecessorHash
	revoked := doc
	revoked.Status = KeyRevoked
	d2.Keys = []PublicKeyDoc{revoked}
	s2, err := SignDiscovery(d2, "root-1", rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	st2, err := VerifySignedDiscovery(s2, rootPub, st1, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("revocation discovery = %v", err)
	}

	// Replay of the OLD still-signed document after the revocation: refused.
	if _, err := VerifySignedDiscovery(s1, rootPub, st2, now.Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("replayed older discovery = %v, want ErrRollback", err)
	}

	// Expired document is refused even with a valid signature.
	expired := d1
	expired.ExpiresAt = now.Add(-time.Minute)
	sExp, err := SignDiscovery(expired, "root-1", rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedDiscovery(sExp, rootPub, DiscoveryState{}, now); err == nil {
		t.Fatal("expired discovery must be refused")
	}

	// Wrong root key fails the signature.
	if _, err := VerifySignedDiscovery(s2, proofPub, st1, now.Add(time.Hour)); err == nil {
		t.Fatal("wrong root key must be refused")
	}

	// Tampered sequence breaks the root signature.
	bad := s2
	bad.Discovery.Sequence = 99
	if _, err := VerifySignedDiscovery(bad, rootPub, st1, now.Add(time.Hour)); err == nil {
		t.Fatal("tampered discovery must be refused")
	}
}

func TestSignedDiscoveryChainBreakRefused(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	d1 := NewDiscovery(now)
	d1.Sequence = 1
	d1.ExpiresAt = now.Add(time.Hour)
	s1, err := SignDiscovery(d1, "root", rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	st1, err := VerifySignedDiscovery(s1, rootPub, DiscoveryState{}, now)
	if err != nil {
		t.Fatal(err)
	}
	d2 := NewDiscovery(now)
	d2.Sequence = 2
	d2.ExpiresAt = now.Add(2 * time.Hour)
	d2.PredecessorHash = strings.Repeat("0", 64) // wrong chain link
	s2, err := SignDiscovery(d2, "root", rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySignedDiscovery(s2, rootPub, st1, now); err == nil || !strings.Contains(err.Error(), "predecessor") {
		t.Fatalf("broken chain = %v, want predecessor refusal", err)
	}
}
