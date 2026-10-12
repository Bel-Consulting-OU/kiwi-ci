package verifyapi

import (
	"errors"
	"testing"
	"time"
)

// TestLeaseRegistryRegisterAndExpire: a live lease is discoverable, an
// expired lease disappears (expiry is the cluster semantics of a dynamic
// capability), and a dead row never blocks a new registration.
func TestLeaseRegistryRegisterAndExpire(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	reg := NewLeaseRegistry(func() time.Time { return now })
	c := baseCapability()

	if err := reg.Register(c, "verifier-a", time.Minute); err != nil {
		t.Fatalf("Register = %v", err)
	}
	if !reg.Live(c) {
		t.Fatal("live lease reported dead")
	}
	if got := reg.Query(CapabilityQuery{Kind: c.Kind}); len(got) != 1 {
		t.Fatalf("query = %d rows, want 1", len(got))
	}

	// Advance past the lease: the capability stops being advertised.
	now = now.Add(2 * time.Minute)
	if reg.Live(c) {
		t.Fatal("expired lease reported live")
	}
	if got := reg.Query(CapabilityQuery{}); len(got) != 0 {
		t.Fatalf("query after expiry = %d rows, want 0", len(got))
	}

	// Expire sweeps dead rows; Query above already pruned this one.
	if err := reg.Register(c, "verifier-c", time.Minute); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if n := reg.Expire(); n != 1 {
		t.Fatalf("Expire removed %d, want 1", n)
	}
	if n := reg.Expire(); n != 0 {
		t.Fatalf("Expire again removed %d, want 0", n)
	}

	// A dead row never blocks a new holder.
	if err := reg.Register(c, "verifier-b", time.Minute); err != nil {
		t.Fatalf("Register after expiry = %v", err)
	}
	if !reg.Live(c) {
		t.Fatal("replacement lease reported dead")
	}
}

// TestLeaseRegistryHolderRules: a competitor cannot steal a live lease; the
// same holder renews; renewal of an expired or foreign lease is refused.
func TestLeaseRegistryHolderRules(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	reg := NewLeaseRegistry(func() time.Time { return now })
	c := baseCapability()

	if err := reg.Register(c, "verifier-a", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(c, "verifier-b", time.Minute); !errors.Is(err, ErrExists) {
		t.Fatalf("steal live lease = %v, want ErrExists", err)
	}
	if err := reg.Register(c, "verifier-a", 2*time.Minute); err != nil {
		t.Fatalf("same-holder re-register = %v", err)
	}
	if err := reg.Renew(c, "verifier-b", time.Minute); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("foreign Renew = %v, want ErrUnauthorized", err)
	}
	if err := reg.Renew(c, "verifier-a", time.Minute); err != nil {
		t.Fatalf("same-holder Renew = %v", err)
	}

	// Expire, then renewal is refused (proof of liveness, not takeover).
	now = now.Add(10 * time.Minute)
	if err := reg.Renew(c, "verifier-a", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Renew after expiry = %v, want ErrNotFound", err)
	}
	if err := reg.Register(c, "verifier-a", time.Minute); err != nil {
		t.Fatalf("re-register after expiry = %v", err)
	}
	if err := reg.Revoke(c, "verifier-b"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("foreign Revoke = %v, want ErrUnauthorized", err)
	}
	if err := reg.Revoke(c, "verifier-a"); err != nil {
		t.Fatalf("Revoke = %v", err)
	}
	if reg.Live(c) {
		t.Fatal("revoked lease reported live")
	}
}

// TestLeaseRegistryValidateFailClosed: invalid capabilities, empty holders
// and non-positive TTLs are refused before anything is stored.
func TestLeaseRegistryValidateFailClosed(t *testing.T) {
	reg := NewLeaseRegistry(nil)
	c := baseCapability()
	if err := reg.Register(c, "", time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty holder = %v, want ErrInvalid", err)
	}
	if err := reg.Register(c, "h", 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero ttl = %v, want ErrInvalid", err)
	}
	bad := c
	bad.Kind = ""
	if err := reg.Register(bad, "h", time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid capability = %v, want ErrInvalid", err)
	}
	if err := reg.Renew(c, "", time.Minute); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Renew empty holder = %v, want ErrInvalid", err)
	}
}

// TestLeaseRegistryQueryFilter: the live query applies the same AND-across-
// dimensions filter as the static registry, and ordering is (kind, version).
func TestLeaseRegistryQueryFilter(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)
	reg := NewLeaseRegistry(func() time.Time { return now })
	a := baseCapability()
	b := VerifierCapability{
		Kind:            "policy-audit",
		Version:         "v1",
		ClaimClasses:    []string{"policy"},
		AssuranceLevels: []string{"basic"},
		Platforms:       []string{"any"},
		EvidenceTypes:   []string{"json-report"},
	}
	if err := reg.Register(a, "h1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(b, "h2", time.Minute); err != nil {
		t.Fatal(err)
	}
	all := reg.Query(CapabilityQuery{})
	if len(all) != 2 {
		t.Fatalf("zero query = %d, want 2", len(all))
	}
	if all[0].Kind != "execution-attestation" || all[1].Kind != "policy-audit" {
		t.Fatalf("query order = %q, %q", all[0].Kind, all[1].Kind)
	}
	if got := reg.Query(CapabilityQuery{Platform: "linux/amd64"}); len(got) != 1 || got[0].Kind != "execution-attestation" {
		t.Fatalf("platform filter = %v", got)
	}
	if got := reg.Query(CapabilityQuery{Kind: "nope"}); len(got) != 0 {
		t.Fatalf("unknown kind filter = %v, want empty", got)
	}
}
