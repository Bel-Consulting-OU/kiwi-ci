package app

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// Capability-shape stores for the startup validator: every embedded interface
// contributes its method set, so the struct value satisfies exactly the
// interfaces listed. Nil embedded values are never called — the validator only
// type-asserts.
type completeDBStore struct {
	storage.Store
	storage.DigestFenceStore
	storage.CASGCLeaseStore
	storage.LeaseCommitStore
	storage.RunnerTokenStore
}

type noFenceDBStore struct {
	storage.Store
	storage.CASGCLeaseStore
	storage.LeaseCommitStore
	storage.RunnerTokenStore
}

type noCASGCLeaseDBStore struct {
	storage.Store
	storage.DigestFenceStore
	storage.LeaseCommitStore
	storage.RunnerTokenStore
}

type noLeaseCommitDBStore struct {
	storage.Store
	storage.DigestFenceStore
	storage.CASGCLeaseStore
	storage.RunnerTokenStore
}

type noRunnerTokenDBStore struct {
	storage.Store
	storage.DigestFenceStore
	storage.CASGCLeaseStore
	storage.LeaseCommitStore
}

// TestValidateDBStoreCapabilities proves the enforced DB-mode capability set
// rejects any store missing one of the mandatory contracts and names the
// missing one. The three unconditional contracts are DigestFenceStore,
// CASGCLeaseStore and LeaseCommitStore.
func TestValidateDBStoreCapabilities(t *testing.T) {
	if err := validateDBStoreCapabilities(nil, true); err != nil {
		t.Fatalf("memory/fs mode (nil store) = %v, want nil", err)
	}
	if err := validateDBStoreCapabilities(completeDBStore{}, false); err != nil {
		t.Fatalf("complete store = %v, want nil", err)
	}
	cases := []struct {
		name string
		db   storage.Store
		want string
	}{
		{"missing fence", noFenceDBStore{}, "DigestFenceStore"},
		{"missing gc lease", noCASGCLeaseDBStore{}, "CASGCLeaseStore"},
		{"missing lease commit", noLeaseCommitDBStore{}, "LeaseCommitStore"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDBStoreCapabilities(tc.db, false)
			if err == nil {
				t.Fatalf("store missing %s was accepted", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the missing capability %s", err, tc.want)
			}
			if !strings.Contains(err.Error(), "refusing to start") {
				t.Fatalf("error %q is not a startup refusal", err)
			}
		})
	}
}

// TestValidateDBStoreCapabilitiesRunnerTokensConditional proves
// RunnerTokenStore is enforced only when per-runner bearer tokens are
// configured for provisioning ("where applicable").
func TestValidateDBStoreCapabilitiesRunnerTokensConditional(t *testing.T) {
	if err := validateDBStoreCapabilities(noRunnerTokenDBStore{}, false); err != nil {
		t.Fatalf("store without RunnerTokenStore and no runner tokens = %v, want nil", err)
	}
	err := validateDBStoreCapabilities(noRunnerTokenDBStore{}, true)
	if err == nil {
		t.Fatal("store without RunnerTokenStore accepted with runner tokens configured")
	}
	if !strings.Contains(err.Error(), "RunnerTokenStore") {
		t.Fatalf("error %q does not name RunnerTokenStore", err)
	}
	if !strings.Contains(err.Error(), "DigestFenceStore") {
		t.Fatalf("error %q does not report the enforced set", err)
	}
}

// TestRequiredDBStoreCapabilitiesReportsEnforcedSet pins the reported set so
// the startup error (and this test) always state exactly what DB mode
// enforces.
func TestRequiredDBStoreCapabilitiesReportsEnforcedSet(t *testing.T) {
	reqs := requiredDBStoreCapabilities(completeDBStore{}, true)
	var names []string
	for _, r := range reqs {
		if !r.Held {
			t.Fatalf("complete store reports %s missing", r.Name)
		}
		names = append(names, r.Name)
	}
	want := []string{"DigestFenceStore", "CASGCLeaseStore", "LeaseCommitStore", "RunnerTokenStore"}
	if len(names) != len(want) {
		t.Fatalf("enforced set = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("enforced set = %v, want %v", names, want)
		}
	}
	if got := requiredDBStoreCapabilities(nil, true); got != nil {
		t.Fatalf("nil store requirements = %v, want nil", got)
	}
}
