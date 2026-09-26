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
	storage.LeaseOIDCIssueStore
	storage.RunnerTokenStore
}

type noFenceDBStore struct {
	storage.Store
	storage.CASGCLeaseStore
	storage.LeaseCommitStore
	storage.LeaseOIDCIssueStore
	storage.RunnerTokenStore
}

type noCASGCLeaseDBStore struct {
	storage.Store
	storage.DigestFenceStore
	storage.LeaseCommitStore
	storage.LeaseOIDCIssueStore
	storage.RunnerTokenStore
}

type noLeaseCommitDBStore struct {
	storage.Store
	storage.DigestFenceStore
	storage.CASGCLeaseStore
	storage.LeaseOIDCIssueStore
	storage.RunnerTokenStore
}

type noOIDCIssueDBStore struct {
	storage.Store
	storage.DigestFenceStore
	storage.CASGCLeaseStore
	storage.LeaseCommitStore
	storage.RunnerTokenStore
}

type noRunnerTokenDBStore struct {
	storage.Store
	storage.DigestFenceStore
	storage.CASGCLeaseStore
	storage.LeaseCommitStore
	storage.LeaseOIDCIssueStore
}

// TestValidateDBStoreCapabilities proves the enforced DB-mode capability set
// rejects any store missing one of the unconditional contracts and names the
// missing one. The three unconditional contracts are DigestFenceStore,
// CASGCLeaseStore and LeaseCommitStore.
func TestValidateDBStoreCapabilities(t *testing.T) {
	if err := validateDBStoreCapabilities(nil, true, true); err != nil {
		t.Fatalf("memory/fs mode (nil store) = %v, want nil", err)
	}
	if err := validateDBStoreCapabilities(completeDBStore{}, false, false); err != nil {
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
			err := validateDBStoreCapabilities(tc.db, false, false)
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
	if err := validateDBStoreCapabilities(noRunnerTokenDBStore{}, false, true); err != nil {
		t.Fatalf("store without RunnerTokenStore and no runner tokens = %v, want nil", err)
	}
	err := validateDBStoreCapabilities(noRunnerTokenDBStore{}, true, true)
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

// TestValidateDBStoreCapabilitiesOIDCConditional proves LeaseOIDCIssueStore is
// enforced exactly when OIDC issuance is enabled (an external URL makes the
// issuance endpoint serve) and that the refusal names the interface.
func TestValidateDBStoreCapabilitiesOIDCConditional(t *testing.T) {
	if err := validateDBStoreCapabilities(noOIDCIssueDBStore{}, false, false); err != nil {
		t.Fatalf("store without LeaseOIDCIssueStore and OIDC disabled = %v, want nil", err)
	}
	err := validateDBStoreCapabilities(noOIDCIssueDBStore{}, false, true)
	if err == nil {
		t.Fatal("store without LeaseOIDCIssueStore accepted with OIDC issuance enabled")
	}
	if !strings.Contains(err.Error(), "LeaseOIDCIssueStore") {
		t.Fatalf("error %q does not name LeaseOIDCIssueStore", err)
	}
	if !strings.Contains(err.Error(), "refusing to start") {
		t.Fatalf("error %q is not a startup refusal", err)
	}
	if !strings.Contains(err.Error(), "DigestFenceStore, CASGCLeaseStore, LeaseCommitStore, LeaseOIDCIssueStore") {
		t.Fatalf("error %q does not report the enforced set", err)
	}
	if err := validateDBStoreCapabilities(completeDBStore{}, false, true); err != nil {
		t.Fatalf("complete store with OIDC enabled = %v, want nil", err)
	}
}

// TestRequiredDBStoreCapabilitiesReportsEnforcedSet pins the reported set so
// the startup error (and this test) always state exactly what DB mode
// enforces.
func TestRequiredDBStoreCapabilitiesReportsEnforcedSet(t *testing.T) {
	reqs := requiredDBStoreCapabilities(completeDBStore{}, true, true)
	var names []string
	for _, r := range reqs {
		if !r.Held {
			t.Fatalf("complete store reports %s missing", r.Name)
		}
		names = append(names, r.Name)
	}
	want := []string{"DigestFenceStore", "CASGCLeaseStore", "LeaseCommitStore", "LeaseOIDCIssueStore", "RunnerTokenStore"}
	if len(names) != len(want) {
		t.Fatalf("enforced set = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("enforced set = %v, want %v", names, want)
		}
	}
	if got := requiredDBStoreCapabilities(nil, true, true); got != nil {
		t.Fatalf("nil store requirements = %v, want nil", got)
	}
	// With OIDC disabled the interface is not part of the set.
	for _, r := range requiredDBStoreCapabilities(completeDBStore{}, false, false) {
		if r.Name == "LeaseOIDCIssueStore" {
			t.Fatal("LeaseOIDCIssueStore required with OIDC issuance disabled")
		}
	}
}
