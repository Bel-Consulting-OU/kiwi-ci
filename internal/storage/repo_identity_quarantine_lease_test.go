package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestLeasePredicateDeniesQuarantinedJobUnderGlobalAllow pins R1-6 at the
// predicate level: a job carrying the durable repo_identity_quarantined flag
// is denied even when the runner's repository allowlist is EMPTY (the global
// allow-everything policy), while an identical unflagged job is admitted. The
// SQL claim mirrors the branch through ClaimAllowsRunner.
func TestLeasePredicateDeniesQuarantinedJobUnderGlobalAllow(t *testing.T) {
	runner := model.Runner{ID: "r", Capacity: 4} // empty allowlist = global allow
	job := model.Job{ID: "j", RunID: "run", Status: model.StatusQueued, RepoID: "github.com/acme/api"}
	if !(LeasePredicate{Runner: runner, Job: job}).Allows() {
		t.Fatal("control: an unflagged job must be admitted under the global allow policy")
	}
	job.RepoIdentityQuarantined = true
	if (LeasePredicate{Runner: runner, Job: job}).Allows() {
		t.Fatal("quarantined job was leased under a global allow policy")
	}
	if ClaimAllowsRunner(runner, LeaseClaim{}) != true {
		t.Fatal("control: ClaimAllowsRunner must admit an unflagged claim")
	}
	if ClaimAllowsRunner(runner, LeaseClaim{Quarantined: true}) {
		t.Fatal("ClaimAllowsRunner admitted a quarantined claim under a global allow policy")
	}
}

// TestMemStoreQuarantineInert pins the mem/FaultyStore mirror: a quarantined
// job cannot be leased through the atomic claim path (LeasePredicate) or the
// non-atomic AcquireLease path, while an unflagged job with the same global
// allow runner can.
func TestMemStoreQuarantineInert(t *testing.T) {
	ctx := context.Background()
	claim := LeaseClaim{JobID: "job", RunnerID: "runner", TokenHash: []byte("tok"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour)}

	control := newMemStore()
	control.runners["runner"] = model.Runner{ID: "runner", Capacity: 4}
	control.jobs["job"] = model.Job{ID: "job", RunID: "run", Status: model.StatusQueued, RepoID: "github.com/acme/api"}
	if _, err := control.AcquireLeaseAtomic(ctx, claim); err != nil {
		t.Fatalf("control AcquireLeaseAtomic: %v", err)
	}

	quarantined := newMemStore()
	quarantined.runners["runner"] = model.Runner{ID: "runner", Capacity: 4}
	quarantined.jobs["job"] = model.Job{ID: "job", RunID: "run", Status: model.StatusQueued, RepoID: "quarantine.invalid/quarantined/deadbeef", RepoIdentityQuarantined: true}
	if _, err := quarantined.AcquireLeaseAtomic(ctx, claim); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("quarantined AcquireLeaseAtomic err = %v, want ErrNoCapacity", err)
	}

	nonAtomic := newMemStore()
	nonAtomic.runners["runner"] = model.Runner{ID: "runner", Capacity: 4}
	nonAtomic.jobs["job"] = model.Job{ID: "job", RunID: "run", Status: model.StatusQueued, RepoID: "github.com/acme/api", RepoIdentityQuarantined: true}
	if _, err := nonAtomic.AcquireLease(ctx, "job", "runner", []byte("tok"), 1, time.Now().UTC().Add(time.Hour)); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("quarantined AcquireLease err = %v, want ErrLeaseConflict", err)
	}
}
