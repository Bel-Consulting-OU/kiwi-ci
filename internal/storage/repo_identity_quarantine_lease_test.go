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

// TestMemStoreLeaseParentRunPredicate is the T1-3 mem/SQL parity pin: a queued
// child of a CANCELLED or QUARANTINED parent run is ineligible on BOTH claim
// paths, even on a global-allow runner, while a healthy parent run (or a
// missing run row, the documented legacy/orphan tolerance) admits it.
func TestMemStoreLeaseParentRunPredicate(t *testing.T) {
	ctx := context.Background()
	claim := LeaseClaim{JobID: "job", RunnerID: "runner", TokenHash: []byte("tok"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	queuedJob := func() model.Job {
		return model.Job{ID: "job", RunID: "run", Status: model.StatusQueued, RepoID: "github.com/acme/api"}
	}

	cases := []struct {
		name    string
		run     *model.Run
		wantErr error
	}{
		{
			name:    "healthy parent run admits",
			run:     &model.Run{ID: "run", Status: model.StatusQueued},
			wantErr: nil,
		},
		{
			name:    "cancelled parent run denies",
			run:     &model.Run{ID: "run", Status: model.StatusCancelled},
			wantErr: ErrNoCapacity,
		},
		{
			name:    "failed parent run denies",
			run:     &model.Run{ID: "run", Status: model.StatusFailure},
			wantErr: ErrNoCapacity,
		},
		{
			name:    "quarantined parent run denies",
			run:     &model.Run{ID: "run", Status: model.StatusQueued, RepoIdentityQuarantined: true},
			wantErr: ErrNoCapacity,
		},
		{
			name:    "missing parent run tolerates (legacy/orphan)",
			run:     nil,
			wantErr: nil,
		},
	}
	for _, tc := range cases {
		t.Run("atomic/"+tc.name, func(t *testing.T) {
			m := newMemStore()
			m.runners["runner"] = model.Runner{ID: "runner", Capacity: 4}
			m.jobs["job"] = queuedJob()
			if tc.run != nil {
				m.runs["run"] = *tc.run
			}
			_, err := m.AcquireLeaseAtomic(ctx, claim)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("AcquireLeaseAtomic err = %v, want %v", err, tc.wantErr)
			}
		})
		t.Run("non-atomic/"+tc.name, func(t *testing.T) {
			m := newMemStore()
			m.runners["runner"] = model.Runner{ID: "runner", Capacity: 4}
			m.jobs["job"] = queuedJob()
			if tc.run != nil {
				m.runs["run"] = *tc.run
			}
			want := tc.wantErr
			if want == ErrNoCapacity {
				// The non-atomic claim reports a conflict, mirroring the SQL
				// path (ErrLeaseConflict).
				want = ErrLeaseConflict
			}
			_, err := m.AcquireLease(ctx, "job", "runner", []byte("tok"), 1, time.Now().UTC().Add(time.Hour))
			if !errors.Is(err, want) {
				t.Fatalf("AcquireLease err = %v, want %v", err, want)
			}
		})
	}
}
