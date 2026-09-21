package storage

// Reservation admission and release-lifecycle tests for the in-memory store.
// They mirror the real-PostgreSQL integration tests in
// postgres_resource_reservation_it_test.go: the two stores must make the same
// admission decision and expose the same exactly-once release lifecycle.

import (
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// resourceProfileRunner seeds a runner linked to a profile carrying both a
// job-count capacity and the resource capacities under test.
func resourceProfileRunner(t *testing.T, m *memStore, runnerID, profileID, serial string, countCapacity int, capacity model.ResourceCapacity) {
	t.Helper()
	if err := m.UpsertProfile(ctx(), model.RunnerProfile{
		ID: profileID, MaxCapacity: countCapacity,
		MaxCPU: capacity.CPU, MaxMemory: capacity.Memory, MaxDisk: capacity.Disk, MaxPIDs: capacity.PIDs,
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.BindCertProfile(ctx(), serial, profileID); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertRunner(ctx(), model.Runner{ID: runnerID, Name: runnerID, Capacity: countCapacity, CertSerial: serial}); err != nil {
		t.Fatal(err)
	}
}

// resourceJob seeds a queued job carrying the given requests.
func resourceJob(t *testing.T, m *memStore, runID, jobID string, request model.ResourceCapacity) {
	t.Helper()
	if _, err := m.GetRun(ctx(), runID); errors.Is(err, ErrNotFound) {
		if err := m.InsertRun(ctx(), model.Run{ID: runID, Repo: leaseRepo, Status: model.StatusQueued, CreatedAt: time.Unix(1000, 0).UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.InsertJob(ctx(), model.Job{
		ID: jobID, RunID: runID, Key: "build", Status: model.StatusQueued,
		RepoURL: leaseRepo, RepoFullName: "o/r", CreatedAt: time.Unix(1001, 0).UTC(),
		MaxInfraRetries: 2,
		CPURequest:      request.CPU, MemoryRequest: request.Memory, DiskRequest: request.Disk, PIDsRequest: request.PIDs,
	}); err != nil {
		t.Fatal(err)
	}
}

// resourceClaim builds a claim for one job carrying the job's requests.
func resourceClaim(jobID, runnerID string, request model.ResourceCapacity) LeaseClaim {
	c := leaseClaimFor(jobID, runnerID, 8)
	c.CPURequest, c.MemoryRequest, c.DiskRequest, c.PIDsRequest = request.CPU, request.Memory, request.Disk, request.PIDs
	return c
}

func assertReserved(t *testing.T, m *memStore, runnerID string, want model.ResourceCapacity) {
	t.Helper()
	got, err := m.RunnerReservedResources(ctx(), runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("reserved = %+v, want %+v", got, want)
	}
	list, err := m.ListResourceReservations(ctx(), runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) == 0 && (want != model.ResourceCapacity{}) {
		t.Fatalf("reservation ledger empty, want %+v", want)
	}
	for _, r := range list {
		if r.Capacity() == (model.ResourceCapacity{}) {
			t.Fatalf("reservation row %s carries no quantities", r.JobID)
		}
	}
}

// TestResourceAdmissionPredicate pins the shared predicate: a zero capacity
// dimension is unconstrained, a request above a configured capacity is
// permanently unsatisfiable, and reserved+requested beyond capacity exceeds
// the remaining capacity.
func TestResourceAdmissionPredicate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		capacity  model.ResourceCapacity
		reserved  model.ResourceCapacity
		requested model.ResourceCapacity
		allows    bool
		ever      bool
	}{
		{"unconstrained admits anything", model.ResourceCapacity{}, model.ResourceCapacity{}, model.ResourceCapacity{CPU: 64, Memory: 1 << 40}, true, true},
		{"exact fit", model.ResourceCapacity{CPU: 4, Memory: 8 << 30}, model.ResourceCapacity{}, model.ResourceCapacity{CPU: 4, Memory: 8 << 30}, true, true},
		{"above configured capacity", model.ResourceCapacity{Memory: 8 << 30}, model.ResourceCapacity{}, model.ResourceCapacity{Memory: 9 << 30}, false, false},
		{"fits remaining", model.ResourceCapacity{Memory: 8 << 30}, model.ResourceCapacity{Memory: 4 << 30}, model.ResourceCapacity{Memory: 4 << 30}, true, true},
		{"exceeds remaining", model.ResourceCapacity{Memory: 8 << 30}, model.ResourceCapacity{Memory: 4 << 30}, model.ResourceCapacity{Memory: 5 << 30}, false, true},
		{"pids bounded", model.ResourceCapacity{PIDs: 256}, model.ResourceCapacity{PIDs: 200}, model.ResourceCapacity{PIDs: 100}, false, true},
		{"disk bounded", model.ResourceCapacity{Disk: 10 << 30}, model.ResourceCapacity{}, model.ResourceCapacity{Disk: 10<<30 + 1}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ResourceAdmission{Capacity: tc.capacity, Reserved: tc.reserved, Requested: tc.requested}
			if got := a.Allows(); got != tc.allows {
				t.Fatalf("Allows = %v, want %v", got, tc.allows)
			}
			if got := a.EverSatisfiable(); got != tc.ever {
				t.Fatalf("EverSatisfiable = %v, want %v", got, tc.ever)
			}
		})
	}
}

// TestMemResourceOversubscriptionPrevented: a runner with an 8 GiB memory
// capacity cannot lease two 4 GiB jobs — the second is rejected with
// ErrResourceCapacity, waits, and is leased only after the first completes.
func TestMemResourceOversubscriptionPrevented(t *testing.T) {
	m := newMemStore()
	resourceProfileRunner(t, m, leaseRunner, leaseProf, leaseCert, 8, model.ResourceCapacity{Memory: 8 << 30})
	fiveGiB := model.ResourceCapacity{Memory: 5 << 30}
	resourceJob(t, m, leaseRunID, leaseJobID, fiveGiB)
	resourceJob(t, m, leaseRunID, leaseJob2ID, fiveGiB)

	if _, err := m.AcquireLeaseAtomic(ctx(), resourceClaim(leaseJobID, leaseRunner, fiveGiB)); err != nil {
		t.Fatalf("first lease: %v", err)
	}
	assertReserved(t, m, leaseRunner, fiveGiB)

	_, err := m.AcquireLeaseAtomic(ctx(), resourceClaim(leaseJob2ID, leaseRunner, fiveGiB))
	if !errors.Is(err, ErrResourceCapacity) {
		t.Fatalf("second lease error = %v, want ErrResourceCapacity", err)
	}
	// The rejected claim changed nothing: the job is still queued, the
	// runner still holds exactly one reservation.
	j, err := m.GetJob(ctx(), leaseJob2ID)
	if err != nil {
		t.Fatal(err)
	}
	if j.Status != model.StatusQueued || j.Attempts != 0 {
		t.Fatalf("rejected job state = %s/attempts %d, want queued/0", j.Status, j.Attempts)
	}
	assertReserved(t, m, leaseRunner, fiveGiB)

	// Completion returns the capacity: the second job leases immediately.
	receipt := model.CompletionReceipt{JobID: leaseJobID, Generation: 1, RunnerID: leaseRunner}
	if err := m.CompleteJob(ctx(), leaseJobID, 1, leaseRunner, model.StatusSuccess, "", nil, receipt); err != nil {
		t.Fatalf("complete first: %v", err)
	}
	assertReserved(t, m, leaseRunner, model.ResourceCapacity{})
	if _, err := m.AcquireLeaseAtomic(ctx(), resourceClaim(leaseJob2ID, leaseRunner, fiveGiB)); err != nil {
		t.Fatalf("second lease after completion: %v", err)
	}
	assertReserved(t, m, leaseRunner, fiveGiB)
}

// TestMemResourceReservationReleasedExactlyOnce: every lease-ending path
// releases the reservation exactly once; replaying each release leaves the
// ledger empty (no leak, no double release).
func TestMemResourceReservationReleasedExactlyOnce(t *testing.T) {
	request := model.ResourceCapacity{CPU: 2, Memory: 2 << 30, Disk: 3 << 30, PIDs: 100}
	capacity := model.ResourceCapacity{CPU: 4, Memory: 4 << 30, Disk: 6 << 30, PIDs: 200}

	t.Run("completion", func(t *testing.T) {
		m := newMemStore()
		resourceProfileRunner(t, m, leaseRunner, leaseProf, leaseCert, 8, capacity)
		resourceJob(t, m, leaseRunID, leaseJobID, request)
		if _, err := m.AcquireLeaseAtomic(ctx(), resourceClaim(leaseJobID, leaseRunner, request)); err != nil {
			t.Fatal(err)
		}
		receipt := model.CompletionReceipt{JobID: leaseJobID, Generation: 1, RunnerID: leaseRunner}
		if err := m.CompleteJob(ctx(), leaseJobID, 1, leaseRunner, model.StatusSuccess, "", nil, receipt); err != nil {
			t.Fatal(err)
		}
		assertReserved(t, m, leaseRunner, model.ResourceCapacity{})
		// Replayed completion: still exactly zero, and the replay does not
		// resurrect or double-release anything.
		if err := m.CompleteJob(ctx(), leaseJobID, 1, leaseRunner, model.StatusSuccess, "", nil, receipt); err != nil {
			t.Fatalf("replayed completion: %v", err)
		}
		assertReserved(t, m, leaseRunner, model.ResourceCapacity{})
	})

	t.Run("failure completion", func(t *testing.T) {
		m := newMemStore()
		resourceProfileRunner(t, m, leaseRunner, leaseProf, leaseCert, 8, capacity)
		resourceJob(t, m, leaseRunID, leaseJobID, request)
		if _, err := m.AcquireLeaseAtomic(ctx(), resourceClaim(leaseJobID, leaseRunner, request)); err != nil {
			t.Fatal(err)
		}
		receipt := model.CompletionReceipt{JobID: leaseJobID, Generation: 1, RunnerID: leaseRunner}
		if err := m.CompleteJob(ctx(), leaseJobID, 1, leaseRunner, model.StatusFailure, "boom", nil, receipt); err != nil {
			t.Fatal(err)
		}
		assertReserved(t, m, leaseRunner, model.ResourceCapacity{})
	})

	t.Run("run cancellation", func(t *testing.T) {
		m := newMemStore()
		resourceProfileRunner(t, m, leaseRunner, leaseProf, leaseCert, 8, capacity)
		resourceJob(t, m, leaseRunID, leaseJobID, request)
		if _, err := m.AcquireLeaseAtomic(ctx(), resourceClaim(leaseJobID, leaseRunner, request)); err != nil {
			t.Fatal(err)
		}
		if _, err := m.CancelRunJobs(ctx(), leaseRunID, "cancelled"); err != nil {
			t.Fatal(err)
		}
		assertReserved(t, m, leaseRunner, model.ResourceCapacity{})
		if _, err := m.CancelRunJobs(ctx(), leaseRunID, "cancelled again"); err != nil {
			t.Fatalf("replayed cancellation: %v", err)
		}
		assertReserved(t, m, leaseRunner, model.ResourceCapacity{})
	})

	t.Run("lease expiry requeue and terminal failure", func(t *testing.T) {
		m := newMemStore()
		resourceProfileRunner(t, m, leaseRunner, leaseProf, leaseCert, 8, capacity)
		resourceJob(t, m, leaseRunID, leaseJobID, request)
		leased, err := m.AcquireLeaseAtomic(ctx(), resourceClaim(leaseJobID, leaseRunner, request))
		if err != nil {
			t.Fatal(err)
		}
		if leased.Attempts != 1 {
			t.Fatalf("attempts = %d", leased.Attempts)
		}
		if err := m.RecoverExpiredLease(ctx(), leaseJobID, 1, time.Unix(4000, 0).UTC()); err != nil {
			t.Fatalf("recover expired: %v", err)
		}
		assertReserved(t, m, leaseRunner, model.ResourceCapacity{})
		// Replay of the same recovery observes a non-running row: no-op.
		if err := m.RecoverExpiredLease(ctx(), leaseJobID, 1, time.Unix(4000, 0).UTC()); err != nil {
			t.Fatalf("replayed recovery: %v", err)
		}
		assertReserved(t, m, leaseRunner, model.ResourceCapacity{})

		// Terminal branch: exhaust the retry budget, lease again, expire.
		j, err := m.GetJob(ctx(), leaseJobID)
		if err != nil {
			t.Fatal(err)
		}
		if j.Status != model.StatusQueued {
			t.Fatalf("requeued status = %s", j.Status)
		}
		j.MaxInfraRetries = 1
		j.Attempts = 1
		if err := m.UpdateJob(ctx(), j); err != nil {
			t.Fatal(err)
		}
		leased, err = m.AcquireLeaseAtomic(ctx(), resourceClaim(leaseJobID, leaseRunner, request))
		if err != nil {
			t.Fatal(err)
		}
		assertReserved(t, m, leaseRunner, request)
		if err := m.RecoverExpiredLease(ctx(), leaseJobID, leased.LeaseGeneration, time.Unix(5000, 0).UTC()); err != nil {
			t.Fatal(err)
		}
		assertReserved(t, m, leaseRunner, model.ResourceCapacity{})
	})

	t.Run("runner revoke", func(t *testing.T) {
		m := newMemStore()
		resourceProfileRunner(t, m, leaseRunner, leaseProf, leaseCert, 8, capacity)
		resourceJob(t, m, leaseRunID, leaseJobID, request)
		if _, err := m.AcquireLeaseAtomic(ctx(), resourceClaim(leaseJobID, leaseRunner, request)); err != nil {
			t.Fatal(err)
		}
		if _, err := m.RevokeRunnerLeases(ctx(), leaseRunner, "runner disabled"); err != nil {
			t.Fatal(err)
		}
		assertReserved(t, m, leaseRunner, model.ResourceCapacity{})
		if _, err := m.RevokeRunnerLeases(ctx(), leaseRunner, "runner disabled again"); err != nil {
			t.Fatalf("replayed revoke: %v", err)
		}
		assertReserved(t, m, leaseRunner, model.ResourceCapacity{})
	})

	t.Run("runner disable and revoke cert", func(t *testing.T) {
		m := newMemStore()
		resourceProfileRunner(t, m, leaseRunner, leaseProf, leaseCert, 8, capacity)
		resourceJob(t, m, leaseRunID, leaseJobID, request)
		if _, err := m.AcquireLeaseAtomic(ctx(), resourceClaim(leaseJobID, leaseRunner, request)); err != nil {
			t.Fatal(err)
		}
		if _, err := m.DisableRunnerAndRevokeCert(ctx(), leaseRunner, leaseCert, "admin"); err != nil {
			t.Fatal(err)
		}
		assertReserved(t, m, leaseRunner, model.ResourceCapacity{})
	})

	t.Run("legacy ReleaseRunnerJob", func(t *testing.T) {
		m := newMemStore()
		resourceProfileRunner(t, m, leaseRunner, leaseProf, leaseCert, 8, capacity)
		resourceJob(t, m, leaseRunID, leaseJobID, request)
		if _, err := m.AcquireLeaseAtomic(ctx(), resourceClaim(leaseJobID, leaseRunner, request)); err != nil {
			t.Fatal(err)
		}
		if err := m.ReleaseRunnerJob(ctx(), leaseRunner, leaseJobID, model.StatusFailure); err != nil {
			t.Fatal(err)
		}
		assertReserved(t, m, leaseRunner, model.ResourceCapacity{})
	})

	t.Run("supersession", func(t *testing.T) {
		m := newMemStore()
		resourceProfileRunner(t, m, leaseRunner, leaseProf, leaseCert, 8, capacity)
		// The superseded run carries the concurrency group at insert time:
		// the supersede policy matches on the persisted payload.
		if err := m.InsertRun(ctx(), model.Run{ID: leaseRunID, Repo: leaseRepo, ConcurrencyGroup: "g", Status: model.StatusQueued, CreatedAt: time.Unix(1000, 0).UTC()}); err != nil {
			t.Fatal(err)
		}
		resourceJob(t, m, leaseRunID, leaseJobID, request)
		if _, err := m.AcquireLeaseAtomic(ctx(), resourceClaim(leaseJobID, leaseRunner, request)); err != nil {
			t.Fatal(err)
		}
		// A superseding enqueue of the same repository+group cancels the
		// running job and must release its reservation in the same commit.
		newRunID := "55555555555555555555555555555555"
		req := InsertCompiledRunRequest{
			Run:  model.Run{ID: newRunID, Repo: leaseRepo, ConcurrencyGroup: "g", Status: model.StatusQueued, CreatedAt: time.Unix(2000, 0).UTC()},
			Jobs: map[string]model.Job{"new": {ID: "66666666666666666666666666666666", RunID: newRunID, Key: "build", Status: model.StatusQueued, RepoURL: leaseRepo, RepoFullName: "o/r", CreatedAt: time.Unix(2000, 0).UTC()}},
			Supersede: &SupersedePolicy{
				RepoID:           leaseRepoID,
				ConcurrencyGroup: "g",
			},
		}
		if err := m.InsertCompiledRun(ctx(), req); err != nil {
			t.Fatalf("superseding enqueue: %v", err)
		}
		assertReserved(t, m, leaseRunner, model.ResourceCapacity{})
	})
}

// TestMemResourceAdmissionCapacityLessRunnerUnconstrained: a runner without
// configured resource capacities keeps the pre-0030 behavior — job-count
// capacity only, resources unconstrained.
func TestMemResourceAdmissionCapacityLessRunnerUnconstrained(t *testing.T) {
	m := newMemStore()
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 3}); err != nil {
		t.Fatal(err)
	}
	big := model.ResourceCapacity{CPU: 128, Memory: 512 << 30, Disk: 1 << 40, PIDs: 100000}
	resourceJob(t, m, leaseRunID, leaseJobID, big)
	resourceJob(t, m, leaseRunID, leaseJob2ID, big)
	for _, id := range []string{leaseJobID, leaseJob2ID} {
		if _, err := m.AcquireLeaseAtomic(ctx(), resourceClaim(id, leaseRunner, big)); err != nil {
			t.Fatalf("capacity-less runner lease %s rejected: %v", id, err)
		}
	}
	assertReserved(t, m, leaseRunner, model.ResourceCapacity{CPU: 256, Memory: 1024 << 30, Disk: 2 << 40, PIDs: 200000})
}

// TestMemResourceAdmissionExplicitZeroCapacityUnconstrained: a dimension the
// profile leaves at zero is unconstrained even when other dimensions bind.
func TestMemResourceAdmissionExplicitZeroCapacityUnconstrained(t *testing.T) {
	m := newMemStore()
	resourceProfileRunner(t, m, leaseRunner, leaseProf, leaseCert, 8, model.ResourceCapacity{Memory: 4 << 30})
	// CPU/disk/pids requests far above any plausible capacity are admitted
	// because only memory is configured.
	huge := model.ResourceCapacity{CPU: 256, Memory: 1 << 30, Disk: 1 << 50, PIDs: 1000000}
	resourceJob(t, m, leaseRunID, leaseJobID, huge)
	if _, err := m.AcquireLeaseAtomic(ctx(), resourceClaim(leaseJobID, leaseRunner, huge)); err != nil {
		t.Fatalf("lease with unconstrained dimensions rejected: %v", err)
	}
	assertReserved(t, m, leaseRunner, huge)
}
