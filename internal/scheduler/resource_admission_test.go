package scheduler

// Resource-admission tests for the DB scheduler. The real check-and-reserve
// lives in the store's claim transaction (see internal/storage); these tests
// pin the scheduler's half: the candidate PRE-FILTER over the runner's live
// reservations, the resource fields carried into the claim, and the
// ErrResourceCapacity race handling.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// resourceFakeStore wraps atomicFakeStore with the reservation ledger and
// records every claim, so the pre-filter and the claim payload can be
// asserted without a database.
type resourceFakeStore struct {
	*atomicFakeStore

	mu             sync.Mutex
	claims         []storage.LeaseClaim
	reserved       model.ResourceCapacity
	failNextClaims int
}

func newResourceFakeStore() *resourceFakeStore {
	return &resourceFakeStore{atomicFakeStore: newAtomicFakeStore()}
}

var (
	_ storage.AtomicLeaseStore         = (*resourceFakeStore)(nil)
	_ storage.ResourceReservationStore = (*resourceFakeStore)(nil)
)

func (r *resourceFakeStore) AcquireLeaseAtomic(ctx context.Context, claim storage.LeaseClaim) (model.Job, error) {
	r.mu.Lock()
	r.claims = append(r.claims, claim)
	fail := false
	if r.failNextClaims > 0 {
		r.failNextClaims--
		fail = true
	}
	r.mu.Unlock()
	if fail {
		return model.Job{}, fmt.Errorf("%w: injected race", storage.ErrResourceCapacity)
	}
	return r.atomicFakeStore.AcquireLeaseAtomic(ctx, claim)
}

func (r *resourceFakeStore) RunnerReservedResources(ctx context.Context, runnerID string) (model.ResourceCapacity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reserved, nil
}

func (r *resourceFakeStore) ListResourceReservations(ctx context.Context, runnerID string) ([]storage.ResourceReservation, error) {
	return nil, nil
}

func (r *resourceFakeStore) claimCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.claims)
}

func (r *resourceFakeStore) lastClaim(t *testing.T) storage.LeaseClaim {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.claims) == 0 {
		t.Fatal("no claim recorded")
	}
	return r.claims[len(r.claims)-1]
}

// seedResourceScheduler seeds one profile-linked runner with the given
// capacities plus the queued jobs (in order, oldest first).
func seedResourceScheduler(t *testing.T, st *resourceFakeStore, runnerID string, countCapacity int, capacity model.ResourceCapacity, jobs ...model.Job) *DBScheduler {
	t.Helper()
	ctx := context.Background()
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: "prof-" + runnerID, MaxCapacity: countCapacity,
		MaxCPU: capacity.CPU, MaxMemory: capacity.Memory, MaxDisk: capacity.Disk, MaxPIDs: capacity.PIDs}); err != nil {
		t.Fatal(err)
	}
	if err := st.BindCertProfile(ctx, "serial-"+runnerID, "prof-"+runnerID); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: countCapacity, CertSerial: "serial-" + runnerID}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertRun(ctx, model.Run{ID: "run-" + runnerID, Status: model.StatusQueued, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for i, j := range jobs {
		j.RunID = "run-" + runnerID
		if j.Key == "" {
			j.Key = fmt.Sprintf("job%d", i)
		}
		j.Status = model.StatusQueued
		if j.CreatedAt.IsZero() {
			j.CreatedAt = time.Now().UTC().Add(time.Duration(i) * time.Second)
		}
		if err := st.InsertJob(ctx, j); err != nil {
			t.Fatal(err)
		}
	}
	s := NewDB(st, time.Minute, nil, nil)
	if !s.IsLeader(ctx) {
		t.Fatal("not leader")
	}
	return s
}

// TestSchedulerResourceAdmissionPrefilter: a candidate above the runner's
// profile capacity is never claimed (it waits or goes elsewhere), and an
// admitted candidate carries its requests plus the effective runner
// capacity into the claim.
func TestSchedulerResourceAdmissionPrefilter(t *testing.T) {
	ctx := context.Background()
	st := newResourceFakeStore()
	runnerID := "runner-res"
	big := model.Job{ID: "job-big", CPURequest: 0, MemoryRequest: 8 << 30}
	small := model.Job{ID: "job-small", MemoryRequest: 2 << 30}
	s := seedResourceScheduler(t, st, runnerID, 8, model.ResourceCapacity{Memory: 4 << 30}, big, small)

	// The oversized candidate is skipped even though it is the oldest, and
	// the fitting one is leased.
	j, _, _, err := s.Lease(ctx, runnerID, time.Now().UTC())
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if j.ID != "job-small" {
		t.Fatalf("leased %s, want job-small (the oversized candidate must wait)", j.ID)
	}
	claim := st.lastClaim(t)
	if claim.MemoryRequest != 2<<30 || claim.ResourceCapacity.Memory != 4<<30 {
		t.Fatalf("claim requests/capacity = %d/%d, want 2GiB/4GiB", claim.MemoryRequest, claim.ResourceCapacity.Memory)
	}
}

// TestSchedulerResourceAdmissionReservedBlocks: the pre-filter accounts for
// the runner's live reservations, so a job that would fit an idle runner but
// not its remaining capacity is skipped.
func TestSchedulerResourceAdmissionReservedBlocks(t *testing.T) {
	ctx := context.Background()
	st := newResourceFakeStore()
	runnerID := "runner-reserved"
	st.mu.Lock()
	st.reserved = model.ResourceCapacity{Memory: 3 << 30}
	st.mu.Unlock()
	job := model.Job{ID: "job-4g", MemoryRequest: 4 << 30}
	s := seedResourceScheduler(t, st, runnerID, 8, model.ResourceCapacity{Memory: 4 << 30}, job)

	if _, _, _, err := s.Lease(ctx, runnerID, time.Now().UTC()); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("lease error = %v, want ErrNoJobs", err)
	}
	if st.claimCount() != 0 {
		t.Fatalf("claims attempted = %d, want 0 (reserved capacity blocks)", st.claimCount())
	}
	// Free the reservation: the same candidate now leases.
	st.mu.Lock()
	st.reserved = model.ResourceCapacity{}
	st.mu.Unlock()
	if _, _, _, err := s.Lease(ctx, runnerID, time.Now().UTC()); err != nil {
		t.Fatalf("lease after release: %v", err)
	}
	if st.claimCount() != 1 {
		t.Fatalf("claims = %d, want 1", st.claimCount())
	}
}

// TestSchedulerResourceCapacityRaceTriesNextCandidate: a claim rejected
// with ErrResourceCapacity (a concurrent lease won the remaining capacity)
// is treated like every other lost-race predicate — try the next candidate.
func TestSchedulerResourceCapacityRaceTriesNextCandidate(t *testing.T) {
	ctx := context.Background()
	st := newResourceFakeStore()
	runnerID := "runner-race"
	first := model.Job{ID: "job-first", MemoryRequest: 1 << 30}
	second := model.Job{ID: "job-second", MemoryRequest: 1 << 30}
	s := seedResourceScheduler(t, st, runnerID, 8, model.ResourceCapacity{Memory: 8 << 30}, first, second)

	// The first candidate's claim loses the race; the second is leased.
	st.mu.Lock()
	st.failNextClaims = 1
	st.mu.Unlock()
	j, _, _, err := s.Lease(ctx, runnerID, time.Now().UTC())
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if j.ID != "job-second" {
		t.Fatalf("leased %s, want job-second after the first claim lost the resource race", j.ID)
	}
}

// TestSchedulerResourceAdmissionCapacityLessRunner: a runner without
// configured capacities is unconstrained resource-wise (count-only behavior).
func TestSchedulerResourceAdmissionCapacityLessRunner(t *testing.T) {
	ctx := context.Background()
	st := newResourceFakeStore()
	runnerID := "runner-plain"
	big := model.Job{ID: "job-huge", Key: "huge", Status: model.StatusQueued, CreatedAt: time.Now().UTC(),
		CPURequest: 128, MemoryRequest: 512 << 30, PIDsRequest: 100000}
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 1}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertRun(ctx, model.Run{ID: "run-plain", Status: model.StatusQueued, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	big.RunID = "run-plain"
	if err := st.InsertJob(ctx, big); err != nil {
		t.Fatal(err)
	}
	s := NewDB(st, time.Minute, nil, nil)
	if !s.IsLeader(ctx) {
		t.Fatal("not leader")
	}
	if _, _, _, err := s.Lease(ctx, runnerID, time.Now().UTC()); err != nil {
		t.Fatalf("capacity-less runner rejected an oversized job: %v", err)
	}
}
