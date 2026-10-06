package scheduler

// Reservation-head (fragmentation) tests: an aged large job blocked on the
// runner's REMAINING capacity must not be starved forever by a continuous
// stream of smaller backfill jobs that fit the remaining capacity, while
// non-conflicting backfill (a different resource dimension) must still be
// admitted instead of wasting free capacity.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// seedFragmentationBackfill returns n CPU-requesting small jobs created just
// after now, in created_at order.
func seedFragmentationBackfill(now time.Time, n int, cpu float64, memory int64) []model.Job {
	jobs := make([]model.Job, 0, n)
	for i := 0; i < n; i++ {
		jobs = append(jobs, model.Job{
			ID:            fmt.Sprintf("job-small-%02d", i),
			CPURequest:    cpu,
			MemoryRequest: memory,
			CreatedAt:     now.Add(time.Duration(i) * time.Millisecond),
		})
	}
	return jobs
}

// TestSchedulerAgedLargeJobNotStarvedByBackfill: with CPU 7 of 8 reserved, a
// 2h-old CPU-8 job cannot fit, but neither may any CPU-1 backfill job run:
// every poll returns ErrNoJobs with no claim attempted until the reservation
// clears, and the aged large job is then leased with its full request.
func TestSchedulerAgedLargeJobNotStarvedByBackfill(t *testing.T) {
	ctx := context.Background()
	st := newResourceFakeStore()
	runnerID := "runner-frag-cpu"
	now := time.Now().UTC()
	jobs := append([]model.Job{{
		ID: "job-big", CPURequest: 8, CreatedAt: now.Add(-2 * time.Hour),
	}}, seedFragmentationBackfill(now, 20, 1, 0)...)
	s := seedResourceScheduler(t, st, runnerID, 8, model.ResourceCapacity{CPU: 8}, jobs...)
	st.mu.Lock()
	st.reserved = model.ResourceCapacity{CPU: 7}
	st.mu.Unlock()

	// The backfill stream keeps arriving, one fresh CPU-1 job per poll.
	for i := 0; i < 5; i++ {
		if i > 0 {
			extra := model.Job{
				ID: fmt.Sprintf("job-extra-%02d", i), RunID: "run-" + runnerID, Key: fmt.Sprintf("extra-%02d", i),
				Status: model.StatusQueued, CPURequest: 1,
				CreatedAt: now.Add(time.Duration(100+i) * time.Millisecond),
			}
			if err := st.InsertJob(ctx, extra); err != nil {
				t.Fatalf("insert backfill %d: %v", i, err)
			}
		}
		if _, _, _, err := s.Lease(ctx, runnerID, now); !errors.Is(err, ErrNoJobs) {
			t.Fatalf("poll %d: lease error = %v, want ErrNoJobs (backfill must not starve the aged large job)", i, err)
		}
	}
	if st.claimCount() != 0 {
		t.Fatalf("claims attempted = %d, want 0 while the reservation head waits", st.claimCount())
	}

	// The reservation clears: the head leases first with its full request.
	st.mu.Lock()
	st.reserved = model.ResourceCapacity{}
	st.mu.Unlock()
	j, _, _, err := s.Lease(ctx, runnerID, now)
	if err != nil {
		t.Fatalf("lease after reservation release: %v", err)
	}
	if j.ID != "job-big" {
		t.Fatalf("leased %s, want job-big once capacity freed", j.ID)
	}
	claim := st.lastClaim(t)
	if claim.CPURequest != 8 || claim.RequestedResources().CPU != 8 {
		t.Fatalf("claim CPU = %v (total %v), want the 8 CPU request", claim.CPURequest, claim.RequestedResources().CPU)
	}
}

// TestSchedulerReservationKeepsNonConflictingBackfill: the head waits on CPU
// while a memory-only small job fits a free capacity dimension: the small IS
// leased (the reservation must not waste non-conflicting capacity).
func TestSchedulerReservationKeepsNonConflictingBackfill(t *testing.T) {
	ctx := context.Background()
	st := newResourceFakeStore()
	runnerID := "runner-frag-mem"
	now := time.Now().UTC()
	jobs := append([]model.Job{{
		ID: "job-cpu-big", CPURequest: 8, CreatedAt: now.Add(-2 * time.Hour),
	}}, seedFragmentationBackfill(now, 20, 0, 1<<30)...)
	s := seedResourceScheduler(t, st, runnerID, 8, model.ResourceCapacity{CPU: 8, Memory: 4 << 30}, jobs...)
	st.mu.Lock()
	st.reserved = model.ResourceCapacity{CPU: 7}
	st.mu.Unlock()

	j, _, _, err := s.Lease(ctx, runnerID, now)
	if err != nil {
		t.Fatalf("lease memory-only backfill alongside a CPU-blocked head: %v", err)
	}
	if j.CPURequest != 0 || j.MemoryRequest != 1<<30 {
		t.Fatalf("leased %s (cpu=%v mem=%d), want a memory-only small job", j.ID, j.CPURequest, j.MemoryRequest)
	}
}

// TestSchedulerReservationReleasedWhenHeadLeaves: the head blocks backfill
// while blocked, leases when the reservation releases, and the NEXT lease
// starts from a clean request-local state (a small job leases normally).
func TestSchedulerReservationReleasedWhenHeadLeaves(t *testing.T) {
	ctx := context.Background()
	st := newResourceFakeStore()
	runnerID := "runner-frag-release"
	now := time.Now().UTC()
	jobs := append([]model.Job{{
		ID: "job-big", CPURequest: 8, CreatedAt: now.Add(-2 * time.Hour),
	}}, seedFragmentationBackfill(now, 5, 1, 0)...)
	s := seedResourceScheduler(t, st, runnerID, 8, model.ResourceCapacity{CPU: 8}, jobs...)
	st.mu.Lock()
	st.reserved = model.ResourceCapacity{CPU: 7}
	st.mu.Unlock()

	if _, _, _, err := s.Lease(ctx, runnerID, now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("blocked lease = %v, want ErrNoJobs", err)
	}
	if st.claimCount() != 0 {
		t.Fatalf("blocked lease attempted %d claims, want 0", st.claimCount())
	}
	st.mu.Lock()
	st.reserved = model.ResourceCapacity{}
	st.mu.Unlock()
	head, _, _, err := s.Lease(ctx, runnerID, now)
	if err != nil {
		t.Fatalf("head lease after release: %v", err)
	}
	if head.ID != "job-big" {
		t.Fatalf("leased %s, want job-big", head.ID)
	}
	// No stale reservation state: the next poll leases a small normally.
	next, _, _, err := s.Lease(ctx, runnerID, now)
	if err != nil {
		t.Fatalf("lease after the head left: %v", err)
	}
	if next.CPURequest != 1 {
		t.Fatalf("leased %s (cpu=%v), want a CPU-1 small job", next.ID, next.CPURequest)
	}
}

// TestSchedulerReservationWaitAllowsInitialBackfill: a reservation_wait grace
// period lets backfill already fitting the runner run before a freshly queued
// large job activates as the head; with the wait elapsed (0) the head blocks
// the same backfill.
func TestSchedulerReservationWaitAllowsInitialBackfill(t *testing.T) {
	ctx := context.Background()
	st := newResourceFakeStore()
	runnerID := "runner-frag-wait"
	now := time.Now().UTC()
	jobs := append([]model.Job{{
		// "Just queued": the head activation wait has not elapsed.
		ID: "job-big", CPURequest: 8, CreatedAt: now,
	}}, seedFragmentationBackfill(now, 5, 1, 0)...)
	s := seedResourceScheduler(t, st, runnerID, 8, model.ResourceCapacity{CPU: 8}, jobs...)
	st.mu.Lock()
	st.reserved = model.ResourceCapacity{CPU: 7}
	st.mu.Unlock()
	s.SetLeaseScanLimits(0, 0, time.Hour)

	first, _, _, err := s.Lease(ctx, runnerID, now)
	if err != nil {
		t.Fatalf("lease during the reservation wait: %v", err)
	}
	if first.CPURequest != 1 {
		t.Fatalf("leased %s (cpu=%v), want a CPU-1 small job during the wait", first.ID, first.CPURequest)
	}

	// Wait elapsed: the aged blocked job becomes the head and blocks the
	// conflicting backfill.
	s.SetLeaseScanLimits(0, 0, 0)
	if _, _, _, err := s.Lease(ctx, runnerID, now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("lease after the wait elapsed = %v, want ErrNoJobs", err)
	}
	if st.claimCount() != 1 {
		t.Fatalf("claims = %d, want 1 (only the pre-wait backfill)", st.claimCount())
	}
}

// TestSchedulerJobCgroupHeadFitsAlongsideRelaxedEnvelope: on a JobCgroup
// runner the head-fits-alongside check charges each side's own request (the
// kernel bounds the aggregate), so a memory-only small job whose SERVICE
// ENVELOPE would occupy the head's starved CPU dimension is admitted instead
// of being refused. The union control on the same fixture refuses it.
func TestSchedulerJobCgroupHeadFitsAlongsideRelaxedEnvelope(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	newFixture := func(jobCgroup bool) (*resourceFakeStore, *DBScheduler, string) {
		st := newResourceFakeStore()
		runnerID := "runner-frag-cgroup"
		jobs := []model.Job{
			// The aged CPU head cannot fit the remaining 2 CPU (6 reserved
			// + 4 > 8) but is satisfiable once they drain.
			{ID: "job-cpu-big", CPURequest: 4, CreatedAt: now.Add(-2 * time.Hour)},
			// Memory-only job whose SERVICE ENVELOPE requests 2 CPU: the
			// union occupies the head's starved CPU dimension, the relaxed
			// request does not.
			{ID: "job-small", MemoryRequest: 1 << 30, ServiceEnvelopeRequest: model.ResourceCapacity{CPU: 2},
				CreatedAt: now.Add(-time.Minute)},
		}
		s := seedJobCgroupScheduler(t, st, runnerID, 8, model.ResourceCapacity{CPU: 8, Memory: 4 << 30}, jobCgroup, jobs...)
		st.mu.Lock()
		st.reserved = model.ResourceCapacity{CPU: 6}
		st.mu.Unlock()
		return st, s, runnerID
	}

	// Union: the small job's envelope adds 2 CPU to the head-starved
	// dimension, so the admission pre-filter rejects it outright.
	st, s, runnerID := newFixture(false)
	if _, _, _, err := s.Lease(ctx, runnerID, now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("union head lease = %v, want ErrNoJobs", err)
	}
	if st.claimCount() != 0 {
		t.Fatalf("union claims = %d, want 0 while the CPU head waits", st.claimCount())
	}

	// Relaxed: the candidate touches no CPU of its own, so it fits alongside
	// the CPU-blocked head and is leased; the claim reserves the job-only
	// request.
	st, s, runnerID = newFixture(true)
	j, _, _, err := s.Lease(ctx, runnerID, now)
	if err != nil {
		t.Fatalf("JobCgroup head lease: %v", err)
	}
	if j.ID != "job-small" {
		t.Fatalf("leased %s, want job-small alongside the CPU head", j.ID)
	}
	claim := st.lastClaim(t)
	if !claim.IgnoreServiceEnvelope || claim.RequestedResources() != (model.ResourceCapacity{Memory: 1 << 30}) {
		t.Fatalf("claim = %+v (reserved %+v), want the relaxed memory-only job request", claim, claim.RequestedResources())
	}
}

// TestSchedulerAgedLargeJobNotStarvedByDimension repeats the anti-backfill
// property for the memory and PIDs dimensions and for a mixed CPU+memory
// request: the reservation guard is dimension-generic, so each variant must
// refuse backfill that occupies the head's starved dimensions and lease the
// head once the reservations drain.
func TestSchedulerAgedLargeJobNotStarvedByDimension(t *testing.T) {
	cases := []struct {
		name     string
		capacity model.ResourceCapacity
		reserved model.ResourceCapacity
		big      model.Job
		small    model.Job
	}{
		{
			name:     "memory",
			capacity: model.ResourceCapacity{Memory: 8 << 30},
			reserved: model.ResourceCapacity{Memory: 7 << 30},
			big:      model.Job{ID: "job-big-mem", MemoryRequest: 8 << 30},
			small:    model.Job{MemoryRequest: 1 << 30},
		},
		{
			name:     "pids",
			capacity: model.ResourceCapacity{PIDs: 800},
			reserved: model.ResourceCapacity{PIDs: 700},
			big:      model.Job{ID: "job-big-pids", PIDsRequest: 800},
			small:    model.Job{PIDsRequest: 100},
		},
		{
			name:     "mixed",
			capacity: model.ResourceCapacity{CPU: 8, Memory: 8 << 30},
			reserved: model.ResourceCapacity{CPU: 7, Memory: 3 << 30},
			big:      model.Job{ID: "job-big-mixed", CPURequest: 8, MemoryRequest: 4 << 30},
			small:    model.Job{CPURequest: 1, MemoryRequest: 1 << 30},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st := newResourceFakeStore()
			runnerID := "runner-frag-" + tc.name
			now := time.Now().UTC()
			big := tc.big
			big.CreatedAt = now.Add(-2 * time.Hour)
			jobs := []model.Job{big}
			for i := 0; i < 20; i++ {
				s := tc.small
				s.ID = fmt.Sprintf("job-small-%02d", i)
				s.CreatedAt = now.Add(time.Duration(i) * time.Millisecond)
				jobs = append(jobs, s)
			}
			s := seedResourceScheduler(t, st, runnerID, 8, tc.capacity, jobs...)
			st.mu.Lock()
			st.reserved = tc.reserved
			st.mu.Unlock()

			for i := 0; i < 5; i++ {
				if _, _, _, err := s.Lease(ctx, runnerID, now); !errors.Is(err, ErrNoJobs) {
					t.Fatalf("poll %d: lease = %v, want ErrNoJobs (%s backfill must not starve the head)", i, err, tc.name)
				}
			}
			if st.claimCount() != 0 {
				t.Fatalf("claims = %d, want 0 while the %s head waits", st.claimCount(), tc.name)
			}
			st.mu.Lock()
			st.reserved = model.ResourceCapacity{}
			st.mu.Unlock()
			j, _, _, err := s.Lease(ctx, runnerID, now)
			if err != nil {
				t.Fatalf("lease after release: %v", err)
			}
			if j.ID != big.ID {
				t.Fatalf("leased %s, want %s", j.ID, big.ID)
			}
		})
	}
}
