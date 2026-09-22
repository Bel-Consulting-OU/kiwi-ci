package scheduler

// Aggregate service-envelope admission tests for the DB scheduler: the
// candidate pre-filter must charge the job's own request PLUS its aggregate
// service envelope (model.Job.ReservedResources), and an admitted candidate
// must carry the envelope into the claim so the claim transaction reserves
// the same total in the one ledger row — exactly what the fs/dev path and the
// reconciliation charge.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestSchedulerServiceEnvelopeReservationPreFilter: a candidate whose OWN
// request fits the runner but whose aggregate (own + service envelope) does
// not is skipped by the pre-filter — it must wait for a runner with room, not
// oversubscribe this one — while a plain job that fits is leased; the plain
// job's claim carries a zero envelope.
func TestSchedulerServiceEnvelopeReservationPreFilter(t *testing.T) {
	ctx := context.Background()
	st := newResourceFakeStore()
	runnerID := "runner-envelope"
	withServices := model.Job{
		ID: "job-svc", MemoryRequest: 5 << 30,
		ServiceEnvelopeRequest: model.ResourceCapacity{Memory: 2 << 30},
	}
	plain := model.Job{ID: "job-plain", MemoryRequest: 5 << 30}
	// 6 GiB capacity: the plain 5 GiB job fits; the service job's own 5 GiB
	// fits but its aggregate 5+2 GiB does not, so it is never claimed.
	s := seedResourceScheduler(t, st, runnerID, 8, model.ResourceCapacity{Memory: 6 << 30}, withServices, plain)

	j, _, _, err := s.Lease(ctx, runnerID, time.Now().UTC())
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if j.ID != "job-plain" {
		t.Fatalf("leased %s, want job-plain (the service aggregate must not fit)", j.ID)
	}
	if st.claimCount() != 1 {
		t.Fatalf("claims = %d, want 1 (the service candidate must be skipped before a claim)", st.claimCount())
	}
	claim := st.lastClaim(t)
	if claim.MemoryRequest != 5<<30 {
		t.Fatalf("claim own request = %d, want 5GiB", claim.MemoryRequest)
	}
	if claim.ServiceEnvelopeRequest != (model.ResourceCapacity{}) {
		t.Fatalf("plain claim envelope = %+v, want zero", claim.ServiceEnvelopeRequest)
	}
	if claim.RequestedResources().Memory != 5<<30 {
		t.Fatalf("plain claim total = %d, want the own request 5GiB", claim.RequestedResources().Memory)
	}
}

// TestSchedulerServiceEnvelopeCarriedIntoClaim: when the aggregate fits the
// job is leased and the claim carries the envelope;
// LeaseClaim.RequestedResources — the value the claim transaction reserves
// and rows — is own + envelope. A later candidate whose own request would fit
// the REMAINING capacity but whose aggregate does not is skipped, proving the
// live-reservation side is charged the same total.
func TestSchedulerServiceEnvelopeCarriedIntoClaim(t *testing.T) {
	ctx := context.Background()
	st := newResourceFakeStore()
	runnerID := "runner-envelope-fit"
	fit := model.Job{
		ID: "job-svc-fit", MemoryRequest: 3 << 30,
		ServiceEnvelopeRequest: model.ResourceCapacity{CPU: 1, Memory: 2 << 30, PIDs: 512},
	}
	noFit := model.Job{
		ID: "job-svc-nofit", MemoryRequest: 5 << 30,
		ServiceEnvelopeRequest: model.ResourceCapacity{Memory: 1 << 30},
	}
	s := seedResourceScheduler(t, st, runnerID, 8, model.ResourceCapacity{CPU: 4, Memory: 8 << 30, PIDs: 1024}, fit, noFit)

	leased, _, _, err := s.Lease(ctx, runnerID, time.Now().UTC())
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if leased.ID != "job-svc-fit" {
		t.Fatalf("leased %s, want job-svc-fit", leased.ID)
	}
	claim := st.lastClaim(t)
	if claim.ServiceEnvelopeRequest != (model.ResourceCapacity{CPU: 1, Memory: 2 << 30, PIDs: 512}) {
		t.Fatalf("claim envelope = %+v, want the persisted aggregate", claim.ServiceEnvelopeRequest)
	}
	if total, want := claim.RequestedResources(), (model.ResourceCapacity{CPU: 1, Memory: 5 << 30, PIDs: 512}); total != want {
		t.Fatalf("claim total = %+v, want own+envelope %+v", total, want)
	}

	// 3 GiB is now reserved by an older running job: the runner's remaining
	// 5 GiB fits noFit's own 5 GiB but not its 6 GiB aggregate, so no claim
	// is attempted.
	st.mu.Lock()
	st.reserved = model.ResourceCapacity{Memory: 3 << 30}
	st.claims = nil
	st.mu.Unlock()
	if _, _, _, err := s.Lease(ctx, runnerID, time.Now().UTC()); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("second lease error = %v, want ErrNoJobs (aggregate exceeds the remaining 5GiB)", err)
	}
	if st.claimCount() != 0 {
		t.Fatalf("second lease claims = %d, want 0", st.claimCount())
	}
}
