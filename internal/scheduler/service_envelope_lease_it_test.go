package scheduler

// Real-PostgreSQL integration test for the aggregate service-envelope
// reservation through the real DBScheduler.Lease path: the candidate
// pre-filter and the claim transaction (storage.AcquireLeaseAtomic) must
// charge the job's own request PLUS its aggregate service envelope, so a
// runner with room for the job alone never takes it and the durable ledger row
// equals the aggregate. Gated on KIWI_TEST_POSTGRES_URL.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// pgITSchedEnvelopeJob builds a queued job with its own memory request and
// the aggregate service envelope persisted in the payload.
func pgITSchedEnvelopeJob(runID, jobID string, own, envelope model.ResourceCapacity) model.Job {
	j := pgITSchedJob(runID, jobID)
	j.MemoryRequest = own.Memory
	j.ServiceEnvelopeRequest = envelope
	return j
}

// TestIntegrationServiceEnvelopeLeasePostgres: over a real database, a job
// with services reserves own+envelope in the one ledger row, a job whose
// aggregate is above the runner's capacity is never claimed, the remaining
// capacity blocks further work, and completion frees the aggregate so a job
// without services reserves exactly its own request.
func TestIntegrationServiceEnvelopeLeasePostgres(t *testing.T) {
	st := pgITSchedStore(t)
	sched := pgITSchedLeader(t, st)
	ctx := context.Background()
	runnerID, profileID := pgITSchedID(t), "env-sched-"+pgITSchedRandomHex(t, 6)
	serial := "env-sched-serial-" + pgITSchedRandomHex(t, 6)
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: profileID, MaxCapacity: 8, MaxMemory: 8 << 30}); err != nil {
		t.Fatalf("upsert profile: %v", err)
	}
	if err := st.BindCertProfile(ctx, serial, profileID); err != nil {
		t.Fatalf("bind profile: %v", err)
	}
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 8, CertSerial: serial}); err != nil {
		t.Fatalf("upsert runner: %v", err)
	}

	runID := pgITSchedID(t)
	blockedJob, fitJob, tailJob := pgITSchedID(t), pgITSchedID(t), pgITSchedID(t)
	fiveGiB := model.ResourceCapacity{Memory: 5 << 30}
	threeGiB := model.ResourceCapacity{Memory: 3 << 30}
	// Distinct priorities keep lease order deterministic: ties fall back to
	// created_at and random IDs, which made this test order-dependent.
	blocked := pgITSchedEnvelopeJob(runID, blockedJob, fiveGiB, model.ResourceCapacity{Memory: 4 << 30})
	blocked.Priority = 1
	fit := pgITSchedEnvelopeJob(runID, fitJob, fiveGiB, model.ResourceCapacity{Memory: 2 << 30})
	fit.Priority = 10
	tail := pgITSchedEnvelopeJob(runID, tailJob, threeGiB, model.ResourceCapacity{})
	tail.Priority = 5
	req := storage.InsertCompiledRunRequest{
		Run: model.Run{ID: runID, Repo: pgITSchedRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{
			// 5+4 = 9 > 8: permanently above the runner's capacity.
			blockedJob: blocked,
			// 5+2 = 7 <= 8: fits exactly one aggregate.
			fitJob: fit,
			// No services: own request only.
			tailJob: tail,
		},
	}
	if err := st.InsertCompiledRun(ctx, req); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// The blocked candidate is skipped by the aggregate pre-filter and the
	// fitting service job is leased; the returned payload carries the
	// envelope and the ledger row is the aggregate.
	leased, _, _, err := sched.Lease(ctx, runnerID, time.Now().UTC())
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if leased.ID != fitJob {
		t.Fatalf("leased %s, want the fitting service job %s", leased.ID, fitJob)
	}
	if leased.ServiceEnvelopeRequest.Memory != 2<<30 {
		t.Fatalf("leased envelope = %+v, want the persisted 2GiB", leased.ServiceEnvelopeRequest)
	}
	reserved, err := st.RunnerReservedResources(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Memory != 7<<30 {
		t.Fatalf("reserved memory = %d, want the 7GiB aggregate (5GiB job + 2GiB services)", reserved.Memory)
	}
	rows, err := st.ListResourceReservations(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("ledger rows = %d, want 1 (job + services share one row)", len(rows))
	}

	// The remaining 1 GiB cannot take the blocked job (9 GiB) or the tail
	// job (3 GiB).
	if _, _, _, err := sched.Lease(ctx, runnerID, time.Now().UTC()); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("second lease error = %v, want ErrNoJobs", err)
	}
	reserved, err = st.RunnerReservedResources(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Memory != 7<<30 {
		t.Fatalf("reserved memory after refusal = %d, want 7GiB", reserved.Memory)
	}

	// Completing the service job releases the aggregate row; the plain job
	// then leases and reserves exactly its own request.
	receipt := model.CompletionReceipt{JobID: fitJob, Generation: 1, RunnerID: runnerID}
	if err := st.CompleteJob(ctx, fitJob, 1, runnerID, model.StatusSuccess, "", nil, receipt); err != nil {
		t.Fatalf("complete service job: %v", err)
	}
	leased, _, _, err = sched.Lease(ctx, runnerID, time.Now().UTC())
	if err != nil {
		t.Fatalf("lease after release: %v", err)
	}
	if leased.ID != tailJob {
		t.Fatalf("leased %s, want the plain job %s", leased.ID, tailJob)
	}
	if leased.ServiceEnvelopeRequest != (model.ResourceCapacity{}) {
		t.Fatalf("plain job envelope = %+v, want zero", leased.ServiceEnvelopeRequest)
	}
	reserved, err = st.RunnerReservedResources(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Memory != 3<<30 {
		t.Fatalf("plain reserved memory = %d, want exactly its own 3GiB", reserved.Memory)
	}
}
