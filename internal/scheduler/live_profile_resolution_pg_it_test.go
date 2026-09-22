package scheduler

// Real-PostgreSQL integration test for the scheduler's live-profile
// resolution: the candidate pre-filter (effectiveRunner) and the claim
// transaction resolve the runner-ID binding (runner_profile_links) through
// the same shared precedence as the certificate-serial binding, so a profile
// edit takes effect on the NEXT Lease without re-registration, and a
// dangling binding of either source fails closed. Gated on
// KIWI_TEST_POSTGRES_URL via the shared pgITSched* helpers.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestIntegrationLeaseRunnerIDProfilePrefilterPostgres drives the real
// DBScheduler.Lease path (pre-filter + SQL claim) over a bound bearer
// identity.
func TestIntegrationLeaseRunnerIDProfilePrefilterPostgres(t *testing.T) {
	st := pgITSchedStore(t)
	sched := pgITSchedLeader(t, st)
	ctx := context.Background()
	runnerID := pgITSchedID(t)
	profileID := "sched-live-" + pgITSchedRandomHex(t, 6)
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: 9, Labels: []string{"snapshot"}, CostPerHour: 9}); err != nil {
		t.Fatalf("upsert runner: %v", err)
	}
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: profileID, Labels: []string{"bound"}, MaxCapacity: 0, CostPerHour: 3.5}); err != nil {
		t.Fatalf("upsert profile: %v", err)
	}
	if err := st.LinkRunnerProfile(ctx, runnerID, profileID); err != nil {
		t.Fatalf("link runner: %v", err)
	}

	runID, jobID := pgITSchedID(t), pgITSchedID(t)
	job := pgITSchedJob(runID, jobID)
	job.RequiredLabels = []string{"bound"}
	if err := sched.Enqueue(ctx, model.Run{ID: runID, Repo: pgITSchedRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()}, map[string]model.Job{jobID: job}, nil, false); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// The live profile (capacity 0) takes no work even though the
	// registration snapshot says 9.
	if _, _, _, err := sched.Lease(ctx, runnerID, time.Now().UTC()); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("zero-capacity live profile lease = %v, want ErrNoJobs", err)
	}

	// Edit the profile: the NEXT lease honors capacity and rates without any
	// re-registration.
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: profileID, Labels: []string{"bound"}, MaxCapacity: 3, CostPerHour: 4.5}); err != nil {
		t.Fatalf("edit profile: %v", err)
	}
	leased, _, _, err := sched.Lease(ctx, runnerID, time.Now().UTC())
	if err != nil {
		t.Fatalf("lease after profile edit = %v", err)
	}
	if leased.ID != jobID {
		t.Fatalf("leased job = %s, want %s", leased.ID, jobID)
	}
	if leased.CostRate != 4.5 {
		t.Fatalf("frozen cost rate = %v, want 4.5 from the edited live profile", leased.CostRate)
	}

	// Dangling runner-ID binding: the prefilter presents the runner as
	// zero-capacity and the claim fails closed, never falling back to the
	// registration snapshot.
	if err := st.UnlinkRunnerProfile(ctx, runnerID); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if err := st.LinkRunnerProfile(ctx, runnerID, "ghost-"+pgITSchedRandomHex(t, 8)); err != nil {
		t.Fatalf("link dangling: %v", err)
	}
	snapRun, snapJob := pgITSchedID(t), pgITSchedID(t)
	snapshot := pgITSchedJob(snapRun, snapJob)
	snapshot.RequiredLabels = []string{"snapshot"}
	if err := sched.Enqueue(ctx, model.Run{ID: snapRun, Repo: pgITSchedRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()}, map[string]model.Job{snapJob: snapshot}, nil, false); err != nil {
		t.Fatalf("enqueue snapshot job: %v", err)
	}
	if _, _, _, err := sched.Lease(ctx, runnerID, time.Now().UTC()); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("dangling runner-ID binding lease = %v, want ErrNoJobs (fail closed)", err)
	}

	// Dangling certificate binding: the explicit binding wins and fails the
	// lease closed even while the runner-ID binding is live.
	certRunner := pgITSchedID(t)
	certSerial := "sched-dangling-" + pgITSchedRandomHex(t, 6)
	if err := st.UpsertRunner(ctx, model.Runner{ID: certRunner, Name: certRunner, Capacity: 4, Labels: []string{"snapshot"}, CertSerial: certSerial}); err != nil {
		t.Fatalf("upsert cert runner: %v", err)
	}
	if err := st.BindCertProfile(ctx, certSerial, "ghost-"+pgITSchedRandomHex(t, 8)); err != nil {
		t.Fatalf("bind dangling cert: %v", err)
	}
	if err := st.LinkRunnerProfile(ctx, certRunner, profileID); err != nil {
		t.Fatalf("link cert runner: %v", err)
	}
	certRun, certJob := pgITSchedID(t), pgITSchedID(t)
	bound := pgITSchedJob(certRun, certJob)
	bound.RequiredLabels = []string{"bound"}
	if err := sched.Enqueue(ctx, model.Run{ID: certRun, Repo: pgITSchedRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()}, map[string]model.Job{certJob: bound}, nil, false); err != nil {
		t.Fatalf("enqueue cert job: %v", err)
	}
	if _, _, _, err := sched.Lease(ctx, certRunner, time.Now().UTC()); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("dangling cert binding lease = %v, want ErrNoJobs (fail closed)", err)
	}
}
