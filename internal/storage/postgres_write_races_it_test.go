package storage

// Regression tests for the P1 write-path races and the claim-authorization
// divergence between the SQL and in-memory stores:
//
//   - P1-A: a stale Get-then-Upsert runner registration must not clobber the
//     lease-owned fields (active_jobs/busy/current_job) that a concurrent
//     AcquireLeaseAtomic just reserved.
//   - P1-B: a stale approval write must not reset status/lease while the
//     runner slot, quota reservation and resource reservation stay held.
//   - P1-C: the SQL claim and the in-memory claim must make the SAME typed
//     decision for a cross-forge allowlist entry, an "r1:" identity entry and
//     an unlinked runner's registration snapshot.
//
// The in-memory halves run everywhere; the PostgreSQL halves are gated on
// KIWI_TEST_POSTGRES_URL exactly like the other *_it_test.go files.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// raceClaim builds a lease claim for one job/runner pair.
func raceClaim(jobID, runnerID string, gen int64) LeaseClaim {
	return LeaseClaim{
		JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: gen,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
}

// ---------------------------------------------------------------------------
// P1-A: runner Upsert must preserve lease-owned fields
// ---------------------------------------------------------------------------

func TestMemStoreRunnerUpsertPreservesLeaseOwnedFields(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	const runnerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0"
	const runID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
	const jobA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2"
	const jobB = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3"
	if err := m.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: "r", Capacity: 1}); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	for _, id := range []string{jobA, jobB} {
		if err := m.InsertJob(ctx, model.Job{ID: id, RunID: runID, Key: id, RepoURL: pgITRepo, RepoFullName: "kiwi-it/repo", Status: model.StatusQueued, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("seed job %s: %v", id, err)
		}
	}
	// Replica A reads the runner (active set empty) BEFORE replica B claims.
	stale, err := m.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner: %v", err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx, raceClaim(jobA, runnerID, 1)); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	// Replica A re-registers from its stale snapshot.
	stale.Name = "re-registered"
	stale.ActiveJobs = nil
	stale.CurrentJob = ""
	stale.Busy = false
	if err := m.UpsertRunner(ctx, stale); err != nil {
		t.Fatalf("stale upsert: %v", err)
	}
	got, err := m.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner after upsert: %v", err)
	}
	if len(got.ActiveJobs) != 1 || got.ActiveJobs[0] != jobA || got.CurrentJob != jobA {
		t.Fatalf("stale upsert clobbered the lease slot: %+v", got)
	}
	if got.Name != "re-registered" {
		t.Fatalf("profile field not updated by upsert: %+v", got)
	}
	if _, err := m.AcquireLeaseAtomic(ctx, raceClaim(jobB, runnerID, 1)); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("second claim on capacity-1 runner = %v, want ErrNoCapacity", err)
	}
}

func TestPostgresRunnerUpsertDoesNotClobberLeaseRegression(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID := pgITNewID(t)
	pgITSeedRunner(t, st, runnerID, 1, 0, 0)

	runA, jobA := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runA, jobA, pgITRepo)

	// Replica A reads the runner (active set empty) BEFORE replica B claims.
	stale, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, raceClaim(jobA, runnerID, 1)); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	// Replica A re-registers from its stale snapshot (the server's
	// Get-then-Upsert registration path).
	stale.Name = "re-registered"
	stale.ActiveJobs = nil
	stale.CurrentJob = ""
	stale.Busy = false
	if err := st.UpsertRunner(ctx, stale); err != nil {
		t.Fatalf("stale upsert: %v", err)
	}
	got, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner after upsert: %v", err)
	}
	if len(got.ActiveJobs) != 1 || got.ActiveJobs[0] != jobA || got.CurrentJob != jobA {
		t.Fatalf("stale upsert clobbered the lease slot: %+v", got)
	}
	if got.Name != "re-registered" {
		t.Fatalf("profile field not updated by upsert: %+v", got)
	}

	// The capacity-1 runner must now reject a second claim.
	runB, jobB := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runB, jobB, pgITRepo)
	if _, err := st.AcquireLeaseAtomic(ctx, raceClaim(jobB, runnerID, 1)); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("second claim on capacity-1 runner = %v, want ErrNoCapacity", err)
	}

	// UpdateRunnerProfileFields is the explicit guarded operation: it edits
	// the profile, preserves the lease slot, and never creates a runner.
	if err := st.UpdateRunnerProfileFields(ctx, model.Runner{ID: runnerID, Name: "profile-edit", Capacity: 5}); err != nil {
		t.Fatalf("UpdateRunnerProfileFields: %v", err)
	}
	got, err = st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner after profile edit: %v", err)
	}
	if got.Name != "profile-edit" || got.Capacity != 5 || len(got.ActiveJobs) != 1 {
		t.Fatalf("profile edit = %+v, want name/capacity updated with the slot preserved", got)
	}
	if err := st.UpdateRunnerProfileFields(ctx, model.Runner{ID: pgITNewID(t)}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateRunnerProfileFields on a missing runner = %v, want ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// P1-B: approval must not clobber a lease
// ---------------------------------------------------------------------------

// seedApprovalJob enqueues one approval-gated job in waiting_approval.
func seedApprovalJob(t *testing.T, st *PostgresStore, runID, jobID string) {
	t.Helper()
	now := time.Now().UTC()
	job := pgITJob(runID, jobID, pgITRepo)
	job.ApprovalRequired = true
	job.Status = model.StatusWaitingApproval
	job.WaitingSince = &now
	if err := st.InsertCompiledRun(context.Background(), InsertCompiledRunRequest{
		Run:  pgITRun(runID, model.StatusQueued),
		Jobs: map[string]model.Job{jobID: job},
	}); err != nil {
		t.Fatalf("enqueue approval job: %v", err)
	}
}

// assertApprovalStateConsistent verifies the runner slot, quota and resource
// reservation agree with the job's status.
func assertApprovalStateConsistent(t *testing.T, st *PostgresStore, runnerID, jobID string) {
	t.Helper()
	ctx := context.Background()
	j, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	ri, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner: %v", err)
	}
	running, queued, err := st.QuotaCounts(ctx, pgITRepoID, "")
	if err != nil {
		t.Fatalf("quota counts: %v", err)
	}
	res, err := st.ListResourceReservations(ctx, runnerID)
	if err != nil {
		t.Fatalf("reservations: %v", err)
	}
	hasSlot := false
	for _, id := range ri.ActiveJobs {
		if id == jobID {
			hasSlot = true
		}
	}
	hasReservation := false
	for _, r := range res {
		if r.JobID == jobID {
			hasReservation = true
		}
	}
	if j.Status == model.StatusRunning {
		if !hasSlot || !hasReservation || running != 1 || queued != 0 {
			t.Fatalf("running job inconsistent: status=%s slot=%v reservation=%v running=%d queued=%d", j.Status, hasSlot, hasReservation, running, queued)
		}
		return
	}
	if j.Status == model.StatusQueued {
		if hasSlot || hasReservation || running != 0 || queued != 1 {
			t.Fatalf("queued job inconsistent: status=%s slot=%v reservation=%v running=%d queued=%d", j.Status, hasSlot, hasReservation, running, queued)
		}
		return
	}
	t.Fatalf("unexpected job status %s", j.Status)
}

func TestPostgresApproveJobDoesNotClobberLeaseRegression(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID := pgITNewID(t)
	runID, jobID := pgITNewID(t), pgITNewID(t)
	seedApprovalJob(t, st, runID, jobID)
	pgITSeedRunner(t, st, runnerID, 1, 0, 0)

	// The guarded approval moves waiting_approval -> queued.
	approved, err := st.ApproveJob(ctx, jobID, "alice")
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	if approved.Status != model.StatusQueued || approved.ApprovedBy != "alice" {
		t.Fatalf("approved job = %+v, want queued/alice", approved)
	}
	// A concurrent claim now leases the job.
	if _, err := st.AcquireLeaseAtomic(ctx, raceClaim(jobID, runnerID, 1)); err != nil {
		t.Fatalf("claim after approval: %v", err)
	}
	// A stale duplicate approval (the server's Get-then-UpdateJob shape) must
	// not reset the lease: it only (re)records the approver.
	dup, err := st.ApproveJob(ctx, jobID, "bob")
	if err != nil {
		t.Fatalf("duplicate approval: %v", err)
	}
	if dup.Status != model.StatusRunning || dup.LeaseRunnerID != runnerID || dup.LeaseGeneration != 1 {
		t.Fatalf("duplicate approval clobbered the lease: %+v", dup)
	}
	if dup.ApprovedBy != "bob" {
		t.Fatalf("duplicate approval did not record the approver: %+v", dup)
	}
	assertApprovalStateConsistent(t, st, runnerID, jobID)

	// A job that does not require approval is rejected.
	plainRun, plainJob := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, plainRun, plainJob, pgITRepo)
	if _, err := st.ApproveJob(ctx, plainJob, "alice"); !errors.Is(err, ErrApprovalNotRequired) {
		t.Fatalf("approve a plain job = %v, want ErrApprovalNotRequired", err)
	}
}

// TestPostgresApproveVsClaimRaceConsistency races an approval against a claim
// and proves the runner slot, quota counter and resource reservation always
// agree with the final job status.
func TestPostgresApproveVsClaimRaceConsistency(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID := pgITNewID(t)
	runID, jobID := pgITNewID(t), pgITNewID(t)
	seedApprovalJob(t, st, runID, jobID)
	pgITSeedRunner(t, st, runnerID, 1, 0, 0)
	// Move the job to queued so the claim and a duplicate approval race.
	if _, err := st.ApproveJob(ctx, jobID, "alice"); err != nil {
		t.Fatalf("initial approval: %v", err)
	}

	var wg sync.WaitGroup
	approveErr := make(chan error, 1)
	claimErr := make(chan error, 1)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := st.ApproveJob(ctx, jobID, "bob")
		approveErr <- err
	}()
	go func() {
		defer wg.Done()
		_, err := st.AcquireLeaseAtomic(ctx, raceClaim(jobID, runnerID, 1))
		claimErr <- err
	}()
	wg.Wait()
	if err := <-approveErr; err != nil {
		t.Fatalf("racing approval: %v", err)
	}
	if err := <-claimErr; err != nil {
		t.Fatalf("racing claim: %v", err)
	}
	assertApprovalStateConsistent(t, st, runnerID, jobID)
}

func TestMemStoreApproveJobDoesNotClobberLease(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	const runnerID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0"
	const runID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1"
	const jobID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2"
	now := time.Now().UTC()
	if err := m.InsertJob(ctx, model.Job{ID: jobID, RunID: runID, Key: "build", RepoURL: pgITRepo, RepoFullName: "kiwi-it/repo", Status: model.StatusWaitingApproval, ApprovalRequired: true, WaitingSince: &now, CreatedAt: now}); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	if err := m.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: "r", Capacity: 1}); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	approved, err := m.ApproveJob(ctx, jobID, "alice")
	if err != nil || approved.Status != model.StatusQueued {
		t.Fatalf("approval = %+v, %v; want queued", approved, err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx, raceClaim(jobID, runnerID, 1)); err != nil {
		t.Fatalf("claim: %v", err)
	}
	dup, err := m.ApproveJob(ctx, jobID, "bob")
	if err != nil {
		t.Fatalf("duplicate approval: %v", err)
	}
	if dup.Status != model.StatusRunning || dup.LeaseRunnerID != runnerID || dup.LeaseGeneration != 1 || dup.ApprovedBy != "bob" {
		t.Fatalf("duplicate approval clobbered the lease: %+v", dup)
	}
	if _, err := m.ApproveJob(ctx, "ffffffffffffffffffffffffffffffff", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("approve missing = %v, want ErrNotFound", err)
	}
}

// ---------------------------------------------------------------------------
// P1-C: SQL and memory claim authorization must agree
// ---------------------------------------------------------------------------

// claimCase is one claim-authorization scenario evaluated against both stores.
// When profile is non-nil the runner is LINKED through the certificate-serial
// binding; otherwise the runner is unlinked and its registration snapshot is
// the scheduling view.
type claimCase struct {
	runner  model.Runner
	job     model.Job
	claim   LeaseClaim
	serial  string
	profile *model.RunnerProfile
	want    bool
}

// assertClaimCaseParity runs one scenario against the in-memory store and a
// fresh PostgreSQL schema and asserts both make the same decision.
func assertClaimCaseParity(t *testing.T, tc claimCase) {
	t.Helper()
	ctx := context.Background()

	m := newMemStore()
	if err := m.InsertJob(ctx, tc.job); err != nil {
		t.Fatalf("mem insert job: %v", err)
	}
	if tc.profile != nil {
		if err := m.UpsertProfile(ctx, *tc.profile); err != nil {
			t.Fatalf("mem profile: %v", err)
		}
		if err := m.BindCertProfile(ctx, tc.serial, tc.profile.ID); err != nil {
			t.Fatalf("mem bind: %v", err)
		}
	}
	if err := m.UpsertRunner(ctx, tc.runner); err != nil {
		t.Fatalf("mem upsert runner: %v", err)
	}
	_, memErr := m.AcquireLeaseAtomic(ctx, tc.claim)
	memAllowed := memErr == nil

	st := pgITStore(t)
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  model.Run{ID: tc.job.RunID, Repo: tc.job.RepoURL, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{tc.job.ID: tc.job},
	}); err != nil {
		t.Fatalf("sql enqueue: %v", err)
	}
	if tc.profile != nil {
		if err := st.UpsertProfile(ctx, *tc.profile); err != nil {
			t.Fatalf("sql profile: %v", err)
		}
		if err := st.BindCertProfile(ctx, tc.serial, tc.profile.ID); err != nil {
			t.Fatalf("sql bind: %v", err)
		}
	}
	if err := st.UpsertRunner(ctx, tc.runner); err != nil {
		t.Fatalf("sql upsert runner: %v", err)
	}
	_, pgErr := st.AcquireLeaseAtomic(ctx, tc.claim)
	pgAllowed := pgErr == nil

	if memAllowed != tc.want {
		t.Fatalf("%s: memory decision = %v (err=%v), want %v", tc.claim.JobID, memAllowed, memErr, tc.want)
	}
	if pgAllowed != tc.want {
		t.Fatalf("%s: sql decision = %v (err=%v), want %v", tc.claim.JobID, pgAllowed, pgErr, tc.want)
	}
	if pgAllowed != memAllowed {
		t.Fatalf("%s: sql and memory disagree: sql=%v memory=%v", tc.claim.JobID, pgAllowed, memAllowed)
	}
}

// TestClaimParityCrossForge: a LINKED profile allowlist entry for dotless
// host "gitlab" plus nested name must not admit a job that merely presents
// the same nested name on another forge. The old SQL raw-string compare did;
// the typed RepoAllowed (memory) already refused.
func TestClaimParityCrossForge(t *testing.T) {
	serial := "serial-" + pgITNewID(t)
	runnerID := pgITNewID(t)
	runID, jobID := pgITNewID(t), pgITNewID(t)
	job := pgITJob(runID, jobID, "https://example.com/gitlab/acme/widget.git")
	job.RepoFullName = "gitlab/acme/widget"
	claim := raceClaim(jobID, runnerID, 1)
	claim.CanonRepoID = RepoIDForJob(job)
	claim.RepoFullName = job.RepoFullName
	if claim.CanonRepoID == "gitlab/acme/widget" {
		t.Fatalf("scenario does not exercise cross-forge: identity collapsed")
	}
	assertClaimCaseParity(t, claimCase{
		runner:  model.Runner{ID: runnerID, Name: runnerID, Capacity: 1, CertSerial: serial},
		job:     job,
		claim:   claim,
		serial:  serial,
		profile: &model.RunnerProfile{ID: "cross-forge-" + pgITNewID(t), MaxCapacity: 1, Repositories: []string{"gitlab/acme/widget"}},
		want:    false,
	})
}

// TestClaimParityR1Identity: an "r1:" identity allowlist entry must admit the
// same canonical repository. The old SQL compared it to the unprefixed
// identity and denied.
func TestClaimParityR1Identity(t *testing.T) {
	serial := "serial-" + pgITNewID(t)
	runnerID := pgITNewID(t)
	runID, jobID := pgITNewID(t), pgITNewID(t)
	job := pgITJob(runID, jobID, "https://github.com/acme/widget.git")
	job.RepoFullName = "acme/widget"
	canonical := RepoIDForJob(job)
	entry := auth.RepoIdentity{Host: "github.com", FullName: "acme/widget"}.Serialized()
	if entry == "" {
		t.Fatal("failed to build the r1: allowlist entry")
	}
	claim := raceClaim(jobID, runnerID, 1)
	claim.CanonRepoID = canonical
	claim.RepoFullName = job.RepoFullName
	assertClaimCaseParity(t, claimCase{
		runner:  model.Runner{ID: runnerID, Name: runnerID, Capacity: 1, CertSerial: serial},
		job:     job,
		claim:   claim,
		serial:  serial,
		profile: &model.RunnerProfile{ID: "r1-" + pgITNewID(t), MaxCapacity: 1, Repositories: []string{entry}},
		want:    true,
	})
}

// TestClaimParityUnlinkedSnapshot: an UNLINKED runner's registration snapshot
// must bind the SQL claim exactly as it binds memory. The old SQL skipped
// every predicate when no profile was linked.
func TestClaimParityUnlinkedSnapshot(t *testing.T) {
	canonical := "github.com/acme/widget"
	baseRunner := func(runnerID string) model.Runner {
		return model.Runner{
			ID: runnerID, Name: runnerID, Capacity: 1,
			Labels: []string{"cpu"}, Region: "eu", Capabilities: []string{"container"},
			AllowedRepositories: []string{canonical},
		}
	}
	baseJob := func(runID, jobID string) model.Job {
		j := pgITJob(runID, jobID, "https://github.com/acme/widget.git")
		j.RepoFullName = "acme/widget"
		return j
	}

	t.Run("label", func(t *testing.T) {
		runnerID, runID, jobID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		job := baseJob(runID, jobID)
		job.RequiredLabels = []string{"gpu"}
		claim := raceClaim(jobID, runnerID, 1)
		claim.CanonRepoID = canonical
		claim.RepoFullName = job.RepoFullName
		claim.RequiredLabels = []string{"gpu"}
		assertClaimCaseParity(t, claimCase{runner: baseRunner(runnerID), job: job, claim: claim, want: false})
	})
	t.Run("capability", func(t *testing.T) {
		runnerID, runID, jobID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		job := baseJob(runID, jobID)
		job.CompiledJobPayload = compiledPayloadWithRuntime("tart")
		claim := raceClaim(jobID, runnerID, 1)
		claim.CanonRepoID = canonical
		claim.RepoFullName = job.RepoFullName
		claim.Runtime = "tart"
		assertClaimCaseParity(t, claimCase{runner: baseRunner(runnerID), job: job, claim: claim, want: false})
	})
	t.Run("region", func(t *testing.T) {
		runnerID, runID, jobID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		job := baseJob(runID, jobID)
		job.PlacementRegions = []string{"us"}
		claim := raceClaim(jobID, runnerID, 1)
		claim.CanonRepoID = canonical
		claim.RepoFullName = job.RepoFullName
		claim.PlacementRegions = []string{"us"}
		assertClaimCaseParity(t, claimCase{runner: baseRunner(runnerID), job: job, claim: claim, want: false})
	})
	t.Run("positive-control", func(t *testing.T) {
		runnerID, runID, jobID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
		job := baseJob(runID, jobID)
		job.CompiledJobPayload = compiledPayloadWithRuntime("container")
		claim := raceClaim(jobID, runnerID, 1)
		claim.CanonRepoID = canonical
		claim.RepoFullName = job.RepoFullName
		claim.Runtime = "container"
		assertClaimCaseParity(t, claimCase{runner: baseRunner(runnerID), job: job, claim: claim, want: true})
	})
}

// ---------------------------------------------------------------------------
// required-artifact generation scoping and receipt first-wins
// ---------------------------------------------------------------------------

func TestPostgresRequiredArtifactScopedToGeneration(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID := pgITNewID(t)
	pgITSeedRunner(t, st, runnerID, 1, 0, 0)
	contracts := map[string]ArtifactContract{"dist": {Name: "dist", Required: true}}

	runA, jobA := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runA, jobA, pgITRepo)
	if err := st.InsertJobContracts(ctx, jobA, contracts); err != nil {
		t.Fatalf("contracts: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, raceClaim(jobA, runnerID, 1)); err != nil {
		t.Fatalf("claim A: %v", err)
	}
	// An artifact from an EARLIER generation must not satisfy this lease.
	if _, _, err := st.InsertArtifactOnce(ctx, model.ArtifactRecord{ID: pgITNewID(t), RunID: runA, JobID: jobA, Name: "dist", LeaseGeneration: 0, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("stale-generation artifact: %v", err)
	}
	receiptA := model.CompletionReceipt{JobID: jobA, Generation: 1, RunnerID: runnerID}
	if err := st.CompleteJob(ctx, jobA, 1, runnerID, model.StatusSuccess, "", nil, receiptA); !errors.Is(err, ErrRequiredArtifactMissing) {
		t.Fatalf("completion with a stale-generation artifact = %v, want ErrRequiredArtifactMissing", err)
	}
	// The same artifact at the lease generation satisfies it.
	if _, _, err := st.InsertArtifactOnce(ctx, model.ArtifactRecord{ID: pgITNewID(t), RunID: runA, JobID: jobA, Name: "dist", LeaseGeneration: 1, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("current-generation artifact: %v", err)
	}
	if err := st.CompleteJob(ctx, jobA, 1, runnerID, model.StatusSuccess, "", nil, receiptA); err != nil {
		t.Fatalf("completion with the current-generation artifact: %v", err)
	}
}

func TestMemStoreRequiredArtifactScopedToGeneration(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	const runnerID = "ccccccccccccccccccccccccccccccc0"
	const runID = "ccccccccccccccccccccccccccccccc1"
	const jobID = "ccccccccccccccccccccccccccccccc2"
	if err := m.InsertJob(ctx, model.Job{ID: jobID, RunID: runID, Key: "k", RepoURL: pgITRepo, RepoFullName: "kiwi-it/repo", Status: model.StatusRunning, LeaseRunnerID: runnerID, LeaseGeneration: 1, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	if err := m.UpsertRunner(ctx, model.Runner{ID: runnerID, Capacity: 1}); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	if err := m.InsertJobContracts(ctx, jobID, map[string]ArtifactContract{"dist": {Name: "dist", Required: true}}); err != nil {
		t.Fatalf("contracts: %v", err)
	}
	if err := m.InsertArtifact(ctx, model.ArtifactRecord{ID: "ccccccccccccccccccccccccccccccc3", RunID: runID, JobID: jobID, Name: "dist", LeaseGeneration: 0}); err != nil {
		t.Fatalf("stale artifact: %v", err)
	}
	receipt := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID}
	if err := m.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, receipt); !errors.Is(err, ErrRequiredArtifactMissing) {
		t.Fatalf("stale-generation completion = %v, want ErrRequiredArtifactMissing", err)
	}
	if err := m.InsertArtifact(ctx, model.ArtifactRecord{ID: "ccccccccccccccccccccccccccccccc4", RunID: runID, JobID: jobID, Name: "dist", LeaseGeneration: 1}); err != nil {
		t.Fatalf("current artifact: %v", err)
	}
	if err := m.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, receipt); err != nil {
		t.Fatalf("current-generation completion: %v", err)
	}
}

// TestCompletionReceiptFirstWinsParity pins the shared first-wins semantic:
// the first receipt for an identity is never overwritten by a later one.
func TestCompletionReceiptFirstWinsParity(t *testing.T) {
	ctx := context.Background()
	const jobID = "ddddddddddddddddddddddddddddddd0"
	const runnerID = "ddddddddddddddddddddddddddddddd1"

	m := newMemStore()
	if err := m.InsertCompletionReceipt(ctx, model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "first"}); err != nil {
		t.Fatalf("mem first receipt: %v", err)
	}
	if err := m.InsertCompletionReceipt(ctx, model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "second"}); err != nil {
		t.Fatalf("mem second receipt: %v", err)
	}
	memRec, ok, err := m.HasCompletionReceipt(ctx, jobID, 1, runnerID)
	if err != nil || !ok || memRec.ResultHash != "first" {
		t.Fatalf("mem receipt = %+v ok=%v err=%v, want first-wins", memRec, ok, err)
	}

	st := pgITStore(t)
	if err := st.InsertCompletionReceipt(ctx, model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "first"}); err != nil {
		t.Fatalf("sql first receipt: %v", err)
	}
	if err := st.InsertCompletionReceipt(ctx, model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "second"}); err != nil {
		t.Fatalf("sql second receipt: %v", err)
	}
	pgRec, ok, err := st.HasCompletionReceipt(ctx, jobID, 1, runnerID)
	if err != nil || !ok || pgRec.ResultHash != "first" {
		t.Fatalf("sql receipt = %+v ok=%v err=%v, want first-wins", pgRec, ok, err)
	}
	if pgRec.ResultHash != memRec.ResultHash {
		t.Fatalf("receipt semantics diverge: sql=%q mem=%q", pgRec.ResultHash, memRec.ResultHash)
	}
}
