package storage

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

const (
	leaseRunID  = "11111111111111111111111111111111"
	leaseJobID  = "22222222222222222222222222222222"
	leaseJob2ID = "33333333333333333333333333333333"
	leaseRepo   = "https://github.com/o/r.git"
	// leaseRepoID is the canonical identity of leaseRepo: the key every
	// quota counter mutation derives (see RepoIDForJob / QuotaKeys).
	leaseRepoID = "github.com/o/r"
	leaseRunner = "44444444444444444444444444444444"
	leaseCert   = "cert-serial-1"
	leaseProf   = "profile-1"
)

// leaseClaimFor builds a minimal atomic-lease claim (no repo restriction).
func leaseClaimFor(jobID, runnerID string, capacity int) LeaseClaim {
	return LeaseClaim{
		JobID:          jobID,
		RunnerID:       runnerID,
		TokenHash:      []byte("hash"),
		Generation:     1,
		ExpiresAt:      time.Unix(3000, 0).UTC(),
		RunnerCapacity: capacity,
	}
}

// seedLeaseRun seeds one queued job on one repository.
func seedLeaseRun(m *memStore, jobID string) {
	_ = m.InsertRun(ctx(), model.Run{ID: leaseRunID, Repo: leaseRepo, Status: model.StatusQueued, CreatedAt: time.Unix(1000, 0).UTC()})
	_ = m.InsertJob(ctx(), model.Job{ID: jobID, RunID: leaseRunID, Key: "build", Status: model.StatusQueued, RepoURL: leaseRepo, RepoFullName: "o/r", CreatedAt: time.Unix(1001, 0).UTC()})
}

// TestMemStoreLeaseAtomicAttemptsStartedAtRates: the lease increments
// attempts exactly once, stamps started_at on the FIRST lease only (a
// requeue + re-lease preserves the original), and freezes the live usage
// rates into the job.
func TestMemStoreLeaseAtomicAttemptsStartedAtRates(t *testing.T) {
	m := newMemStore()
	seedLeaseRun(m, leaseJobID)
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 1, CostPerHour: 1.5, PowerWatts: 100}); err != nil {
		t.Fatal(err)
	}
	first, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1))
	if err != nil {
		t.Fatalf("first lease: %v", err)
	}
	if first.Attempts != 1 {
		t.Fatalf("attempts after first lease = %d, want 1", first.Attempts)
	}
	if first.StartedAt == nil {
		t.Fatal("started_at not stamped on first lease")
	}
	if first.CostRate != 1.5 || first.PowerWatts != 100 {
		t.Fatalf("frozen rates = %v/%v, want 1.5/100", first.CostRate, first.PowerWatts)
	}
	originalStart := *first.StartedAt

	// Requeue (lost-runner recovery) and re-lease: attempts increments, the
	// original started_at survives.
	first.Status = model.StatusQueued
	first.LeaseRunnerID = ""
	first.LeaseTokenHash = nil
	first.LeaseExpiresAt = nil
	if err := m.UpdateJob(ctx(), first); err != nil {
		t.Fatal(err)
	}
	if err := m.ReleaseRunnerJob(ctx(), leaseRunner, leaseJobID, model.StatusFailure); err != nil {
		t.Fatal(err)
	}
	second, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1))
	if err != nil {
		t.Fatalf("re-lease: %v", err)
	}
	if second.Attempts != 2 {
		t.Fatalf("attempts after re-lease = %d, want 2 (one per lease)", second.Attempts)
	}
	if second.StartedAt == nil || !second.StartedAt.Equal(originalStart) {
		t.Fatalf("started_at after re-lease = %v, want preserved %v", second.StartedAt, originalStart)
	}
}

// TestMemStorePlainLeaseAttemptsStartedAt: the non-atomic AcquireLease path
// applies the same attempts/started_at semantics.
func TestMemStorePlainLeaseAttemptsStartedAt(t *testing.T) {
	m := newMemStore()
	seedLeaseRun(m, leaseJobID)
	j, err := m.AcquireLease(ctx(), leaseJobID, leaseRunner, []byte("h"), 1, time.Unix(3000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if j.Attempts != 1 || j.StartedAt == nil {
		t.Fatalf("plain lease attempts/started_at = %d/%v", j.Attempts, j.StartedAt)
	}
}

// TestMemStoreZeroCapacitySurvivesCompletionAndRelease: capacity 0 is
// meaningful ("take no work") and must survive the completion and release
// paths unchanged; a zero-capacity runner is never leased.
func TestMemStoreZeroCapacitySurvivesCompletionAndRelease(t *testing.T) {
	m := newMemStore()
	seedLeaseRun(m, leaseJobID)
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); err != nil {
		t.Fatal(err)
	}
	// The profile shrank the live capacity to 0 while the job was running.
	ri, err := m.GetRunner(ctx(), leaseRunner)
	if err != nil {
		t.Fatal(err)
	}
	ri.Capacity = 0
	if err := m.UpsertRunner(ctx(), ri); err != nil {
		t.Fatal(err)
	}
	if err := m.CompleteJob(ctx(), leaseJobID, 1, leaseRunner, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: leaseJobID, Generation: 1, RunnerID: leaseRunner}); err != nil {
		t.Fatal(err)
	}
	ri, err = m.GetRunner(ctx(), leaseRunner)
	if err != nil {
		t.Fatal(err)
	}
	if ri.Capacity != 0 {
		t.Fatalf("capacity after completion = %d, want 0 (no clamp)", ri.Capacity)
	}
	if ri.Busy {
		t.Fatal("zero-capacity runner reported busy")
	}
	// A second job is never leased to the zero-capacity runner.
	second := model.Job{ID: leaseJob2ID, RunID: leaseRunID, Key: "second", Status: model.StatusQueued, RepoURL: leaseRepo, RepoFullName: "o/r", CreatedAt: time.Unix(1002, 0).UTC()}
	if err := m.InsertJob(ctx(), second); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJob2ID, leaseRunner, 0)); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("zero-capacity lease = %v, want ErrNoCapacity", err)
	}

	// ReleaseRunnerJob preserves capacity 0 too.
	if err := m.ReleaseRunnerJob(ctx(), leaseRunner, leaseJob2ID, model.StatusFailure); err != nil {
		t.Fatal(err)
	}
	ri, _ = m.GetRunner(ctx(), leaseRunner)
	if ri.Capacity != 0 {
		t.Fatalf("capacity after release = %d, want 0 (no clamp)", ri.Capacity)
	}
}

// TestMemStoreCancelRunReleasesRunnerSlot: a cancelled running job frees the
// runner's slot immediately, so a capacity-1 runner is schedulable again in
// the same operation.
func TestMemStoreCancelRunReleasesRunnerSlot(t *testing.T) {
	m := newMemStore()
	seedLeaseRun(m, leaseJobID)
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); err != nil {
		t.Fatal(err)
	}
	ri, _ := m.GetRunner(ctx(), leaseRunner)
	if len(ri.ActiveJobs) != 1 {
		t.Fatalf("runner active jobs before cancel = %v", ri.ActiveJobs)
	}
	if _, err := m.CancelRunJobs(ctx(), leaseRunID, "cancelled by test"); err != nil {
		t.Fatal(err)
	}
	ri, _ = m.GetRunner(ctx(), leaseRunner)
	if len(ri.ActiveJobs) != 0 || ri.Busy || ri.CurrentJob != "" {
		t.Fatalf("runner after cancel = active=%v busy=%v current=%q, want released", ri.ActiveJobs, ri.Busy, ri.CurrentJob)
	}
	// Immediately schedulable again: a queued job in a second run leases.
	_ = m.InsertRun(ctx(), model.Run{ID: leaseJob2ID, Repo: leaseRepo, Status: model.StatusQueued, CreatedAt: time.Unix(1001, 0).UTC()})
	_ = m.InsertJob(ctx(), model.Job{ID: leaseJob2ID, RunID: leaseJob2ID, Key: "next", Status: model.StatusQueued, RepoURL: leaseRepo, RepoFullName: "o/r", CreatedAt: time.Unix(1002, 0).UTC()})
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJob2ID, leaseRunner, 1)); err != nil {
		t.Fatalf("lease after cancel: %v", err)
	}
}

// TestMemStoreSupersessionReleasesRunnerSlot: the atomic enqueue's
// cancel-superseded path releases the superseded running job's runner slot
// in the same transaction.
func TestMemStoreSupersessionReleasesRunnerSlot(t *testing.T) {
	m := newMemStore()
	old := compiledRunRequest(leaseRunID, leaseJobID, leaseRepo)
	if err := m.InsertCompiledRun(ctx(), old); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); err != nil {
		t.Fatal(err)
	}
	next := compiledRunRequest(leaseJob2ID, "55555555555555555555555555555555", leaseRepo)
	next.CancelPrevious = []string{leaseJobID}
	if err := m.InsertCompiledRun(ctx(), next); err != nil {
		t.Fatal(err)
	}
	ri, _ := m.GetRunner(ctx(), leaseRunner)
	if len(ri.ActiveJobs) != 0 || ri.Busy {
		t.Fatalf("runner after supersession = active=%v busy=%v, want released", ri.ActiveJobs, ri.Busy)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor("55555555555555555555555555555555", leaseRunner, 1)); err != nil {
		t.Fatalf("lease after supersession: %v", err)
	}
}

// TestMemStoreLeaseDisabledDraining: disabled and draining runners take no
// work inside the claim.
func TestMemStoreLeaseDisabledDraining(t *testing.T) {
	m := newMemStore()
	seedLeaseRun(m, leaseJobID)
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 1, Disabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("disabled lease = %v, want ErrNoCapacity", err)
	}
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 1, Draining: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("draining lease = %v, want ErrNoCapacity", err)
	}
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); err != nil {
		t.Fatalf("enabled lease: %v", err)
	}
}

// TestMemStoreLeaseLiveProfileRepoACL: the claim resolves the LIVE profile
// (cert_profile_links -> runner_profiles). Shrinking a profile's repository
// ACL after registration immediately stops matching jobs, even though the
// registration snapshot still carries the old allowlist.
func TestMemStoreLeaseLiveProfileRepoACL(t *testing.T) {
	m := newMemStore()
	seedLeaseRun(m, leaseJobID)
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 1, CertSerial: leaseCert, AllowedRepositories: []string{"github.com/o/r"}}); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertProfile(ctx(), model.RunnerProfile{ID: leaseProf, Repositories: []string{"github.com/o/r"}, MaxCapacity: 1}); err != nil {
		t.Fatal(err)
	}
	if err := m.BindCertProfile(ctx(), leaseCert, leaseProf); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); err != nil {
		t.Fatalf("allowed-repo lease: %v", err)
	}
	// Requeue and shrink the profile ACL: the very next claim must deny.
	j, err := m.GetJob(ctx(), leaseJobID)
	if err != nil {
		t.Fatal(err)
	}
	j.Status = model.StatusQueued
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	if err := m.UpdateJob(ctx(), j); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertProfile(ctx(), model.RunnerProfile{ID: leaseProf, Repositories: []string{"github.com/o/other"}, MaxCapacity: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("shrunk-profile lease = %v, want ErrNoCapacity", err)
	}
	// The registration snapshot still shows the old ACL (display only).
	ri, _ := m.GetRunner(ctx(), leaseRunner)
	if len(ri.AllowedRepositories) != 1 || ri.AllowedRepositories[0] != "github.com/o/r" {
		t.Fatalf("registration snapshot changed: %v", ri.AllowedRepositories)
	}
}

// TestMemStoreLeaseLiveProfileCapacityAndCaps: the claim uses the profile's
// CURRENT max capacity and capability set.
func TestMemStoreLeaseLiveProfileCapacityAndCaps(t *testing.T) {
	m := newMemStore()
	seedLeaseRun(m, leaseJobID)
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 2, CertSerial: leaseCert, Capabilities: []string{"container"}, CostPerHour: 9}); err != nil {
		t.Fatal(err)
	}
	if err := m.UpsertProfile(ctx(), model.RunnerProfile{ID: leaseProf, MaxCapacity: 2, Capabilities: []string{"native"}, CostPerHour: 3, PowerWatts: 7}); err != nil {
		t.Fatal(err)
	}
	if err := m.BindCertProfile(ctx(), leaseCert, leaseProf); err != nil {
		t.Fatal(err)
	}
	// The job runs container; the live profile only grants native.
	job, _ := m.GetJob(ctx(), leaseJobID)
	job.CompiledJobPayload = compiledPayloadWithRuntime("container")
	if err := m.UpdateJob(ctx(), job); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 2)); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("profile capability mismatch = %v, want ErrNoCapacity", err)
	}
	// The profile grants container and a live capacity of 1.
	if err := m.UpsertProfile(ctx(), model.RunnerProfile{ID: leaseProf, MaxCapacity: 1, Capabilities: []string{"container"}, CostPerHour: 3, PowerWatts: 7}); err != nil {
		t.Fatal(err)
	}
	leased, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 2))
	if err != nil {
		t.Fatalf("profile-granted lease: %v", err)
	}
	if leased.CostRate != 3 || leased.PowerWatts != 7 {
		t.Fatalf("frozen profile rates = %v/%v, want 3/7", leased.CostRate, leased.PowerWatts)
	}
}

// TestMemStoreLeaseEnvironmentConcurrency: with EnvironmentConcurrency 1,
// exactly one of two concurrent claims wins the environment slot.
func TestMemStoreLeaseEnvironmentConcurrency(t *testing.T) {
	m := newMemStore()
	_ = m.InsertRun(ctx(), model.Run{ID: leaseRunID, Repo: leaseRepo, Status: model.StatusQueued, CreatedAt: time.Unix(1000, 0).UTC()})
	for _, id := range []string{leaseJobID, leaseJob2ID} {
		_ = m.InsertJob(ctx(), model.Job{ID: id, RunID: leaseRunID, Key: "deploy-" + id[:4], Status: model.StatusQueued, RepoURL: leaseRepo, RepoFullName: "o/r", Environment: "prod", EnvironmentConcurrency: 1, CreatedAt: time.Unix(1001, 0).UTC()})
	}
	for _, id := range []string{leaseRunner, "66666666666666666666666666666666"} {
		if err := m.UpsertRunner(ctx(), model.Runner{ID: id, Capacity: 1}); err != nil {
			t.Fatal(err)
		}
	}
	type result struct {
		jobID string
		err   error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for i, jobID := range []string{leaseJobID, leaseJob2ID} {
		wg.Add(1)
		go func(i int, jobID string) {
			defer wg.Done()
			runnerID := []string{leaseRunner, "66666666666666666666666666666666"}[i]
			claim := leaseClaimFor(jobID, runnerID, 1)
			claim.CanonRepoID = leaseRepoID
			claim.Environment = "prod"
			claim.EnvironmentConcurrency = 1
			_, err := m.AcquireLeaseAtomic(ctx(), claim)
			results <- result{jobID, err}
		}(i, jobID)
	}
	wg.Wait()
	close(results)
	var won int
	for r := range results {
		switch {
		case r.err == nil:
			won++
		case errors.Is(r.err, ErrEnvConcurrency):
		default:
			t.Fatalf("unexpected environment claim error: %v", r.err)
		}
	}
	if won != 1 {
		t.Fatalf("environment-concurrency winners = %d, want exactly 1", won)
	}
}

// TestMemStoreLeaseQuotaConcurrency: the conditional queued->running quota
// transition rejects the second claim against a concurrency-1 repository.
func TestMemStoreLeaseQuotaConcurrency(t *testing.T) {
	m := newMemStore()
	_ = m.InsertRun(ctx(), model.Run{ID: leaseRunID, Repo: leaseRepo, Status: model.StatusQueued, CreatedAt: time.Unix(1000, 0).UTC()})
	for _, id := range []string{leaseJobID, leaseJob2ID} {
		_ = m.InsertJob(ctx(), model.Job{ID: id, RunID: leaseRunID, Key: "job-" + id[:4], Status: model.StatusQueued, RepoURL: leaseRepo, RepoFullName: "o/r", CreatedAt: time.Unix(1001, 0).UTC()})
	}
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 2}); err != nil {
		t.Fatal(err)
	}
	claim := leaseClaimFor(leaseJobID, leaseRunner, 2)
	claim.RepoConcurrency = 1
	if _, err := m.AcquireLeaseAtomic(ctx(), claim); err != nil {
		t.Fatalf("first quota claim: %v", err)
	}
	second := leaseClaimFor(leaseJob2ID, leaseRunner, 2)
	second.RepoConcurrency = 1
	_, err := m.AcquireLeaseAtomic(ctx(), second)
	var qe *QuotaExceededError
	if !errors.As(err, &qe) {
		t.Fatalf("second quota claim = %v, want *QuotaExceededError", err)
	}
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("quota error does not unwrap to ErrQuotaExceeded: %v", err)
	}
	// The rejected job stays queued with no lease and no runner slot.
	j, _ := m.GetJob(ctx(), leaseJob2ID)
	if j.Status != model.StatusQueued || j.LeaseRunnerID != "" {
		t.Fatalf("rejected quota job mutated: %+v", j)
	}
	ri, _ := m.GetRunner(ctx(), leaseRunner)
	if len(ri.ActiveJobs) != 1 {
		t.Fatalf("runner active jobs = %v, want only the winner", ri.ActiveJobs)
	}
}

// TestMemStoreLeaseEnforcedEmptyPolicyDeniesAll: an ENFORCED effective
// policy that grants no runtime denies every runtime.
func TestMemStoreLeaseEnforcedEmptyPolicyDeniesAll(t *testing.T) {
	m := newMemStore()
	seedLeaseRun(m, leaseJobID)
	if err := m.UpsertRunner(ctx(), model.Runner{ID: leaseRunner, Capacity: 1}); err != nil {
		t.Fatal(err)
	}
	job, _ := m.GetJob(ctx(), leaseJobID)
	job.CompiledJobPayload = &model.CompiledJobPayload{EffectivePolicy: policy.Capabilities{Enforced: true}}
	if err := m.UpdateJob(ctx(), job); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("enforced-empty-policy lease = %v, want ErrNoCapacity", err)
	}
	// An enforced policy granting the job's runtime lease normally.
	job.CompiledJobPayload = &model.CompiledJobPayload{EffectiveJob: compiledPayloadWithRuntime("container").EffectiveJob, EffectivePolicy: policy.Capabilities{Enforced: true, Container: true}}
	if err := m.UpdateJob(ctx(), job); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AcquireLeaseAtomic(ctx(), leaseClaimFor(leaseJobID, leaseRunner, 1)); err != nil {
		t.Fatalf("enforced-container-policy lease: %v", err)
	}
}

// compiledPayloadWithRuntime builds a compiled payload carrying a runtime.
func compiledPayloadWithRuntime(runtimeName string) *model.CompiledJobPayload {
	return &model.CompiledJobPayload{
		SchemaVersion: 1,
		EffectiveJob:  map[string]any{"job": map[string]any{"runtime": runtimeName}},
	}
}

// TestPostgresCancelRunJobsCursorIsClosedBeforeUpdates is the structural
// regression test for the pgx cursor misuse: CancelRunJobs must drain the
// FOR UPDATE cursor and close it BEFORE any tx.Exec. The test reads the
// implementation source (there is no live Postgres in unit tests) and
// asserts the ordering inside the function body.
func TestPostgresCancelRunJobsCursorIsClosedBeforeUpdates(t *testing.T) {
	raw, err := os.ReadFile("postgres.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, "func (s *PostgresStore) CancelRunJobs(")
	if start < 0 {
		t.Fatal("CancelRunJobs not found in postgres.go")
	}
	rest := src[start:]
	if end := strings.Index(rest, "\nfunc "); end >= 0 {
		rest = rest[:end]
	}
	nextIdx := strings.Index(rest, "rows.Next()")
	closeIdx := strings.Index(rest, "rows.Close()")
	execIdx := strings.Index(rest, "tx.Exec(ctx,")
	if nextIdx < 0 || closeIdx < 0 || execIdx < 0 {
		t.Fatalf("CancelRunJobs structure changed: next=%d close=%d exec=%d", nextIdx, closeIdx, execIdx)
	}
	if closeIdx < nextIdx {
		t.Fatalf("rows.Close() (at %d) precedes the cursor loop (at %d)", closeIdx, nextIdx)
	}
	if execIdx < closeIdx {
		t.Fatal("CancelRunJobs runs tx.Exec while the FOR UPDATE cursor is still open (pgx cursor misuse)")
	}
	// The cursor loop body itself must not execute statements: the first
	// tx.Exec must come after the loop closed the rows.
	loopBody := rest[nextIdx:closeIdx]
	if strings.Contains(loopBody, "tx.Exec(") || strings.Contains(loopBody, "tx.Query(") || strings.Contains(loopBody, "tx.QueryRow(") {
		t.Fatal("CancelRunJobs issues a statement inside the open-cursor loop")
	}
}
