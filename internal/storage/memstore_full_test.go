package storage

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Canonical test identifiers (32 lowercase hex characters).
const (
	memRunID      = "11111111111111111111111111111111"
	memRunID2     = "12121212121212121212121212121212"
	memJobID      = "22222222222222222222222222222222"
	memJobID2     = "23232323232323232323232323232323"
	memRunnerID   = "33333333333333333333333333333333"
	memArtifactID = "44444444444444444444444444444444"
	memReportID   = "55555555555555555555555555555555"
	memSnapshotID = "66666666666666666666666666666666"
	memDeployID   = "77777777777777777777777777777777"
	memProfileID  = "88888888888888888888888888888888"
	memDigest     = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	memDigest2    = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

func memTestCtx() context.Context { return context.Background() }

func memTestRun(id string, status model.Status) model.Run {
	return model.Run{ID: id, Repo: "https://github.com/acme/api.git", RepoID: "github.com/acme/api", Status: status, CreatedAt: time.Now().UTC()}
}

func memTestJob(id, runID string, status model.Status) model.Job {
	return model.Job{ID: id, RunID: runID, Key: "build", RepoURL: "https://github.com/acme/api.git", RepoID: "github.com/acme/api",
		RepoFullName: "acme/api", Status: status, CreatedAt: time.Now().UTC()}
}

// TestMemStoreRunAndJobReads exercises the whole run/job read surface,
// including the not-found branches of every lookup.
func TestMemStoreRunAndJobReads(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	if err := m.Close(); err != nil {
		t.Fatalf("memStore close: %v", err)
	}
	if err := m.InsertRun(ctx, memTestRun(memRunID, model.StatusQueued)); err != nil {
		t.Fatalf("insert run: %v", err)
	}
	if err := m.InsertJob(ctx, memTestJob(memJobID, memRunID, model.StatusQueued)); err != nil {
		t.Fatalf("insert job: %v", err)
	}
	if _, err := m.GetRun(ctx, "ffffffffffffffffffffffffffffffff"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing run error = %v, want ErrNotFound", err)
	}
	if _, err := m.GetJob(ctx, "ffffffffffffffffffffffffffffffff"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing job error = %v, want ErrNotFound", err)
	}
	if _, err := m.GetRun(ctx, memRunID); err != nil {
		t.Fatalf("get run: %v", err)
	}

	runs, err := m.ListRuns(ctx, 10)
	if err != nil || len(runs) != 1 {
		t.Fatalf("ListRuns = %v, %v", runs, err)
	}
	jobs, err := m.ListJobsByRun(ctx, memRunID)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("ListJobsByRun = %v, %v", jobs, err)
	}
	if jobs, err = m.ListJobsByRun(ctx, memRunID2); err != nil || len(jobs) != 0 {
		t.Fatalf("ListJobsByRun other = %v, %v", jobs, err)
	}
	queued, err := m.ListQueuedJobs(ctx)
	if err != nil || len(queued) != 1 {
		t.Fatalf("ListQueuedJobs = %v, %v", queued, err)
	}

	envJob := memTestJob(memJobID2, memRunID, model.StatusRunning)
	envJob.Environment = "prod"
	// Legacy row: no stored RepoID, SSH clone-URL spelling. The listed key
	// is the canonical identity, so an HTTPS spelling reaches it too.
	envJob.RepoID = ""
	envJob.RepoURL = "git@github.com:acme/api.git"
	if err := m.InsertJob(ctx, envJob); err != nil {
		t.Fatalf("insert env job: %v", err)
	}
	// The listing is keyed by the CANONICAL repository identity: an HTTPS
	// spelling of the same repository reaches the SSH-spelled legacy row.
	byEnv, err := m.ListJobsByEnvironment(ctx, "github.com/acme/api", "prod")
	if err != nil || len(byEnv) != 1 || byEnv[0].ID != memJobID2 {
		t.Fatalf("ListJobsByEnvironment = %v, %v", byEnv, err)
	}
	byEnv, err = m.ListJobsByEnvironment(ctx, "github.com/other/api", "prod")
	if err != nil || len(byEnv) != 0 {
		t.Fatalf("ListJobsByEnvironment other = %v, %v", byEnv, err)
	}
	envJob.LeaseRunnerID = memRunnerID
	if err := m.UpdateJob(ctx, envJob); err != nil {
		t.Fatalf("update job: %v", err)
	}
	byRunner, err := m.ListJobsByRunner(ctx, memRunnerID)
	if err != nil || len(byRunner) != 1 || byRunner[0].ID != memJobID2 {
		t.Fatalf("ListJobsByRunner = %v, %v", byRunner, err)
	}
	byRunner, err = m.ListJobsByRunner(ctx, "ffffffffffffffffffffffffffffffff")
	if err != nil || len(byRunner) != 0 {
		t.Fatalf("ListJobsByRunner other = %v, %v", byRunner, err)
	}

	started := time.Now().UTC()
	finished := started.Add(time.Second)
	if err := m.UpdateRunStatus(ctx, memRunID, model.StatusSuccess, &started, &finished); err != nil {
		t.Fatalf("UpdateRunStatus: %v", err)
	}
	got, _ := m.GetRun(ctx, memRunID)
	if got.Status != model.StatusSuccess || got.StartedAt == nil || got.FinishedAt == nil {
		t.Fatalf("run after status update = %+v", got)
	}
	if err := m.UpdateRunStatus(ctx, memRunID, model.StatusFailure, nil, nil); err != nil {
		t.Fatalf("UpdateRunStatus nil times: %v", err)
	}
	if err := m.UpdateRunStatus(ctx, "ffffffffffffffffffffffffffffffff", model.StatusSuccess, nil, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateRunStatus missing = %v, want ErrNotFound", err)
	}
}

func TestMemStoreLeaseLifecycle(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	if err := m.InsertJob(ctx, memTestJob(memJobID, memRunID, model.StatusQueued)); err != nil {
		t.Fatalf("insert job: %v", err)
	}
	if _, err := m.AcquireLease(ctx, "ffffffffffffffffffffffffffffffff", memRunnerID, nil, 1, time.Now().Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("lease missing job = %v, want ErrNotFound", err)
	}
	expires := time.Now().Add(time.Minute)
	leased, err := m.AcquireLease(ctx, memJobID, memRunnerID, []byte("tok"), 1, expires)
	if err != nil {
		t.Fatalf("AcquireLease: %v", err)
	}
	if leased.Status != model.StatusRunning || leased.Attempts != 1 || leased.StartedAt == nil {
		t.Fatalf("leased job = %+v", leased)
	}
	if _, err := m.AcquireLease(ctx, memJobID, memRunnerID, nil, 2, expires); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("re-lease running job = %v, want ErrLeaseConflict", err)
	}
	if err := m.HeartbeatLease(ctx, "ffffffffffffffffffffffffffffffff", memRunnerID, 1, expires); !errors.Is(err, ErrNotFound) {
		t.Fatalf("heartbeat missing = %v", err)
	}
	if err := m.HeartbeatLease(ctx, memJobID, "99999999999999999999999999999999", 1, expires); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("heartbeat wrong runner = %v", err)
	}
	if err := m.HeartbeatLease(ctx, memJobID, memRunnerID, 2, expires); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("heartbeat wrong generation = %v", err)
	}
	later := expires.Add(time.Minute)
	if err := m.HeartbeatLease(ctx, memJobID, memRunnerID, 1, later); err != nil {
		t.Fatalf("HeartbeatLease: %v", err)
	}
	got, _ := m.GetJob(ctx, memJobID)
	if got.LeaseExpiresAt == nil || !got.LeaseExpiresAt.Equal(later) {
		t.Fatalf("heartbeat expiry = %v", got.LeaseExpiresAt)
	}
}

func TestMemStoreCompleteJobBranches(t *testing.T) {
	ctx := memTestCtx()
	newLeased := func(t *testing.T) *memStore {
		t.Helper()
		m := newMemStore()
		if err := m.InsertRun(ctx, memTestRun(memRunID, model.StatusRunning)); err != nil {
			t.Fatalf("insert run: %v", err)
		}
		if err := m.InsertJob(ctx, memTestJob(memJobID, memRunID, model.StatusQueued)); err != nil {
			t.Fatalf("insert job: %v", err)
		}
		if _, err := m.AcquireLease(ctx, memJobID, memRunnerID, nil, 3, time.Now().Add(time.Minute)); err != nil {
			t.Fatalf("lease: %v", err)
		}
		return m
	}
	receipt := func() model.CompletionReceipt {
		return model.CompletionReceipt{JobID: memJobID, Generation: 3, RunnerID: memRunnerID, ResultHash: "hash"}
	}

	m := newLeased(t)
	if err := m.CompleteJob(ctx, memJobID, -1, memRunnerID, model.StatusSuccess, "", nil, receipt()); err == nil {
		t.Fatal("negative generation must fail")
	}
	badReceipt := receipt()
	badReceipt.RunnerID = "99999999999999999999999999999999"
	if err := m.CompleteJob(ctx, memJobID, 3, memRunnerID, model.StatusSuccess, "", nil, badReceipt); err == nil {
		t.Fatal("mismatched receipt must fail")
	}
	if err := m.CompleteJob(ctx, "ffffffffffffffffffffffffffffffff", 3, memRunnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: "ffffffffffffffffffffffffffffffff", Generation: 3, RunnerID: memRunnerID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing job = %v", err)
	}
	if err := m.CompleteJob(ctx, memJobID, 4, memRunnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: memJobID, Generation: 4, RunnerID: memRunnerID}); !errors.Is(err, ErrGenerationMismatch) {
		t.Fatalf("stale generation = %v, want ErrGenerationMismatch", err)
	}

	// Required artifacts fail the completion closed until the artifact row
	// exists; the success then clears the contract requirement.
	if err := m.InsertJobContracts(ctx, memJobID, map[string]ArtifactContract{"bin": {Name: "bin", Required: true}}); err != nil {
		t.Fatalf("contracts: %v", err)
	}
	if err := m.CompleteJob(ctx, memJobID, 3, memRunnerID, model.StatusSuccess, "", nil, receipt()); !errors.Is(err, ErrRequiredArtifactMissing) {
		t.Fatalf("missing required artifact = %v", err)
	}
	if err := m.InsertArtifact(ctx, model.ArtifactRecord{ID: memArtifactID, RunID: memRunID, JobID: memJobID, Name: "bin", LeaseGeneration: 3}); err != nil {
		t.Fatalf("artifact: %v", err)
	}
	// A non-required contract entry never blocks the completion.
	if err := m.InsertJobContracts(ctx, memJobID, map[string]ArtifactContract{
		"bin":    {Name: "bin", Required: true},
		"report": {Name: "report"},
	}); err != nil {
		t.Fatalf("contracts: %v", err)
	}
	if err := m.CompleteJob(ctx, memJobID, 3, memRunnerID, model.StatusSuccess, "err", map[string]string{"k": "v"}, receipt()); err != nil {
		t.Fatalf("completion: %v", err)
	}
	// Replay of the same receipt is idempotent.
	if err := m.CompleteJob(ctx, memJobID, 3, memRunnerID, model.StatusSuccess, "", nil, receipt()); err != nil {
		t.Fatalf("replayed completion = %v", err)
	}
	// A different receipt for the now-terminal job is a generation mismatch.
	if err := m.CompleteJob(ctx, memJobID, 3, memRunnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: memJobID, Generation: 3, RunnerID: "99999999999999999999999999999999"}); err == nil {
		t.Fatal("identity-mismatched replay must fail")
	}
	got, _ := m.GetJob(ctx, memJobID)
	if got.Status != model.StatusSuccess || got.Error != "err" || got.LeaseRunnerID != "" || got.FinishedAt == nil || got.Outputs["k"] != "v" {
		t.Fatalf("completed job = %+v", got)
	}
	pending, err := m.OutboxPending(ctx)
	// Split design: exactly two intents per completion — the internal
	// completion_reconcile row and the external forge_delivery row.
	if err != nil || len(pending) != 2 {
		t.Fatalf("completion outbox = %v, %v", pending, err)
	}
	kinds := map[string]bool{}
	for _, it := range pending {
		kinds[it.Kind] = true
	}
	if !kinds[OutboxKindCompletionReconcile] || !kinds[OutboxKindForgeDelivery] {
		t.Fatalf("completion outbox kinds = %v", kinds)
	}

	// Runner slot bookkeeping: capacity survivors, busy recompute, counters.
	m2 := newLeased(t)
	r := model.Runner{ID: memRunnerID, Capacity: 2, ActiveJobs: []string{memJobID, memJobID2}, CurrentJob: memJobID}
	if err := m2.UpsertRunner(ctx, r); err != nil {
		t.Fatalf("runner: %v", err)
	}
	if err := m2.CompleteJob(ctx, memJobID, 3, memRunnerID, model.StatusFailure, "boom", nil, receipt()); err != nil {
		t.Fatalf("failure completion: %v", err)
	}
	gotRunner, _ := m2.GetRunner(ctx, memRunnerID)
	if gotRunner.Failed != 1 || gotRunner.CurrentJob != memJobID2 || gotRunner.Busy || len(gotRunner.ActiveJobs) != 1 {
		t.Fatalf("runner after failure = %+v", gotRunner)
	}
}

func TestMemStoreRunnerLifecycle(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	if _, err := m.GetRunner(ctx, memRunnerID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing runner = %v", err)
	}
	if err := m.UpsertRunner(ctx, model.Runner{ID: memRunnerID, Capacity: 2, ActiveJobs: []string{memJobID, memJobID2}, CurrentJob: memJobID}); err != nil {
		t.Fatalf("upsert runner: %v", err)
	}
	runners, err := m.ListRunners(ctx)
	if err != nil || len(runners) != 1 {
		t.Fatalf("ListRunners = %v, %v", runners, err)
	}
	if err := m.InsertJob(ctx, memTestJob(memJobID, memRunID, model.StatusRunning)); err != nil {
		t.Fatalf("insert job: %v", err)
	}
	// Releasing the current job promotes the next active job and recomputes
	// busy; the success counter moves.
	if err := m.ReleaseRunnerJob(ctx, memRunnerID, memJobID, model.StatusSuccess); err != nil {
		t.Fatalf("ReleaseRunnerJob: %v", err)
	}
	got, _ := m.GetRunner(ctx, memRunnerID)
	if got.CurrentJob != memJobID2 || len(got.ActiveJobs) != 1 || got.Completed != 1 || got.Busy {
		t.Fatalf("runner after release = %+v", got)
	}
	// Releasing the last job clears current_job entirely.
	if err := m.ReleaseRunnerJob(ctx, memRunnerID, memJobID2, model.StatusFailure); err != nil {
		t.Fatalf("ReleaseRunnerJob last: %v", err)
	}
	got, _ = m.GetRunner(ctx, memRunnerID)
	if got.CurrentJob != "" || len(got.ActiveJobs) != 0 || got.Failed != 1 {
		t.Fatalf("runner after last release = %+v", got)
	}
	// A deregistered runner still releases the job's reserved quota.
	if err := m.ReleaseRunnerJob(ctx, "ffffffffffffffffffffffffffffffff", memJobID, model.StatusSuccess); !errors.Is(err, ErrNotFound) {
		t.Fatalf("release on missing runner = %v", err)
	}
}

func TestMemStoreArtifactReportLogAuditDelivery(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	art := model.ArtifactRecord{ID: memArtifactID, RunID: memRunID, JobID: memJobID, LeaseGeneration: 1, Name: "bin", SHA256: "aaa"}
	emptyJobArt := art
	emptyJobArt.ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	emptyJobArt.RunID = memRunID2
	emptyJobArt.JobID = ""
	if err := m.InsertArtifact(ctx, emptyJobArt); err != nil {
		t.Fatalf("artifact without job: %v", err)
	}
	stored, created, err := m.InsertArtifactOnce(ctx, art)
	if err != nil || !created || stored.ID != memArtifactID {
		t.Fatalf("InsertArtifactOnce = %+v, %v, %v", stored, created, err)
	}
	stored, created, err = m.InsertArtifactOnce(ctx, art)
	if err != nil || created || stored.ID != memArtifactID {
		t.Fatalf("InsertArtifactOnce replay = %+v, %v, %v", stored, created, err)
	}
	conflict := art
	conflict.SHA256 = "bbb"
	if _, _, err := m.InsertArtifactOnce(ctx, conflict); !errors.Is(err, ErrArtifactDigestConflict) {
		t.Fatalf("digest conflict = %v", err)
	}
	if _, err := m.GetArtifact(ctx, memArtifactID); err != nil {
		t.Fatalf("GetArtifact: %v", err)
	}
	if _, err := m.GetArtifact(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatalf("GetArtifact jobless: %v", err)
	}
	if _, err := m.GetArtifact(ctx, "ffffffffffffffffffffffffffffffff"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetArtifact missing = %v", err)
	}
	arts, err := m.ListArtifacts(ctx, memRunID)
	if err != nil || len(arts) != 1 {
		t.Fatalf("ListArtifacts = %v, %v", arts, err)
	}
	if err := m.SetArtifactSidecars(ctx, memArtifactID, "sbom.json", "s1", "sig.json", "s2"); err != nil {
		t.Fatalf("SetArtifactSidecars: %v", err)
	}
	gotArt, _ := m.GetArtifact(ctx, memArtifactID)
	if gotArt.SBOMPath != "sbom.json" || gotArt.SBOMSHA256 != "s1" || gotArt.SigstorePath != "sig.json" || gotArt.SigstoreSHA256 != "s2" {
		t.Fatalf("sidecars = %+v", gotArt)
	}
	if err := m.SetArtifactSidecars(ctx, "ffffffffffffffffffffffffffffffff", "x", "", "", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("sidecars missing = %v", err)
	}

	if err := m.InsertTestReport(ctx, model.TestReport{ID: memReportID, RunID: memRunID, Tests: 1}); err != nil {
		t.Fatalf("InsertTestReport: %v", err)
	}
	reports, err := m.ListTestReports(ctx, memRunID)
	if err != nil || len(reports) != 1 {
		t.Fatalf("ListTestReports = %v, %v", reports, err)
	}
	if reports, err = m.ListTestReports(ctx, memRunID2); err != nil || len(reports) != 0 {
		t.Fatalf("ListTestReports other = %v, %v", reports, err)
	}
	if all, err := m.ListTestReportsAll(ctx); err != nil || len(all) != 1 {
		t.Fatalf("ListTestReportsAll = %v, %v", all, err)
	}

	if err := m.AppendLog(ctx, model.LogEntry{Seq: 1, RunID: memRunID, Line: "a"}); err != nil {
		t.Fatalf("AppendLog: %v", err)
	}
	if err := m.AppendLog(ctx, model.LogEntry{Seq: 2, RunID: memRunID, Line: "b"}); err != nil {
		t.Fatalf("AppendLog: %v", err)
	}
	if err := m.AppendLog(ctx, model.LogEntry{Seq: 3, RunID: memRunID2, Line: "c"}); err != nil {
		t.Fatalf("AppendLog: %v", err)
	}
	logs, err := m.ReadLogs(ctx, memRunID, 1, 10)
	if err != nil || len(logs) != 1 || logs[0].Seq != 2 {
		t.Fatalf("ReadLogs = %v, %v", logs, err)
	}
	if err := m.AppendAudit(ctx, model.AuditEvent{ID: "a1", Action: "x"}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	audit, err := m.ReadAudit(ctx, 10)
	if err != nil || len(audit) != 1 {
		t.Fatalf("ReadAudit = %v, %v", audit, err)
	}

	if err := m.InsertCompletionReceipt(ctx, model.CompletionReceipt{JobID: memJobID, Generation: 1, RunnerID: memRunnerID}); err != nil {
		t.Fatalf("InsertCompletionReceipt: %v", err)
	}
	rec, ok, err := m.HasCompletionReceipt(ctx, memJobID, 1, memRunnerID)
	if err != nil || !ok || rec.JobID != memJobID {
		t.Fatalf("HasCompletionReceipt = %+v, %v, %v", rec, ok, err)
	}
	if _, ok, err := m.HasCompletionReceipt(ctx, memJobID, 2, memRunnerID); err != nil || ok {
		t.Fatalf("HasCompletionReceipt missing = %v, %v", ok, err)
	}

	if err := m.UpsertDelivery(ctx, "github", "d1", memRunID, "digest"); err != nil {
		t.Fatalf("UpsertDelivery: %v", err)
	}
	v, ok, err := m.FindDelivery(ctx, "github", "d1")
	if err != nil || !ok || v != memRunID+"/digest" {
		t.Fatalf("FindDelivery = %q, %v, %v", v, ok, err)
	}
	if _, ok, err := m.FindDelivery(ctx, "github", "missing"); err != nil || ok {
		t.Fatalf("FindDelivery missing = %v, %v", ok, err)
	}

	if ok, err := m.TryAcquireLeadership(ctx, "leader", time.Minute); err != nil || !ok {
		t.Fatalf("TryAcquireLeadership = %v, %v", ok, err)
	}
	if err := m.ReleaseLeadership(ctx, "leader"); err != nil {
		t.Fatalf("ReleaseLeadership: %v", err)
	}
	if err := m.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	version, err := m.SchemaVersion(ctx)
	if err != nil || version != 1 {
		t.Fatalf("SchemaVersion = %d, %v", version, err)
	}
}

func TestMemStoreOutbox(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	now := time.Now().UTC()
	first := OutboxItem{ID: "o1", Kind: "k", CreatedAt: now}
	if err := m.OutboxAppend(ctx, first); err != nil {
		t.Fatalf("OutboxAppend: %v", err)
	}
	if err := m.OutboxAppend(ctx, first); err == nil {
		t.Fatal("duplicate outbox id must fail")
	}
	if err := m.OutboxAppend(ctx, OutboxItem{ID: "o2", Kind: "k", CreatedAt: now}); err != nil {
		t.Fatalf("OutboxAppend second: %v", err)
	}
	pending, err := m.OutboxPending(ctx)
	if err != nil || len(pending) != 2 {
		t.Fatalf("OutboxPending = %v, %v", pending, err)
	}

	if claimed, err := m.ClaimOutbox(ctx, "", 10); err != nil || claimed != nil {
		t.Fatalf("empty claimer = %v, %v", claimed, err)
	}
	if claimed, err := m.ClaimOutbox(ctx, "flusher", 0); err != nil || claimed != nil {
		t.Fatalf("zero limit = %v, %v", claimed, err)
	}
	claimed, err := m.ClaimOutbox(ctx, "flusher", 10)
	if err != nil || len(claimed) != 2 {
		t.Fatalf("ClaimOutbox = %v, %v", claimed, err)
	}
	again, err := m.ClaimOutbox(ctx, "other", 10)
	if err != nil || len(again) != 0 {
		t.Fatalf("fresh claims must be skipped = %v, %v", again, err)
	}
	// A stale claim is reclaimable; fresh claims (and the boundary claim
	// exactly at the cutoff) are still honored.
	m.mu.Lock()
	m.outboxClaims["o1"] = outboxClaim{claimer: "flusher", at: time.Now().UTC().Add(-OutboxClaimTTL - time.Hour)}
	m.mu.Unlock()
	reclaimed, err := m.ClaimOutbox(ctx, "other", 10)
	if err != nil || len(reclaimed) != 1 || reclaimed[0].ID != "o1" {
		t.Fatalf("stale reclaim = %v, %v", reclaimed, err)
	}
	m.mu.Lock()
	m.outboxClaims["o1"] = outboxClaim{claimer: "flusher", at: time.Now().UTC().Add(-OutboxClaimTTL + time.Hour)}
	m.mu.Unlock()
	if honored, err := m.ClaimOutbox(ctx, "other", 10); err != nil || len(honored) != 0 {
		t.Fatalf("boundary claim must be honored = %v, %v", honored, err)
	}
	if err := m.ReleaseOutboxClaim(ctx, "o1", "other"); err != nil {
		t.Fatalf("ReleaseOutboxClaim: %v", err)
	}
	if err := m.ReleaseOutboxClaim(ctx, "o2", "wrong-claimer"); err != nil {
		t.Fatalf("ReleaseOutboxClaim wrong claimer: %v", err)
	}
	if err := m.OutboxAck(ctx, "o1"); err != nil {
		t.Fatalf("OutboxAck: %v", err)
	}
	pending, err = m.OutboxPending(ctx)
	if err != nil || len(pending) != 1 || pending[0].ID != "o2" {
		t.Fatalf("after ack = %v, %v", pending, err)
	}
}

func TestMemStoreSchedulesAndOccurrences(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	nominal := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	created := time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)
	if err := m.UpsertSchedule(ctx, Schedule{ID: "s1", Repository: "acme/api", Spec: "@daily", CreatedAt: created}); err != nil {
		t.Fatalf("UpsertSchedule: %v", err)
	}
	// A zero CreatedAt on update preserves the stored creation time.
	if err := m.UpsertSchedule(ctx, Schedule{ID: "s1", Repository: "acme/api", Spec: "@hourly"}); err != nil {
		t.Fatalf("UpsertSchedule update: %v", err)
	}
	schedules, err := m.ListSchedules(ctx)
	if err != nil || len(schedules) != 1 || !schedules[0].CreatedAt.Equal(created) || schedules[0].Spec != "@hourly" {
		t.Fatalf("ListSchedules = %+v, %v", schedules, err)
	}
	// A fresh schedule keeps its own zero value (nothing to preserve).
	if err := m.UpsertSchedule(ctx, Schedule{ID: "s2", Repository: "acme/other"}); err != nil {
		t.Fatalf("UpsertSchedule fresh: %v", err)
	}

	claimed, err := m.ClaimScheduleOccurrence(ctx, "s1", nominal, memRunID)
	if err != nil || !claimed {
		t.Fatalf("claim = %v, %v", claimed, err)
	}
	if claimed, err = m.ClaimScheduleOccurrence(ctx, "s1", nominal, memRunID); err != nil || !claimed {
		t.Fatalf("idempotent claim = %v, %v", claimed, err)
	}
	if claimed, err = m.ClaimScheduleOccurrence(ctx, "s1", nominal, memRunID2); err != nil || claimed {
		t.Fatalf("conflicting claim = %v, %v", claimed, err)
	}
	later := nominal.Add(24 * time.Hour)
	if claimed, err = m.ClaimScheduleOccurrence(ctx, "s1", later, memRunID2); err != nil || !claimed {
		t.Fatalf("second nominal claim = %v, %v", claimed, err)
	}
	occurrences, err := m.ListOccurrences(ctx, "s1")
	if err != nil || len(occurrences) != 2 || !occurrences[0].Nominal.Equal(nominal) || occurrences[1].RunID != memRunID2 {
		t.Fatalf("ListOccurrences = %+v, %v", occurrences, err)
	}
	if occurrences, err = m.ListOccurrences(ctx, "missing"); err != nil || len(occurrences) != 0 {
		t.Fatalf("ListOccurrences missing = %+v, %v", occurrences, err)
	}
}

func TestMemStoreDeploymentsAndSnapshots(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	started := time.Now().UTC()
	finished := started.Add(time.Minute)
	if err := m.InsertDeployment(ctx, model.Deployment{ID: memDeployID, RunID: memRunID, Environment: "prod", Status: model.StatusRunning}); err != nil {
		t.Fatalf("InsertDeployment: %v", err)
	}
	if err := m.InsertDeployment(ctx, model.Deployment{ID: memSnapshotID, RunID: memRunID2, Environment: "dev"}); err != nil {
		t.Fatalf("InsertDeployment other: %v", err)
	}
	deps, err := m.ListDeploymentsByRun(ctx, memRunID)
	if err != nil || len(deps) != 1 || deps[0].ID != memDeployID {
		t.Fatalf("ListDeploymentsByRun = %+v, %v", deps, err)
	}
	if err := m.UpdateDeploymentStatus(ctx, memDeployID, model.StatusSuccess, &finished); err != nil {
		t.Fatalf("UpdateDeploymentStatus: %v", err)
	}
	deps, _ = m.ListDeploymentsByRun(ctx, memRunID)
	if deps[0].Status != model.StatusSuccess || deps[0].FinishedAt == nil {
		t.Fatalf("updated deployment = %+v", deps[0])
	}
	// A nil finishedAt leaves the stored value untouched.
	if err := m.UpdateDeploymentStatus(ctx, memDeployID, model.StatusFailure, nil); err != nil {
		t.Fatalf("UpdateDeploymentStatus nil: %v", err)
	}
	if err := m.UpdateDeploymentStatus(ctx, "ffffffffffffffffffffffffffffffff", model.StatusFailure, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing deployment = %v", err)
	}

	if err := m.InsertSnapshotRecord(ctx, model.SnapshotRecord{ID: memSnapshotID, RunID: memRunID, Version: 1}); err != nil {
		t.Fatalf("InsertSnapshotRecord: %v", err)
	}
	snaps, err := m.ListSnapshotsByRun(ctx, memRunID)
	if err != nil || len(snaps) != 1 || snaps[0].ID != memSnapshotID {
		t.Fatalf("ListSnapshotsByRun = %+v, %v", snaps, err)
	}
	if snaps, err = m.ListSnapshotsByRun(ctx, memRunID2); err != nil || len(snaps) != 0 {
		t.Fatalf("ListSnapshotsByRun other = %+v, %v", snaps, err)
	}
}

func TestMemStoreContractsAndQueueReasons(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	if err := m.InsertJob(ctx, memTestJob(memJobID, memRunID, model.StatusQueued)); err != nil {
		t.Fatalf("insert job: %v", err)
	}
	contracts := map[string]ArtifactContract{"bin": {Name: "bin", Required: true}}
	if err := m.InsertJobContracts(ctx, memJobID, contracts); err != nil {
		t.Fatalf("InsertJobContracts: %v", err)
	}
	// The store copies the map: mutating the caller's copy is invisible.
	contracts["bin"] = ArtifactContract{Name: "mutated"}
	got, ok, err := m.GetJobContracts(ctx, memJobID)
	if err != nil || !ok || got["bin"].Name != "bin" {
		t.Fatalf("GetJobContracts = %+v, %v, %v", got, ok, err)
	}
	got["bin"] = ArtifactContract{Name: "mutated"}
	again, _, _ := m.GetJobContracts(ctx, memJobID)
	if again["bin"].Name != "bin" {
		t.Fatal("GetJobContracts must return a copy")
	}
	if _, ok, err := m.GetJobContracts(ctx, memJobID2); err != nil || ok {
		t.Fatalf("GetJobContracts missing = %v, %v", ok, err)
	}
	if err := m.InsertJobContracts(ctx, "ffffffffffffffffffffffffffffffff", contracts); !errors.Is(err, ErrNotFound) {
		t.Fatalf("contracts for missing job = %v", err)
	}

	if err := m.SetQueueReasons(ctx, map[string]string{memJobID: "waiting for runner"}); err != nil {
		t.Fatalf("SetQueueReasons: %v", err)
	}
	job, _ := m.GetJob(ctx, memJobID)
	if job.QueueReason != "waiting for runner" {
		t.Fatalf("queue reason = %q", job.QueueReason)
	}
	// Unknown job IDs are ignored.
	if err := m.SetQueueReasons(ctx, map[string]string{"ffffffffffffffffffffffffffffffff": "x"}); err != nil {
		t.Fatalf("SetQueueReasons unknown: %v", err)
	}
}

func TestMemStoreGeneratedJobs(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	if err := m.InsertGeneratedJobs(ctx, memJobID, 1, map[string]model.Job{memJobID2: memTestJob(memJobID2, memRunID, model.StatusQueued)}, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing parent = %v", err)
	}
	if err := m.InsertJob(ctx, memTestJob(memJobID, memRunID, model.StatusRunning)); err != nil {
		t.Fatalf("insert parent: %v", err)
	}
	if err := m.InsertGeneratedJobs(ctx, memJobID, 1, map[string]model.Job{memJobID2: memTestJob(memJobID2, memRunID, model.StatusQueued)}, map[string][]string{memJobID2: {memJobID}}); err != nil {
		t.Fatalf("InsertGeneratedJobs: %v", err)
	}
	if _, err := m.GetJob(ctx, memJobID2); err != nil {
		t.Fatalf("generated job missing: %v", err)
	}
}

func TestMemStoreDownstreamLinks(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	link := DownstreamLink{ParentJobID: memJobID, TargetRepo: "acme/child", TargetRef: "main", LaunchToken: "tok"}
	if err := m.InsertDownstreamLink(ctx, link); err != nil {
		t.Fatalf("InsertDownstreamLink: %v", err)
	}
	// A duplicate link insert is a no-op.
	if err := m.InsertDownstreamLink(ctx, DownstreamLink{ParentJobID: memJobID, TargetRepo: "acme/child", TargetRef: "main", LaunchToken: "other"}); err != nil {
		t.Fatalf("duplicate link: %v", err)
	}
	got, ok, err := m.GetDownstreamLink(ctx, memJobID, "acme/child", "main")
	if err != nil || !ok || got.LaunchToken != "tok" || got.CreatedAt.IsZero() {
		t.Fatalf("GetDownstreamLink = %+v, %v, %v", got, ok, err)
	}
	if _, ok, err := m.GetDownstreamLink(ctx, memJobID, "acme/other", "main"); err != nil || ok {
		t.Fatalf("missing link = %v, %v", ok, err)
	}

	// Reserve on a missing row creates the reservation.
	reserved, err := m.ReserveDownstreamLaunch(ctx, memJobID, "acme/new", "main", "tok-new")
	if err != nil || !reserved {
		t.Fatalf("reserve new = %v, %v", reserved, err)
	}
	// A reserved link refuses a second reservation until released.
	if reserved, err = m.ReserveDownstreamLaunch(ctx, memJobID, "acme/new", "main", "tok-new"); err != nil || reserved {
		t.Fatalf("double reserve = %v, %v", reserved, err)
	}
	if err := m.ReleaseDownstreamReservation(ctx, memJobID, "acme/new", "main"); err != nil {
		t.Fatalf("ReleaseDownstreamReservation: %v", err)
	}
	released, _, _ := m.GetDownstreamLink(ctx, memJobID, "acme/new", "main")
	if released.Reserved || released.ReservedAt != nil {
		t.Fatalf("release did not clear reservation: %+v", released)
	}
	// A pre-existing record with no launch token gets the reserver's token.
	if err := m.InsertDownstreamLink(ctx, DownstreamLink{ParentJobID: memJobID, TargetRepo: "acme/child", TargetRef: "feature"}); err != nil {
		t.Fatalf("InsertDownstreamLink empty token: %v", err)
	}
	if reserved, err = m.ReserveDownstreamLaunch(ctx, memJobID, "acme/child", "feature", "tok-filled"); err != nil || !reserved {
		t.Fatalf("re-reserve = %v, %v", reserved, err)
	}
	released, _, _ = m.GetDownstreamLink(ctx, memJobID, "acme/child", "feature")
	if released.LaunchToken != "tok-filled" {
		t.Fatalf("launch token = %q", released.LaunchToken)
	}

	// Expiry releases stale reservations but never launched links.
	stale, err := m.ReserveDownstreamLaunch(ctx, memJobID, "acme/stale", "main", "tok")
	if err != nil || !stale {
		t.Fatalf("stale reserve = %v, %v", stale, err)
	}
	noTime, err := m.ReserveDownstreamLaunch(ctx, memJobID, "acme/notime", "main", "tok")
	if err != nil || !noTime {
		t.Fatalf("notime reserve = %v, %v", noTime, err)
	}
	m.mu.Lock()
	l := m.downstream[memJobID+"\x00acme/stale\x00main"]
	old := time.Now().UTC().Add(-time.Hour)
	l.ReservedAt = &old
	m.downstream[memJobID+"\x00acme/stale\x00main"] = l
	// A reservation with a nil ReservedAt is stale by definition.
	l = m.downstream[memJobID+"\x00acme/notime\x00main"]
	l.ReservedAt = nil
	m.downstream[memJobID+"\x00acme/notime\x00main"] = l
	m.mu.Unlock()
	expired, err := m.ExpireDownstreamReservations(ctx, time.Now().UTC().Add(-time.Minute))
	if err != nil || expired != 2 {
		t.Fatalf("ExpireDownstreamReservations = %d, %v", expired, err)
	}
	// Launched links and unclaimed rows are untouched by expiry.
	if reserved, err = m.ReserveDownstreamLaunch(ctx, memJobID, "acme/launched", "main", "tok"); err != nil || !reserved {
		t.Fatalf("launched reserve = %v, %v", reserved, err)
	}
	if err := m.MarkDownstreamLaunched(ctx, memJobID, "acme/launched", "main", memRunID2); err != nil {
		t.Fatalf("MarkDownstreamLaunched: %v", err)
	}
	launched, _, _ := m.GetDownstreamLink(ctx, memJobID, "acme/launched", "main")
	if launched.ChildRunID != memRunID2 || launched.Reserved {
		t.Fatalf("launched link = %+v", launched)
	}
	// Marking an already-launched or missing link is a no-op.
	if err := m.MarkDownstreamLaunched(ctx, memJobID, "acme/launched", "main", memRunID); err != nil {
		t.Fatalf("re-mark launched: %v", err)
	}
	if err := m.MarkDownstreamLaunched(ctx, memJobID, "acme/none", "main", memRunID); err != nil {
		t.Fatalf("mark missing: %v", err)
	}
	// Releasing a launched or missing reservation is a no-op.
	if err := m.ReleaseDownstreamReservation(ctx, memJobID, "acme/launched", "main"); err != nil {
		t.Fatalf("release launched: %v", err)
	}
	if err := m.ReleaseDownstreamReservation(ctx, memJobID, "acme/none", "main"); err != nil {
		t.Fatalf("release missing: %v", err)
	}
	if reserved, err := m.ReserveDownstreamLaunch(ctx, memJobID, "acme/launched", "main", "tok"); err != nil || reserved {
		t.Fatalf("reserve launched = %v, %v", reserved, err)
	}
	if err := m.ReleaseDownstreamReservation(ctx, memJobID, "acme/child", "feature"); err != nil {
		t.Fatalf("release feature: %v", err)
	}
	expired, err = m.ExpireDownstreamReservations(ctx, time.Now().UTC())
	if err != nil || expired != 0 {
		t.Fatalf("expiry with nothing stale = %d, %v", expired, err)
	}
}

func TestMemStoreUsageAndDownstreamRuns(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	now := time.Now().UTC()
	cost, energy, err := m.RecentUsage(ctx, now.Add(-time.Hour))
	if err != nil || cost != 0 || energy != 0 {
		t.Fatalf("empty usage = %v, %v, %v", cost, energy, err)
	}
	finished := now
	j := memTestJob(memJobID, memRunID, model.StatusSuccess)
	j.FinishedAt = &finished
	j.Cost = 2.5
	j.EnergyWh = 10
	if err := m.InsertJob(ctx, j); err != nil {
		t.Fatalf("insert job: %v", err)
	}
	unfinished := memTestJob(memJobID2, memRunID, model.StatusRunning)
	if err := m.InsertJob(ctx, unfinished); err != nil {
		t.Fatalf("insert job: %v", err)
	}
	cost, energy, err = m.RecentUsage(ctx, now.Add(-time.Hour))
	if err != nil || cost != 2.5 || energy != 10 {
		t.Fatalf("usage = %v, %v, %v", cost, energy, err)
	}
	if cost, energy, err = m.RecentUsage(ctx, now.Add(time.Hour)); err != nil || cost != 0 || energy != 0 {
		t.Fatalf("usage before cutoff = %v, %v, %v", cost, energy, err)
	}

	if err := m.AppendDownstreamRun(ctx, "ffffffffffffffffffffffffffffffff", memRunID2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("append to missing run = %v", err)
	}
	if err := m.InsertRun(ctx, memTestRun(memRunID, model.StatusSuccess)); err != nil {
		t.Fatalf("insert run: %v", err)
	}
	if err := m.AppendDownstreamRun(ctx, memRunID, memRunID2); err != nil {
		t.Fatalf("AppendDownstreamRun: %v", err)
	}
	// Appending the same child twice is idempotent.
	if err := m.AppendDownstreamRun(ctx, memRunID, memRunID2); err != nil {
		t.Fatalf("AppendDownstreamRun replay: %v", err)
	}
	run, _ := m.GetRun(ctx, memRunID)
	if len(run.DownstreamRuns) != 1 {
		t.Fatalf("downstream runs = %v", run.DownstreamRuns)
	}
	if err := m.ReopenRunForChildren(ctx, "ffffffffffffffffffffffffffffffff"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reopen missing = %v", err)
	}
	if err := m.ReopenRunForChildren(ctx, memRunID); err != nil {
		t.Fatalf("ReopenRunForChildren: %v", err)
	}
	run, _ = m.GetRun(ctx, memRunID)
	if run.Status != model.StatusRunning || run.FinishedAt != nil {
		t.Fatalf("reopened run = %+v", run)
	}
	// A non-success run is left untouched.
	if err := m.ReopenRunForChildren(ctx, memRunID); err != nil {
		t.Fatalf("reopen running: %v", err)
	}
}

func TestMemStoreQuotaCounters(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	if keys := memQuotaKeys("github.com/acme/api"); len(keys) != 2 {
		t.Fatalf("memQuotaKeys = %v", keys)
	}
	if err := m.AdjustQuotaCounter(ctx, "github.com/acme/api", "github.com/acme", 3, 4); err != nil {
		t.Fatalf("AdjustQuotaCounter: %v", err)
	}
	running, queued, err := m.QuotaCounts(ctx, "github.com/acme/api", "github.com/acme")
	if err != nil || running != 6 || queued != 8 {
		t.Fatalf("QuotaCounts = %d, %d, %v", running, queued, err)
	}
	// Empty keys are skipped and negative deltas clamp at zero.
	if err := m.AdjustQuotaCounter(ctx, "", "", -5, -5); err != nil {
		t.Fatalf("AdjustQuotaCounter empty: %v", err)
	}
	if err := m.AdjustQuotaCounter(ctx, "github.com/acme/api", "github.com/acme", -100, -100); err != nil {
		t.Fatalf("AdjustQuotaCounter clamp: %v", err)
	}
	running, queued, err = m.QuotaCounts(ctx, "github.com/acme/api", "github.com/acme")
	if err != nil || running != 0 || queued != 0 {
		t.Fatalf("clamped QuotaCounts = %d, %d, %v", running, queued, err)
	}
	// adjustQuotaLocked clamps too and tolerates unknown keys.
	m.mu.Lock()
	m.adjustQuotaLocked("", -1, -1)
	m.adjustQuotaLocked("gitlab.example.com/team/proj", -1, -1)
	m.mu.Unlock()
	if running, queued, _ := m.QuotaCounts(ctx, "gitlab.example.com/team/proj", ""); running != 0 || queued != 0 {
		t.Fatalf("clamped adjust = %d, %d", running, queued)
	}
}

func TestMemStorePendingSidecarBranches(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	if err := m.RememberPendingSidecar(ctx, memJobID, 1, "bin", ArtifactSidecarKindSBOM, memDigest); err != nil {
		t.Fatalf("RememberPendingSidecar: %v", err)
	}
	// A re-upload of the SAME generation replaces the digest.
	if err := m.RememberPendingSidecar(ctx, memJobID, 1, "bin", ArtifactSidecarKindSBOM, memDigest2); err != nil {
		t.Fatalf("RememberPendingSidecar replace: %v", err)
	}
	got, ok, err := m.PendingSidecar(ctx, memJobID, 1, "bin", ArtifactSidecarKindSBOM)
	if err != nil || !ok || got != memDigest2 {
		t.Fatalf("PendingSidecar = %q, %v, %v", got, ok, err)
	}
	if _, ok, err := m.PendingSidecar(ctx, memJobID, 1, "bin", ArtifactSidecarKindSigstore); err != nil || ok {
		t.Fatalf("missing sidecar = %v, %v", ok, err)
	}
	// A DIFFERENT generation is a different row: a retry generation never
	// resolves the previous generation's pending sidecar.
	if _, ok, _ := m.PendingSidecar(ctx, memJobID, 2, "bin", ArtifactSidecarKindSBOM); ok {
		t.Fatal("pending row leaked across lease generations")
	}
	if err := m.RememberPendingSidecar(ctx, memJobID, 2, "bin", ArtifactSidecarKindSBOM, memDigest); err != nil {
		t.Fatalf("remember generation 2: %v", err)
	}
	if d, ok, _ := m.PendingSidecar(ctx, memJobID, 1, "bin", ArtifactSidecarKindSBOM); !ok || d != memDigest2 {
		t.Fatalf("generation 1 row mutated by generation 2: %q ok=%v", d, ok)
	}
	// A stale consumer must not delete a newer digest.
	if err := m.ConsumePendingSidecar(ctx, memJobID, 1, "bin", ArtifactSidecarKindSBOM, memDigest); err != nil {
		t.Fatalf("stale consume: %v", err)
	}
	if _, ok, _ := m.PendingSidecar(ctx, memJobID, 1, "bin", ArtifactSidecarKindSBOM); !ok {
		t.Fatal("stale consume dropped a newer digest")
	}
	// Consuming an older generation never touches the other generation.
	if err := m.ConsumePendingSidecar(ctx, memJobID, 1, "bin", ArtifactSidecarKindSBOM, memDigest2); err != nil {
		t.Fatalf("ConsumePendingSidecar: %v", err)
	}
	if _, ok, _ := m.PendingSidecar(ctx, memJobID, 1, "bin", ArtifactSidecarKindSBOM); ok {
		t.Fatal("consume did not delete the row")
	}
	if _, ok, _ := m.PendingSidecar(ctx, memJobID, 2, "bin", ArtifactSidecarKindSBOM); !ok {
		t.Fatal("consume of generation 1 deleted generation 2's row")
	}
	// Consuming a missing row is a no-op.
	if err := m.ConsumePendingSidecar(ctx, memJobID, 1, "bin", ArtifactSidecarKindSBOM, memDigest2); err != nil {
		t.Fatalf("consume missing: %v", err)
	}

	// Artifact scoping: another artifact name in the same generation keeps
	// its own row.
	if err := m.RememberPendingSidecar(ctx, memJobID, 1, "bin", ArtifactSidecarKindSBOM, memDigest); err != nil {
		t.Fatalf("remember: %v", err)
	}
	if err := m.RememberPendingSidecar(ctx, memJobID, 1, "lib", ArtifactSidecarKindSigstore, memDigest); err != nil {
		t.Fatalf("remember other: %v", err)
	}
	if err := m.ConsumePendingSidecar(ctx, memJobID, 1, "bin", ArtifactSidecarKindSBOM, memDigest); err != nil {
		t.Fatalf("consume bin: %v", err)
	}
	if d, ok, _ := m.PendingSidecar(ctx, memJobID, 1, "lib", ArtifactSidecarKindSigstore); !ok || d != memDigest {
		t.Fatal("consume of bin dropped lib's pending row")
	}

	// Prune drops only rows older than the cutoff; fresh rows (whatever the
	// generation) survive.
	pruned, err := m.PrunePendingSidecars(ctx, time.Now().UTC().Add(-time.Hour))
	if err != nil || pruned != 0 {
		t.Fatalf("prune fresh = %d, %v", pruned, err)
	}
	pruned, err = m.PrunePendingSidecars(ctx, time.Now().UTC().Add(time.Hour))
	if err != nil || pruned != 2 {
		t.Fatalf("prune stale = %d, %v", pruned, err)
	}
}

func TestMemStoreSecretClaims(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	first, err := m.ClaimSecretDelivery(ctx, memJobID, 1, "TOKEN")
	if err != nil || !first {
		t.Fatalf("first claim = %v, %v", first, err)
	}
	second, err := m.ClaimSecretDelivery(ctx, memJobID, 1, "TOKEN")
	if err != nil || second {
		t.Fatalf("replayed claim = %v, %v", second, err)
	}
	if err := m.ReleaseSecretDelivery(ctx, memJobID, 1, "TOKEN"); err != nil {
		t.Fatalf("ReleaseSecretDelivery: %v", err)
	}
	third, err := m.ClaimSecretDelivery(ctx, memJobID, 1, "TOKEN")
	if err != nil || !third {
		t.Fatalf("claim after release = %v, %v", third, err)
	}
}

func TestMemStoreProfileAndTokenBranches(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	if _, err := m.GetProfile(ctx, memProfileID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing profile = %v", err)
	}
	// A zero CreatedAt is stamped on insert.
	if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: memProfileID, MaxCapacity: 2}); err != nil {
		t.Fatalf("UpsertProfile: %v", err)
	}
	p, err := m.GetProfile(ctx, memProfileID)
	if err != nil || p.CreatedAt.IsZero() {
		t.Fatalf("profile = %+v, %v", p, err)
	}
	// An explicit CreatedAt is preserved.
	explicit := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := m.UpsertProfile(ctx, model.RunnerProfile{ID: memJobID, CreatedAt: explicit}); err != nil {
		t.Fatalf("UpsertProfile explicit: %v", err)
	}
	if p, _ = m.GetProfile(ctx, memJobID); !p.CreatedAt.Equal(explicit) {
		t.Fatalf("explicit CreatedAt lost: %v", p.CreatedAt)
	}
	profiles, err := m.ListProfiles(ctx)
	if err != nil || len(profiles) != 2 || profiles[0].ID >= profiles[1].ID {
		t.Fatalf("ListProfiles = %+v, %v", profiles, err)
	}

	if _, ok, err := m.ProfileForSerial(ctx, "serial-missing"); err != nil || ok {
		t.Fatalf("unlinked serial = %v, %v", ok, err)
	}
	// A dangling link resolves to not-found rather than an error.
	if err := m.BindCertProfile(ctx, "serial-dangling", "99999999999999999999999999999999"); err != nil {
		t.Fatalf("BindCertProfile: %v", err)
	}
	if p, ok, err := m.ProfileForSerial(ctx, "serial-dangling"); err != nil || ok || p.ID != "" {
		t.Fatalf("dangling serial = %+v, %v, %v", p, ok, err)
	}
	if err := m.BindCertProfile(ctx, "serial", memProfileID); err != nil {
		t.Fatalf("BindCertProfile: %v", err)
	}
	if p, ok, err := m.ProfileForSerial(ctx, "serial"); err != nil || !ok || p.ID != memProfileID {
		t.Fatalf("ProfileForSerial = %+v, %v, %v", p, ok, err)
	}

	if has, err := m.HasRunnerTokens(ctx); err != nil || has {
		t.Fatalf("empty token set = %v, %v", has, err)
	}
	if err := m.UpsertRunnerToken(ctx, memRunnerID, "digest"); err != nil {
		t.Fatalf("UpsertRunnerToken: %v", err)
	}
	if id, ok, err := m.RunnerIDForToken(ctx, "digest"); err != nil || !ok || id != memRunnerID {
		t.Fatalf("RunnerIDForToken = %q, %v, %v", id, ok, err)
	}
	if _, ok, err := m.RunnerIDForToken(ctx, "unknown"); err != nil || ok {
		t.Fatalf("unknown token = %v, %v", ok, err)
	}
	if has, err := m.HasRunnerTokens(ctx); err != nil || !has {
		t.Fatalf("token set = %v, %v", has, err)
	}
}

func TestMemStoreRevocationsAndGrants(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	revoked, err := m.CertRevoked(ctx, "serial")
	if err != nil || revoked {
		t.Fatalf("fresh cert = %v, %v", revoked, err)
	}
	// The production revocation path is the runner-disable transaction (the
	// standalone RevokeCert was removed as dead code).
	if err := m.UpsertRunner(ctx, model.Runner{ID: memRunnerID, Name: memRunnerID, Capacity: 1, CertSerial: "serial"}); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	if _, err := m.DisableRunnerAndRevokeCert(ctx, memRunnerID, "serial", "admin"); err != nil {
		t.Fatalf("DisableRunnerAndRevokeCert: %v", err)
	}
	if revoked, err = m.CertRevoked(ctx, "serial"); err != nil || !revoked {
		t.Fatalf("revoked cert = %v, %v", revoked, err)
	}

	if _, err := m.ConsumeEnrollGrant(ctx, "unknown", "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown grant = %v", err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	if err := m.PutEnrollGrant(ctx, "digest", expires, []string{"linux"}); err != nil {
		t.Fatalf("PutEnrollGrant: %v", err)
	}
	rec, ok, err := m.GetEnrollGrant(ctx, "digest")
	if err != nil || !ok || rec.ExpiresAt.IsZero() || len(rec.BoundLabels) != 1 || rec.Consumed {
		t.Fatalf("GetEnrollGrant = %+v, %v, %v", rec, ok, err)
	}
	if _, ok, err := m.GetEnrollGrant(ctx, "missing"); err != nil || ok {
		t.Fatalf("GetEnrollGrant missing = %v, %v", ok, err)
	}
	consumed, err := m.ConsumeEnrollGrant(ctx, "digest", "admin")
	if err != nil || !consumed.Consumed {
		t.Fatalf("ConsumeEnrollGrant = %+v, %v", consumed, err)
	}
	if _, err := m.ConsumeEnrollGrant(ctx, "digest", "admin"); !errors.Is(err, ErrGrantConsumed) {
		t.Fatalf("second consume = %v, want ErrGrantConsumed", err)
	}
	if err := m.PutEnrollGrant(ctx, "expired", time.Now().UTC().Add(-time.Minute), nil); err != nil {
		t.Fatalf("PutEnrollGrant expired: %v", err)
	}
	if _, err := m.ConsumeEnrollGrant(ctx, "expired", "admin"); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("expired consume = %v, want ErrGrantExpired", err)
	}
}

func TestMemStoreTestHistory(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	version, stats, err := m.LoadTestHistory(ctx)
	if err != nil || version != 0 || stats != nil {
		t.Fatalf("empty history = %d, %v, %v", version, stats, err)
	}
	v1, err := m.SaveTestHistory(ctx, []byte(`{"a":1}`))
	if err != nil || v1 != 1 {
		t.Fatalf("SaveTestHistory = %d, %v", v1, err)
	}
	v2, err := m.SaveTestHistory(ctx, []byte(`{"a":2}`))
	if err != nil || v2 != 2 {
		t.Fatalf("SaveTestHistory = %d, %v", v2, err)
	}
	version, stats, err = m.LoadTestHistory(ctx)
	if err != nil || version != 2 || string(stats) != `{"a":2}` {
		t.Fatalf("history = %d, %s, %v", version, stats, err)
	}
	// The returned bytes are a copy.
	stats[0] = 'X'
	_, again, _ := m.LoadTestHistory(ctx)
	if again[0] == 'X' {
		t.Fatal("LoadTestHistory must return a copy")
	}
}

func TestMemStoreFragmentHelpers(t *testing.T) {
	if got := pendingSidecarKey("j", 3, "a", "k"); got != "j\x003\x00a\x00k" {
		t.Fatalf("pendingSidecarKey = %q", got)
	}
	if pendingSidecarKey("j", 3, "a", "k") == pendingSidecarKey("j", 4, "a", "k") {
		t.Fatal("pendingSidecarKey must include the lease generation")
	}
	if got := fragmentKey("j", 3, "f"); got != "j|3|f" {
		t.Fatalf("fragmentKey = %q", got)
	}
	if got := (&memStore{}).receiptKey("j", 3, "r"); got != "j|3|r" {
		t.Fatalf("receiptKey = %q", got)
	}
}

func TestMemStoreOutboxClaimBoundary(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	if err := m.OutboxAppend(ctx, OutboxItem{ID: "boundary"}); err != nil {
		t.Fatalf("append: %v", err)
	}
	// A claim exactly at the TTL boundary is still honored: only strictly
	// older claims are reclaimable.
	m.mu.Lock()
	m.outboxClaims["boundary"] = outboxClaim{claimer: "a", at: time.Now().UTC().Add(-OutboxClaimTTL + time.Hour)}
	m.mu.Unlock()
	claimed, err := m.ClaimOutbox(ctx, "b", 1)
	if err != nil || len(claimed) != 0 {
		t.Fatalf("boundary claim = %v, %v", claimed, err)
	}
	m.mu.Lock()
	m.outboxClaims["boundary"] = outboxClaim{claimer: "a", at: time.Now().UTC().Add(-OutboxClaimTTL - time.Hour)}
	m.mu.Unlock()
	claimed, err = m.ClaimOutbox(ctx, "b", 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("stale boundary claim = %v, %v", claimed, err)
	}
}

func TestMemStoreClaimOutboxRespectsLimit(t *testing.T) {
	ctx := memTestCtx()
	m := newMemStore()
	for i := 0; i < 3; i++ {
		if err := m.OutboxAppend(ctx, OutboxItem{ID: fmt.Sprintf("item-%d", i)}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	claimed, err := m.ClaimOutbox(ctx, "flusher", 2)
	if err != nil || len(claimed) != 2 {
		t.Fatalf("limited claim = %v, %v", claimed, err)
	}
	claimed, err = m.ClaimOutbox(ctx, "flusher", 2)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("remaining claim = %v, %v", claimed, err)
	}
}
