package storage

// Closed-pool error-path sweep: every PostgresStore method that talks to the
// database is called once after Close(), so the "query/begin failed" returns
// execute without needing fault injection. Validators and pure helpers are
// covered by their own tests.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestPostgresClosedPoolErrorPaths(t *testing.T) {
	dsn := pgITDSN(t)
	st, err := NewPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatalf("NewPostgres: %v", err)
	}
	_ = st.Close()
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	runnerID := pgITNewID(t)
	profileID := pgITNewID(t)
	now := time.Now().UTC()
	run := model.Run{ID: runID, Status: model.StatusQueued, CreatedAt: now}
	job := model.Job{ID: jobID, RunID: runID, Key: "build", Status: model.StatusQueued, CreatedAt: now}
	runner := model.Runner{ID: runnerID, Capacity: 1}

	type call struct {
		name string
		fn   func() error
	}
	calls := []call{
		{"InsertRun", func() error { return st.InsertRun(ctx, run) }},
		{"InsertCompiledRun", func() error { return st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: run}) }},
		{"Migrate", func() error { return st.Migrate(ctx) }},
		{"GetRun", func() error { _, err := st.GetRun(ctx, runID); return err }},
		{"UpdateRunStatus", func() error { return st.UpdateRunStatus(ctx, runID, model.StatusRunning, nil, nil) }},
		{"ListRuns", func() error { _, err := st.ListRuns(ctx, 5); return err }},
		{"InsertJob", func() error { return st.InsertJob(ctx, job) }},
		{"GetJob", func() error { _, err := st.GetJob(ctx, jobID); return err }},
		{"ListJobsByRun", func() error { _, err := st.ListJobsByRun(ctx, runID); return err }},
		{"ListJobsByEnvironment", func() error { _, err := st.ListJobsByEnvironment(ctx, pgITRepo, "prod"); return err }},
		{"ListQueuedJobs", func() error { _, err := st.ListQueuedJobs(ctx); return err }},
		{"ListJobsByRunner", func() error { _, err := st.ListJobsByRunner(ctx, runnerID); return err }},
		{"UpdateJob", func() error { return st.UpdateJob(ctx, job) }},
		{"AcquireLease", func() error {
			_, err := st.AcquireLease(ctx, jobID, runnerID, nil, 1, now.Add(time.Minute))
			return err
		}},
		{"AcquireLeaseAtomic", func() error {
			_, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID})
			return err
		}},
		{"HeartbeatLease", func() error { return st.HeartbeatLease(ctx, jobID, runnerID, 1, now) }},
		{"CompleteJob", func() error {
			return st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID})
		}},
		{"CancelRunJobs", func() error { _, err := st.CancelRunJobs(ctx, runID, "reason"); return err }},
		{"UpsertRunner", func() error { return st.UpsertRunner(ctx, runner) }},
		{"GetRunner", func() error { _, err := st.GetRunner(ctx, runnerID); return err }},
		{"ListRunners", func() error { _, err := st.ListRunners(ctx); return err }},
		{"ReleaseRunnerJob", func() error { return st.ReleaseRunnerJob(ctx, runnerID, jobID, model.StatusSuccess) }},
		{"ClaimSecretDelivery", func() error { _, err := st.ClaimSecretDelivery(ctx, jobID, 1, "TOKEN"); return err }},
		{"ReleaseSecretDelivery", func() error { return st.ReleaseSecretDelivery(ctx, jobID, 1, "TOKEN") }},
		{"InsertArtifact", func() error { return st.InsertArtifact(ctx, model.ArtifactRecord{ID: memArtifactID}) }},
		{"InsertArtifactOnce", func() error {
			_, _, err := st.InsertArtifactOnce(ctx, model.ArtifactRecord{ID: memArtifactID, JobID: jobID, Name: "bin"})
			return err
		}},
		{"ListArtifacts", func() error { _, err := st.ListArtifacts(ctx, runID); return err }},
		{"GetArtifact", func() error { _, err := st.GetArtifact(ctx, memArtifactID); return err }},
		{"InsertTestReport", func() error { return st.InsertTestReport(ctx, model.TestReport{ID: memReportID, RunID: runID}) }},
		{"ListTestReports", func() error { _, err := st.ListTestReports(ctx, runID); return err }},
		{"ListTestReportsAll", func() error { _, err := st.ListTestReportsAll(ctx); return err }},
		{"AppendLog", func() error { return st.AppendLog(ctx, model.LogEntry{RunID: runID, Line: "l"}) }},
		{"ReadLogs", func() error { _, err := st.ReadLogs(ctx, runID, 0, 5); return err }},
		{"AppendAudit", func() error { return st.AppendAudit(ctx, model.AuditEvent{ID: memReportID, Action: "a"}) }},
		{"ReadAudit", func() error { _, err := st.ReadAudit(ctx, 5); return err }},
		{"InsertCompletionReceipt", func() error {
			return st.InsertCompletionReceipt(ctx, model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID})
		}},
		{"HasCompletionReceipt", func() error {
			_, _, err := st.HasCompletionReceipt(ctx, jobID, 1, runnerID)
			return err
		}},
		{"UpsertDelivery", func() error { return st.UpsertDelivery(ctx, "github", "d", runID, "digest") }},
		{"FindDelivery", func() error { _, _, err := st.FindDelivery(ctx, "github", "d"); return err }},
		{"OutboxAppend", func() error { return st.OutboxAppend(ctx, OutboxItem{ID: "o", CreatedAt: now}) }},
		{"OutboxAck", func() error { return st.OutboxAck(ctx, "o") }},
		{"OutboxPending", func() error { _, err := st.OutboxPending(ctx); return err }},
		{"ClaimOutbox", func() error { _, err := st.ClaimOutbox(ctx, "f", 1); return err }},
		{"ReleaseOutboxClaim", func() error { return st.ReleaseOutboxClaim(ctx, "o", "f") }},
		{"UpsertSchedule", func() error { return st.UpsertSchedule(ctx, Schedule{ID: memReportID, Spec: "@daily"}) }},
		{"ListSchedules", func() error { _, err := st.ListSchedules(ctx); return err }},
		{"ClaimScheduleOccurrence", func() error {
			_, err := st.ClaimScheduleOccurrence(ctx, memReportID, now, runID)
			return err
		}},
		{"ListOccurrences", func() error { _, err := st.ListOccurrences(ctx, memReportID); return err }},
		{"InsertDeployment", func() error { return st.InsertDeployment(ctx, model.Deployment{ID: memDeployID}) }},
		{"ListDeploymentsByRun", func() error { _, err := st.ListDeploymentsByRun(ctx, runID); return err }},
		{"UpdateDeploymentStatus", func() error { return st.UpdateDeploymentStatus(ctx, memDeployID, model.StatusSuccess, nil) }},
		{"InsertSnapshotRecord", func() error { return st.InsertSnapshotRecord(ctx, model.SnapshotRecord{ID: memSnapshotID}) }},
		{"ListSnapshotsByRun", func() error { _, err := st.ListSnapshotsByRun(ctx, runID); return err }},
		{"InsertJobContracts", func() error { return st.InsertJobContracts(ctx, jobID, testContracts) }},
		{"GetJobContracts", func() error { _, _, err := st.GetJobContracts(ctx, jobID); return err }},
		{"SetQueueReasons", func() error { return st.SetQueueReasons(ctx, map[string]string{jobID: "x"}) }},
		{"InsertGeneratedJobs", func() error {
			return st.InsertGeneratedJobs(ctx, jobID, 1, map[string]model.Job{memJobID: {ID: memJobID}}, nil)
		}},
		{"GetGeneratedFragment", func() error { _, _, err := st.GetGeneratedFragment(ctx, jobID, 1, "f"); return err }},
		{"InsertGeneratedFragmentTx", func() error {
			_, _, err := st.InsertGeneratedFragmentTx(ctx, GeneratedFragmentRequest{ParentJobID: jobID, FragmentID: "f"}, nil)
			return err
		}},
		{"InsertDownstreamLink", func() error {
			return st.InsertDownstreamLink(ctx, DownstreamLink{ParentJobID: jobID, TargetRepo: "r", TargetRef: "ref", LaunchToken: "t"})
		}},
		{"GetDownstreamLink", func() error {
			_, _, err := st.GetDownstreamLink(ctx, jobID, "r", "ref")
			return err
		}},
		{"ReserveDownstreamLaunch", func() error {
			_, err := st.ReserveDownstreamLaunch(ctx, jobID, "r", "ref", "t")
			return err
		}},
		{"MarkDownstreamLaunched", func() error { return st.MarkDownstreamLaunched(ctx, jobID, "r", "ref", runID) }},
		{"ReleaseDownstreamReservation", func() error { return st.ReleaseDownstreamReservation(ctx, jobID, "r", "ref") }},
		{"ExpireDownstreamReservations", func() error { _, err := st.ExpireDownstreamReservations(ctx, now); return err }},
		{"RecentUsage", func() error { _, _, err := st.RecentUsage(ctx, now); return err }},
		{"AdjustQuotaCounter", func() error { return st.AdjustQuotaCounter(ctx, "k1", "k2", 1, 1) }},
		{"QuotaCounts", func() error { _, _, err := st.QuotaCounts(ctx, "k1", "k2"); return err }},
		{"PutCacheManifest", func() error {
			return st.PutCacheManifest(ctx, CacheManifestRecord{Repo: "r", TrustDomain: "t", LogicalKey: "l", BlobSHA256: memDigest})
		}},
		{"GetCacheManifest", func() error { _, _, err := st.GetCacheManifest(ctx, "r", "t", "l"); return err }},
		{"SetArtifactSidecars", func() error { return st.SetArtifactSidecars(ctx, memArtifactID, "p", "", "", "") }},
		{"RememberPendingSidecar", func() error {
			return st.RememberPendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM, memDigest)
		}},
		{"PendingSidecar", func() error {
			_, _, err := st.PendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM)
			return err
		}},
		{"ConsumePendingSidecar", func() error {
			return st.ConsumePendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM, memDigest)
		}},
		{"DeletePendingSidecars", func() error { return st.DeletePendingSidecars(ctx, jobID) }},
		{"PrunePendingSidecars", func() error { _, err := st.PrunePendingSidecars(ctx, now); return err }},
		{"AppendDownstreamRun", func() error { return st.AppendDownstreamRun(ctx, runID, runID) }},
		{"ReopenRunForChildren", func() error { return st.ReopenRunForChildren(ctx, runID) }},
		{"LoadTestHistory", func() error { _, _, err := st.LoadTestHistory(ctx); return err }},
		{"SaveTestHistory", func() error { _, err := st.SaveTestHistory(ctx, []byte("{}")); return err }},
		{"Migrate", func() error { return st.Migrate(ctx) }},
		{"SchemaVersion", func() error { _, err := st.SchemaVersion(ctx); return err }},
		{"UpsertProfile", func() error { return st.UpsertProfile(ctx, model.RunnerProfile{ID: profileID}) }},
		{"GetProfile", func() error { _, err := st.GetProfile(ctx, profileID); return err }},
		{"ListProfiles", func() error { _, err := st.ListProfiles(ctx); return err }},
		{"BindCertProfile", func() error { return st.BindCertProfile(ctx, "serial", profileID) }},
		{"ProfileForSerial", func() error { _, _, err := st.ProfileForSerial(ctx, "serial"); return err }},
		{"UpsertRunnerToken", func() error { return st.UpsertRunnerToken(ctx, runnerID, "digest") }},
		{"RunnerIDForToken", func() error { _, _, err := st.RunnerIDForToken(ctx, "digest"); return err }},
		{"HasRunnerTokens", func() error { _, err := st.HasRunnerTokens(ctx); return err }},
		{"RevokeCert", func() error { return st.RevokeCert(ctx, "serial", runnerID, "reason") }},
		{"CertRevoked", func() error { _, err := st.CertRevoked(ctx, "serial"); return err }},
		{"PutEnrollGrant", func() error { return st.PutEnrollGrant(ctx, "digest", now.Add(time.Hour), nil) }},
		{"GetEnrollGrant", func() error { _, _, err := st.GetEnrollGrant(ctx, "digest"); return err }},
		{"ConsumeEnrollGrant", func() error { _, err := st.ConsumeEnrollGrant(ctx, "digest", "admin"); return err }},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			err := c.fn()
			if err == nil {
				t.Fatalf("%s on a closed pool must report an error", c.name)
			}
			if errors.Is(err, ErrNotFound) {
				t.Fatalf("%s: closed pool must not masquerade as ErrNotFound", c.name)
			}
		})
	}
}
