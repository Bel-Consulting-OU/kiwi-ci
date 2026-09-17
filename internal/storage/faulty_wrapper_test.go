package storage

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// wrapperCase drives one FaultyStore wrapper twice: once with fault
// injection disabled (the pass-through must succeed) and, for mutating
// wrappers, once with a fault armed (the injected error must surface).
type wrapperCase struct {
	mutates bool
	seed    func(*memStore)
	call    func(*FaultyStore) error
}

func faultyWrapperCases() map[string]wrapperCase {
	artifact := model.ArtifactRecord{ID: "dddddddddddddddddddddddddddddddd", RunID: testRun.ID, JobID: testJob.ID, Name: "bin", SHA256: "e", CreatedAt: time.Unix(1002, 0).UTC()}
	pending := func(m *memStore) {
		_ = m.RememberPendingSidecar(ctx(), testJob.ID, "bin", ArtifactSidecarKindSBOM, memDigest)
	}
	fragment := func(m *memStore) {
		seedRunningJob(m)
		req := GeneratedFragmentRequest{
			ParentJobID:     testJob.ID,
			LeaseGeneration: 1,
			FragmentID:      "frag",
			Jobs:            map[string]model.Job{},
		}
		_, _, _ = m.InsertGeneratedFragmentTx(ctx(), req, nil)
	}
	cacheMan := func(m *memStore) {
		_ = m.PutCacheManifest(ctx(), CacheManifestRecord{Repo: "github.com/o/r", TrustDomain: "td", LogicalKey: "l"})
	}
	grant := func(m *memStore) {
		_ = m.PutEnrollGrant(ctx(), "digest", time.Now().UTC().Add(time.Hour), []string{"linux"})
	}
	reserved := func(m *memStore) {
		_, _ = m.ReserveDownstreamLaunch(ctx(), testJob.ID, "acme/child", "refs/heads/main", "tok")
	}
	return map[string]wrapperCase{
		"InsertRun": {mutates: true, call: func(f *FaultyStore) error { return f.InsertRun(ctx(), testRun) }},
		"GetRun":    {seed: seedRunAndJob, call: func(f *FaultyStore) error { _, err := f.GetRun(ctx(), testRun.ID); return err }},
		"UpdateRunStatus": {mutates: true, seed: seedRunAndJob, call: func(f *FaultyStore) error {
			return f.UpdateRunStatus(ctx(), testRun.ID, model.StatusRunning, nil, nil)
		}},
		"ListRuns":  {seed: seedRunAndJob, call: func(f *FaultyStore) error { _, err := f.ListRuns(ctx(), 10); return err }},
		"InsertJob": {mutates: true, seed: seedRunAndJob, call: func(f *FaultyStore) error { return f.InsertJob(ctx(), testJob) }},
		"GetJob":    {seed: seedRunAndJob, call: func(f *FaultyStore) error { _, err := f.GetJob(ctx(), testJob.ID); return err }},
		"ListJobsByRun": {seed: seedRunAndJob, call: func(f *FaultyStore) error {
			_, err := f.ListJobsByRun(ctx(), testRun.ID)
			return err
		}},
		"ListQueuedJobs": {seed: seedRunAndJob, call: func(f *FaultyStore) error { _, err := f.ListQueuedJobs(ctx()); return err }},
		"ListJobsByEnvironment": {seed: func(m *memStore) {
			j := testJob
			j.Environment = "prod"
			_ = m.InsertJob(ctx(), j)
		}, call: func(f *FaultyStore) error {
			_, err := f.ListJobsByEnvironment(ctx(), RepoIDForJob(testJob), "prod")
			return err
		}},
		"ListJobsByRunner": {seed: func(m *memStore) {
			j := testJob
			j.Status = model.StatusRunning
			j.LeaseRunnerID = testRunner.ID
			_ = m.InsertJob(ctx(), j)
		}, call: func(f *FaultyStore) error {
			_, err := f.ListJobsByRunner(ctx(), testRunner.ID)
			return err
		}},
		"UpdateJob": {mutates: true, seed: seedRunAndJob, call: func(f *FaultyStore) error {
			j := testJob
			j.Status = model.StatusRunning
			return f.UpdateJob(ctx(), j)
		}},
		"AcquireLease": {mutates: true, seed: seedRunAndJob, call: func(f *FaultyStore) error {
			_, err := f.AcquireLease(ctx(), testJob.ID, testRunner.ID, []byte("hash"), 1, time.Unix(2000, 0).UTC())
			return err
		}},
		"HeartbeatLease": {mutates: true, seed: func(m *memStore) { seedRunningJob(m); seedRunner(m) }, call: func(f *FaultyStore) error {
			return f.HeartbeatLease(ctx(), testJob.ID, testRunner.ID, 1, time.Unix(3000, 0).UTC())
		}},
		"CompleteJob": {mutates: true, seed: func(m *memStore) { seedRunningJob(m); seedRunner(m) }, call: func(f *FaultyStore) error {
			return f.CompleteJob(ctx(), testJob.ID, 1, testRunner.ID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: testJob.ID, Generation: 1, RunnerID: testRunner.ID})
		}},
		"CancelRunJobs": {mutates: true, seed: seedRunAndJob, call: func(f *FaultyStore) error {
			_, err := f.CancelRunJobs(ctx(), testRun.ID, "reason")
			return err
		}},
		"UpsertRunner": {mutates: true, seed: seedRunner, call: func(f *FaultyStore) error { return f.UpsertRunner(ctx(), testRunner) }},
		"GetRunner":    {seed: seedRunner, call: func(f *FaultyStore) error { _, err := f.GetRunner(ctx(), testRunner.ID); return err }},
		"ListRunners":  {seed: seedRunner, call: func(f *FaultyStore) error { _, err := f.ListRunners(ctx()); return err }},
		"ReleaseRunnerJob": {mutates: true, seed: func(m *memStore) { seedRunningJob(m); seedRunner(m) }, call: func(f *FaultyStore) error {
			return f.ReleaseRunnerJob(ctx(), testRunner.ID, testJob.ID, model.StatusSuccess)
		}},
		"InsertArtifact": {mutates: true, call: func(f *FaultyStore) error { return f.InsertArtifact(ctx(), artifact) }},
		"ListArtifacts": {seed: func(m *memStore) { _ = m.InsertArtifact(ctx(), artifact) }, call: func(f *FaultyStore) error {
			_, err := f.ListArtifacts(ctx(), testRun.ID)
			return err
		}},
		"InsertArtifactOnce": {mutates: true, call: func(f *FaultyStore) error {
			_, _, err := f.InsertArtifactOnce(ctx(), artifact)
			return err
		}},
		"InsertTestReport": {mutates: true, call: func(f *FaultyStore) error {
			return f.InsertTestReport(ctx(), model.TestReport{ID: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", RunID: testRun.ID})
		}},
		"ListTestReports": {seed: func(m *memStore) {
			_ = m.InsertTestReport(ctx(), model.TestReport{ID: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", RunID: testRun.ID})
		}, call: func(f *FaultyStore) error {
			_, err := f.ListTestReports(ctx(), testRun.ID)
			return err
		}},
		"ListTestReportsAll": {seed: func(m *memStore) {
			_ = m.InsertTestReport(ctx(), model.TestReport{ID: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", RunID: testRun.ID})
		}, call: func(f *FaultyStore) error {
			_, err := f.ListTestReportsAll(ctx())
			return err
		}},
		"AppendLog": {mutates: true, call: func(f *FaultyStore) error {
			return f.AppendLog(ctx(), model.LogEntry{Seq: 1, RunID: testRun.ID, Line: "l"})
		}},
		"ReadLogs": {seed: func(m *memStore) {
			_ = m.AppendLog(ctx(), model.LogEntry{Seq: 1, RunID: testRun.ID, Line: "l"})
		}, call: func(f *FaultyStore) error {
			_, err := f.ReadLogs(ctx(), testRun.ID, 0, 10)
			return err
		}},
		"AppendAudit": {mutates: true, call: func(f *FaultyStore) error {
			return f.AppendAudit(ctx(), model.AuditEvent{ID: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", Action: "a"})
		}},
		"ReadAudit": {seed: func(m *memStore) {
			_ = m.AppendAudit(ctx(), model.AuditEvent{ID: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", Action: "a"})
		}, call: func(f *FaultyStore) error {
			_, err := f.ReadAudit(ctx(), 10)
			return err
		}},
		"InsertCompletionReceipt": {mutates: true, call: func(f *FaultyStore) error {
			return f.InsertCompletionReceipt(ctx(), model.CompletionReceipt{JobID: testJob.ID, Generation: 1, RunnerID: testRunner.ID})
		}},
		"HasCompletionReceipt": {seed: func(m *memStore) {
			_ = m.InsertCompletionReceipt(ctx(), model.CompletionReceipt{JobID: testJob.ID, Generation: 1, RunnerID: testRunner.ID})
		}, call: func(f *FaultyStore) error {
			_, _, err := f.HasCompletionReceipt(ctx(), testJob.ID, 1, testRunner.ID)
			return err
		}},
		"UpsertDelivery": {mutates: true, call: func(f *FaultyStore) error {
			return f.UpsertDelivery(ctx(), "github", "d1", testRun.ID, "digest")
		}},
		"FindDelivery": {seed: func(m *memStore) { _ = m.UpsertDelivery(ctx(), "github", "d1", testRun.ID, "digest") }, call: func(f *FaultyStore) error {
			_, _, err := f.FindDelivery(ctx(), "github", "d1")
			return err
		}},
		"TryAcquireLeadership": {mutates: true, call: func(f *FaultyStore) error {
			_, err := f.TryAcquireLeadership(ctx(), "key", time.Minute)
			return err
		}},
		"ReleaseLeadership": {mutates: true, call: func(f *FaultyStore) error { return f.ReleaseLeadership(ctx(), "key") }},
		"Migrate":           {mutates: true, call: func(f *FaultyStore) error { return f.Migrate(ctx()) }},
		"SchemaVersion":     {call: func(f *FaultyStore) error { _, err := f.SchemaVersion(ctx()); return err }},
		"OutboxAppend":      {mutates: true, call: func(f *FaultyStore) error { return f.OutboxAppend(ctx(), OutboxItem{ID: "o1"}) }},
		"OutboxAck":         {mutates: true, call: func(f *FaultyStore) error { return f.OutboxAck(ctx(), "o1") }},
		"OutboxPending":     {call: func(f *FaultyStore) error { _, err := f.OutboxPending(ctx()); return err }},
		"ClaimOutbox":       {mutates: true, call: func(f *FaultyStore) error { _, err := f.ClaimOutbox(ctx(), "flusher", 1); return err }},
		"ReleaseOutboxClaim": {mutates: true, call: func(f *FaultyStore) error {
			return f.ReleaseOutboxClaim(ctx(), "o1", "flusher")
		}},
		"UpsertSchedule": {mutates: true, call: func(f *FaultyStore) error { return f.UpsertSchedule(ctx(), testSchedule) }},
		"ListSchedules": {seed: func(m *memStore) { _ = m.UpsertSchedule(ctx(), testSchedule) }, call: func(f *FaultyStore) error {
			_, err := f.ListSchedules(ctx())
			return err
		}},
		"ClaimScheduleOccurrence": {mutates: true, call: func(f *FaultyStore) error {
			_, err := f.ClaimScheduleOccurrence(ctx(), testSchedule.ID, time.Unix(2000, 0).UTC(), testRun.ID)
			return err
		}},
		"ListOccurrences": {seed: func(m *memStore) {
			_, _ = m.ClaimScheduleOccurrence(ctx(), testSchedule.ID, time.Unix(2000, 0).UTC(), testRun.ID)
		}, call: func(f *FaultyStore) error {
			_, err := f.ListOccurrences(ctx(), testSchedule.ID)
			return err
		}},
		"InsertDeployment": {mutates: true, call: func(f *FaultyStore) error { return f.InsertDeployment(ctx(), testDeployment) }},
		"ListDeploymentsByRun": {seed: func(m *memStore) { _ = m.InsertDeployment(ctx(), testDeployment) }, call: func(f *FaultyStore) error {
			_, err := f.ListDeploymentsByRun(ctx(), testRun.ID)
			return err
		}},
		"UpdateDeploymentStatus": {mutates: true, seed: func(m *memStore) { _ = m.InsertDeployment(ctx(), testDeployment) }, call: func(f *FaultyStore) error {
			return f.UpdateDeploymentStatus(ctx(), testDeployment.ID, model.StatusSuccess, nil)
		}},
		"InsertSnapshotRecord": {mutates: true, call: func(f *FaultyStore) error { return f.InsertSnapshotRecord(ctx(), testSnapshot) }},
		"ListSnapshotsByRun": {seed: func(m *memStore) { _ = m.InsertSnapshotRecord(ctx(), testSnapshot) }, call: func(f *FaultyStore) error {
			_, err := f.ListSnapshotsByRun(ctx(), testRun.ID)
			return err
		}},
		"InsertJobContracts": {mutates: true, seed: seedRunAndJob, call: func(f *FaultyStore) error {
			return f.InsertJobContracts(ctx(), testJob.ID, testContracts)
		}},
		"GetJobContracts": {seed: func(m *memStore) {
			seedRunAndJob(m)
			_ = m.InsertJobContracts(ctx(), testJob.ID, testContracts)
		}, call: func(f *FaultyStore) error {
			_, _, err := f.GetJobContracts(ctx(), testJob.ID)
			return err
		}},
		"SetQueueReasons": {mutates: true, seed: seedRunAndJob, call: func(f *FaultyStore) error {
			return f.SetQueueReasons(ctx(), map[string]string{testJob.ID: "waiting"})
		}},
		"InsertGeneratedJobs": {mutates: true, seed: seedRunningJob, call: func(f *FaultyStore) error {
			return f.InsertGeneratedJobs(ctx(), testJob.ID, 1, map[string]model.Job{memJobID: {ID: memJobID, RunID: testRun.ID}}, nil)
		}},
		"InsertDownstreamLink": {mutates: true, call: func(f *FaultyStore) error { return f.InsertDownstreamLink(ctx(), testDownstreamLink) }},
		"GetDownstreamLink": {seed: func(m *memStore) { _ = m.InsertDownstreamLink(ctx(), testDownstreamLink) }, call: func(f *FaultyStore) error {
			_, _, err := f.GetDownstreamLink(ctx(), testJob.ID, "acme/child", "refs/heads/main")
			return err
		}},
		"MarkDownstreamLaunched": {mutates: true, seed: reserved, call: func(f *FaultyStore) error {
			return f.MarkDownstreamLaunched(ctx(), testJob.ID, "acme/child", "refs/heads/main", testRun.ID)
		}},
		"RecentUsage": {seed: seedRunAndJob, call: func(f *FaultyStore) error {
			_, _, err := f.RecentUsage(ctx(), time.Unix(0, 0).UTC())
			return err
		}},
		"AppendDownstreamRun": {mutates: true, seed: seedRunAndJob, call: func(f *FaultyStore) error {
			return f.AppendDownstreamRun(ctx(), testRun.ID, memRunID2)
		}},
		"ReopenRunForChildren": {mutates: true, seed: func(m *memStore) {
			r := testRun
			r.Status = model.StatusSuccess
			_ = m.InsertRun(ctx(), r)
		}, call: func(f *FaultyStore) error { return f.ReopenRunForChildren(ctx(), testRun.ID) }},
		"GetArtifact": {seed: func(m *memStore) {
			_ = m.InsertArtifact(ctx(), model.ArtifactRecord{ID: memArtifactID})
		}, call: func(f *FaultyStore) error {
			_, err := f.GetArtifact(ctx(), memArtifactID)
			return err
		}},
		"InsertCompiledRun": {mutates: true, call: func(f *FaultyStore) error {
			return f.InsertCompiledRun(ctx(), InsertCompiledRunRequest{Run: testRun})
		}},
		"AcquireLeaseAtomic": {mutates: true, seed: func(m *memStore) { seedRunAndJob(m); seedRunner(m) }, call: func(f *FaultyStore) error {
			_, err := f.AcquireLeaseAtomic(ctx(), LeaseClaim{JobID: testJob.ID, RunnerID: testRunner.ID})
			return err
		}},
		"AdjustQuotaCounter": {mutates: true, call: func(f *FaultyStore) error {
			return f.AdjustQuotaCounter(ctx(), "github.com/o/r", "github.com/o", 1, 1)
		}},
		"QuotaCounts": {call: func(f *FaultyStore) error {
			_, _, err := f.QuotaCounts(ctx(), "github.com/o/r", "github.com/o")
			return err
		}},
		"ReserveDownstreamLaunch": {mutates: true, seed: func(m *memStore) { _ = m.InsertDownstreamLink(ctx(), testDownstreamLink) }, call: func(f *FaultyStore) error {
			_, err := f.ReserveDownstreamLaunch(ctx(), testJob.ID, "acme/child", "refs/heads/main", "tok2")
			return err
		}},
		"ReleaseDownstreamReservation": {mutates: true, seed: reserved, call: func(f *FaultyStore) error {
			return f.ReleaseDownstreamReservation(ctx(), testJob.ID, "acme/child", "refs/heads/main")
		}},
		"ExpireDownstreamReservations": {mutates: true, seed: reserved, call: func(f *FaultyStore) error {
			_, err := f.ExpireDownstreamReservations(ctx(), time.Unix(5000, 0).UTC())
			return err
		}},
		"InsertGeneratedFragmentTx": {mutates: true, seed: seedRunningJob, call: func(f *FaultyStore) error {
			_, _, err := f.InsertGeneratedFragmentTx(ctx(), GeneratedFragmentRequest{ParentJobID: testJob.ID, LeaseGeneration: 1, FragmentID: "frag"}, nil)
			return err
		}},
		"GetGeneratedFragment": {seed: fragment, call: func(f *FaultyStore) error {
			_, _, err := f.GetGeneratedFragment(ctx(), testJob.ID, 1, "frag")
			return err
		}},
		"PutCacheManifest": {mutates: true, call: func(f *FaultyStore) error {
			return f.PutCacheManifest(ctx(), CacheManifestRecord{Repo: "r", TrustDomain: "t", LogicalKey: "l"})
		}},
		"GetCacheManifest": {seed: cacheMan, call: func(f *FaultyStore) error {
			_, _, err := f.GetCacheManifest(ctx(), "github.com/o/r", "td", "l")
			return err
		}},
		"SetArtifactSidecars": {mutates: true, seed: func(m *memStore) { _ = m.InsertArtifact(ctx(), artifact) }, call: func(f *FaultyStore) error {
			return f.SetArtifactSidecars(ctx(), artifact.ID, "sbom", "s1", "sig", "s2")
		}},
		"RememberPendingSidecar": {mutates: true, call: func(f *FaultyStore) error {
			return f.RememberPendingSidecar(ctx(), testJob.ID, "bin", ArtifactSidecarKindSBOM, memDigest)
		}},
		"PendingSidecar": {seed: pending, call: func(f *FaultyStore) error {
			_, _, err := f.PendingSidecar(ctx(), testJob.ID, "bin", ArtifactSidecarKindSBOM)
			return err
		}},
		"ConsumePendingSidecar": {mutates: true, seed: pending, call: func(f *FaultyStore) error {
			return f.ConsumePendingSidecar(ctx(), testJob.ID, "bin", ArtifactSidecarKindSBOM, memDigest)
		}},
		"DeletePendingSidecars": {mutates: true, seed: pending, call: func(f *FaultyStore) error {
			return f.DeletePendingSidecars(ctx(), testJob.ID)
		}},
		"PrunePendingSidecars": {mutates: true, seed: pending, call: func(f *FaultyStore) error {
			_, err := f.PrunePendingSidecars(ctx(), time.Unix(6000, 0).UTC())
			return err
		}},
		"ClaimSecretDelivery": {mutates: true, call: func(f *FaultyStore) error {
			_, err := f.ClaimSecretDelivery(ctx(), testJob.ID, 1, "TOKEN")
			return err
		}},
		"ReleaseSecretDelivery": {mutates: true, call: func(f *FaultyStore) error {
			return f.ReleaseSecretDelivery(ctx(), testJob.ID, 1, "TOKEN")
		}},
		"UpsertProfile": {mutates: true, call: func(f *FaultyStore) error {
			return f.UpsertProfile(ctx(), model.RunnerProfile{ID: memProfileID, MaxCapacity: 2})
		}},
		"GetProfile": {seed: func(m *memStore) { _ = m.UpsertProfile(ctx(), model.RunnerProfile{ID: memProfileID}) }, call: func(f *FaultyStore) error {
			_, err := f.GetProfile(ctx(), memProfileID)
			return err
		}},
		"ListProfiles": {seed: func(m *memStore) { _ = m.UpsertProfile(ctx(), model.RunnerProfile{ID: memProfileID}) }, call: func(f *FaultyStore) error {
			_, err := f.ListProfiles(ctx())
			return err
		}},
		"BindCertProfile": {mutates: true, call: func(f *FaultyStore) error { return f.BindCertProfile(ctx(), "serial", memProfileID) }},
		"ProfileForSerial": {seed: func(m *memStore) {
			_ = m.UpsertProfile(ctx(), model.RunnerProfile{ID: memProfileID})
			_ = m.BindCertProfile(ctx(), "serial", memProfileID)
		}, call: func(f *FaultyStore) error {
			_, _, err := f.ProfileForSerial(ctx(), "serial")
			return err
		}},
		"UpsertRunnerToken": {mutates: true, call: func(f *FaultyStore) error {
			return f.UpsertRunnerToken(ctx(), testRunner.ID, "digest")
		}},
		"RunnerIDForToken": {seed: func(m *memStore) { _ = m.UpsertRunnerToken(ctx(), testRunner.ID, "digest") }, call: func(f *FaultyStore) error {
			_, _, err := f.RunnerIDForToken(ctx(), "digest")
			return err
		}},
		"HasRunnerTokens": {seed: func(m *memStore) { _ = m.UpsertRunnerToken(ctx(), testRunner.ID, "digest") }, call: func(f *FaultyStore) error {
			_, err := f.HasRunnerTokens(ctx())
			return err
		}},
		"RevokeCert": {mutates: true, call: func(f *FaultyStore) error {
			return f.RevokeCert(ctx(), "serial", testRunner.ID, "reason")
		}},
		"CertRevoked": {seed: func(m *memStore) { _ = m.RevokeCert(ctx(), "serial", testRunner.ID, "reason") }, call: func(f *FaultyStore) error {
			_, err := f.CertRevoked(ctx(), "serial")
			return err
		}},
		"PutEnrollGrant": {mutates: true, call: func(f *FaultyStore) error {
			return f.PutEnrollGrant(ctx(), "digest", time.Now().UTC().Add(time.Hour), []string{"linux"})
		}},
		"GetEnrollGrant": {seed: grant, call: func(f *FaultyStore) error {
			_, _, err := f.GetEnrollGrant(ctx(), "digest")
			return err
		}},
		"ConsumeEnrollGrant": {mutates: true, seed: grant, call: func(f *FaultyStore) error {
			_, err := f.ConsumeEnrollGrant(ctx(), "digest", "admin")
			return err
		}},
		"LoadTestHistory": {seed: func(m *memStore) { _, _ = m.SaveTestHistory(ctx(), []byte(`{}`)) }, call: func(f *FaultyStore) error {
			_, _, err := f.LoadTestHistory(ctx())
			return err
		}},
		"SaveTestHistory": {mutates: true, call: func(f *FaultyStore) error {
			_, err := f.SaveTestHistory(ctx(), []byte(`{}`))
			return err
		}},
	}
}

// TestFaultyStoreWrappersPassThroughAndFault drives every FaultyStore wrapper
// method: the fault-free call must reach the inner store, and a mutating
// wrapper armed with FailAfter=1 must surface the injected error without
// touching the inner store.
func TestFaultyStoreWrappersPassThroughAndFault(t *testing.T) {
	for name, tc := range faultyWrapperCases() {
		t.Run(name, func(t *testing.T) {
			inner := newMemStore()
			if tc.seed != nil {
				tc.seed(inner)
			}
			baseline := inner.snapshot()
			fs := &FaultyStore{Inner: inner}
			if err := tc.call(fs); err != nil {
				t.Fatalf("pass-through: %v", err)
			}
			if tc.mutates && fs.Mutations() != 0 {
				t.Fatalf("Mutations() = %d before any faulted call", fs.Mutations())
			}
			if !tc.mutates {
				if fs.Mutations() != 0 {
					t.Fatalf("read-only wrapper counted a mutation: %d", fs.Mutations())
				}
				return
			}
			faulted := newMemStore()
			if tc.seed != nil {
				tc.seed(faulted)
			}
			faultBaseline := faulted.snapshot()
			fs2 := &FaultyStore{Inner: faulted, FailAfter: 1, Err: errBoom}
			if err := tc.call(fs2); !errors.Is(err, errBoom) {
				t.Fatalf("expected injected error, got %v", err)
			}
			if fs2.Mutations() != 1 {
				t.Fatalf("Mutations() = %d, want 1", fs2.Mutations())
			}
			if got := faulted.snapshot(); !equalSnapshots(got, faultBaseline) {
				t.Fatalf("faulted wrapper leaked a write")
			}
			_ = baseline
		})
	}
}

func equalSnapshots(a, b memSnapshot) bool {
	return len(a.runs) == len(b.runs) && len(a.jobs) == len(b.jobs) && len(a.runners) == len(b.runners) &&
		a.auditLen == b.auditLen && a.logsLen == b.logsLen && len(a.artifacts) == len(b.artifacts) &&
		a.reportsLen == b.reportsLen && len(a.outbox) == len(b.outbox) && len(a.deployments) == len(b.deployments) &&
		len(a.snapshots) == len(b.snapshots) && len(a.fragments) == len(b.fragments) &&
		len(a.pendingSidecars) == len(b.pendingSidecars) && len(a.claims) == len(b.claims) &&
		len(a.outboxClaims) == len(b.outboxClaims)
}

func TestFaultyStoreCloseAndFaultState(t *testing.T) {
	fs := &FaultyStore{Inner: newMemStore()}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// FailAfter without an error never faults; reads never count mutations.
	noErr := &FaultyStore{Inner: newMemStore(), FailAfter: 1}
	if err := noErr.InsertRun(ctx(), testRun); err != nil {
		t.Fatalf("FailAfter without Err must pass through: %v", err)
	}
	if noErr.Mutations() != 0 {
		t.Fatalf("Mutations() = %d with no configured error", noErr.Mutations())
	}
	// Faults only fire on the configured Nth mutating call.
	third := &FaultyStore{Inner: newMemStore(), FailAfter: 3, Err: errBoom}
	for i := 1; i <= 2; i++ {
		if err := third.OutboxAppend(ctx(), OutboxItem{ID: fmt.Sprintf("ok-%d", i)}); err != nil {
			t.Fatalf("call %d must pass through: %v", i, err)
		}
	}
	if err := third.OutboxAppend(ctx(), OutboxItem{ID: "boom"}); !errors.Is(err, errBoom) {
		t.Fatalf("third call = %v, want injected", err)
	}
	if err := third.OutboxAppend(ctx(), OutboxItem{ID: "after"}); err != nil {
		t.Fatalf("call after the fault must pass through: %v", err)
	}
	if third.Mutations() != 4 {
		t.Fatalf("Mutations() = %d, want 4", third.Mutations())
	}
}
