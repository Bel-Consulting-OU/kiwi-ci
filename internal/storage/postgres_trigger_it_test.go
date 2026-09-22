package storage

// Trigger-based SQL failure injection: a BEFORE trigger that always raises
// makes one table's write fail deterministically, so every SQL error branch
// of the store can be exercised without touching PostgreSQL internals. Each
// case runs on its own throwaway schema.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITBoom makes every INSERT/UPDATE/DELETE on table fail with an exception.
func pgITBoom(t *testing.T, st *PostgresStore, table string) {
	t.Helper()
	ctx := context.Background()
	fn := "kiwi_boom_" + table
	if _, err := st.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION `+fn+`() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected failure on `+table+`'; END; $$ LANGUAGE plpgsql`); err != nil {
		t.Fatalf("create trigger function for %s: %v", table, err)
	}
	for _, ev := range []string{"INSERT", "UPDATE", "DELETE"} {
		if _, err := st.pool.Exec(ctx, `CREATE TRIGGER `+fn+`_`+strings.ToLower(ev)+` BEFORE `+ev+` ON `+table+` FOR EACH ROW EXECUTE FUNCTION `+fn+`()`); err != nil {
			t.Fatalf("create trigger on %s: %v", table, err)
		}
	}
}

type boomerIds struct {
	run, job, runner, profile, schedule, artifact, deployment string
}

func boomerSeed(t *testing.T, st *PostgresStore) *boomerIds {
	t.Helper()
	ctx := context.Background()
	ids := &boomerIds{run: pgITNewID(t), job: pgITNewID(t), runner: pgITNewID(t), profile: pgITNewID(t), schedule: pgITNewID(t)}
	pgITEnqueueOne(t, st, ids.run, ids.job, pgITRepo)
	if err := st.UpsertRunner(ctx, model.Runner{ID: ids.runner, Name: "r", Capacity: 4, LastSeen: time.Now().UTC()}); err != nil {
		t.Fatalf("seed runner: %v", err)
	}
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: ids.profile, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	if err := st.UpsertSchedule(ctx, Schedule{ID: ids.schedule, Repository: "r", Spec: "@daily", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("seed schedule: %v", err)
	}
	return ids
}

// boomSeeds run BEFORE the trigger is installed, so the failing statement is
// the one under test rather than the fixture insert.
var boomSeeds = map[string]func(t *testing.T, st *PostgresStore, ids *boomerIds){
	"artifacts/SetArtifactSidecars": func(t *testing.T, st *PostgresStore, ids *boomerIds) {
		ids.artifact = pgITNewID(t)
		if err := st.InsertArtifact(context.Background(), model.ArtifactRecord{ID: ids.artifact, RunID: ids.run, Name: "bin", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("artifact: %v", err)
		}
	},
	"downstream_links/claimLaunch":  linkSeed,
	"downstream_links/Reserve":      linkSeed,
	"downstream_links/MarkLaunched": linkSeed,
	"downstream_links/Expire": func(t *testing.T, st *PostgresStore, ids *boomerIds) {
		if _, err := st.ReserveDownstreamLaunch(context.Background(), ids.job, "acme/child", "main", "tok"); err != nil {
			t.Fatalf("reserve: %v", err)
		}
	},
	"deployments/UpdateDeploymentStatus": func(t *testing.T, st *PostgresStore, ids *boomerIds) {
		ids.deployment = pgITNewID(t)
		if err := st.InsertDeployment(context.Background(), model.Deployment{ID: ids.deployment, RunID: ids.run, Status: model.StatusRunning, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("deployment: %v", err)
		}
	},
	"artifact_pending_sidecars/Consume": sidecarSeed,
	"artifact_pending_sidecars/Delete":  sidecarSeed,
	"artifact_pending_sidecars/Prune":   sidecarSeed,
	"secret_claims/Release": func(t *testing.T, st *PostgresStore, ids *boomerIds) {
		if _, err := st.ClaimSecretDelivery(context.Background(), ids.job, 1, "TOKEN"); err != nil {
			t.Fatalf("secret claim: %v", err)
		}
	},
	"enrollment_grants/Consume": func(t *testing.T, st *PostgresStore, ids *boomerIds) {
		if err := st.PutEnrollGrant(context.Background(), "digest", time.Now().Add(time.Hour), nil); err != nil {
			t.Fatalf("grant: %v", err)
		}
	},
	"quota_reservations/adjust": func(t *testing.T, st *PostgresStore, ids *boomerIds) {
		if _, err := st.pool.Exec(context.Background(), `INSERT INTO quota_reservations (key, running, queued) VALUES ('github.com/o/r', 0, 0), ('github.com/o', 0, 0) ON CONFLICT (key) DO NOTHING`); err != nil {
			t.Fatalf("quota rows: %v", err)
		}
	},
	"outbox/OutboxAck": func(t *testing.T, st *PostgresStore, ids *boomerIds) {
		if _, err := st.pool.Exec(context.Background(), `INSERT INTO outbox (id, kind, payload, created_at) VALUES ('o1', 'k', '{}'::jsonb, now())`); err != nil {
			t.Fatalf("outbox row: %v", err)
		}
	},
	"jobs/CompleteJob":        leaseSeed,
	"jobs/recomputeDependent": leaseSeed,
	"runners/completeRunner":  leaseSeed,
	"runners/releaseSlot":     leaseSeed,
	"downstream_links/Release": func(t *testing.T, st *PostgresStore, ids *boomerIds) {
		if err := st.InsertDownstreamLink(context.Background(), DownstreamLink{ParentJobID: ids.job, TargetRepo: "acme/child", TargetRef: "main", LaunchToken: "tok", Reserved: true, ReservedAt: timePtr(time.Now().UTC())}); err != nil {
			t.Fatalf("link: %v", err)
		}
	},
	"runs/ReopenRunForChildren": func(t *testing.T, st *PostgresStore, ids *boomerIds) {
		if _, err := st.pool.Exec(context.Background(), `UPDATE runs SET status='success' WHERE id=$1`, ids.run); err != nil {
			t.Fatalf("mark run success: %v", err)
		}
	},
}

func timePtr(t time.Time) *time.Time { return &t }

func leaseSeed(t *testing.T, st *PostgresStore, ids *boomerIds) {
	t.Helper()
	leaseJob(t, st, ids, 1)
}

func linkSeed(t *testing.T, st *PostgresStore, ids *boomerIds) {
	t.Helper()
	if err := st.InsertDownstreamLink(context.Background(), DownstreamLink{ParentJobID: ids.job, TargetRepo: "acme/child", TargetRef: "main", LaunchToken: "tok"}); err != nil {
		t.Fatalf("link: %v", err)
	}
}

func sidecarSeed(t *testing.T, st *PostgresStore, ids *boomerIds) {
	t.Helper()
	if err := st.RememberPendingSidecar(context.Background(), ids.job, 1, "bin", ArtifactSidecarKindSBOM, memDigest); err != nil {
		t.Fatalf("pending sidecar: %v", err)
	}
}

func TestPostgresIntegrationTriggeredSQLErrors(t *testing.T) {
	ctx := context.Background()
	cases := map[string]struct {
		table string
		op    func(t *testing.T, st *PostgresStore, ids *boomerIds)
	}{
		"audit_events/AppendAudit": {"audit_events", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.AppendAudit(ctx, model.AuditEvent{ID: pgITNewID(t), Action: "a", CreatedAt: time.Now().UTC()}); err == nil {
				t.Fatal("expected the audit insert to fail")
			}
		}},
		"audit_events/CompleteJob": {"audit_events", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			leaseJob(t, st, ids, 1)
			receipt := model.CompletionReceipt{JobID: ids.job, Generation: 1, RunnerID: ids.runner}
			if err := st.CompleteJob(ctx, ids.job, 1, ids.runner, model.StatusSuccess, "", nil, receipt); err == nil {
				t.Fatal("expected the completion audit insert to fail")
			}
		}},
		"audit_events/cancelSuperseded": {"audit_events", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), CancelPrevious: []string{ids.job}})
			if err == nil {
				t.Fatal("expected the supersede audit insert to fail")
			}
		}},
		"outbox/OutboxAppend": {"outbox", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.OutboxAppend(ctx, OutboxItem{ID: "o1", Kind: "k", CreatedAt: time.Now().UTC()}); err == nil {
				t.Fatal("expected the outbox insert to fail")
			}
		}},
		"outbox/OutboxAck": {"outbox", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.OutboxAck(ctx, "o1"); err == nil {
				t.Fatal("expected the outbox delete to fail")
			}
		}},
		"outbox/completionEffects": {"outbox", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			leaseJob(t, st, ids, 1)
			receipt := model.CompletionReceipt{JobID: ids.job, Generation: 1, RunnerID: ids.runner}
			if err := st.CompleteJob(ctx, ids.job, 1, ids.runner, model.StatusSuccess, "", nil, receipt); err == nil {
				t.Fatal("expected the completion outbox insert to fail")
			}
		}},
		"quota_reservations/adjust": {"quota_reservations", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.AdjustQuotaCounter(ctx, "github.com/o/r", "github.com/o", 1, 1); err == nil {
				t.Fatal("expected the quota update to fail")
			}
		}},
		"quota_reservations/lease": {"quota_reservations", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: ids.job, RunnerID: ids.runner, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err == nil {
				t.Fatal("expected the quota claim to fail")
			}
		}},
		"quota_reservations/enqueue": {"quota_reservations", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
				Run:   pgITRun(pgITNewID(t), model.StatusQueued),
				Quota: &QuotaReservation{RepoKey: "github.com/o/r", JobCount: 1},
			})
			if err == nil {
				t.Fatal("expected the quota reservation to fail")
			}
		}},
		"runs/InsertRun": {"runs", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.InsertRun(ctx, pgITRun(pgITNewID(t), model.StatusQueued)); err == nil {
				t.Fatal("expected the run insert to fail")
			}
		}},
		"runs/UpdateRunStatus": {"runs", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.UpdateRunStatus(ctx, ids.run, model.StatusRunning, nil, nil); err == nil {
				t.Fatal("expected the run update to fail")
			}
		}},
		"runs/InsertCompiledRun": {"runs", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued)}); err == nil {
				t.Fatal("expected the enqueue run insert to fail")
			}
		}},
		"runs/cancelSupersededRun": {"runs", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), CancelPrevious: []string{ids.job}})
			if err == nil {
				t.Fatal("expected the superseded run update to fail")
			}
		}},
		"runs/CancelRunJobs": {"runs", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if _, err := st.CancelRunJobs(ctx, ids.run, "stop"); err == nil {
				t.Fatal("expected the run cancel update to fail")
			}
		}},
		"runs/AppendDownstreamRun": {"runs", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.AppendDownstreamRun(ctx, ids.run, pgITNewID(t)); err == nil {
				t.Fatal("expected the downstream run update to fail")
			}
		}},
		"runs/ReopenRunForChildren": {"runs", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.ReopenRunForChildren(ctx, ids.run); err == nil {
				t.Fatal("expected the reopen update to fail")
			}
		}},
		"runs/recomputeRun": {"runs", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			leaseJob(t, st, ids, 1)
			receipt := model.CompletionReceipt{JobID: ids.job, Generation: 1, RunnerID: ids.runner}
			if err := st.CompleteJob(ctx, ids.job, 1, ids.runner, model.StatusSuccess, "", nil, receipt); err == nil {
				t.Fatal("expected the run recompute update to fail")
			}
		}},
		"jobs/InsertJob": {"jobs", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.InsertJob(ctx, pgITJob(ids.run, pgITNewID(t), pgITRepo)); err == nil {
				t.Fatal("expected the job insert to fail")
			}
		}},
		"jobs/UpdateJob": {"jobs", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.UpdateJob(ctx, pgITJob(ids.run, ids.job, pgITRepo)); err == nil {
				t.Fatal("expected the job upsert to fail")
			}
		}},
		"jobs/CompleteJob": {"jobs", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			receipt := model.CompletionReceipt{JobID: ids.job, Generation: 1, RunnerID: ids.runner}
			if err := st.CompleteJob(ctx, ids.job, 1, ids.runner, model.StatusSuccess, "", nil, receipt); err == nil {
				t.Fatal("expected the job completion update to fail")
			}
		}},
		"jobs/cancelSuperseded": {"jobs", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), CancelPrevious: []string{ids.job}})
			if err == nil {
				t.Fatal("expected the superseded job update to fail")
			}
		}},
		"jobs/CancelRunJobs": {"jobs", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if _, err := st.CancelRunJobs(ctx, ids.run, "stop"); err == nil {
				t.Fatal("expected the job cancel update to fail")
			}
		}},
		"jobs/recomputeDependent": {"jobs", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			receipt := model.CompletionReceipt{JobID: ids.job, Generation: 1, RunnerID: ids.runner}
			if err := st.CompleteJob(ctx, ids.job, 1, ids.runner, model.StatusSuccess, "", nil, receipt); err == nil {
				t.Fatal("expected the dependent recompute update to fail")
			}
		}},
		"jobs/leaseAtomic": {"jobs", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: ids.job, RunnerID: ids.runner, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err == nil {
				t.Fatal("expected the job claim update to fail")
			}
		}},
		"job_dependencies/replace": {"job_dependencies", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			job := pgITJob(ids.run, pgITNewID(t), pgITRepo)
			job.Needs = []string{ids.job}
			if err := st.InsertJob(ctx, job); err == nil {
				t.Fatal("expected the dependency insert to fail")
			}
		}},
		"runners/UpsertRunner": {"runners", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.UpsertRunner(ctx, model.Runner{ID: pgITNewID(t), Capacity: 1, Registered: time.Now().UTC()}); err == nil {
				t.Fatal("expected the runner upsert to fail")
			}
		}},
		"runners/ReleaseRunnerJob": {"runners", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.ReleaseRunnerJob(ctx, ids.runner, ids.job, model.StatusSuccess); err == nil {
				t.Fatal("expected the runner release update to fail")
			}
		}},
		"runners/completeRunner": {"runners", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			receipt := model.CompletionReceipt{JobID: ids.job, Generation: 1, RunnerID: ids.runner}
			if err := st.CompleteJob(ctx, ids.job, 1, ids.runner, model.StatusSuccess, "", nil, receipt); err == nil {
				t.Fatal("expected the runner counter update to fail")
			}
		}},
		"runners/releaseSlot": {"runners", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if _, err := st.CancelRunJobs(ctx, ids.run, "stop"); err == nil {
				t.Fatal("expected the runner slot splice to fail")
			}
		}},
		"artifacts/InsertArtifact": {"artifacts", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			a := model.ArtifactRecord{ID: pgITNewID(t), RunID: ids.run, JobID: ids.job, Name: "bin", CreatedAt: time.Now().UTC()}
			if err := st.InsertArtifact(ctx, a); err == nil {
				t.Fatal("expected the artifact insert to fail")
			}
		}},
		"artifacts/InsertArtifactOnce": {"artifacts", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			a := model.ArtifactRecord{ID: pgITNewID(t), RunID: ids.run, JobID: ids.job, Name: "bin", CreatedAt: time.Now().UTC()}
			if _, _, err := st.InsertArtifactOnce(ctx, a); err == nil {
				t.Fatal("expected the idempotent artifact insert to fail")
			}
		}},
		"artifacts/SetArtifactSidecars": {"artifacts", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.SetArtifactSidecars(ctx, ids.artifact, "p", "s", "q", "t"); err == nil {
				t.Fatal("expected the sidecar update to fail")
			}
		}},
		"test_results/InsertTestReport": {"test_results", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.InsertTestReport(ctx, model.TestReport{ID: pgITNewID(t), RunID: ids.run, CreatedAt: time.Now().UTC()}); err == nil {
				t.Fatal("expected the report insert to fail")
			}
		}},
		"test_cases/InsertTestReport": {"test_cases", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			rep := model.TestReport{ID: pgITNewID(t), RunID: ids.run, CreatedAt: time.Now().UTC(), Cases: []model.TestResult{{Name: "t", Passed: true}}}
			if err := st.InsertTestReport(ctx, rep); err == nil {
				t.Fatal("expected the test case insert to fail")
			}
		}},
		"log_entries/AppendLog": {"log_entries", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.AppendLog(ctx, model.LogEntry{RunID: ids.run, Line: "l", CreatedAt: time.Now().UTC()}); err == nil {
				t.Fatal("expected the log insert to fail")
			}
		}},
		"completion_receipts/InsertCompletionReceipt": {"completion_receipts", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			r := model.CompletionReceipt{JobID: ids.job, Generation: 1, RunnerID: ids.runner}
			if err := st.InsertCompletionReceipt(ctx, r); err == nil {
				t.Fatal("expected the receipt insert to fail")
			}
		}},
		"completion_receipts/CompleteJob": {"completion_receipts", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			leaseJob(t, st, ids, 1)
			r := model.CompletionReceipt{JobID: ids.job, Generation: 1, RunnerID: ids.runner}
			if err := st.CompleteJob(ctx, ids.job, 1, ids.runner, model.StatusSuccess, "", nil, r); err == nil {
				t.Fatal("expected the completion receipt insert to fail")
			}
		}},
		"webhook_deliveries/claim": {"webhook_deliveries", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
				Run:          pgITRun(pgITNewID(t), model.StatusQueued),
				WebhookClaim: &WebhookClaim{Forge: "github", DeliveryID: "d", RunID: ids.run},
			})
			if err == nil {
				t.Fatal("expected the webhook claim insert to fail")
			}
		}},
		"downstream_links/claimLaunch": {"downstream_links", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			linkKey := ids.job + "\x00acme/child\x00main"
			err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
				Run:              pgITRun(pgITNewID(t), model.StatusQueued),
				DownstreamLaunch: &DownstreamLaunchClaim{LinkKey: linkKey, StableChildID: memDigest},
			})
			if err == nil {
				t.Fatal("expected the downstream claim update to fail")
			}
		}},
		"downstream_links/Reserve": {"downstream_links", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if _, err := st.ReserveDownstreamLaunch(ctx, ids.job, "acme/child", "main", "tok2"); err == nil {
				t.Fatal("expected the reservation update to fail")
			}
		}},
		"downstream_links/MarkLaunched": {"downstream_links", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.MarkDownstreamLaunched(ctx, ids.job, "acme/child", "main", pgITNewID(t)); err == nil {
				t.Fatal("expected the launch mark to fail")
			}
		}},
		"downstream_links/Release": {"downstream_links", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.ReleaseDownstreamReservation(ctx, ids.job, "acme/child", "main"); err == nil {
				t.Fatal("expected the reservation release to fail")
			}
		}},
		"downstream_links/Expire": {"downstream_links", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if _, err := st.ExpireDownstreamReservations(ctx, time.Now().UTC().Add(time.Hour)); err == nil {
				t.Fatal("expected the expiry update to fail")
			}
		}},
		"schedule_occurrences/claim": {"schedule_occurrences", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if _, err := st.ClaimScheduleOccurrence(ctx, ids.schedule, time.Now().UTC().Truncate(time.Microsecond), ids.run); err == nil {
				t.Fatal("expected the occurrence claim to fail")
			}
		}},
		"schedule_occurrences/enqueue": {"schedule_occurrences", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
				Run:           pgITRun(pgITNewID(t), model.StatusQueued),
				ScheduleClaim: &ScheduleClaim{ScheduleID: ids.schedule, Nominal: time.Now().UTC().Truncate(time.Microsecond)},
			})
			if err == nil {
				t.Fatal("expected the schedule claim insert to fail")
			}
		}},
		"deployments/InsertDeployment": {"deployments", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.InsertDeployment(ctx, model.Deployment{ID: pgITNewID(t), RunID: ids.run, CreatedAt: time.Now().UTC()}); err == nil {
				t.Fatal("expected the deployment insert to fail")
			}
		}},
		"deployments/UpdateDeploymentStatus": {"deployments", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.UpdateDeploymentStatus(ctx, ids.deployment, model.StatusSuccess, nil); err == nil {
				t.Fatal("expected the deployment update to fail")
			}
		}},
		"workspace_snapshots/InsertSnapshotRecord": {"workspace_snapshots", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.InsertSnapshotRecord(ctx, model.SnapshotRecord{ID: pgITNewID(t), RunID: ids.run, CreatedAt: time.Now().UTC()}); err == nil {
				t.Fatal("expected the snapshot insert to fail")
			}
		}},
		"cache_manifests/PutCacheManifest": {"cache_manifests", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			rec := CacheManifestRecord{Repo: "r", TrustDomain: "t", LogicalKey: "l", BlobSHA256: memDigest, CreatedAt: time.Now().UTC()}
			if err := st.PutCacheManifest(ctx, rec); err == nil {
				t.Fatal("expected the cache manifest upsert to fail")
			}
		}},
		"generated_fragments/Insert": {"generated_fragments", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			req := GeneratedFragmentRequest{ParentJobID: ids.job, LeaseGeneration: 1, FragmentID: "f", Jobs: map[string]model.Job{}}
			if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err == nil {
				t.Fatal("expected the fragment insert to fail")
			}
		}},
		"artifact_pending_sidecars/Remember": {"artifact_pending_sidecars", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.RememberPendingSidecar(ctx, ids.job, 1, "bin", ArtifactSidecarKindSBOM, memDigest); err == nil {
				t.Fatal("expected the pending sidecar upsert to fail")
			}
		}},
		"artifact_pending_sidecars/Consume": {"artifact_pending_sidecars", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.ConsumePendingSidecar(ctx, ids.job, 1, "bin", ArtifactSidecarKindSBOM, memDigest); err == nil {
				t.Fatal("expected the pending sidecar delete to fail")
			}
		}},
		"artifact_pending_sidecars/Prune": {"artifact_pending_sidecars", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if _, err := st.PrunePendingSidecars(ctx, time.Now().UTC().Add(time.Hour)); err == nil {
				t.Fatal("expected the pending sidecar prune to fail")
			}
		}},
		"secret_claims/Claim": {"secret_claims", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if _, err := st.ClaimSecretDelivery(ctx, ids.job, 1, "TOKEN"); err == nil {
				t.Fatal("expected the secret claim insert to fail")
			}
		}},
		"secret_claims/Release": {"secret_claims", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.ReleaseSecretDelivery(ctx, ids.job, 1, "TOKEN"); err == nil {
				t.Fatal("expected the secret claim delete to fail")
			}
		}},
		"runner_profiles/Upsert": {"runner_profiles", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: pgITNewID(t)}); err == nil {
				t.Fatal("expected the profile upsert to fail")
			}
		}},
		"cert_profile_links/Bind": {"cert_profile_links", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.BindCertProfile(ctx, "serial", pgITNewID(t)); err == nil {
				t.Fatal("expected the profile binding to fail")
			}
		}},
		"runner_profile_links/Link": {"runner_profile_links", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.LinkRunnerProfile(ctx, ids.runner, pgITNewID(t)); err == nil {
				t.Fatal("expected the runner profile link to fail")
			}
		}},
		"runner_profile_links/Unlink": {"runner_profile_links", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			// BEFORE DELETE ... FOR EACH ROW only fires for rows the statement
			// actually touches, and the Link case above fails by design, so
			// seed one binding with user triggers disabled to give the
			// injected failure a row to fire on.
			if _, err := st.pool.Exec(ctx, `ALTER TABLE runner_profile_links DISABLE TRIGGER USER`); err != nil {
				t.Fatalf("disable triggers: %v", err)
			}
			if _, err := st.pool.Exec(ctx, `INSERT INTO runner_profile_links (runner_id, profile_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, ids.runner, pgITNewID(t)); err != nil {
				t.Fatalf("seed link: %v", err)
			}
			if _, err := st.pool.Exec(ctx, `ALTER TABLE runner_profile_links ENABLE TRIGGER USER`); err != nil {
				t.Fatalf("enable triggers: %v", err)
			}
			if err := st.UnlinkRunnerProfile(ctx, ids.runner); err == nil {
				t.Fatal("expected the runner profile unlink to fail")
			}
		}},
		"runner_bearer_tokens/Upsert": {"runner_bearer_tokens", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.UpsertRunnerToken(ctx, ids.runner, "digest"); err == nil {
				t.Fatal("expected the token upsert to fail")
			}
		}},
		"cert_revocations/DisableRevoke": {"cert_revocations", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if _, err := st.DisableRunnerAndRevokeCert(ctx, ids.runner, "serial", "admin"); err == nil {
				t.Fatal("expected the revocation insert to fail")
			}
		}},
		"enrollment_grants/Put": {"enrollment_grants", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if err := st.PutEnrollGrant(ctx, "digest", time.Now().Add(time.Hour), nil); err == nil {
				t.Fatal("expected the grant insert to fail")
			}
		}},
		"enrollment_grants/Consume": {"enrollment_grants", func(t *testing.T, st *PostgresStore, ids *boomerIds) {
			if _, err := st.ConsumeEnrollGrant(ctx, "digest", "admin"); err == nil {
				t.Fatal("expected the grant consume to fail")
			}
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			st := pgITStore(t)
			ids := boomerSeed(t, st)
			if seed, ok := boomSeeds[name]; ok {
				seed(t, st, ids)
			}
			pgITBoom(t, st, tc.table)
			tc.op(t, st, ids)
		})
	}
}

func leaseJob(t *testing.T, st *PostgresStore, ids *boomerIds, generation int64) {
	t.Helper()
	ctx := context.Background()
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: ids.job, RunnerID: ids.runner, Generation: generation, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("lease: %v", err)
	}
}

// TestPostgresIntegrationDroppedTableReadErrors covers the read paths whose
// queries fail when the underlying relation is gone.
func TestPostgresIntegrationDroppedTableReadErrors(t *testing.T) {
	ctx := context.Background()
	readCases := map[string]struct {
		table string
		op    func(t *testing.T, st *PostgresStore, ids *boomerIds) error
	}{
		"OutboxPending": {"outbox", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.OutboxPending(ctx)
			return err
		}},
		"ClaimOutbox": {"outbox", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.ClaimOutbox(ctx, "f", 1)
			return err
		}},
		"ListSchedules": {"schedules", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.ListSchedules(ctx)
			return err
		}},
		"ListOccurrences": {"schedule_occurrences", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.ListOccurrences(ctx, ids.schedule)
			return err
		}},
		"ListDeployments": {"deployments", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.ListDeploymentsByRun(ctx, ids.run)
			return err
		}},
		"ListSnapshots": {"workspace_snapshots", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.ListSnapshotsByRun(ctx, ids.run)
			return err
		}},
		"GetJobContracts": {"jobs", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, _, err := st.GetJobContracts(ctx, ids.job)
			return err
		}},
		"SetQueueReasons": {"jobs", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			return st.SetQueueReasons(ctx, map[string]string{ids.job: "x"})
		}},
		"GetGeneratedFrag": {"generated_fragments", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, _, err := st.GetGeneratedFragment(ctx, ids.job, 1, "f")
			return err
		}},
		"GetDownstream": {"downstream_links", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, _, err := st.GetDownstreamLink(ctx, ids.job, "r", "x")
			return err
		}},
		"RecentUsage": {"jobs", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, _, err := st.RecentUsage(ctx, time.Now().Add(-time.Hour))
			return err
		}},
		"QuotaCounts": {"quota_reservations", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, _, err := st.QuotaCounts(ctx, "k", "")
			return err
		}},
		"GetCacheManifest": {"cache_manifests", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, _, err := st.GetCacheManifest(ctx, "r", "t", "l")
			return err
		}},
		"PendingSidecar": {"artifact_pending_sidecars", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, _, err := st.PendingSidecar(ctx, ids.job, 1, "bin", ArtifactSidecarKindSBOM)
			return err
		}},
		"LoadTestHistory": {"test_history", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, _, err := st.LoadTestHistory(ctx)
			return err
		}},
		"SaveTestHistory": {"test_history", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.SaveTestHistory(ctx, []byte("{}"))
			return err
		}},
		"GetProfile": {"runner_profiles", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.GetProfile(ctx, ids.profile)
			return err
		}},
		"ListProfiles": {"runner_profiles", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.ListProfiles(ctx)
			return err
		}},
		"ProfileForSerial": {"cert_profile_links", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, _, err := st.ProfileForSerial(ctx, "serial")
			return err
		}},
		"ProfileForRunnerID": {"runner_profile_links", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, _, err := st.ProfileForRunnerID(ctx, ids.runner)
			return err
		}},
		"RunnerIDsForProfile": {"runner_profile_links", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.RunnerIDsForProfile(ctx, pgITNewID(t))
			return err
		}},
		"RunnerIDForToken": {"runner_bearer_tokens", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, _, err := st.RunnerIDForToken(ctx, "digest")
			return err
		}},
		"HasRunnerTokens": {"runner_bearer_tokens", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.HasRunnerTokens(ctx)
			return err
		}},
		"CertRevoked": {"cert_revocations", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.CertRevoked(ctx, "serial")
			return err
		}},
		"GetEnrollGrant": {"enrollment_grants", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, _, err := st.GetEnrollGrant(ctx, "digest")
			return err
		}},
		"ConsumeGrant": {"enrollment_grants", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.ConsumeEnrollGrant(ctx, "digest", "a")
			return err
		}},
		"GetArtifact": {"artifacts", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.GetArtifact(ctx, pgITNewID(t))
			return err
		}},
		"ListArtifacts": {"artifacts", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.ListArtifacts(ctx, ids.run)
			return err
		}},
		"ListTestReports": {"test_results", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.ListTestReports(ctx, ids.run)
			return err
		}},
		"ListAllReports": {"test_results", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.ListTestReportsAll(ctx)
			return err
		}},
		"ReadAudit": {"audit_events", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.ReadAudit(ctx, 1)
			return err
		}},
		"ReadLogs": {"log_entries", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.ReadLogs(ctx, ids.run, 0, 1)
			return err
		}},
		"FindDelivery": {"webhook_deliveries", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, _, err := st.FindDelivery(ctx, "github", "d")
			return err
		}},
		"HasReceipt": {"completion_receipts", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, _, err := st.HasCompletionReceipt(ctx, ids.job, 1, ids.runner)
			return err
		}},
		"ListRuns": {"runs", func(t *testing.T, st *PostgresStore, ids *boomerIds) error { _, err := st.ListRuns(ctx, 1); return err }},
		"ListJobsByRun": {"jobs", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.ListJobsByRun(ctx, ids.run)
			return err
		}},
		"ListQueuedJobs": {"jobs", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.ListQueuedJobs(ctx)
			return err
		}},
		"ListJobsByEnv": {"jobs", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.ListJobsByEnvironment(ctx, pgITRepoID, "prod")
			return err
		}},
		"ListJobsByRunner": {"jobs", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.ListJobsByRunner(ctx, ids.runner)
			return err
		}},
		"ListRunners": {"runners", func(t *testing.T, st *PostgresStore, ids *boomerIds) error { _, err := st.ListRunners(ctx); return err }},
		"GetRunner": {"runners", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.GetRunner(ctx, ids.runner)
			return err
		}},
		"GetJob": {"jobs", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.GetJob(ctx, ids.job)
			return err
		}},
		"GetRun": {"runs", func(t *testing.T, st *PostgresStore, ids *boomerIds) error {
			_, err := st.GetRun(ctx, ids.run)
			return err
		}},
	}
	for name, tc := range readCases {
		t.Run(name, func(t *testing.T) {
			st := pgITStore(t)
			ids := boomerSeed(t, st)
			if _, err := st.pool.Exec(ctx, `DROP TABLE `+tc.table+` CASCADE`); err != nil {
				t.Fatalf("drop %s: %v", tc.table, err)
			}
			if err := tc.op(t, st, ids); err == nil {
				t.Fatalf("expected the query against a dropped %s to fail", tc.table)
			}
		})
	}
}
