package storage

// Third error-branch batch: corrupted scanner inputs, direct helper calls on
// a live transaction, and the remaining trigger-driven SQL failures.

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestPostgresIntegrationScannerCorruption(t *testing.T) {
	ctx := context.Background()
	st := pgITStore(t)
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	runnerID := pgITNewID(t)
	profileID := pgITNewID(t)
	otherRun := pgITNewID(t)

	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	pgITEnqueueOne(t, st, otherRun, pgITNewID(t), pgITRepo)
	pgITSeedRunner(t, st, runnerID, 1, 0, 0)
	if err := st.UpsertRunner(ctx, model.Runner{ID: pgITNewID(t), Name: "registered", Capacity: 1, Registered: time.Now().UTC(), LastSeen: time.Now().UTC()}); err != nil {
		t.Fatalf("registered runner: %v", err)
	}
	if err := st.InsertArtifact(ctx, model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, Name: "bin", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("artifact: %v", err)
	}
	if err := st.InsertTestReport(ctx, model.TestReport{ID: pgITNewID(t), RunID: runID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("report: %v", err)
	}
	if err := st.AppendAudit(ctx, model.AuditEvent{ID: pgITNewID(t), Action: "a", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("audit: %v", err)
	}
	if err := st.UpsertSchedule(ctx, Schedule{ID: pgITNewID(t), Repository: "r", Spec: "@daily", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if err := st.InsertDeployment(ctx, model.Deployment{ID: pgITNewID(t), RunID: runID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("deployment: %v", err)
	}
	if err := st.InsertSnapshotRecord(ctx, model.SnapshotRecord{ID: pgITNewID(t), RunID: runID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: profileID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("profile: %v", err)
	}
	if err := st.BindCertProfile(ctx, "serial", profileID); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := st.PutCacheManifest(ctx, CacheManifestRecord{Repo: "r", TrustDomain: "t", LogicalKey: "l", BlobSHA256: memDigest, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if err := st.PutEnrollGrant(ctx, "digest", time.Now().Add(time.Hour), []string{"linux"}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := st.InsertCompletionReceipt(ctx, model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID}); err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if err := st.AppendLog(ctx, model.LogEntry{RunID: runID, Line: "l", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("log: %v", err)
	}
	if err := st.UpsertRunnerToken(ctx, runnerID, "digest"); err != nil {
		t.Fatalf("token: %v", err)
	}

	// Every payload column becomes a JSON scalar, so the decode helpers fail.
	corruptions := []struct {
		table  string
		where  string
		column string
	}{
		{"jobs", "id='" + jobID + "'", "payload"},
		{"jobs", "id='" + jobID + "'", "outputs"},
		{"runs", "id='" + runID + "'", "payload"},
		{"runners", "id='" + runnerID + "'", "payload"},
		{"artifacts", "name='bin'", "payload"},
		{"test_results", "run_id='" + runID + "'", "payload"},
		{"deployments", "run_id='" + runID + "'", "payload"},
		{"workspace_snapshots", "run_id='" + runID + "'", "payload"},
		{"runner_profiles", "id='" + profileID + "'", "labels"},
		{"runner_profiles", "id='" + profileID + "'", "repositories"},
		{"runner_profiles", "id='" + profileID + "'", "capabilities"},
		{"cache_manifests", "repo='r'", "payload"},
	}
	for _, c := range corruptions {
		if _, err := st.pool.Exec(ctx, `UPDATE `+c.table+` SET `+c.column+`='"scalar"'::jsonb WHERE `+c.where); err != nil {
			t.Fatalf("corrupt %s.%s: %v", c.table, c.column, err)
		}
	}
	// A project-wide corrupt payload breaks the decode of every scanner,
	// including the profile scanner's per-field decode errors.
	expectErr := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: expected a decode error", name)
		}
	}
	_, err := st.GetJob(ctx, jobID)
	expectErr("GetJob", err)
	_, err = st.GetJob(ctx, pgITNewID(t))
	if err == nil {
		t.Fatal("missing job must still be ErrNotFound")
	}
	_, err = st.ListJobsByRun(ctx, runID)
	expectErr("ListJobsByRun", err)
	// The environment listing matches on payload fields, so the payload must
	// stay an object; a type-conflicting field makes the decode fail.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload = jsonb_build_object('environment','prod','repo_url',$2::text,'status',123) WHERE id=$1`, jobID, pgITRepo); err != nil {
		t.Fatalf("corrupt env job: %v", err)
	}
	_, err = st.ListJobsByEnvironment(ctx, pgITRepoID, "prod")
	expectErr("ListJobsByEnvironment", err)
	_, err = st.ListQueuedJobs(ctx)
	expectErr("ListQueuedJobs", err)
	// The runner listing matches on real columns, so the lease is restored
	// before the corrupted payload is decoded.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET status='running', lease_runner_id=$2 WHERE id=$1`, jobID, runnerID); err != nil {
		t.Fatalf("lease row: %v", err)
	}
	_, err = st.ListJobsByRunner(ctx, runnerID)
	expectErr("ListJobsByRunner", err)
	_, err = st.ListRuns(ctx, 5)
	expectErr("ListRuns", err)
	_, err = st.GetRun(ctx, runID)
	expectErr("GetRun", err)
	_, err = st.GetRunner(ctx, runnerID)
	expectErr("GetRunner", err)
	_, err = st.ListRunners(ctx)
	expectErr("ListRunners", err)
	_, err = st.ListArtifacts(ctx, runID)
	expectErr("ListArtifacts", err)
	_, err = st.ListTestReports(ctx, runID)
	expectErr("ListTestReports", err)
	_, err = st.ListTestReportsAll(ctx)
	expectErr("ListTestReportsAll", err)
	_, err = st.ListDeploymentsByRun(ctx, runID)
	expectErr("ListDeploymentsByRun", err)
	_, err = st.ListSnapshotsByRun(ctx, runID)
	expectErr("ListSnapshotsByRun", err)
	_, err = st.GetProfile(ctx, profileID)
	expectErr("GetProfile", err)
	_, err = st.ListProfiles(ctx)
	expectErr("ListProfiles", err)
	_, _, err = st.GetCacheManifest(ctx, "r", "t", "l")
	expectErr("GetCacheManifest", err)

	// UpdateRunStatus decodes the row it just rewrote.
	if _, err := st.pool.Exec(ctx, `UPDATE runs SET payload='"scalar"'::jsonb WHERE id=$1`, runID); err != nil {
		t.Fatalf("corrupt run: %v", err)
	}
	expectErr("UpdateRunStatus", st.UpdateRunStatus(ctx, runID, model.StatusRunning, nil, nil))

	// ReadAudit's metadata decode fails on a scalar metadata column.
	if _, err := st.pool.Exec(ctx, `UPDATE audit_events SET metadata='"scalar"'::jsonb`); err != nil {
		t.Fatalf("corrupt audit metadata: %v", err)
	}
	_, err = st.ReadAudit(ctx, 5)
	expectErr("ReadAudit", err)

	// ListSchedules decodes real columns only; a broken enum-like value is
	// caught by the scan of last_run (NULL is allowed).
	if _, err := st.pool.Exec(ctx, `UPDATE schedules SET repo_id='fresh'`); err != nil {
		t.Fatalf("touch schedule: %v", err)
	}
	if _, err := st.ListSchedules(ctx); err != nil {
		t.Fatalf("ListSchedules: %v", err)
	}

	// GetEnrollGrant decodes the bound labels column.
	if _, err := st.pool.Exec(ctx, `UPDATE enrollment_grants SET bound_labels='"scalar"'::jsonb`); err != nil {
		t.Fatalf("corrupt grant labels: %v", err)
	}
	_, _, err = st.GetEnrollGrant(ctx, "digest")
	expectErr("GetEnrollGrant", err)
	_, err = st.ConsumeEnrollGrant(ctx, "digest", "admin")
	expectErr("ConsumeEnrollGrant", err)

	// ProfileForSerial decodes its own row.
	if _, err := st.pool.Exec(ctx, `UPDATE cert_profile_links SET profile_id=$1 WHERE serial='serial'`, profileID); err != nil {
		t.Fatalf("touch link: %v", err)
	}
	_, _, err = st.ProfileForSerial(ctx, "serial")
	expectErr("ProfileForSerial", err)
}

func TestPostgresIntegrationDirectHelperCalls(t *testing.T) {
	ctx := context.Background()
	st := pgITStore(t)

	// reserveQuotaTx clamps a negative job count and enforces running limits.
	if err := pgITTx(ctx, st, func(ctx context.Context, tx pgx.Tx) error {
		return st.reserveQuotaTx(ctx, tx, &QuotaReservation{RepoKey: "github.com/o/r", JobCount: -1})
	}); err != nil {
		t.Fatalf("negative job count: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `INSERT INTO quota_reservations (key, running, queued) VALUES ('github.com/o/r', 5, 0) ON CONFLICT (key) DO UPDATE SET running=5, queued=0`); err != nil {
		t.Fatalf("quota row: %v", err)
	}
	err := pgITTx(ctx, st, func(ctx context.Context, tx pgx.Tx) error {
		return st.reserveQuotaTx(ctx, tx, &QuotaReservation{RepoKey: "github.com/o/r", JobCount: 1, RepoConcurrency: 5})
	})
	var qerr *QuotaExceededError
	if err == nil {
		t.Fatal("expected the running limit to reject the reservation")
	}
	if !asQuotaErr(err, &qerr) || qerr.Reason != "REPO_QUOTA" {
		t.Fatalf("quota error = %#v", err)
	}

	// A runner with an unlinked certificate serial resolves to unlinked.
	runnerID := pgITNewID(t)
	jobID := pgITNewID(t)
	runID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Capacity: 2, CertSerial: "unlinked-serial"}); err != nil {
		t.Fatalf("runner: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID}); err != nil {
		t.Fatalf("lease with an unlinked serial: %v", err)
	}

	// profileForSerialTx query errors surface (aborted transaction).
	_, ack := pgITAbortedTx(t, st)
	if _, _, _, err := profileForSerialTx(ctx, ack, "serial"); err == nil {
		t.Fatal("expected the profile lookup to fail on an aborted transaction")
	}
	// The cert link lookup then the profile lookup each fail.
	_, ack2 := pgITAbortedTx(t, st)
	if err := st.BindCertProfile(ctx, "serial-2", pgITNewID(t)); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if _, _, _, err := profileForSerialTx(ctx, ack2, "serial-2"); err == nil {
		t.Fatal("expected the aborted profile lookup to fail")
	}
}

func pgITTx(ctx context.Context, st *PostgresStore, fn func(context.Context, pgx.Tx) error) error {
	tx, err := st.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	return fn(ctx, tx)
}

func asQuotaErr(err error, target **QuotaExceededError) bool {
	for err != nil {
		if q, ok := err.(*QuotaExceededError); ok {
			*target = q
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestPostgresIntegrationSupersedeDeepErrors(t *testing.T) {
	ctx := context.Background()

	// A corrupt dependent payload surfaces through the supersede path.
	t.Run("corrupt-dep", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		parent := pgITNewID(t)
		dep := pgITNewID(t)
		depJob := pgITJob(runID, dep, pgITRepo)
		depJob.Needs = []string{parent}
		if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
			Run:  pgITRun(runID, model.StatusQueued),
			Jobs: map[string]model.Job{parent: pgITJob(runID, parent, pgITRepo), dep: depJob},
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, dep); err != nil {
			t.Fatalf("corrupt: %v", err)
		}
		err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), CancelPrevious: []string{parent}})
		if err == nil {
			t.Fatal("a corrupt dependent must fail the supersede cancel")
		}
	})
	// A corrupt run payload surfaces through the supersede run update.
	t.Run("corrupt-run", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		job := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, job, pgITRepo)
		if _, err := st.pool.Exec(ctx, `UPDATE runs SET payload='42'::jsonb WHERE id=$1`, runID); err != nil {
			t.Fatalf("corrupt: %v", err)
		}
		err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), CancelPrevious: []string{job}})
		if err == nil {
			t.Fatal("a corrupt run payload must fail the supersede run update")
		}
	})
	// A terminal superseded run is left untouched, and the cancel succeeds.
	t.Run("terminal-run", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		job := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, job, pgITRepo)
		if _, err := st.pool.Exec(ctx, `UPDATE runs SET status='success' WHERE id=$1`, runID); err != nil {
			t.Fatalf("terminalize: %v", err)
		}
		if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), CancelPrevious: []string{job}}); err != nil {
			t.Fatalf("cancel with a terminal run: %v", err)
		}
	})
	// A schedule claim replayed for the same run is idempotent.
	t.Run("schedule-idempotent", func(t *testing.T) {
		st := pgITStore(t)
		schedID := pgITNewID(t)
		if err := st.UpsertSchedule(ctx, Schedule{ID: schedID, Repository: "r", Spec: "@daily", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("schedule: %v", err)
		}
		nominal := time.Now().UTC().Truncate(time.Microsecond)
		runID := pgITNewID(t)
		claim := &ScheduleClaim{ScheduleID: schedID, Nominal: nominal}
		if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(runID, model.StatusQueued), ScheduleClaim: claim}); err != nil {
			t.Fatalf("first claim: %v", err)
		}
		// The same claim for the same run replays cleanly only while the run
		// is absent; the second enqueue collides on the run row instead.
		if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), ScheduleClaim: claim}); err == nil {
			t.Fatal("a schedule claim for an existing occurrence must not re-claim")
		}
	})
	// A repository-less supersede policy is a no-op.
	t.Run("empty-supersede", func(t *testing.T) {
		st := pgITStore(t)
		if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
			Run:       pgITRun(pgITNewID(t), model.StatusQueued),
			Supersede: &SupersedePolicy{RepoID: "", ConcurrencyGroup: ""},
		}); err != nil {
			t.Fatalf("empty supersede: %v", err)
		}
	})
}

func TestPostgresIntegrationTriggerExtras(t *testing.T) {
	ctx := context.Background()

	t.Run("supersede-runner-slot", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: ids.job, RunnerID: ids.runner, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("lease: %v", err)
		}
		pgITBoom(t, st, "runners")
		err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), CancelPrevious: []string{ids.job}})
		if err == nil {
			t.Fatal("expected the supersede runner slot release to fail")
		}
	})
	t.Run("supersede-quota", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		if _, err := st.pool.Exec(ctx, `INSERT INTO quota_reservations (key, running, queued) VALUES ('github.com/kiwi-it/repo', 1, 0), ('kiwi-it/repo', 1, 0), ('github.com/kiwi-it', 1, 0) ON CONFLICT (key) DO NOTHING`); err != nil {
			t.Fatalf("quota row: %v", err)
		}
		pgITBoom(t, st, "quota_reservations")
		err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), CancelPrevious: []string{ids.job}})
		if err == nil {
			t.Fatal("expected the supersede quota release to fail")
		}
	})
	t.Run("insert-job-nan-cost", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		job := pgITJob(ids.run, pgITNewID(t), pgITRepo)
		job.CostRate = math.NaN()
		if err := st.InsertJob(ctx, job); err == nil {
			t.Fatal("a NaN cost rate must fail the job marshal")
		}
		if err := st.UpdateJob(ctx, job); err == nil {
			t.Fatal("a NaN cost rate must fail the job upsert marshal")
		}
	})
	t.Run("heartbeat-nul-runner", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		if err := st.HeartbeatLease(ctx, ids.job, "run\x00ner", 1, time.Now().Add(time.Minute)); err == nil {
			t.Fatal("a NUL runner id must fail the heartbeat update")
		}
	})
	t.Run("complete-nul-error", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: ids.job, RunnerID: ids.runner, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("lease: %v", err)
		}
		receipt := model.CompletionReceipt{JobID: ids.job, Generation: 1, RunnerID: ids.runner}
		if err := st.CompleteJob(ctx, ids.job, 1, ids.runner, model.StatusFailure, "bad\x00error", nil, receipt); err == nil {
			t.Fatal("a NUL error message must fail the job update")
		}
	})
	t.Run("lease-nul-runtime", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: ids.job, RunnerID: ids.runner, Runtime: "bad\x00runtime", Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err == nil {
			t.Fatal("a NUL runtime must fail the runner slot update")
		}
	})
	t.Run("cancel-nul-reason", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		if _, err := st.CancelRunJobs(ctx, ids.run, "bad\x00reason"); err == nil {
			t.Fatal("a NUL cancel reason must fail the job update")
		}
	})
	t.Run("cancel-corrupt-job", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, ids.job); err != nil {
			t.Fatalf("corrupt: %v", err)
		}
		if _, err := st.CancelRunJobs(ctx, ids.run, "stop"); err == nil {
			t.Fatal("a corrupt job payload must fail the run cancel")
		}
	})
	t.Run("cancel-corrupt-run", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		if _, err := st.pool.Exec(ctx, `UPDATE runs SET payload='"scalar"'::jsonb WHERE id=$1`, ids.run); err != nil {
			t.Fatalf("corrupt: %v", err)
		}
		if _, err := st.CancelRunJobs(ctx, ids.run, "stop"); err == nil {
			t.Fatal("a corrupt run payload must fail the run cancel")
		}
	})
	t.Run("append-downstream-corrupt", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		if _, err := st.pool.Exec(ctx, `UPDATE runs SET payload='"scalar"'::jsonb WHERE id=$1`, ids.run); err != nil {
			t.Fatalf("corrupt: %v", err)
		}
		if err := st.AppendDownstreamRun(ctx, ids.run, pgITNewID(t)); err == nil {
			t.Fatal("a corrupt run payload must fail the downstream append")
		}
	})
	t.Run("update-deployment-corrupt", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		depID := pgITNewID(t)
		if err := st.InsertDeployment(ctx, model.Deployment{ID: depID, RunID: ids.run, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("deployment: %v", err)
		}
		if _, err := st.pool.Exec(ctx, `UPDATE deployments SET payload='"scalar"'::jsonb WHERE id=$1`, depID); err != nil {
			t.Fatalf("corrupt: %v", err)
		}
		if err := st.UpdateDeploymentStatus(ctx, depID, model.StatusSuccess, nil); err == nil {
			t.Fatal("a corrupt deployment payload must fail the status update")
		}
	})
	t.Run("snapshot-corrupt", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		snapID := pgITNewID(t)
		if err := st.InsertSnapshotRecord(ctx, model.SnapshotRecord{ID: snapID, RunID: ids.run, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		if _, err := st.pool.Exec(ctx, `UPDATE workspace_snapshots SET payload='"scalar"'::jsonb WHERE id=$1`, snapID); err != nil {
			t.Fatalf("corrupt: %v", err)
		}
		if _, err := st.ListSnapshotsByRun(ctx, ids.run); err == nil {
			t.Fatal("a corrupt snapshot payload must fail the list decode")
		}
	})
}

func boomerSeedFor(t *testing.T, st *PostgresStore, repo string) *boomerIds {
	t.Helper()
	return boomerSeed(t, st)
}
