package storage

// Error-branch integration tests. Every reachable validation guard, SQL
// failure return and decode-error path of the PostgresStore surface is
// driven once: invalid/empty arguments for the guards, an aborted transaction
// for the helper-level SQL errors, and deliberately corrupted payload
// columns for the scanner decode errors.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITAbortedTx opens a transaction and aborts it with a division by zero, so
// every subsequent statement on it fails with SQLSTATE 25P02. The caller
// rolls it back.
func pgITAbortedTx(t *testing.T, st *PostgresStore) (context.Context, pgx.Tx) {
	t.Helper()
	ctx := context.Background()
	tx, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(ctx, `SELECT 1/0`); err == nil {
		t.Fatalf("expected the transaction to abort")
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	return ctx, tx
}

func TestPostgresIntegrationValidationSweep(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	bad := func(name string, err error, wantErr bool) {
		t.Helper()
		if wantErr && err == nil {
			t.Fatalf("%s: expected an error", name)
		}
		if !wantErr && err != nil {
			t.Fatalf("%s: unexpected error %v", name, err)
		}
	}
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	good := pgITNewID(t)

	bad("InsertArtifact/bad-id", st.InsertArtifact(ctx, model.ArtifactRecord{ID: "bad", RunID: runID}), true)
	bad("InsertArtifact/bad-run", st.InsertArtifact(ctx, model.ArtifactRecord{ID: good, RunID: "bad"}), true)
	bad("InsertArtifactOnce/bad-id", func() error { _, _, err := st.InsertArtifactOnce(ctx, model.ArtifactRecord{ID: "bad"}); return err }(), true)
	bad("InsertArtifactOnce/bad-run", func() error {
		_, _, err := st.InsertArtifactOnce(ctx, model.ArtifactRecord{ID: good, RunID: "bad"})
		return err
	}(), true)
	bad("GetArtifact/bad-id", func() error { _, err := st.GetArtifact(ctx, "bad"); return err }(), true)
	bad("ListArtifacts/bad-run", func() error { _, err := st.ListArtifacts(ctx, "bad"); return err }(), true)
	bad("InsertTestReport/bad-id", st.InsertTestReport(ctx, model.TestReport{ID: "bad", RunID: runID}), true)
	bad("InsertTestReport/bad-run", st.InsertTestReport(ctx, model.TestReport{ID: good, RunID: "bad"}), true)
	bad("ListTestReports/bad-run", func() error { _, err := st.ListTestReports(ctx, "bad"); return err }(), true)
	bad("AppendLog/bad-run", st.AppendLog(ctx, model.LogEntry{RunID: "bad"}), true)
	bad("AppendAudit/bad-id", st.AppendAudit(ctx, model.AuditEvent{ID: "bad"}), true)
	bad("ReadLogs/bad-run", func() error { _, err := st.ReadLogs(ctx, "bad", 0, 1); return err }(), true)
	bad("InsertCompletionReceipt/bad-job", st.InsertCompletionReceipt(ctx, model.CompletionReceipt{JobID: "bad"}), true)
	bad("UpsertDelivery/empty-forge", st.UpsertDelivery(ctx, "", "d", runID, "digest"), true)
	bad("UpsertDelivery/empty-delivery", st.UpsertDelivery(ctx, "github", "", runID, "digest"), true)
	bad("OutboxAck/empty-id", st.OutboxAck(ctx, ""), true)
	bad("ReleaseOutboxClaim/empty-id", st.ReleaseOutboxClaim(ctx, "", "flusher"), true)
	bad("ListOccurrences/empty-id", func() error { _, err := st.ListOccurrences(ctx, ""); return err }(), true)
	bad("ClaimScheduleOccurrence/empty", func() error { _, err := st.ClaimScheduleOccurrence(ctx, "", time.Now(), runID); return err }(), true)
	bad("InsertDownstreamLink/bad-parent", st.InsertDownstreamLink(ctx, DownstreamLink{ParentJobID: "bad", TargetRepo: "r", TargetRef: "x", LaunchToken: "t"}), true)
	bad("InsertDownstreamLink/incomplete", st.InsertDownstreamLink(ctx, DownstreamLink{ParentJobID: jobID, TargetRepo: "", TargetRef: "x", LaunchToken: "t"}), true)
	bad("GetDownstreamLink/bad-parent", func() error { _, _, err := st.GetDownstreamLink(ctx, "bad", "r", "x"); return err }(), true)
	bad("ReserveDownstreamLaunch/bad-parent", func() error {
		_, err := st.ReserveDownstreamLaunch(ctx, "bad", "r", "x", "t")
		return err
	}(), true)
	bad("ReserveDownstreamLaunch/incomplete", func() error {
		_, err := st.ReserveDownstreamLaunch(ctx, jobID, "", "x", "t")
		return err
	}(), true)
	bad("MarkDownstreamLaunched/bad-parent", st.MarkDownstreamLaunched(ctx, "bad", "r", "x", runID), true)
	bad("MarkDownstreamLaunched/empty-child", st.MarkDownstreamLaunched(ctx, jobID, "r", "x", ""), true)
	bad("ReleaseDownstreamReservation/bad-parent", st.ReleaseDownstreamReservation(ctx, "bad", "r", "x"), true)
	bad("PutCacheManifest/incomplete", st.PutCacheManifest(ctx, CacheManifestRecord{Repo: "r"}), true)
	bad("PutCacheManifest/bad-digest", st.PutCacheManifest(ctx, CacheManifestRecord{Repo: "r", TrustDomain: "t", LogicalKey: "l", BlobSHA256: "short"}), true)
	bad("SetArtifactSidecars/bad-id", st.SetArtifactSidecars(ctx, "bad", "p", "", "", ""), true)
	bad("PendingSidecar/bad-key", func() error {
		_, _, err := st.PendingSidecar(ctx, "bad", "bin", ArtifactSidecarKindSBOM)
		return err
	}(), true)
	bad("AppendDownstreamRun/bad-run", st.AppendDownstreamRun(ctx, "bad", runID), true)
	bad("AppendDownstreamRun/empty-child", st.AppendDownstreamRun(ctx, runID, ""), true)
	bad("ClaimSecretDelivery/bad-job", func() error { _, err := st.ClaimSecretDelivery(ctx, "bad", 1, "S"); return err }(), true)
	bad("ClaimSecretDelivery/negative-gen", func() error { _, err := st.ClaimSecretDelivery(ctx, jobID, -1, "S"); return err }(), true)
	bad("ClaimSecretDelivery/empty-name", func() error { _, err := st.ClaimSecretDelivery(ctx, jobID, 1, "  "); return err }(), true)
	bad("ReleaseSecretDelivery/bad-job", st.ReleaseSecretDelivery(ctx, "bad", 1, "S"), true)
	bad("ReleaseSecretDelivery/negative-gen", st.ReleaseSecretDelivery(ctx, jobID, -1, "S"), true)
	bad("ReleaseSecretDelivery/empty-name", st.ReleaseSecretDelivery(ctx, jobID, 1, ""), true)
	bad("UpsertRunner/bad-id", st.UpsertRunner(ctx, model.Runner{ID: "bad"}), true)
	bad("GetRunner/bad-id", func() error { _, err := st.GetRunner(ctx, "bad"); return err }(), true)
	bad("ReleaseRunnerJob/bad-runner", st.ReleaseRunnerJob(ctx, "bad", jobID, model.StatusSuccess), true)
	bad("ReleaseRunnerJob/bad-job", st.ReleaseRunnerJob(ctx, good, "bad", model.StatusSuccess), true)
	bad("InsertGeneratedJobs/bad-parent", st.InsertGeneratedJobs(ctx, "bad", 1, nil, nil), true)
	bad("GetGeneratedFragment/bad-parent", func() error { _, _, err := st.GetGeneratedFragment(ctx, "bad", 1, "f"); return err }(), true)
	bad("GetGeneratedFragment/empty-fragment", func() error { _, _, err := st.GetGeneratedFragment(ctx, jobID, 1, ""); return err }(), true)
	bad("InsertGeneratedFragmentTx/bad-parent", func() error {
		_, _, err := st.InsertGeneratedFragmentTx(ctx, GeneratedFragmentRequest{ParentJobID: "bad", FragmentID: "f"}, nil)
		return err
	}(), true)
	bad("InsertGeneratedFragmentTx/empty-fragment", func() error {
		_, _, err := st.InsertGeneratedFragmentTx(ctx, GeneratedFragmentRequest{ParentJobID: jobID}, nil)
		return err
	}(), true)
	bad("InsertGeneratedFragmentTx/bad-job-id", func() error {
		_, _, err := st.InsertGeneratedFragmentTx(ctx, GeneratedFragmentRequest{ParentJobID: jobID, FragmentID: "f", Jobs: map[string]model.Job{"bad": {ID: "bad"}}}, nil)
		return err
	}(), true)
	bad("InsertJobContracts/bad-job", st.InsertJobContracts(ctx, "bad", testContracts), true)
	bad("SetQueueReasons/bad-job", st.SetQueueReasons(ctx, map[string]string{"bad": "x"}), true)
	bad("InsertDeployment/bad-id", st.InsertDeployment(ctx, model.Deployment{ID: "bad"}), true)
	bad("UpdateDeploymentStatus/bad-id", st.UpdateDeploymentStatus(ctx, "bad", model.StatusSuccess, nil), true)
	bad("InsertSnapshotRecord/bad-id", st.InsertSnapshotRecord(ctx, model.SnapshotRecord{ID: "bad"}), true)
	bad("ListSnapshotsByRun/bad-run", func() error { _, err := st.ListSnapshotsByRun(ctx, "bad"); return err }(), true)
	bad("ListDeploymentsByRun/bad-run", func() error { _, err := st.ListDeploymentsByRun(ctx, "bad"); return err }(), true)
	bad("BindCertProfile/empty-serial", st.BindCertProfile(ctx, "", good), true)
	bad("BindCertProfile/empty-profile", st.BindCertProfile(ctx, "serial", ""), true)
	bad("ProfileForSerial/empty-serial", func() error {
		_, ok, err := st.ProfileForSerial(ctx, "")
		if ok || err != nil {
			t.Fatalf("empty serial = %v, %v", ok, err)
		}
		return nil
	}(), false)
	bad("UpsertRunnerToken/empty-runner", st.UpsertRunnerToken(ctx, "", "digest"), true)
	bad("UpsertRunnerToken/empty-digest", st.UpsertRunnerToken(ctx, good, ""), true)
	bad("RunnerIDForToken/empty-digest", func() error {
		_, ok, err := st.RunnerIDForToken(ctx, "")
		if ok || err != nil {
			t.Fatalf("empty digest = %v, %v", ok, err)
		}
		return nil
	}(), false)
	bad("RevokeCert/empty-serial", st.RevokeCert(ctx, "", good, "reason"), true)
	bad("CertRevoked/empty-serial", func() error {
		revoked, err := st.CertRevoked(ctx, "")
		if revoked || err != nil {
			t.Fatalf("empty serial = %v, %v", revoked, err)
		}
		return nil
	}(), false)
	bad("PutEnrollGrant/empty-digest", st.PutEnrollGrant(ctx, "", time.Now().Add(time.Hour), nil), true)
	bad("GetEnrollGrant/empty-digest", func() error {
		_, ok, err := st.GetEnrollGrant(ctx, "")
		if ok || err != nil {
			t.Fatalf("empty digest = %v, %v", ok, err)
		}
		return nil
	}(), false)
	bad("UpsertProfile/empty-id", st.UpsertProfile(ctx, model.RunnerProfile{ID: ""}), true)
	bad("TryAcquireLeadership/empty-key", func() error { _, err := st.TryAcquireLeadership(ctx, "", time.Minute); return err }(), true)
	bad("TryAcquireLeadership/zero-ttl", func() error { _, err := st.TryAcquireLeadership(ctx, "k", 0); return err }(), true)
	bad("ReleaseLeadership/unknown-key", st.ReleaseLeadership(ctx, "never-held"), false)
	bad("InsertCompiledRun/bad-job-run", st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  pgITRun(pgITNewID(t), model.StatusQueued),
		Jobs: map[string]model.Job{good: {ID: good, RunID: "bad"}},
	}), true)
	bad("InsertCompiledRun/incomplete-webhook", st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:          pgITRun(pgITNewID(t), model.StatusQueued),
		WebhookClaim: &WebhookClaim{Forge: "github", DeliveryID: "", RunID: pgITNewID(t)},
	}), true)
	bad("InsertCompiledRun/bad-claim-run", st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:          pgITRun(pgITNewID(t), model.StatusQueued),
		WebhookClaim: &WebhookClaim{Forge: "github", DeliveryID: "d", RunID: "bad"},
	}), true)
	bad("AcquireLeaseAtomic/bad-job", func() error {
		_, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: "bad", RunnerID: good})
		return err
	}(), true)
	bad("AcquireLeaseAtomic/empty-runner", func() error {
		_, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: ""})
		return err
	}(), true)
	bad("CompleteJob/bad-id", st.CompleteJob(ctx, "bad", 1, good, model.StatusSuccess, "", nil, model.CompletionReceipt{}), true)
	bad("CompleteJob/negative-gen", st.CompleteJob(ctx, jobID, -1, good, model.StatusSuccess, "", nil, model.CompletionReceipt{}), true)
	bad("CancelRunJobs/bad-run", func() error { _, err := st.CancelRunJobs(ctx, "bad", "r"); return err }(), true)
}

func TestPostgresIntegrationTxAbortedHelperSweep(t *testing.T) {
	st := pgITStore(t)
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	runnerID := pgITNewID(t)
	now := time.Now().UTC()
	run := pgITRun(runID, model.StatusQueued)
	job := pgITJob(runID, jobID, pgITRepo)
	cases := map[string]func(ctx context.Context, tx pgx.Tx) error{
		"adjustQuotaTx": func(ctx context.Context, tx pgx.Tx) error {
			return st.adjustQuotaTx(ctx, tx, "github.com/o/r", 1, 1)
		},
		"reserveQuotaTx": func(ctx context.Context, tx pgx.Tx) error {
			return st.reserveQuotaTx(ctx, tx, &QuotaReservation{RepoKey: "github.com/o/r", JobCount: 1})
		},
		"claimQuotaTx": func(ctx context.Context, tx pgx.Tx) error {
			return st.claimQuotaTx(ctx, tx, "github.com/o/r", 0, 0)
		},
		"insertRunTx":           func(ctx context.Context, tx pgx.Tx) error { return st.insertRunTx(ctx, tx, run) },
		"insertJobRowTx":        func(ctx context.Context, tx pgx.Tx) error { return st.insertJobRowTx(ctx, tx, job) },
		"replaceDependenciesTx": func(ctx context.Context, tx pgx.Tx) error { return st.replaceDependenciesTx(ctx, tx, job) },
		"insertWebhookClaimTx": func(ctx context.Context, tx pgx.Tx) error {
			return st.insertWebhookClaimTx(ctx, tx, &WebhookClaim{Forge: "github", DeliveryID: "d", RunID: runID})
		},
		"insertScheduleClaimTx": func(ctx context.Context, tx pgx.Tx) error {
			return st.insertScheduleClaimTx(ctx, tx, &ScheduleClaim{ScheduleID: "schedule", Nominal: now}, runID)
		},
		"claimDownstreamLaunchTx": func(ctx context.Context, tx pgx.Tx) error {
			return st.claimDownstreamLaunchTx(ctx, tx, &DownstreamLaunchClaim{LinkKey: jobID + "\x00r\x00x", StableChildID: memDigest}, pgITNewID(t))
		},
		"supersededJobIDsTx": func(ctx context.Context, tx pgx.Tx) error {
			_, err := st.supersededJobIDsTx(ctx, tx, &SupersedePolicy{RepoID: "r", ConcurrencyGroup: "g"}, runID)
			return err
		},
		"cancelSupersededTx": func(ctx context.Context, tx pgx.Tx) error {
			return st.cancelSupersededTx(ctx, tx, []string{jobID}, runID)
		},
		"cancelSupersededRunTx": func(ctx context.Context, tx pgx.Tx) error {
			return st.cancelSupersededRunTx(ctx, tx, runID, now)
		},
		"completeRunnerTx": func(ctx context.Context, tx pgx.Tx) error {
			return st.completeRunnerTx(ctx, tx, runnerID, jobID, model.StatusSuccess, now)
		},
		"recomputeDependentsTx": func(ctx context.Context, tx pgx.Tx) error {
			return st.recomputeDependentsTx(ctx, tx, jobID, now)
		},
		"recomputeDependentTx": func(ctx context.Context, tx pgx.Tx) error {
			return st.recomputeDependentTx(ctx, tx, jobID, now)
		},
		"recomputeRunTx": func(ctx context.Context, tx pgx.Tx) error { return st.recomputeRunTx(ctx, tx, runID) },
		"releaseJobQuotaTx": func(ctx context.Context, tx pgx.Tx) error {
			return st.releaseJobQuotaTx(ctx, tx, jobID)
		},
		"releaseRunnerSlotTx": func(ctx context.Context, tx pgx.Tx) error {
			return st.releaseRunnerSlotTx(ctx, tx, runnerID, jobID)
		},
		"requiredArtifactMissingTx": func(ctx context.Context, tx pgx.Tx) error {
			_, err := st.requiredArtifactMissingTx(ctx, tx, jobID, []byte(`{"artifact_contracts":{"bundle":{"name":"bundle","required":true}}}`))
			return err
		},
		"artifactByGenerationKey": func(ctx context.Context, tx pgx.Tx) error {
			_, err := st.artifactByGenerationKey(ctx, jobID, 1, "bin")
			return err
		},
		"insertCompletionEffectsTx": func(ctx context.Context, tx pgx.Tx) error {
			return st.insertCompletionEffectsTx(ctx, tx, jobID, runID, 1, now)
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			ctx, tx := pgITAbortedTx(t, st)
			if err := fn(ctx, tx); err == nil {
				t.Fatalf("aborted transaction must surface an error")
			}
		})
	}
}

func TestPostgresIntegrationCorruptStateErrorBranches(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	// A job payload that is valid JSON but not an object breaks every decode.
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)

	// InsertCompiledRun: contracts on a scalar payload fail the jsonb_set.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, jobID); err != nil {
		t.Fatalf("corrupt job: %v", err)
	}
	err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:       pgITRun(pgITNewID(t), model.StatusQueued),
		Jobs:      map[string]model.Job{},
		Contracts: map[string]map[string]ArtifactContract{jobID: testContracts},
	})
	if err == nil {
		t.Fatal("contracts on a scalar payload must fail")
	}
	// InsertCompiledRun: a dependency edge to a nonexistent job fails the FK.
	depJob := pgITNewID(t)
	err = st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  pgITRun(pgITNewID(t), model.StatusQueued),
		Jobs: map[string]model.Job{depJob: {ID: depJob, RunID: runID, Key: "dep", Status: model.StatusQueued, CreatedAt: time.Now().UTC(), Needs: []string{pgITNewID(t)}}},
	})
	if err == nil {
		t.Fatal("dependency edge to a missing job must fail")
	}
	// InsertCompiledRun: a valid-format but nonexistent run id fails the FK.
	fkJob := pgITNewID(t)
	err = st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  pgITRun(pgITNewID(t), model.StatusQueued),
		Jobs: map[string]model.Job{fkJob: {ID: fkJob, RunID: pgITNewID(t), Key: "orphan", Status: model.StatusQueued, CreatedAt: time.Now().UTC()}},
	})
	if err == nil {
		t.Fatal("orphan job must fail the FK")
	}
	// InsertCompiledRun: an invalid contracts map key fails validation.
	err = st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:       pgITRun(pgITNewID(t), model.StatusQueued),
		Contracts: map[string]map[string]ArtifactContract{"bad": {}},
	})
	if err == nil {
		t.Fatal("invalid contract job id must fail")
	}
	// InsertCompiledRun: the supersede resolver fails on a NUL repository.
	err = st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:       pgITRun(pgITNewID(t), model.StatusQueued),
		Supersede: &SupersedePolicy{RepoID: "r\x00x", ConcurrencyGroup: "g"},
	})
	if err == nil {
		t.Fatal("supersede with a NUL repository must fail")
	}
	// InsertCompiledRun with a corrupt superseded job payload fails closed.
	badJob := pgITNewID(t)
	badRun := pgITNewID(t)
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  pgITRun(badRun, model.StatusQueued),
		Jobs: map[string]model.Job{badJob: pgITJob(badRun, badJob, pgITRepo)},
	}); err != nil {
		t.Fatalf("seed superseded run: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, badJob); err != nil {
		t.Fatalf("corrupt superseded job: %v", err)
	}
	err = st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:            pgITRun(pgITNewID(t), model.StatusQueued),
		CancelPrevious: []string{badJob},
	})
	if err == nil {
		t.Fatal("cancelling a corrupt job payload must fail")
	}
	// A cancel target that does not exist or is already terminal is skipped.
	terminalRun := pgITNewID(t)
	terminalJob := pgITNewID(t)
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  pgITRun(terminalRun, model.StatusQueued),
		Jobs: map[string]model.Job{terminalJob: pgITJob(terminalRun, terminalJob, pgITRepo)},
	}); err != nil {
		t.Fatalf("seed terminal target: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET status='success' WHERE id=$1`, terminalJob); err != nil {
		t.Fatalf("terminalize: %v", err)
	}
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:            pgITRun(pgITNewID(t), model.StatusQueued),
		CancelPrevious: []string{terminalJob, pgITNewID(t), "bad"},
	}); err == nil {
		t.Fatal("an invalid cancel id must fail the enqueue validation")
	}

	// Downstream launch claim: a link already launched for another run fails
	// closed, and an invalid parent id fails validation.
	parentJob := pgITNewID(t)
	if err := st.InsertDownstreamLink(ctx, DownstreamLink{ParentJobID: parentJob, TargetRepo: "acme/child", TargetRef: "main", LaunchToken: "tok"}); err != nil {
		t.Fatalf("insert link: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE downstream_links SET child_run_id=$2 WHERE parent_job_id=$1 AND target_repo='acme/child' AND target_ref='main'`, parentJob, pgITNewID(t)); err != nil {
		t.Fatalf("launch link: %v", err)
	}
	linkKey := parentJob + "\x00acme/child\x00main"
	err = st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:              pgITRun(pgITNewID(t), model.StatusQueued),
		DownstreamLaunch: &DownstreamLaunchClaim{LinkKey: linkKey, StableChildID: memDigest},
	})
	if err == nil {
		t.Fatal("a link launched for another run must fail closed")
	}
	err = st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:              pgITRun(pgITNewID(t), model.StatusQueued),
		DownstreamLaunch: &DownstreamLaunchClaim{LinkKey: "bad\x00r\x00x", StableChildID: memDigest},
	})
	if err == nil {
		t.Fatal("an invalid parent job id must fail the launch claim")
	}
	err = st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:              pgITRun(pgITNewID(t), model.StatusQueued),
		DownstreamLaunch: &DownstreamLaunchClaim{LinkKey: parentJob + "\x00acme/child\x00main", StableChildID: memDigest},
		Jobs:             map[string]model.Job{},
	})
	if err == nil {
		t.Fatal("a claimed link must reject the enqueue")
	}

	// CompleteJob: a queued job with a matching empty identity is a lease
	// conflict, and a scalar payload fails the decode.
	queuedRun := pgITNewID(t)
	queuedJob := pgITNewID(t)
	pgITEnqueueOne(t, st, queuedRun, queuedJob, pgITRepo)
	err = st.CompleteJob(ctx, queuedJob, 0, "", model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: queuedJob, Generation: 0, RunnerID: ""})
	if !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("queued completion = %v, want ErrLeaseConflict", err)
	}
	runnerID := pgITNewID(t)
	pgITSeedRunner(t, st, runnerID, 2, 0, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: queuedJob, RunnerID: runnerID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("lease: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, queuedJob); err != nil {
		t.Fatalf("corrupt job: %v", err)
	}
	err = st.CompleteJob(ctx, queuedJob, 1, runnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: queuedJob, Generation: 1, RunnerID: runnerID})
	if err == nil {
		t.Fatal("completing a scalar payload must fail the decode")
	}
}

func TestPostgresIntegrationCompleteJobErrorBranches(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	runnerID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	pgITSeedRunner(t, st, runnerID, 2, 0, 0)

	// A receipt whose result hash carries a NUL byte fails the insert.
	lease := func(t *testing.T) {
		t.Helper()
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET status='queued', lease_runner_id=NULL, lease_generation=0, lease_expires_at=NULL WHERE id=$1`, jobID); err != nil {
			t.Fatalf("reset job: %v", err)
		}
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("lease: %v", err)
		}
	}
	lease(t)
	badHash := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "bad\x00hash"}
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, badHash); err == nil {
		t.Fatal("a NUL result hash must fail the receipt insert")
	}

	// A pre-existing outbox row under the deterministic effect ID fails the
	// effects insert and rolls the completion back.
	lease(t)
	if _, err := st.pool.Exec(ctx, `INSERT INTO outbox (id, kind, payload, created_at) VALUES ($1, 'occupied', '{}'::jsonb, now())`, CompletionEffectID(jobID, 1, CompletionEffectKinds()[0])); err != nil {
		t.Fatalf("occupy effect id: %v", err)
	}
	good := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID}
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, good); err == nil {
		t.Fatal("an occupied effect id must roll the completion back")
	}
	stillRunning, _ := st.GetJob(ctx, jobID)
	if stillRunning.Status != model.StatusRunning {
		t.Fatalf("rolled-back completion must leave the job running: %+v", stillRunning)
	}
	if _, err := st.pool.Exec(ctx, `DELETE FROM outbox WHERE id=$1`, CompletionEffectID(jobID, 1, CompletionEffectKinds()[0])); err != nil {
		t.Fatalf("clear effect id: %v", err)
	}

	// A missing quota_reservations table fails the quota adjustment.
	if _, err := st.pool.Exec(ctx, `ALTER TABLE quota_reservations RENAME TO quota_reservations_hidden`); err != nil {
		t.Fatalf("hide quota table: %v", err)
	}
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, good); err == nil {
		t.Fatal("a missing quota table must fail the quota adjustment")
	}
	if _, err := st.pool.Exec(ctx, `ALTER TABLE quota_reservations_hidden RENAME TO quota_reservations`); err != nil {
		t.Fatalf("restore quota table: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE runners SET payload='42'::jsonb WHERE id=$1`, runnerID); err != nil {
		t.Fatalf("corrupt runner: %v", err)
	}
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, good); err == nil {
		t.Fatal("a corrupt runner payload must fail the completion")
	}
	// A corrupt active_jobs column is its own decode error.
	if _, err := st.pool.Exec(ctx, `UPDATE runners SET payload='{}'::jsonb, active_jobs='{"not":"array"}'::jsonb WHERE id=$1`, runnerID); err != nil {
		t.Fatalf("corrupt active jobs: %v", err)
	}
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, good); err == nil {
		t.Fatal("a corrupt active_jobs column must fail the completion")
	}
	// A runner with a remaining active job promotes the next current job.
	if _, err := st.pool.Exec(ctx, `UPDATE runners SET payload='{}'::jsonb, active_jobs=to_jsonb(ARRAY[$2::text]) WHERE id=$1`, runnerID, memJobID); err != nil {
		t.Fatalf("seed active job: %v", err)
	}
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, good); err != nil {
		t.Fatalf("completion with a remaining active job: %v", err)
	}
	runner, _ := st.GetRunner(ctx, runnerID)
	if runner.CurrentJob != memJobID {
		t.Fatalf("current job after completion = %q", runner.CurrentJob)
	}

	// A corrupt dependent job payload fails the dependent recomputation.
	depRun := pgITNewID(t)
	depParent := pgITNewID(t)
	depChild := pgITNewID(t)
	child := pgITJob(depRun, depChild, pgITRepo)
	child.Needs = []string{depParent}
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  pgITRun(depRun, model.StatusQueued),
		Jobs: map[string]model.Job{depParent: pgITJob(depRun, depParent, pgITRepo), depChild: child},
	}); err != nil {
		t.Fatalf("seed dependents: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, depChild); err != nil {
		t.Fatalf("corrupt dependent: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: depParent, RunnerID: runnerID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("lease dependent parent: %v", err)
	}
	depReceipt := model.CompletionReceipt{JobID: depParent, Generation: 1, RunnerID: runnerID}
	if err := st.CompleteJob(ctx, depParent, 1, runnerID, model.StatusSuccess, "", nil, depReceipt); err == nil {
		t.Fatal("a corrupt dependent payload must fail the completion")
	}

	// A corrupt run payload fails the run recomputation.
	runnerB := pgITNewID(t)
	pgITSeedRunner(t, st, runnerB, 4, 0, 0)
	orphanRun := pgITNewID(t)
	orphanJob := pgITNewID(t)
	pgITEnqueueOne(t, st, orphanRun, orphanJob, pgITRepo)
	if _, err := st.pool.Exec(ctx, `UPDATE runs SET payload='"scalar"'::jsonb WHERE id=$1`, orphanRun); err != nil {
		t.Fatalf("corrupt run: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: orphanJob, RunnerID: runnerB, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("lease orphan: %v", err)
	}
	orphanReceipt := model.CompletionReceipt{JobID: orphanJob, Generation: 1, RunnerID: runnerB}
	if err := st.CompleteJob(ctx, orphanJob, 1, runnerB, model.StatusSuccess, "", nil, orphanReceipt); err == nil {
		t.Fatal("a corrupt run payload must fail the completion")
	}

	// Artifact contracts that are not an object and non-required entries.
	contractRun := pgITNewID(t)
	contractJob := pgITNewID(t)
	pgITEnqueueOne(t, st, contractRun, contractJob, pgITRepo)
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload = jsonb_set(payload, '{artifact_contracts}', '"scalar"'::jsonb, true) WHERE id=$1`, contractJob); err != nil {
		t.Fatalf("scalar contracts: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: contractJob, RunnerID: runnerB, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("lease contract job: %v", err)
	}
	contractReceipt := model.CompletionReceipt{JobID: contractJob, Generation: 1, RunnerID: runnerB}
	if err := st.CompleteJob(ctx, contractJob, 1, runnerB, model.StatusSuccess, "", nil, contractReceipt); err == nil {
		t.Fatal("a non-object contracts payload must fail the completion")
	}
	// A non-required contract entry does not block success.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload = jsonb_set(payload, '{artifact_contracts}', '{"report":{"name":"report"}}'::jsonb, true) WHERE id=$1`, contractJob); err != nil {
		t.Fatalf("optional contract: %v", err)
	}
	if err := st.CompleteJob(ctx, contractJob, 1, runnerB, model.StatusSuccess, "", nil, contractReceipt); err != nil {
		t.Fatalf("a non-required contract must not block success: %v", err)
	}
}

func TestPostgresIntegrationLinkedProfileLease(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	runnerID := pgITNewID(t)
	profileID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)

	// The runner is linked to a profile with a mismatched repository ACL.
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: profileID, MaxCapacity: 2, Repositories: []string{"github.com/other/repo"}, Labels: []string{"linux"}, Region: "eu", Capabilities: []string{"container"}}); err != nil {
		t.Fatalf("profile: %v", err)
	}
	if err := st.BindCertProfile(ctx, "serial-1", profileID); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Capacity: 9, CertSerial: "serial-1"}); err != nil {
		t.Fatalf("runner: %v", err)
	}
	_, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, CanonRepoID: pgITRepoID, RequiredLabels: []string{"linux"}})
	if !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("repo ACL mismatch = %v, want ErrNoCapacity", err)
	}
	// Unknown runtime capability.
	_, err = st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, CanonRepoID: "github.com/other/repo", Runtime: "tart"})
	if !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("capability mismatch = %v, want ErrNoCapacity", err)
	}
	// Missing required label.
	_, err = st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, CanonRepoID: "github.com/other/repo", RequiredLabels: []string{"gpu"}})
	if !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("label mismatch = %v, want ErrNoCapacity", err)
	}
	// Placement region mismatch.
	_, err = st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, CanonRepoID: "github.com/other/repo", PlacementRegions: []string{"us"}})
	if !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("region mismatch = %v, want ErrNoCapacity", err)
	}
	// The bare repo full name alias is accepted.
	leased, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, RepoFullName: "github.com/other/repo", Runtime: "container"})
	if err != nil {
		t.Fatalf("alias lease: %v", err)
	}
	if leased.Status != model.StatusRunning {
		t.Fatalf("leased job = %+v", leased)
	}
	// The live profile capacity wins over the registration snapshot.
	if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: profileID, MaxCapacity: 0, Repositories: []string{"github.com/other/repo"}}); err != nil {
		t.Fatalf("shrink profile: %v", err)
	}
	otherJob := pgITNewID(t)
	otherRun := pgITNewID(t)
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  pgITRun(otherRun, model.StatusQueued),
		Jobs: map[string]model.Job{otherJob: pgITJob(otherRun, otherJob, pgITRepo)},
	}); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: otherJob, RunnerID: runnerID, RepoFullName: "github.com/other/repo"}); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("zero live capacity = %v, want ErrNoCapacity", err)
	}
	// A runner whose linked profile vanished is denied.
	elseJob := pgITNewID(t)
	elseRun := pgITNewID(t)
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  pgITRun(elseRun, model.StatusQueued),
		Jobs: map[string]model.Job{elseJob: pgITJob(elseRun, elseJob, pgITRepo)},
	}); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	if err := st.BindCertProfile(ctx, "serial-2", pgITNewID(t)); err != nil {
		t.Fatalf("bind dangling: %v", err)
	}
	danglingRunner := pgITNewID(t)
	if err := st.UpsertRunner(ctx, model.Runner{ID: danglingRunner, Capacity: 2, CertSerial: "serial-2"}); err != nil {
		t.Fatalf("dangling runner: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: elseJob, RunnerID: danglingRunner}); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("dangling profile = %v, want ErrNoCapacity", err)
	}
}

func TestPostgresIntegrationAcquireLeaseAtomicExtraBranches(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	runnerID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	pgITSeedRunner(t, st, runnerID, 1, 0, 0)

	// A queued job with a future lease_expires_at is rejected by the claim
	// UPDATE even though the status is queued.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET lease_expires_at = now() + interval '1 hour' WHERE id=$1`, jobID); err != nil {
		t.Fatalf("future lease: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID}); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("future lease = %v, want ErrLeaseConflict", err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET lease_expires_at = NULL WHERE id=$1`, jobID); err != nil {
		t.Fatalf("clear lease: %v", err)
	}
	// The environment concurrency predicate rejects a full environment.
	envRun := pgITNewID(t)
	holder := pgITNewID(t)
	blocked := pgITNewID(t)
	holderJob := pgITJob(envRun, holder, pgITRepo)
	holderJob.Environment = "prod"
	blockedJob := pgITJob(envRun, blocked, pgITRepo)
	blockedJob.Environment = "prod"
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  pgITRun(envRun, model.StatusQueued),
		Jobs: map[string]model.Job{holder: holderJob, blocked: blockedJob},
	}); err != nil {
		t.Fatalf("seed env jobs: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: holder, RunnerID: runnerID}); err != nil {
		t.Fatalf("lease holder: %v", err)
	}
	envClaim := LeaseClaim{JobID: blocked, RunnerID: runnerID, Environment: "prod", EnvironmentConcurrency: 1, CanonRepoID: pgITRepoID}
	if _, err := st.AcquireLeaseAtomic(ctx, envClaim); !errors.Is(err, ErrEnvConcurrency) {
		t.Fatalf("environment concurrency = %v, want ErrEnvConcurrency", err)
	}
	// The runner capacity bound rejects the second job on a capacity-1 runner.
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: blocked, RunnerID: runnerID}); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("runner capacity = %v, want ErrNoCapacity", err)
	}
	// A corrupt job payload fails the returned-job decode.
	corruptJob := pgITNewID(t)
	corruptRun := pgITNewID(t)
	pgITEnqueueOne(t, st, corruptRun, corruptJob, pgITRepo)
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, corruptJob); err != nil {
		t.Fatalf("corrupt job: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: corruptJob, RunnerID: runnerID}); err == nil {
		t.Fatal("a corrupt job payload must fail the lease")
	}
	// A missing runner row is ErrNoCapacity.
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: pgITNewID(t)}); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("missing runner = %v, want ErrNoCapacity", err)
	}
}

func TestPostgresIntegrationReleaseRunnerJobBranches(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID := pgITNewID(t)
	jobID := pgITNewID(t)

	// A missing runner row with a missing job row is a tolerated release.
	if err := st.ReleaseRunnerJob(ctx, pgITNewID(t), pgITNewID(t), model.StatusSuccess); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing runner and job = %v, want ErrNotFound", err)
	}
	// A missing runner row whose quota release fails surfaces that error.
	badRepoJob := pgITNewID(t)
	badRepoRun := pgITNewID(t)
	pgITEnqueueOne(t, st, badRepoRun, badRepoJob, pgITRepo)
	if _, err := st.pool.Exec(ctx, `ALTER TABLE quota_reservations RENAME TO quota_reservations_hidden`); err != nil {
		t.Fatalf("hide quota table: %v", err)
	}
	if err := st.ReleaseRunnerJob(ctx, pgITNewID(t), badRepoJob, model.StatusSuccess); err == nil {
		t.Fatal("a missing quota table must fail the quota release")
	}
	if _, err := st.pool.Exec(ctx, `ALTER TABLE quota_reservations_hidden RENAME TO quota_reservations`); err != nil {
		t.Fatalf("restore quota table: %v", err)
	}

	// A corrupt runner payload fails the release decode.
	pgITSeedRunner(t, st, runnerID, 2, 0, 0)
	if _, err := st.pool.Exec(ctx, `UPDATE runners SET payload='7'::jsonb WHERE id=$1`, runnerID); err != nil {
		t.Fatalf("corrupt runner: %v", err)
	}
	if err := st.ReleaseRunnerJob(ctx, runnerID, jobID, model.StatusSuccess); err == nil {
		t.Fatal("a corrupt runner payload must fail the release")
	}
	// A corrupt active_jobs column fails its decode.
	if _, err := st.pool.Exec(ctx, `UPDATE runners SET payload='{}'::jsonb, active_jobs='{"x":1}'::jsonb WHERE id=$1`, runnerID); err != nil {
		t.Fatalf("corrupt active jobs: %v", err)
	}
	if err := st.ReleaseRunnerJob(ctx, runnerID, jobID, model.StatusSuccess); err == nil {
		t.Fatal("a corrupt active_jobs column must fail the release")
	}
	// Releasing promotes the next active job and moves the failure counter.
	if _, err := st.pool.Exec(ctx, `UPDATE runners SET payload='{}'::jsonb, active_jobs=to_jsonb(ARRAY[$2::text, $3::text]), capacity=3 WHERE id=$1`, runnerID, jobID, memJobID); err != nil {
		t.Fatalf("seed active jobs: %v", err)
	}
	if err := st.ReleaseRunnerJob(ctx, runnerID, jobID, model.StatusFailure); err != nil {
		t.Fatalf("release: %v", err)
	}
	runner, _ := st.GetRunner(ctx, runnerID)
	if runner.CurrentJob != memJobID || runner.Failed != 1 || len(runner.ActiveJobs) != 1 {
		t.Fatalf("runner after release = %+v", runner)
	}
	// Releasing an unknown job from a live runner is a silent no-op.
	if err := st.ReleaseRunnerJob(ctx, runnerID, pgITNewID(t), model.StatusSuccess); err != nil {
		t.Fatalf("release of an unknown job = %v", err)
	}
}
