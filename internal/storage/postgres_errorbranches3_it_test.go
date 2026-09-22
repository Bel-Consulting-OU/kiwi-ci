package storage

// Fourth error-branch batch: the remaining reachable validations, decodes,
// conditional-trigger SQL failures and pure-helper cases.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

func TestPostgresIntegrationOutputsDecodeError(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	// Only the outputs column is malformed: the payload still decodes, so
	// the outputs decode is the failure under test.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET outputs='"scalar"'::jsonb WHERE id=$1`, jobID); err != nil {
		t.Fatalf("corrupt outputs: %v", err)
	}
	if _, err := st.GetJob(ctx, jobID); err == nil {
		t.Fatal("a scalar outputs column must fail the job decode")
	}
}

func TestPostgresIntegrationSupersedeJobErrorBranch(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	superseded := pgITRun(runID, model.StatusQueued)
	superseded.ConcurrencyGroup = "deploy"
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  superseded,
		Jobs: map[string]model.Job{jobID: pgITJob(runID, jobID, pgITRepo)},
	}); err != nil {
		t.Fatalf("seed superseded run: %v", err)
	}
	// A superseded job whose payload cannot be decoded fails the cancel.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, jobID); err != nil {
		t.Fatalf("corrupt job: %v", err)
	}
	err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:       pgITRun(pgITNewID(t), model.StatusQueued),
		Supersede: &SupersedePolicy{RepoID: pgITRepoID, ConcurrencyGroup: "deploy"},
	})
	if err == nil {
		t.Fatal("expected the supersede cancel to fail on a corrupt job payload")
	}
}

func TestPostgresIntegrationSupersedeRunningQuotaError(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	ids := boomerSeedFor(t, st, pgITRepo)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: ids.job, RunnerID: ids.runner, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("lease: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `INSERT INTO quota_reservations (key, running, queued) VALUES ('github.com/kiwi-it/repo', 1, 0), ('kiwi-it/repo', 1, 0), ('github.com/kiwi-it', 1, 0) ON CONFLICT (key) DO NOTHING`); err != nil {
		t.Fatalf("quota row: %v", err)
	}
	pgITBoom(t, st, "quota_reservations")
	// The cancelled job is running, so the running-slot branch fires.
	err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITRun(pgITNewID(t), model.StatusQueued), CancelPrevious: []string{ids.job}})
	if err == nil {
		t.Fatal("expected the running-slot quota release to fail")
	}
}

func TestPostgresIntegrationUpdateJobDependencyError(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	ids := boomerSeedFor(t, st, pgITRepo)
	dep := pgITNewID(t)
	if err := st.InsertJob(ctx, pgITJob(ids.run, dep, pgITRepo)); err != nil {
		t.Fatalf("dependency job: %v", err)
	}
	pgITBoom(t, st, "job_dependencies")
	job := pgITJob(ids.run, ids.job, pgITRepo)
	job.Needs = []string{dep}
	if err := st.UpdateJob(ctx, job); err == nil {
		t.Fatal("expected the dependency rewrite to fail")
	}
}

func TestPostgresIntegrationAcquireLeaseMissingJob(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runnerID := pgITNewID(t)
	pgITSeedRunner(t, st, runnerID, 1, 0, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: pgITNewID(t), RunnerID: runnerID}); err == nil {
		t.Fatal("a missing job must report a lease conflict")
	}
}

func TestPostgresIntegrationProfileLinkTableMissing(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	runnerID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	pgITSeedRunner(t, st, runnerID, 1, 0, 0)
	if _, err := st.pool.Exec(ctx, `UPDATE runners SET payload = jsonb_set(payload, '{cert_serial}', to_jsonb($2::text), true) WHERE id=$1`, runnerID, "serial"); err != nil {
		t.Fatalf("set serial: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `DROP TABLE cert_profile_links`); err != nil {
		t.Fatalf("drop links: %v", err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID}); err == nil {
		t.Fatal("expected the profile link lookup to fail")
	}
}

func TestPostgresIntegrationCompleteRunnerMissing(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	err := pgITTx(ctx, st, func(ctx context.Context, tx pgx.Tx) error {
		return st.completeRunnerTx(ctx, tx, pgITNewID(t), pgITNewID(t), model.StatusSuccess, time.Now().UTC())
	})
	if err != nil {
		t.Fatalf("a missing runner must be tolerated: %v", err)
	}
}

func TestPostgresIntegrationRecomputeHelperBranches(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)

	// recomputeDependentTx tolerates a missing dependent.
	if err := pgITTx(ctx, st, func(ctx context.Context, tx pgx.Tx) error {
		return st.recomputeDependentTx(ctx, tx, pgITNewID(t), time.Now().UTC())
	}); err != nil {
		t.Fatalf("missing dependent: %v", err)
	}
	// A terminal dependent is left untouched.
	if err := st.UpdateRunStatus(ctx, runID, model.StatusSuccess, nil, nil); err != nil {
		t.Fatalf("run status: %v", err)
	}
	terminal := pgITJob(runID, jobID, pgITRepo)
	terminal.Status = model.StatusSuccess
	if err := st.UpdateJob(ctx, terminal); err != nil {
		t.Fatalf("terminal job: %v", err)
	}
	if err := pgITTx(ctx, st, func(ctx context.Context, tx pgx.Tx) error {
		return st.recomputeDependentTx(ctx, tx, jobID, time.Now().UTC())
	}); err != nil {
		t.Fatalf("terminal dependent: %v", err)
	}
	// A dependent with a pending need is left queued.
	otherRun := pgITNewID(t)
	pending := pgITNewID(t)
	waiting := pgITNewID(t)
	waitingJob := pgITJob(otherRun, waiting, pgITRepo)
	waitingJob.Needs = []string{pending}
	pendingJob := pgITJob(otherRun, pending, pgITRepo)
	pendingJob.Status = model.StatusRunning
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  pgITRun(otherRun, model.StatusQueued),
		Jobs: map[string]model.Job{pending: pendingJob, waiting: waitingJob},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := pgITTx(ctx, st, func(ctx context.Context, tx pgx.Tx) error {
		return st.recomputeDependentTx(ctx, tx, waiting, time.Now().UTC())
	}); err != nil {
		t.Fatalf("pending dependent: %v", err)
	}
	// recomputeRunTx tolerates a missing run and reports no change.
	if err := pgITTx(ctx, st, func(ctx context.Context, tx pgx.Tx) error {
		return st.recomputeRunTx(ctx, tx, pgITNewID(t))
	}); err != nil {
		t.Fatalf("missing run: %v", err)
	}
	if err := pgITTx(ctx, st, func(ctx context.Context, tx pgx.Tx) error {
		return st.recomputeRunTx(ctx, tx, otherRun)
	}); err != nil {
		t.Fatalf("unchanged run: %v", err)
	}
	// A run whose status is already cancelled reports no change.
	if err := pgITTx(ctx, st, func(ctx context.Context, tx pgx.Tx) error {
		return st.recomputeRunTx(ctx, tx, runID)
	}); err != nil {
		t.Fatalf("terminal run: %v", err)
	}
}

func TestRecomputeRunStatusBranches(t *testing.T) {
	now := time.Now().UTC()
	started := now.Add(-time.Minute)
	finished := now.Add(time.Minute)
	for _, tc := range []struct {
		name  string
		run   model.Run
		state []jobState
		check func(*testing.T, *model.Run, bool)
	}{
		{
			name:  "no jobs",
			run:   model.Run{Status: model.StatusQueued},
			state: nil,
			check: func(t *testing.T, r *model.Run, changed bool) {
				if changed || r.Status != model.StatusQueued {
					t.Fatalf("empty run changed: %v %v", changed, r.Status)
				}
			},
		},
		{
			name:  "already cancelled",
			run:   model.Run{Status: model.StatusCancelled},
			state: []jobState{{status: model.StatusSuccess, finishedAt: &finished}},
			check: func(t *testing.T, r *model.Run, changed bool) {
				if changed || r.Status != model.StatusCancelled {
					t.Fatalf("cancelled run changed: %v %v", changed, r.Status)
				}
			},
		},
		{
			name:  "all cancelled",
			run:   model.Run{Status: model.StatusRunning},
			state: []jobState{{status: model.StatusCancelled}, {status: model.StatusSuccess}},
			check: func(t *testing.T, r *model.Run, changed bool) {
				if !changed || r.Status != model.StatusCancelled {
					t.Fatalf("cancelled jobs = %v %v", changed, r.Status)
				}
			},
		},
		{
			name:  "waiting approval",
			run:   model.Run{Status: model.StatusQueued},
			state: []jobState{{status: model.StatusWaitingApproval, startedAt: &started}},
			check: func(t *testing.T, r *model.Run, changed bool) {
				if !changed || r.Status != model.StatusWaitingApproval || r.StartedAt == nil {
					t.Fatalf("waiting run = %v %+v", changed, r)
				}
			},
		},
		{
			name:  "terminal without finish time",
			run:   model.Run{Status: model.StatusRunning},
			state: []jobState{{status: model.StatusSuccess}},
			check: func(t *testing.T, r *model.Run, changed bool) {
				if !changed || r.Status != model.StatusSuccess || r.FinishedAt == nil {
					t.Fatalf("terminal run = %v %+v", changed, r)
				}
			},
		},
		{
			name:  "no change",
			run:   model.Run{Status: model.StatusRunning, StartedAt: &started},
			state: []jobState{{status: model.StatusRunning, startedAt: &started}},
			check: func(t *testing.T, r *model.Run, changed bool) {
				if changed {
					t.Fatalf("running run reported a change: %+v", r)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := tc.run
			changed := recomputeRunStatus(&run, tc.state)
			tc.check(t, &run, changed)
		})
	}
	if !equalTimePtr(nil, nil) || equalTimePtr(&now, nil) || equalTimePtr(nil, &now) {
		t.Fatal("equalTimePtr nil handling")
	}
	if !equalTimePtr(&now, &now) || equalTimePtr(&now, &finished) {
		t.Fatal("equalTimePtr comparison")
	}
	earlier := now.Add(-time.Hour)
	if equalTimePtr(&now, &earlier) {
		t.Fatal("equalTimePtr must compare instants")
	}
}

func TestPostgresIntegrationCancelRunJobsQuotaErrors(t *testing.T) {
	ctx := context.Background()
	quotaKeys := []string{"github.com/kiwi-it/repo", "kiwi-it/repo", "github.com/kiwi-it"}
	seedQuota := func(t *testing.T, st *PostgresStore, running, queued int) {
		t.Helper()
		for _, k := range quotaKeys {
			if _, err := st.pool.Exec(ctx, `INSERT INTO quota_reservations (key, running, queued) VALUES ($1, $2, $3) ON CONFLICT (key) DO UPDATE SET running=$2, queued=$3`, k, running, queued); err != nil {
				t.Fatalf("quota row: %v", err)
			}
		}
	}
	t.Run("running", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: ids.job, RunnerID: ids.runner, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("lease: %v", err)
		}
		seedQuota(t, st, 1, 0)
		pgITBoom(t, st, "quota_reservations")
		if _, err := st.CancelRunJobs(ctx, ids.run, "stop"); err == nil {
			t.Fatal("expected the running quota release to fail")
		}
	})
	t.Run("queued", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		seedQuota(t, st, 0, 1)
		pgITBoom(t, st, "quota_reservations")
		if _, err := st.CancelRunJobs(ctx, ids.run, "stop"); err == nil {
			t.Fatal("expected the queued quota release to fail")
		}
	})
}

func TestPostgresIntegrationMiscValidationBranches(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)

	// AppendAudit with metadata exercises the marshal branch.
	if err := st.AppendAudit(ctx, model.AuditEvent{ID: pgITNewID(t), Action: "a", Metadata: map[string]string{"k": "v"}, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("audit with metadata: %v", err)
	}
	// HasCompletionReceipt validates the job id.
	if _, _, err := st.HasCompletionReceipt(ctx, "bad", 1, pgITNewID(t)); err == nil {
		t.Fatal("invalid job id must fail")
	}
	// UpsertDelivery validates the run id.
	if err := st.UpsertDelivery(ctx, "github", "d", "bad", "digest"); err == nil {
		t.Fatal("invalid run id must fail")
	}
	// OutboxAppend fills the id and creation time.
	if err := st.OutboxAppend(ctx, OutboxItem{Kind: "k"}); err != nil {
		t.Fatalf("OutboxAppend with defaults: %v", err)
	}
	// InsertJobContracts on a missing job reports not-found.
	if err := st.InsertJobContracts(ctx, pgITNewID(t), testContracts); err != ErrNotFound {
		t.Fatalf("contracts for a missing job = %v, want ErrNotFound", err)
	}
	// GetJobContracts: invalid id, absent payload key and corrupt contracts.
	if _, _, err := st.GetJobContracts(ctx, "bad"); err == nil {
		t.Fatal("invalid job id must fail")
	}
	noContracts := pgITNewID(t)
	if err := st.InsertJob(ctx, pgITJob(runID, noContracts, pgITRepo)); err != nil {
		t.Fatalf("job: %v", err)
	}
	if contracts, ok, err := st.GetJobContracts(ctx, noContracts); err != nil || ok || contracts != nil {
		t.Fatalf("absent contracts = %v, %v, %v", contracts, ok, err)
	}
	corrupt := pgITNewID(t)
	if err := st.InsertJob(ctx, pgITJob(runID, corrupt, pgITRepo)); err != nil {
		t.Fatalf("job: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload = jsonb_set(payload, '{artifact_contracts}', '"scalar"'::jsonb, true) WHERE id=$1`, corrupt); err != nil {
		t.Fatalf("corrupt contracts: %v", err)
	}
	if _, _, err := st.GetJobContracts(ctx, corrupt); err == nil {
		t.Fatal("a scalar contracts value must fail the decode")
	}
	// InsertGeneratedJobs validates every generated job id.
	if err := st.InsertGeneratedJobs(ctx, jobID, 1, map[string]model.Job{"bad": {ID: "bad"}}, nil); err == nil {
		t.Fatal("invalid generated job id must fail")
	}
	// ConsumePendingSidecar validates the digest.
	if err := st.ConsumePendingSidecar(ctx, jobID, 1, "bin", ArtifactSidecarKindSBOM, "short"); err == nil {
		t.Fatal("invalid digest must fail")
	}
	// nullBytes distinguishes empty from non-empty input.
	if nullBytes(nil) != nil || nullBytes([]byte{}) != nil {
		t.Fatal("empty byte slices must map to nil")
	}
	if got := nullBytes([]byte("x")); got == nil {
		t.Fatal("non-empty byte slices must pass through")
	}
	// GetEnrollGrant and ConsumeEnrollGrant treat an empty digest as absent.
	if _, ok, err := st.GetEnrollGrant(ctx, ""); err != nil || ok {
		t.Fatalf("empty grant digest = %v, %v", ok, err)
	}
	if _, err := st.ConsumeEnrollGrant(ctx, "", "admin"); err != ErrNotFound {
		t.Fatalf("empty grant digest = %v, want ErrNotFound", err)
	}
}

func TestPostgresIntegrationFragmentErrorBranches(t *testing.T) {
	ctx := context.Background()
	t.Run("corrupt-receipt", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		req := GeneratedFragmentRequest{ParentJobID: ids.job, LeaseGeneration: 1, FragmentID: "f", Jobs: map[string]model.Job{}}
		if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err != nil {
			t.Fatalf("fragment: %v", err)
		}
		if _, err := st.pool.Exec(ctx, `UPDATE generated_fragments SET children='"scalar"'::jsonb`); err != nil {
			t.Fatalf("corrupt children: %v", err)
		}
		if _, _, err := st.GetGeneratedFragment(ctx, ids.job, 1, "f"); err == nil {
			t.Fatal("a scalar children column must fail the decode")
		}
		if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err == nil {
			t.Fatal("a replay with a scalar children column must fail the decode")
		}
	})
	t.Run("corrupt-parent", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, ids.job); err != nil {
			t.Fatalf("corrupt parent: %v", err)
		}
		req := GeneratedFragmentRequest{ParentJobID: ids.job, LeaseGeneration: 1, FragmentID: "f", Jobs: map[string]model.Job{}}
		if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err == nil {
			t.Fatal("a corrupt parent payload must fail the fragment")
		}
	})
	t.Run("job-insert", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		pgITBoom(t, st, "jobs")
		child := pgITNewID(t)
		req := GeneratedFragmentRequest{ParentJobID: ids.job, LeaseGeneration: 1, FragmentID: "f", Jobs: map[string]model.Job{child: pgITJob(ids.run, child, pgITRepo)}}
		if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err == nil {
			t.Fatal("expected the fragment job insert to fail")
		}
	})
	t.Run("dependency-insert", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		pgITBoom(t, st, "job_dependencies")
		child := pgITNewID(t)
		job := pgITJob(ids.run, child, pgITRepo)
		job.Needs = []string{ids.job}
		req := GeneratedFragmentRequest{ParentJobID: ids.job, LeaseGeneration: 1, FragmentID: "f", Jobs: map[string]model.Job{child: job}}
		if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err == nil {
			t.Fatal("expected the fragment dependency insert to fail")
		}
	})
	t.Run("contract-update", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		child := pgITNewID(t)
		job := pgITJob(ids.run, child, pgITRepo)
		if err := st.InsertJob(ctx, job); err != nil {
			t.Fatalf("job: %v", err)
		}
		if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload='"scalar"'::jsonb WHERE id=$1`, child); err != nil {
			t.Fatalf("corrupt job: %v", err)
		}
		req := GeneratedFragmentRequest{ParentJobID: ids.job, LeaseGeneration: 1, FragmentID: "f", Jobs: map[string]model.Job{}, Contracts: map[string]map[string]ArtifactContract{child: testContracts}}
		if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err == nil {
			t.Fatal("expected the contract update to fail on a scalar payload")
		}
	})
	t.Run("receipt-insert", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		pgITBoom(t, st, "generated_fragments")
		req := GeneratedFragmentRequest{ParentJobID: ids.job, LeaseGeneration: 1, FragmentID: "f", Jobs: map[string]model.Job{}}
		if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); err == nil {
			t.Fatal("expected the fragment receipt insert to fail")
		}
	})
}

func TestPostgresIntegrationReservationAndSidecarErrors(t *testing.T) {
	ctx := context.Background()
	t.Run("reserve-insert", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		pgITBoom(t, st, "downstream_links")
		// The first UPDATE matches no row (no trigger), the SELECT finds none
		// and the INSERT fails.
		if _, err := st.ReserveDownstreamLaunch(ctx, ids.job, "acme/child", "main", "tok"); err == nil {
			t.Fatal("expected the reservation insert to fail")
		}
	})
	t.Run("sidecar-fields", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		art := model.ArtifactRecord{ID: pgITNewID(t), RunID: ids.run, Name: "bin", CreatedAt: time.Now().UTC()}
		if err := st.InsertArtifact(ctx, art); err != nil {
			t.Fatalf("artifact: %v", err)
		}
		for _, field := range []struct {
			name                         string
			path, digest, sigPath, sigSH string
		}{
			{"sbom-path", "p", "", "", ""},
			{"sbom-sha", "", "s", "", ""},
			{"sigstore-path", "", "", "q", ""},
			{"sigstore-sha", "", "", "", "t"},
		} {
			t.Run(field.name, func(t *testing.T) {
				pgITBoom(t, st, "artifacts")
				if err := st.SetArtifactSidecars(ctx, art.ID, field.path, field.digest, field.sigPath, field.sigSH); err == nil {
					t.Fatalf("expected the %s update to fail", field.name)
				}
				if _, err := st.pool.Exec(ctx, `DROP TRIGGER kiwi_boom_artifacts_insert ON artifacts; DROP TRIGGER kiwi_boom_artifacts_update ON artifacts; DROP TRIGGER kiwi_boom_artifacts_delete ON artifacts`); err != nil {
					t.Fatalf("drop triggers: %v", err)
				}
			})
		}
	})
}

func TestPostgresIntegrationDisableRunnerUpdateError(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	ids := boomerSeedFor(t, st, pgITRepo)
	pgITBoom(t, st, "runners")
	if _, err := st.DisableRunnerAndRevokeCert(ctx, ids.runner, "serial", "admin"); err == nil {
		t.Fatal("expected the runner disable update to fail")
	}
}

func TestPostgresIntegrationSchemaVersionBrokenTable(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	if _, err := st.pool.Exec(ctx, `ALTER TABLE schema_migrations ALTER COLUMN version TYPE jsonb USING to_jsonb(version)`); err != nil {
		t.Fatalf("alter column: %v", err)
	}
	if _, err := st.SchemaVersion(ctx); err == nil {
		t.Fatal("expected the version aggregate to fail on a jsonb column")
	}
}

func TestPostgresIntegrationMigrationInsertError(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	pgITBoom(t, st, "schema_migrations")
	m := migrations.Migration{Version: 9991, Name: "9991_probe.sql", Statements: []string{"SELECT 1"}}
	if err := st.applyMigration(ctx, m); err == nil {
		t.Fatal("expected the migration insert to fail")
	}
}

func TestPostgresIntegrationProfileColumnDecodeErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		column string
	}{
		{"labels", "labels"},
		{"repositories", "repositories"},
		{"capabilities", "capabilities"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := pgITStore(t)
			ctx := context.Background()
			profileID := pgITNewID(t)
			if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: profileID, CreatedAt: time.Now().UTC()}); err != nil {
				t.Fatalf("profile: %v", err)
			}
			if err := st.BindCertProfile(ctx, "serial", profileID); err != nil {
				t.Fatalf("bind: %v", err)
			}
			if _, err := st.pool.Exec(ctx, `UPDATE runner_profiles SET `+tc.column+`='"scalar"'::jsonb WHERE id=$1`, profileID); err != nil {
				t.Fatalf("corrupt %s: %v", tc.column, err)
			}
			if _, err := st.GetProfile(ctx, profileID); err == nil {
				t.Fatalf("a scalar %s column must fail the profile decode", tc.column)
			}
			if _, err := st.ListProfiles(ctx); err == nil {
				t.Fatalf("a scalar %s column must fail the profile list decode", tc.column)
			}
			if _, _, err := st.ProfileForSerial(ctx, "serial"); err == nil {
				t.Fatalf("a scalar %s column must fail the serial lookup", tc.column)
			}
		})
	}
}
