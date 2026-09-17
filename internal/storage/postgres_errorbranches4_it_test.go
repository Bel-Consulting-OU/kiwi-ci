package storage

// Final error-branch batch: statement-specific triggers and the remaining
// validation/decode paths.

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITBoomPayloadUpdate makes only UPDATEs that change the payload column
// fail, so multi-statement functions reach their second write.
func pgITBoomPayloadUpdate(t *testing.T, st *PostgresStore, table string) {
	t.Helper()
	ctx := context.Background()
	fn := "kiwi_boom_payload_" + table
	if _, err := st.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION `+fn+`() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected payload failure on `+table+`'; END; $$ LANGUAGE plpgsql`); err != nil {
		t.Fatalf("create trigger function: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `CREATE TRIGGER `+fn+` BEFORE UPDATE ON `+table+` FOR EACH ROW WHEN (OLD.payload IS DISTINCT FROM NEW.payload) EXECUTE FUNCTION `+fn+`()`); err != nil {
		t.Fatalf("create trigger on %s: %v", table, err)
	}
}

func TestPostgresIntegrationUpdateRunStatusPayloadError(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
	pgITBoomPayloadUpdate(t, st, "runs")
	if err := st.UpdateRunStatus(ctx, runID, model.StatusRunning, nil, nil); err == nil {
		t.Fatal("expected the payload rewrite to fail")
	}
}

func TestPostgresIntegrationArtifactErrorBranches(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)

	if _, _, err := st.InsertArtifactOnce(ctx, model.ArtifactRecord{ID: pgITNewID(t), RunID: "bad", JobID: jobID, Name: "bin"}); err == nil {
		t.Fatal("invalid run id must fail")
	}
	art := model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, Name: "bin", SHA256: "a", LeaseGeneration: 1, CreatedAt: time.Now().UTC()}
	if _, _, err := st.InsertArtifactOnce(ctx, art); err != nil {
		t.Fatalf("artifact: %v", err)
	}
	// A conflicting artifact with a corrupt stored payload fails the lookup
	// rather than reporting a digest conflict.
	if _, err := st.pool.Exec(ctx, `UPDATE artifacts SET payload='"scalar"'::jsonb WHERE id=$1`, art.ID); err != nil {
		t.Fatalf("corrupt artifact: %v", err)
	}
	conflict := art
	conflict.ID = pgITNewID(t)
	conflict.SHA256 = "b"
	if _, _, err := st.InsertArtifactOnce(ctx, conflict); err == nil {
		t.Fatal("a corrupt stored artifact must fail the conflict lookup")
	}
	if _, err := st.GetArtifact(ctx, art.ID); err == nil {
		t.Fatal("a corrupt artifact payload must fail the decode")
	}
	if _, err := st.GetArtifact(ctx, pgITNewID(t)); err == nil {
		t.Fatal("a missing artifact must report not-found")
	}
	// A missing artifacts relation fails the generation-key lookup.
	st2 := pgITStore(t)
	ctx2 := context.Background()
	run2 := pgITNewID(t)
	job2 := pgITNewID(t)
	pgITEnqueueOne(t, st2, run2, job2, pgITRepo)
	if _, err := st2.pool.Exec(ctx2, `DROP TABLE artifacts`); err != nil {
		t.Fatalf("drop artifacts: %v", err)
	}
	if _, err := st2.artifactByGenerationKey(ctx2, job2, 1, "bin"); err == nil {
		t.Fatal("a missing artifacts relation must fail the lookup")
	}
}

func TestPostgresIntegrationTestReportErrorBranches(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	// A non-finite report duration fails the payload marshal.
	rep := model.TestReport{ID: pgITNewID(t), RunID: runID, Duration: math.NaN(), CreatedAt: time.Now().UTC()}
	if err := st.InsertTestReport(ctx, rep); err == nil {
		t.Fatal("a NaN report duration must fail the marshal")
	}
	// A non-finite case duration fails the case marshal after the report row
	// insert rolls back.
	cases := model.TestReport{ID: pgITNewID(t), RunID: runID, CreatedAt: time.Now().UTC(), Cases: []model.TestResult{{Name: "t", Duration: math.NaN()}}}
	if err := st.InsertTestReport(ctx, cases); err == nil {
		t.Fatal("a NaN case duration must fail the marshal")
	}
}

func TestPostgresIntegrationQueueReasonErrorBranches(t *testing.T) {
	ctx := context.Background()
	t.Run("set", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		pgITBoom(t, st, "jobs")
		if err := st.SetQueueReasons(ctx, map[string]string{ids.job: "waiting"}); err == nil {
			t.Fatal("expected the queue reason update to fail")
		}
	})
	t.Run("clear", func(t *testing.T) {
		st := pgITStore(t)
		ids := boomerSeedFor(t, st, pgITRepo)
		pgITBoom(t, st, "jobs")
		if err := st.SetQueueReasons(ctx, map[string]string{ids.job: ""}); err == nil {
			t.Fatal("expected the queue reason clear to fail")
		}
	})
}

func TestPostgresIntegrationUpsertRunnerErrorBranches(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	// A non-finite cost rate fails the runner payload marshal.
	if err := st.UpsertRunner(ctx, model.Runner{ID: pgITNewID(t), Capacity: 1, CostPerHour: math.NaN()}); err == nil {
		t.Fatal("a NaN cost rate must fail the runner marshal")
	}
}

func TestPostgresIntegrationReleaseRunnerQuotaError(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	ids := boomerSeedFor(t, st, pgITRepo)
	if _, err := st.pool.Exec(ctx, `INSERT INTO quota_reservations (key, running, queued) VALUES ('github.com/kiwi-it/repo', 1, 0), ('kiwi-it/repo', 1, 0), ('github.com/kiwi-it', 1, 0) ON CONFLICT (key) DO NOTHING`); err != nil {
		t.Fatalf("quota rows: %v", err)
	}
	// A live runner row whose quota release fails surfaces the quota error.
	pgITBoom(t, st, "quota_reservations")
	if err := st.ReleaseRunnerJob(ctx, ids.runner, ids.job, model.StatusSuccess); err == nil {
		t.Fatal("expected the quota release to fail")
	}
}
