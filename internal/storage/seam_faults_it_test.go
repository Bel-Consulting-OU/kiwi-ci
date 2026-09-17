package storage

// Integration coverage for per-statement fault branches: schema type breaks,
// value-discriminated BEFORE triggers and skip triggers force the exact SQL
// statement to fail while every earlier statement in the same helper
// succeeds.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITSkipWrites makes every INSERT/UPDATE event on table a no-op by
// returning NULL from a BEFORE trigger, so the statement succeeds with zero
// affected rows.
func pgITSkipWrites(t *testing.T, st *PostgresStore, table, event string) {
	t.Helper()
	ctx := context.Background()
	fn := "kiwi_skip_" + table + "_" + event
	if _, err := st.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION `+fn+`() RETURNS trigger AS $$ BEGIN RETURN NULL; END; $$ LANGUAGE plpgsql`); err != nil {
		t.Fatalf("create skip function for %s: %v", table, err)
	}
	if _, err := st.pool.Exec(ctx, `CREATE TRIGGER `+fn+`_t BEFORE `+event+` ON `+table+` FOR EACH ROW EXECUTE FUNCTION `+fn+`()`); err != nil {
		t.Fatalf("create skip trigger on %s: %v", table, err)
	}
}

// pgITDropExpressionIndexes drops every index on table whose definition
// references column, so the column can be retyped.
func pgITDropExpressionIndexes(t *testing.T, st *PostgresStore, table, column string) {
	t.Helper()
	ctx := context.Background()
	rows, err := st.pool.Query(ctx, `SELECT indexname FROM pg_indexes WHERE schemaname=current_schema() AND tablename=$1 AND indexdef LIKE '%'||$2||'%'`, table, column)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	rows.Close()
	for _, n := range names {
		if _, err := st.pool.Exec(ctx, `DROP INDEX `+n); err != nil {
			t.Fatalf("drop index %s: %v", n, err)
		}
	}
}

// pgITBreakColumnToBytea retypes a column to bytea so scanning it into a
// string destination cannot succeed.
func pgITBreakColumnToBytea(t *testing.T, st *PostgresStore, table, column string) {
	t.Helper()
	q := fmt.Sprintf(`ALTER TABLE %s ALTER COLUMN %s DROP DEFAULT`, table, column)
	if _, err := st.pool.Exec(context.Background(), q); err != nil {
		t.Fatalf("drop default %s.%s: %v", table, column, err)
	}
	q = fmt.Sprintf(`ALTER TABLE %s ALTER COLUMN %s TYPE bytea USING '\x00'::bytea`, table, column)
	if _, err := st.pool.Exec(context.Background(), q); err != nil {
		t.Fatalf("break %s.%s to bytea: %v", table, column, err)
	}
}

// pgITBoomOnCostRate fails only UPDATEs of jobs that freeze a cost rate,
// discriminating on the NEW payload value so the earlier status update passes.
func pgITBoomOnCostRate(t *testing.T, st *PostgresStore) {
	t.Helper()
	ctx := context.Background()
	if _, err := st.pool.Exec(ctx, `CREATE OR REPLACE FUNCTION kiwi_boom_cost_rate() RETURNS trigger AS $$ BEGIN IF NEW.payload->>'cost_rate' IS NOT NULL AND OLD.payload->>'cost_rate' IS NULL THEN RAISE EXCEPTION 'injected cost-rate failure'; END IF; RETURN NEW; END; $$ LANGUAGE plpgsql`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.pool.Exec(ctx, `CREATE TRIGGER kiwi_boom_cost_rate_t BEFORE UPDATE ON jobs FOR EACH ROW EXECUTE FUNCTION kiwi_boom_cost_rate()`); err != nil {
		t.Fatal(err)
	}
}

// pgITDropFKsOn drops every foreign key constraint touching table so a
// column type break cannot fail on referential integrity.
func pgITDropFKsOn(t *testing.T, st *PostgresStore, table string) {
	t.Helper()
	ctx := context.Background()
	rows, err := st.pool.Query(ctx, `SELECT conrelid::regclass::text, conname FROM pg_constraint WHERE contype='f' AND (confrelid=$1::regclass OR conrelid=$1::regclass)`, table)
	if err != nil {
		t.Fatal(err)
	}
	type fk struct{ tbl, name string }
	var fks []fk
	for rows.Next() {
		var f fk
		if err := rows.Scan(&f.tbl, &f.name); err != nil {
			t.Fatal(err)
		}
		fks = append(fks, f)
	}
	rows.Close()
	for _, f := range fks {
		if _, err := st.pool.Exec(ctx, `ALTER TABLE `+f.tbl+` DROP CONSTRAINT `+f.name); err != nil {
			t.Fatalf("drop fk %s: %v", f.name, err)
		}
	}
}

func TestPostgresIntegrationStatementFaults(t *testing.T) {
	ctx := context.Background()

	t.Run("AcquireLeaseAtomic/jobLock", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		pgITSeedRunner(t, st, pgITNewID(t), 1, 0, 0)
		pgITDropFKsOn(t, st, "jobs")
		pgITBreakColumn(t, st, "jobs", "id")
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerIDForTest(t, st)}); err == nil {
			t.Fatal("job lock with a mistyped id returned a lease")
		}
	})
	t.Run("AcquireLeaseAtomic/envCount", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		runnerID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		pgITDropExpressionIndexes(t, st, "jobs", "payload")
		pgITBreakColumnToArray(t, st, "jobs", "payload")
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, RepoURL: pgITRepo, Environment: "prod", EnvironmentConcurrency: 1}); err == nil {
			t.Fatal("env-count with a mistyped payload succeeded")
		}
	})
	t.Run("AcquireLeaseAtomic/runnerScan", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		runnerID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		pgITBreakColumnToArray(t, st, "runners", "payload")
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID}); err == nil {
			t.Fatal("runner scan with a mistyped payload succeeded")
		}
	})
	t.Run("AcquireLeaseAtomic/labelsEncode", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		runnerID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		defer seamPGFailAll(t)()
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID}); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("labels encode failure = %v", err)
		}
	})
	t.Run("AcquireLeaseAtomic/regionsEncode", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		runnerID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		defer seamPGFailAt(t, 2)()
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID}); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("regions encode failure = %v", err)
		}
	})
	t.Run("AcquireLeaseAtomic/profileEncode", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		runnerID := pgITNewID(t)
		serial := "serial-" + pgITNewID(t)
		profileID := pgITNewID(t)
		if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: profileID, MaxCapacity: 2, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		if err := st.BindCertProfile(ctx, serial, profileID); err != nil {
			t.Fatal(err)
		}
		if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: "linked", Capacity: 2, CertSerial: serial}); err != nil {
			t.Fatal(err)
		}
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		defer seamPGFailAll(t)()
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID}); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("profile encode failure = %v", err)
		}
	})
	t.Run("AcquireLeaseAtomic/usageFreeze", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		runnerID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		pgITBoomOnCostRate(t, st)
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err == nil {
			t.Fatal("usage freeze trigger did not fail the lease")
		}
		// The transaction rolled back: the job is still queued.
		j, err := st.GetJob(ctx, jobID)
		if err != nil || j.Status != model.StatusQueued {
			t.Fatalf("job after failed lease = %+v, %v; want queued", j, err)
		}
	})
	t.Run("HeartbeatLease/update", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		pgITBoomOp(t, st, "jobs", "UPDATE")
		if err := st.HeartbeatLease(ctx, jobID, "runner", 1, time.Now().Add(time.Minute)); err == nil {
			t.Fatal("heartbeat with a failing update trigger succeeded")
		}
	})
	t.Run("CompleteJob/jobLock", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		runnerID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		pgITBreakColumnToArray(t, st, "jobs", "key")
		err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID})
		if err == nil {
			t.Fatal("completion with a mistyped run_id column succeeded")
		}
	})
	t.Run("CompleteJob/receiptExists", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		runnerID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumn(t, st, "completion_receipts", "runner_id")
		// Generation 2 makes the live job look stale, so the helper probes
		// the receipts table and must surface its failure.
		err := st.CompleteJob(ctx, jobID, 2, runnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: jobID, Generation: 2, RunnerID: runnerID})
		if err == nil {
			t.Fatal("completion with a mistyped receipts column succeeded")
		}
	})
	t.Run("recomputeDependentsTx/scan", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		depJobID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, depJobID, pgITRepo)
		dependsOn := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), dependsOn, pgITRepo)
		if _, err := st.pool.Exec(ctx, `INSERT INTO job_dependencies (job_id, depends_on) VALUES ($1, $2)`, dependsOn, depJobID); err != nil {
			t.Fatal(err)
		}
		pgITDropFKsOn(t, st, "job_dependencies")
		pgITBreakColumnToBytea(t, st, "job_dependencies", "job_id")
		tx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err := st.recomputeDependentsTx(ctx, tx, depJobID, time.Now().UTC()); err == nil {
			t.Fatal("dependent recompute with a mistyped dependency column succeeded")
		}
	})
	t.Run("CancelRunJobs/scan", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)
		pgITBreakColumnToArray(t, st, "jobs", "lease_runner_id")
		if _, err := st.CancelRunJobs(ctx, runID, "seam"); err == nil {
			t.Fatal("cancel with a mistyped lease column succeeded")
		}
	})
	t.Run("ReleaseRunnerJob/runnerScan", func(t *testing.T) {
		st := pgITStore(t)
		jobID := pgITNewID(t)
		runnerID := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), jobID, pgITRepo)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		pgITBreakColumnToArray(t, st, "runners", "payload")
		if err := st.ReleaseRunnerJob(ctx, runnerID, jobID, model.StatusFailure); err == nil {
			t.Fatal("release with a mistyped runner payload succeeded")
		}
	})
	t.Run("ClaimScheduleOccurrence/missing", func(t *testing.T) {
		st := pgITStore(t)
		pgITSkipWrites(t, st, "schedule_occurrences", "INSERT")
		claimed, err := st.ClaimScheduleOccurrence(ctx, "schedule-1", time.Now().UTC().Truncate(time.Second), pgITNewID(t))
		if err != nil || !claimed {
			t.Fatalf("skipped claim = %v, %v; want unclaimed", claimed, err)
		}
	})
	t.Run("ReserveDownstreamLaunch/read", func(t *testing.T) {
		st := pgITStore(t)
		pgITBreakColumn(t, st, "downstream_links", "parent_job_id")
		if _, err := st.ReserveDownstreamLaunch(ctx, pgITNewID(t), pgITRepo, "main", "token"); err == nil {
			t.Fatal("reserve with a mistyped parent column succeeded")
		}
	})
	t.Run("ConsumeEnrollGrant/read", func(t *testing.T) {
		st := pgITStore(t)
		digest := pgITNewID(t)
		if err := st.PutEnrollGrant(ctx, digest, time.Now().Add(time.Hour), nil); err != nil {
			t.Fatal(err)
		}
		pgITSkipWrites(t, st, "enrollment_grants", "UPDATE")
		pgITBreakColumnToArray(t, st, "enrollment_grants", "bound_labels")
		if _, err := st.ConsumeEnrollGrant(ctx, digest, "runner-1"); err == nil {
			t.Fatal("consume with a mistyped labels column succeeded")
		}
	})
	t.Run("InsertCompiledRun/contracts", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		jobID := pgITNewID(t)
		defer seamPGFailAt(t, 3)()
		err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
			Run:       pgITSeamRun(runID),
			Jobs:      map[string]model.Job{jobID: {ID: jobID, RunID: runID, Key: "build", Status: model.StatusQueued, CreatedAt: time.Now().UTC()}},
			Contracts: map[string]map[string]ArtifactContract{jobID: {"bin": {Name: "bin"}}},
		})
		if !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("contracts encode failure = %v", err)
		}
	})
	t.Run("CancelRunJobs/cancelledPayload", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		jobID := pgITNewID(t)
		runnerID := pgITNewID(t)
		pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
		pgITSeedRunner(t, st, runnerID, 1, 0, 0)
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		defer seamPGFailAt(t, 2)()
		if _, err := st.CancelRunJobs(ctx, runID, "seam"); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("cancel payload encode failure = %v", err)
		}
	})
	t.Run("recomputeDependentTx/payload", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		aID := pgITNewID(t)
		bID := pgITNewID(t)
		now := time.Now().UTC()
		if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
			Run:  pgITSeamRun(runID),
			Jobs: map[string]model.Job{aID: {ID: aID, RunID: runID, Key: "a", Status: model.StatusQueued, CreatedAt: now}, bID: {ID: bID, RunID: runID, Key: "b", Status: model.StatusQueued, CreatedAt: now}},
			Deps: map[string][]string{bID: {aID}},
		}); err != nil {
			t.Fatal(err)
		}
		if err := st.UpdateJob(ctx, model.Job{ID: aID, RunID: runID, Key: "a", Status: model.StatusSuccess, CreatedAt: now, FinishedAt: &now}); err != nil {
			t.Fatal(err)
		}
		tx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		defer seamPGFailAll(t)()
		if err := st.recomputeDependentTx(ctx, tx, bID, now); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("dependent payload encode failure = %v", err)
		}
	})
}

// runnerIDForTest returns any seeded runner id.
func runnerIDForTest(t *testing.T, st *PostgresStore) string {
	t.Helper()
	runners, err := st.ListRunners(context.Background())
	if err != nil || len(runners) == 0 {
		t.Fatalf("no runners: %v", err)
	}
	return runners[len(runners)-1].ID
}
