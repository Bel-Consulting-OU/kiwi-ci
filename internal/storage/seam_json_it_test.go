package storage

// Integration coverage for the Postgres store's JSON-encoder error branches:
// production always uses encoding/json.Marshal (jsonMarshal's default); the
// seam overrides make the otherwise impossible encode failures reachable so
// every store method can prove it fails closed and rolls back.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

var errPGSeamJSON = errors.New("seam: json marshal failed")

// seamPGFailAll fails every encode.
func seamPGFailAll(t *testing.T) func() {
	t.Helper()
	old := jsonMarshal
	jsonMarshal = func(any) ([]byte, error) { return nil, errPGSeamJSON }
	return func() { jsonMarshal = old }
}

// seamPGFailAt lets the first n-1 encodes succeed and fails from the n-th.
func seamPGFailAt(t *testing.T, n int) func() {
	t.Helper()
	old := jsonMarshal
	calls := 0
	jsonMarshal = func(v any) ([]byte, error) {
		calls++
		if calls >= n {
			return nil, errPGSeamJSON
		}
		return json.Marshal(v)
	}
	return func() { jsonMarshal = old }
}

func pgITSeamRun(runID string) model.Run {
	return model.Run{ID: runID, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()}
}

func TestPostgresIntegrationJSONSeamSweep(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	runnerID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	pgITSeedRunner(t, st, runnerID, 2, 0, 0)

	// begin opens a throwaway transaction for the internal helpers.
	begin := func(t *testing.T) (context.Context, func()) {
		t.Helper()
		tx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		return ctx, func() { _ = tx.Rollback(ctx) }
	}

	t.Run("InsertCompiledRun/contracts", func(t *testing.T) {
		defer seamPGFailAll(t)()
		err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
			Run:       pgITSeamRun(pgITNewID(t)),
			Jobs:      map[string]model.Job{pgITNewID(t): pgITJob(runID, jobID, pgITRepo)},
			Contracts: map[string]map[string]ArtifactContract{jobID: {"bin": {Name: "bin"}}},
		})
		if !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("contracts encode failure = %v", err)
		}
	})
	t.Run("InsertCompiledRun/run", func(t *testing.T) {
		defer seamPGFailAll(t)()
		err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{Run: pgITSeamRun(pgITNewID(t))})
		if !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("run encode failure = %v", err)
		}
	})
	t.Run("InsertRun", func(t *testing.T) {
		defer seamPGFailAll(t)()
		if err := st.InsertRun(ctx, pgITSeamRun(pgITNewID(t))); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("InsertRun = %v", err)
		}
	})
	t.Run("UpdateRunStatus", func(t *testing.T) {
		defer seamPGFailAll(t)()
		if err := st.UpdateRunStatus(ctx, runID, model.StatusRunning, nil, nil); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("UpdateRunStatus = %v", err)
		}
	})
	t.Run("jobWriteArgs/outputs", func(t *testing.T) {
		defer seamPGFailAt(t, 2)()
		if err := st.InsertJob(ctx, model.Job{ID: pgITNewID(t), RunID: runID, Status: model.StatusQueued,
			Outputs: map[string]string{"a": "b"}, CreatedAt: time.Now().UTC()}); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("InsertJob outputs = %v", err)
		}
	})
	t.Run("insertRunTx", func(t *testing.T) {
		_, done := begin(t)
		defer done()
		tx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		defer seamPGFailAll(t)()
		if err := st.insertRunTx(ctx, tx, pgITSeamRun(pgITNewID(t))); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("insertRunTx = %v", err)
		}
	})
	t.Run("cancelSupersededTx", func(t *testing.T) {
		tx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		defer seamPGFailAll(t)()
		if err := st.cancelSupersededTx(ctx, tx, []string{jobID}, pgITNewID(t)); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("cancelSupersededTx = %v", err)
		}
	})
	t.Run("cancelSupersededRunTx", func(t *testing.T) {
		tx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		defer seamPGFailAll(t)()
		if err := st.cancelSupersededRunTx(ctx, tx, runID, time.Now().UTC()); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("cancelSupersededRunTx = %v", err)
		}
	})
	t.Run("insertCompletionEffectsTx", func(t *testing.T) {
		tx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		defer seamPGFailAll(t)()
		if err := st.insertCompletionEffectsTx(ctx, tx, jobID, runID, 1, time.Now().UTC()); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("insertCompletionEffectsTx = %v", err)
		}
	})
	t.Run("completeRunnerTx", func(t *testing.T) {
		tx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		defer seamPGFailAll(t)()
		if err := st.completeRunnerTx(ctx, tx, runnerID, jobID, model.StatusSuccess, time.Now().UTC()); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("completeRunnerTx = %v", err)
		}
	})
	t.Run("recomputeRunTx", func(t *testing.T) {
		// The stored run status must disagree with its jobs so the
		// recomputation rewrites the payload.
		if err := st.UpdateRunStatus(ctx, runID, model.StatusRunning, nil, nil); err != nil {
			t.Fatal(err)
		}
		tx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		defer seamPGFailAll(t)()
		if err := st.recomputeRunTx(ctx, tx, runID); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("recomputeRunTx = %v", err)
		}
	})
	t.Run("CancelRunJobs", func(t *testing.T) {
		defer seamPGFailAll(t)()
		if _, err := st.CancelRunJobs(ctx, runID, "seam"); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("CancelRunJobs = %v", err)
		}
	})
	t.Run("UpsertRunner", func(t *testing.T) {
		defer seamPGFailAt(t, 2)()
		if err := st.UpsertRunner(ctx, model.Runner{ID: pgITNewID(t), Name: "seam", Capacity: 1}); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("UpsertRunner = %v", err)
		}
	})
	t.Run("ReleaseRunnerJob", func(t *testing.T) {
		defer seamPGFailAll(t)()
		if err := st.ReleaseRunnerJob(ctx, runnerID, jobID, model.StatusFailure); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("ReleaseRunnerJob = %v", err)
		}
	})
	t.Run("ReleaseRunnerJob/active", func(t *testing.T) {
		defer seamPGFailAt(t, 2)()
		if err := st.ReleaseRunnerJob(ctx, runnerID, jobID, model.StatusFailure); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("ReleaseRunnerJob active = %v", err)
		}
	})
	t.Run("InsertArtifact", func(t *testing.T) {
		defer seamPGFailAll(t)()
		if err := st.InsertArtifact(ctx, model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, Name: "bin"}); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("InsertArtifact = %v", err)
		}
	})
	t.Run("InsertArtifactOnce", func(t *testing.T) {
		defer seamPGFailAll(t)()
		if _, _, err := st.InsertArtifactOnce(ctx, model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, Name: "bin"}); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("InsertArtifactOnce = %v", err)
		}
	})
	t.Run("InsertTestReport/case", func(t *testing.T) {
		defer seamPGFailAt(t, 2)()
		if err := st.InsertTestReport(ctx, model.TestReport{ID: pgITNewID(t), RunID: runID, JobID: jobID, CreatedAt: time.Now().UTC(),
			Cases: []model.TestResult{{Name: "case"}}}); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("InsertTestReport case = %v", err)
		}
	})
	t.Run("InsertTestReport", func(t *testing.T) {
		defer seamPGFailAll(t)()
		if err := st.InsertTestReport(ctx, model.TestReport{ID: pgITNewID(t), RunID: runID, JobID: jobID, CreatedAt: time.Now().UTC(),
			Cases: []model.TestResult{{Name: "case"}}}); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("InsertTestReport = %v", err)
		}
	})
	t.Run("AppendAudit", func(t *testing.T) {
		defer seamPGFailAll(t)()
		if err := st.AppendAudit(ctx, model.AuditEvent{ID: pgITNewID(t), Action: "seam", Metadata: map[string]string{"k": "v"}, CreatedAt: time.Now().UTC()}); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("AppendAudit = %v", err)
		}
	})
	t.Run("InsertDeployment", func(t *testing.T) {
		defer seamPGFailAll(t)()
		if err := st.InsertDeployment(ctx, model.Deployment{ID: pgITNewID(t), RunID: runID, JobID: jobID, Environment: "prod", CreatedAt: time.Now().UTC()}); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("InsertDeployment = %v", err)
		}
	})
	t.Run("UpdateDeploymentStatus", func(t *testing.T) {
		depID := pgITNewID(t)
		if err := st.InsertDeployment(ctx, model.Deployment{ID: depID, RunID: runID, JobID: jobID, Environment: "prod", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		defer seamPGFailAll(t)()
		if err := st.UpdateDeploymentStatus(ctx, depID, model.StatusSuccess, nil); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("UpdateDeploymentStatus = %v", err)
		}
	})
	t.Run("InsertSnapshotRecord", func(t *testing.T) {
		defer seamPGFailAll(t)()
		if err := st.InsertSnapshotRecord(ctx, model.SnapshotRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, CreatedAt: time.Now().UTC()}); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("InsertSnapshotRecord = %v", err)
		}
	})
	t.Run("InsertJobContracts", func(t *testing.T) {
		defer seamPGFailAll(t)()
		if err := st.InsertJobContracts(ctx, jobID, map[string]ArtifactContract{"bin": {Name: "bin"}}); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("InsertJobContracts = %v", err)
		}
	})
	t.Run("PutCacheManifest", func(t *testing.T) {
		defer seamPGFailAll(t)()
		if err := st.PutCacheManifest(ctx, CacheManifestRecord{Repo: pgITRepoID, TrustDomain: "trusted", LogicalKey: "k", BlobSHA256: strings.Repeat("0", 64)}); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("PutCacheManifest = %v", err)
		}
	})
	t.Run("AppendDownstreamRun", func(t *testing.T) {
		defer seamPGFailAll(t)()
		if err := st.AppendDownstreamRun(ctx, runID, pgITNewID(t)); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("AppendDownstreamRun = %v", err)
		}
	})
	t.Run("UpsertProfile", func(t *testing.T) {
		defer seamPGFailAll(t)()
		if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: pgITNewID(t), CreatedAt: time.Now().UTC()}); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("UpsertProfile = %v", err)
		}
	})
	t.Run("UpsertProfile/second", func(t *testing.T) {
		defer seamPGFailAt(t, 2)()
		if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: pgITNewID(t), CreatedAt: time.Now().UTC()}); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("UpsertProfile second encode = %v", err)
		}
	})
	t.Run("UpsertProfile/third", func(t *testing.T) {
		defer seamPGFailAt(t, 3)()
		if err := st.UpsertProfile(ctx, model.RunnerProfile{ID: pgITNewID(t), CreatedAt: time.Now().UTC()}); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("UpsertProfile third encode = %v", err)
		}
	})
	t.Run("PutEnrollGrant", func(t *testing.T) {
		defer seamPGFailAll(t)()
		if err := st.PutEnrollGrant(ctx, pgITNewID(t), time.Now().Add(time.Hour), nil); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("PutEnrollGrant = %v", err)
		}
	})
	t.Run("InsertGeneratedFragmentTx/contracts", func(t *testing.T) {
		childID := pgITNewID(t)
		defer seamPGFailAt(t, 2)()
		_, _, err := st.InsertGeneratedFragmentTx(ctx, GeneratedFragmentRequest{
			ParentJobID: jobID, FragmentID: pgITNewID(t), LeaseGeneration: 1,
			Jobs:      map[string]model.Job{"child": {ID: childID, RunID: runID, Key: "child", Status: model.StatusQueued, CreatedAt: time.Now().UTC()}},
			Contracts: map[string]map[string]ArtifactContract{childID: {"bin": {Name: "bin"}}},
		}, nil)
		if !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("InsertGeneratedFragmentTx contracts = %v", err)
		}
	})
	t.Run("InsertGeneratedFragmentTx/children", func(t *testing.T) {
		childID := pgITNewID(t)
		defer seamPGFailAt(t, 3)()
		_, _, err := st.InsertGeneratedFragmentTx(ctx, GeneratedFragmentRequest{
			ParentJobID: jobID, FragmentID: pgITNewID(t), LeaseGeneration: 1,
			Jobs:      map[string]model.Job{"child": {ID: childID, RunID: runID, Key: "child", Status: model.StatusQueued, CreatedAt: time.Now().UTC()}},
			Contracts: map[string]map[string]ArtifactContract{childID: {"bin": {Name: "bin"}}},
		}, nil)
		if !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("InsertGeneratedFragmentTx children = %v", err)
		}
	})
	t.Run("CompleteJob", func(t *testing.T) {
		leased := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), leased, pgITRepo)
		pgITSeedRunner(t, st, runnerID, 2, 0, 0)
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: leased, RunnerID: runnerID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		defer seamPGFailAll(t)()
		err := st.CompleteJob(ctx, leased, 1, runnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: leased, Generation: 1, RunnerID: runnerID})
		if !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("CompleteJob = %v", err)
		}
	})
	t.Run("CompleteJob/outputs", func(t *testing.T) {
		leased := pgITNewID(t)
		pgITEnqueueOne(t, st, pgITNewID(t), leased, pgITRepo)
		if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: leased, RunnerID: runnerID, Generation: 1, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		defer seamPGFailAt(t, 2)()
		err := st.CompleteJob(ctx, leased, 1, runnerID, model.StatusSuccess, "", map[string]string{"o": "v"}, model.CompletionReceipt{JobID: leased, Generation: 1, RunnerID: runnerID})
		if !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("CompleteJob outputs = %v", err)
		}
	})
	t.Run("completeRunnerTx/active", func(t *testing.T) {
		tx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		defer seamPGFailAt(t, 2)()
		if err := st.completeRunnerTx(ctx, tx, runnerID, jobID, model.StatusSuccess, time.Now().UTC()); !errors.Is(err, errPGSeamJSON) {
			t.Fatalf("completeRunnerTx active = %v", err)
		}
	})
}

var _ = json.Marshal
