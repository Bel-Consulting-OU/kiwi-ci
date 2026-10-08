package storage

// Real-PostgreSQL tests for run-scoped logical job identity (finding 7):
// migration 0048 conditionally installs the (run_id, key) unique index, and
// InsertGeneratedFragmentTx additionally admits every fragment child key under
// a per-run advisory lock, so a collision fails closed even on a database
// where the index had to be skipped. Gated on KIWI_TEST_POSTGRES_URL like the
// other storage integration tests.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITIndexExists reports whether a relation exists in the current schema.
func pgITIndexExists(t *testing.T, st *PostgresStore, name string) bool {
	t.Helper()
	var exists bool
	if err := st.pool.QueryRow(context.Background(), `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists); err != nil {
		t.Fatalf("read to_regclass(%s): %v", name, err)
	}
	return exists
}

// TestPostgresIntegrationGeneratedFragmentChildKeyCollidesWithExistingRunJob:
// a generated child declaring a key that already identifies a job of the run
// is rejected with the typed conflict and inserts nothing; matrix variants
// (distinct Keys sharing BaseKey) coexist, a key equal to neither is admitted,
// and the conditional unique index is present on a clean database. The key
// lookup resolves the addressed matrix variant.
func TestPostgresIntegrationGeneratedFragmentChildKeyCollidesWithExistingRunJob(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	runID, parentID, macID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	parent := pgITJob(runID, parentID, pgITRepo)
	parent.Key, parent.BaseKey = "build[os=linux]", "build"
	mac := pgITJob(runID, macID, pgITRepo)
	mac.Key, mac.BaseKey = "build[os=mac]", "build"
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  pgITRun(runID, model.StatusQueued),
		Jobs: map[string]model.Job{parentID: parent, macID: mac},
	}); err != nil {
		t.Fatalf("compiled matrix run: %v", err)
	}

	// The addressed matrix variant resolves unambiguously by Key.
	jobs, err := st.ListJobsByRun(ctx, runID)
	if err != nil || len(jobs) != 2 {
		t.Fatalf("ListJobsByRun = %d jobs, %v", len(jobs), err)
	}
	byKey := map[string]model.Job{}
	for _, j := range jobs {
		byKey[j.Key] = j
	}
	if byKey["build[os=linux]"].ID != parentID || byKey["build[os=mac]"].ID != macID {
		t.Fatalf("matrix jobs = %+v, want linux=%s mac=%s", byKey, parentID, macID)
	}

	runnerID := pgITNewID(t)
	leased, err := st.AcquireLease(ctx, parentID, runnerID, []byte("run-key-conflict"), 1, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("AcquireLease: %v", err)
	}

	// Collision with the existing matrix variant.
	child := pgITJob(runID, pgITNewID(t), pgITRepo)
	child.Key = "build[os=mac]"
	req := GeneratedFragmentRequest{
		ParentJobID: parentID, RunnerID: leased.LeaseRunnerID, LeaseGeneration: leased.LeaseGeneration,
		LeaseTokenHash: leased.LeaseTokenHash, Depth: 1, FragmentID: "frag-key-collision",
		Jobs:     map[string]model.Job{child.ID: child},
		Children: []GeneratedFragmentChild{{Key: child.Key, ID: child.ID}},
	}
	if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); !errors.Is(err, ErrGeneratedJobKeyConflict) {
		t.Fatalf("colliding fragment = %v, want ErrGeneratedJobKeyConflict", err)
	} else {
		var conflict *GeneratedJobKeyConflictError
		if !errors.As(err, &conflict) || conflict.RunID != runID || conflict.Key != "build[os=mac]" || conflict.ExistingJobID != macID {
			t.Fatalf("conflict = %+v (err %v)", conflict, err)
		}
	}
	if jobs, err := st.ListJobsByRun(ctx, runID); err != nil || len(jobs) != 2 {
		t.Fatalf("run jobs after rejection = %d, %v; want the original 2", len(jobs), err)
	}
	if _, found, err := st.GetGeneratedFragment(ctx, parentID, GeneratedFragmentMutationSlotDefault); err != nil || found {
		t.Fatalf("rejected fragment receipt found=%v err=%v", found, err)
	}

	// A key equal to neither matrix variant is admitted.
	free := pgITJob(runID, pgITNewID(t), pgITRepo)
	free.Key = "package"
	req.FragmentID = "frag-free"
	req.Jobs = map[string]model.Job{free.ID: free}
	req.Children = []GeneratedFragmentChild{{Key: free.Key, ID: free.ID}}
	rec, replayed, err := st.InsertGeneratedFragmentTx(ctx, req, nil)
	if err != nil || replayed || len(rec.Children) != 1 || rec.Children[0].ID != free.ID {
		t.Fatalf("free-key fragment = %+v replayed=%v err=%v", rec, replayed, err)
	}
	if jobs, err := st.ListJobsByRun(ctx, runID); err != nil || len(jobs) != 3 {
		t.Fatalf("run jobs after admission = %d, %v; want 3", len(jobs), err)
	}

	// The clean database carries the conditional unique index.
	if !pgITIndexExists(t, st, "jobs_run_key_idx") {
		t.Fatal("jobs_run_key_idx missing on a clean database")
	}
}

// TestPostgresIntegrationGeneratedFragmentChildKeyCollidesAcrossFragments:
// two different parents of one run emitting the same child key — the second
// fragment is rejected and inserts nothing.
func TestPostgresIntegrationGeneratedFragmentChildKeyCollidesAcrossFragments(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	runID, parentA, parentB := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	jobA := pgITJob(runID, parentA, pgITRepo)
	jobA.Key = "build[os=linux]"
	jobB := pgITJob(runID, parentB, pgITRepo)
	jobB.Key = "build[os=mac]"
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  pgITRun(runID, model.StatusQueued),
		Jobs: map[string]model.Job{parentA: jobA, parentB: jobB},
	}); err != nil {
		t.Fatalf("compiled run: %v", err)
	}
	runnerA, runnerB := pgITNewID(t), pgITNewID(t)
	leasedA, err := st.AcquireLease(ctx, parentA, runnerA, []byte("run-key-a"), 1, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("AcquireLease A: %v", err)
	}
	leasedB, err := st.AcquireLease(ctx, parentB, runnerB, []byte("run-key-b"), 1, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("AcquireLease B: %v", err)
	}

	first := pgITJob(runID, pgITNewID(t), pgITRepo)
	first.Key = "shared-child"
	reqA := GeneratedFragmentRequest{
		ParentJobID: parentA, RunnerID: leasedA.LeaseRunnerID, LeaseGeneration: leasedA.LeaseGeneration,
		LeaseTokenHash: leasedA.LeaseTokenHash, Depth: 1, FragmentID: "frag-a",
		Jobs:     map[string]model.Job{first.ID: first},
		Children: []GeneratedFragmentChild{{Key: first.Key, ID: first.ID}},
	}
	if _, _, err := st.InsertGeneratedFragmentTx(ctx, reqA, nil); err != nil {
		t.Fatalf("first fragment: %v", err)
	}

	second := pgITJob(runID, pgITNewID(t), pgITRepo)
	second.Key = "shared-child"
	reqB := GeneratedFragmentRequest{
		ParentJobID: parentB, RunnerID: leasedB.LeaseRunnerID, LeaseGeneration: leasedB.LeaseGeneration,
		LeaseTokenHash: leasedB.LeaseTokenHash, Depth: 1, FragmentID: "frag-b",
		Jobs:     map[string]model.Job{second.ID: second},
		Children: []GeneratedFragmentChild{{Key: second.Key, ID: second.ID}},
	}
	if _, _, err := st.InsertGeneratedFragmentTx(ctx, reqB, nil); !errors.Is(err, ErrGeneratedJobKeyConflict) {
		t.Fatalf("second parent same child key = %v, want ErrGeneratedJobKeyConflict", err)
	}
	if jobs, err := st.ListJobsByRun(ctx, runID); err != nil || len(jobs) != 3 {
		t.Fatalf("run jobs = %d, %v; want 3 (two parents + the first child only)", len(jobs), err)
	}
	if _, found, err := st.GetGeneratedFragment(ctx, parentB, GeneratedFragmentMutationSlotDefault); err != nil || found {
		t.Fatalf("rejected fragment receipt found=%v err=%v", found, err)
	}
}

// TestPostgresIntegrationUpgradeWithDuplicateRunKeysSkipsUniqueIndex builds a
// scratch database through v47, seeds the bug shape (two jobs with the same
// (run_id, key) under different ids), then runs the real Migrate: 0048 must
// succeed, skip jobs_run_key_idx (RAISE NOTICE only), and the generated-
// fragment admission must still reject a colliding key on that dirty
// database. A clean scratch database gets the index.
func TestPostgresIntegrationUpgradeWithDuplicateRunKeysSkipsUniqueIndex(t *testing.T) {
	env := pgITSetupAtVersion(t, 47)
	st := env.open(t)
	ctx := context.Background()

	runID := pgITNewID(t)
	if err := st.InsertRun(ctx, pgITRun(runID, model.StatusQueued)); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	const dupKey = "build[os=linux]"
	first, second := pgITJob(runID, pgITNewID(t), pgITRepo), pgITJob(runID, pgITNewID(t), pgITRepo)
	first.Key, second.Key = dupKey, dupKey
	if err := st.InsertJob(ctx, first); err != nil {
		t.Fatalf("seed first duplicate job: %v", err)
	}
	if err := st.InsertJob(ctx, second); err != nil {
		t.Fatalf("seed second duplicate job: %v", err)
	}

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate over duplicate (run_id,key) rows: %v", err)
	}
	if v, err := st.SchemaVersion(ctx); err != nil || v != pgITLatestVersion(t) {
		t.Fatalf("SchemaVersion = %d, %v; want %d", v, err, pgITLatestVersion(t))
	}
	if pgITIndexExists(t, st, "jobs_run_key_idx") {
		t.Fatal("jobs_run_key_idx must be skipped on a database with duplicate (run_id,key) rows")
	}

	// The admission rule stays authoritative on the dirty database: lease the
	// first duplicate as the parent and submit a child with the same key.
	runnerID := pgITNewID(t)
	leased, err := st.AcquireLease(ctx, first.ID, runnerID, []byte("upgrade-run-key"), 1, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("AcquireLease: %v", err)
	}
	child := pgITJob(runID, pgITNewID(t), pgITRepo)
	child.Key = dupKey
	req := GeneratedFragmentRequest{
		ParentJobID: first.ID, RunnerID: leased.LeaseRunnerID, LeaseGeneration: leased.LeaseGeneration,
		LeaseTokenHash: leased.LeaseTokenHash, Depth: 1, FragmentID: "frag-upgrade-collision",
		Jobs:     map[string]model.Job{child.ID: child},
		Children: []GeneratedFragmentChild{{Key: child.Key, ID: child.ID}},
	}
	if _, _, err := st.InsertGeneratedFragmentTx(ctx, req, nil); !errors.Is(err, ErrGeneratedJobKeyConflict) {
		t.Fatalf("colliding fragment on dirty database = %v, want ErrGeneratedJobKeyConflict", err)
	}
	if _, err := st.GetJob(ctx, child.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected fragment leaked a job: %v", err)
	}

	// A clean scratch database DOES get the conditional index.
	fresh := pgITStore(t)
	if !pgITIndexExists(t, fresh, "jobs_run_key_idx") {
		t.Fatal("jobs_run_key_idx missing on a clean database")
	}
}
