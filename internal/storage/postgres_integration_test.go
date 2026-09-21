package storage

// Real-PostgreSQL integration tests for the storage package. They are gated
// on KIWI_TEST_POSTGRES_URL (skipped when the variable is unset, and in
// -short mode) so `go test ./...` stays hermetic without a database.
//
// Every test opens its own throwaway schema (kiwi_it_<random>) by setting
// search_path on the pool and DROP SCHEMA ... CASCADE on cleanup, so tests
// never share tables and never depend on local state. The exported store
// APIs under test are the same ones the control plane uses in production.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

const pgITRepo = "https://github.com/kiwi-it/repo.git"

// pgITRepoID is the canonical repository identity of pgITRepo: the identity
// migration keys quota reservations and counters by the canonical ID (with
// the repository URL only as a legacy fallback), so the tests derive the key
// through the same exported helpers the store uses.
var pgITRepoID = CanonicalRepoID(RepoHost(pgITRepo), "kiwi-it/repo")

// pgITDSN returns the integration DSN or skips the test.
func pgITDSN(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("postgres integration tests skipped in -short mode")
	}
	dsn := strings.TrimSpace(os.Getenv("KIWI_TEST_POSTGRES_URL"))
	if dsn == "" {
		t.Skip("KIWI_TEST_POSTGRES_URL not set; skipping PostgreSQL integration tests")
	}
	return dsn
}

// pgITLatestVersion returns the newest embedded migration version, so
// version-pinning tests track the migration set instead of a stale literal.
func pgITLatestVersion(t *testing.T) int {
	t.Helper()
	all, err := migrations.All()
	if err != nil {
		t.Fatalf("migrations.All: %v", err)
	}
	return all[len(all)-1].Version
}

// pgITRandomHex returns n random lowercase hex characters.
func pgITRandomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random bytes: %v", err)
	}
	return hex.EncodeToString(b)[:n]
}

// pgITNewID returns a canonical 32-hex-char ID accepted by ValidateID.
func pgITNewID(t *testing.T) string {
	t.Helper()
	return pgITRandomHex(t, 32)
}

// pgITEnv owns one per-test schema and can open additional pools on it (used
// to exercise concurrent stores/instances over the same tables).
type pgITEnv struct {
	base   string
	schema string
}

// pgITSetup creates the throwaway schema and registers its teardown.
func pgITSetup(t *testing.T) *pgITEnv {
	t.Helper()
	base := pgITDSN(t)
	schema := "kiwi_it_" + pgITRandomHex(t, 12)
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect to KIWI_TEST_POSTGRES_URL: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create schema %s: %v", schema, err)
	}
	if err := admin.Close(ctx); err != nil {
		t.Fatalf("close admin connection: %v", err)
	}
	t.Cleanup(func() {
		cctx := context.Background()
		c, cerr := pgx.Connect(cctx, base)
		if cerr != nil {
			t.Logf("drop schema %s: connect: %v", schema, cerr)
			return
		}
		defer func() { _ = c.Close(cctx) }()
		if _, err := c.Exec(cctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Logf("drop schema %s: %v", schema, err)
		}
	})
	return &pgITEnv{base: base, schema: schema}
}

// open opens one pool bound to the test schema (search_path) and closes it
// on cleanup before the schema is dropped.
func (e *pgITEnv) open(t *testing.T) *PostgresStore {
	t.Helper()
	schema := e.schema
	st, err := NewPostgresOpt(context.Background(), e.base, func(c *pgxpool.Config) {
		if c.ConnConfig.RuntimeParams == nil {
			c.ConnConfig.RuntimeParams = map[string]string{}
		}
		c.ConnConfig.RuntimeParams["search_path"] = schema
	})
	if err != nil {
		t.Fatalf("open store on schema %s: %v", schema, err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// migrate applies the embedded migrations to the test schema through the
// real PostgresStore.Migrate (bootstrap included: migration 0001 creates
// schema_migrations on the fresh schema).
func (e *pgITEnv) migrate(t *testing.T, st *PostgresStore) {
	t.Helper()
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

// pgITArmFence makes st present the durable current leadership epoch, so
// leader-fenced store operations are admissible (a real leader's store
// retains exactly this value from its own acquisition). The helper does NOT
// take the database-wide leadership advisory lock: that lock is shared by
// every test schema in the process and taking it in every test would
// serialize unrelated integration tests behind each other. Presenting the
// current epoch is the whole fence contract; tests that exercise acquisition
// itself use TryAcquireLeadership directly.
func pgITArmFence(t *testing.T, st *PostgresStore) int64 {
	t.Helper()
	epoch, err := st.ReadLeaderEpoch(context.Background())
	if err != nil {
		t.Fatalf("read leader epoch: %v", err)
	}
	st.SetLeaderEpoch(epoch)
	return epoch
}

// pgITStore returns a migrated store on a fresh schema that presents the
// durable current leadership epoch, so leader-fenced operations run without
// every test restating the arm. Tests that need a standby (or exercise
// acquisition contention) open a raw store instead.
func pgITStore(t *testing.T) *PostgresStore {
	t.Helper()
	env := pgITSetup(t)
	st := env.open(t)
	env.migrate(t, st)
	pgITArmFence(t, st)
	return st
}

// pgITSeedRunner upserts a runner with the given capacity and rates.
func pgITSeedRunner(t *testing.T, st *PostgresStore, runnerID string, capacity int, cost, watts float64) {
	t.Helper()
	if err := st.UpsertRunner(context.Background(), model.Runner{ID: runnerID, Name: runnerID, Capacity: capacity, CostPerHour: cost, PowerWatts: watts}); err != nil {
		t.Fatalf("upsert runner %s: %v", runnerID, err)
	}
}

// pgITJob builds a minimal queued job.
func pgITJob(runID, jobID, repo string) model.Job {
	return model.Job{ID: jobID, RunID: runID, Key: "build", RepoURL: repo, RepoFullName: "kiwi-it/repo", Status: model.StatusQueued, CreatedAt: time.Now().UTC()}
}

// pgITEnqueueOne enqueues one run with one job through the atomic enqueue.
func pgITEnqueueOne(t *testing.T, st *PostgresStore, runID, jobID, repo string) {
	t.Helper()
	req := InsertCompiledRunRequest{
		Run:  model.Run{ID: runID, Repo: repo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{jobID: pgITJob(runID, jobID, repo)},
	}
	if err := st.InsertCompiledRun(context.Background(), req); err != nil {
		t.Fatalf("enqueue %s/%s: %v", runID, jobID, err)
	}
}

func TestPostgresIntegrationMigrateAndSchemaVersion(t *testing.T) {
	st := pgITStore(t)
	all, err := migrations.All()
	if err != nil {
		t.Fatalf("migrations.All: %v", err)
	}
	want := all[len(all)-1].Version
	v, err := st.SchemaVersion(context.Background())
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v != want {
		t.Fatalf("SchemaVersion = %d, want %d", v, want)
	}
	// Migrate is idempotent against the real database.
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if v2, err := st.SchemaVersion(context.Background()); err != nil || v2 != want {
		t.Fatalf("SchemaVersion after re-migrate = %d, %v; want %d", v2, err, want)
	}
}

// TestPostgresIntegrationMigrateFreshDatabase proves Migrate bootstraps a
// completely FRESH database: migration 0001 itself creates schema_migrations,
// so a scratch schema cannot expose a bootstrap defect (and a pre-created
// schema_migrations would mask it). The test owns a dedicated database on the
// local server, asserts version 0 before the first Migrate, then applies
// Migrate TWICE and asserts the final SchemaVersion equals the last embedded
// migration both times (idempotency).
func TestPostgresIntegrationMigrateFreshDatabase(t *testing.T) {
	base := pgITDSN(t)
	ctx := context.Background()
	dbName := "kiwi_mig_" + pgITRandomHex(t, 12)
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{dbName}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create database %s: %v", dbName, err)
	}
	if err := admin.Close(ctx); err != nil {
		t.Fatalf("close admin connection: %v", err)
	}
	// FORCE disconnects any leftover backend before dropping the database.
	t.Cleanup(func() {
		cctx := context.Background()
		c, cerr := pgx.Connect(cctx, base)
		if cerr != nil {
			t.Logf("drop database %s: connect: %v", dbName, cerr)
			return
		}
		defer func() { _ = c.Close(cctx) }()
		if _, err := c.Exec(cctx, `DROP DATABASE IF EXISTS `+pgx.Identifier{dbName}.Sanitize()+` WITH (FORCE)`); err != nil {
			t.Logf("drop database %s: %v", dbName, err)
		}
	})

	cfg, err := pgxpool.ParseConfig(base)
	if err != nil {
		t.Fatalf("parse base dsn: %v", err)
	}
	cfg.ConnConfig.Database = dbName
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open pool on %s: %v", dbName, err)
	}
	st := NewPostgresFromPool(pool)
	defer func() { _ = st.Close() }()

	all, err := migrations.All()
	if err != nil {
		t.Fatalf("migrations.All: %v", err)
	}
	want := all[len(all)-1].Version
	if v, err := st.SchemaVersion(ctx); err != nil || v != 0 {
		t.Fatalf("fresh SchemaVersion = %d err=%v, want 0", v, err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("first Migrate on fresh database: %v", err)
	}
	if v, err := st.SchemaVersion(ctx); err != nil || v != want {
		t.Fatalf("SchemaVersion after first Migrate = %d err=%v, want %d", v, err, want)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate (idempotency): %v", err)
	}
	if v, err := st.SchemaVersion(ctx); err != nil || v != want {
		t.Fatalf("SchemaVersion after second Migrate = %d err=%v, want %d", v, err, want)
	}
	// Every embedded migration is recorded exactly once and the schema is
	// usable: the enqueue path writes against the bootstrap-created tables.
	if n, err := st.OutboxPending(ctx); err != nil || len(n) != 0 {
		t.Fatalf("fresh schema not usable: pending=%d err=%v", len(n), err)
	}
}

// TestPostgresIntegrationInsertCompiledRun exercises the full atomic enqueue
// (run + jobs + dependency edges + artifact contracts + quota reservation +
// webhook claim + supersede policy with runner-slot release) and proves the
// rollback on injected conflicts leaves zero rows behind.
func TestPostgresIntegrationInsertCompiledRun(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo := pgITRepo

	oldRun := pgITNewID(t)
	oldQueued := pgITNewID(t)
	oldRunning := pgITNewID(t)
	runner := pgITNewID(t)
	depRun := pgITNewID(t)
	depJob := pgITNewID(t)

	oldReq := InsertCompiledRunRequest{
		Run: model.Run{ID: oldRun, Repo: repo, ConcurrencyGroup: "grp", Status: model.StatusRunning, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{
			oldQueued:  pgITJob(oldRun, oldQueued, repo),
			oldRunning: pgITJob(oldRun, oldRunning, repo),
		},
		Quota:        &QuotaReservation{RepoKey: pgITRepoID, JobCount: 2},
		WebhookClaim: &WebhookClaim{Forge: "github", DeliveryID: "del-old", RunID: oldRun},
	}
	if err := st.InsertCompiledRun(ctx, oldReq); err != nil {
		t.Fatalf("seed superseded run: %v", err)
	}
	pgITSeedRunner(t, st, runner, 1, 0, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: oldRunning, RunnerID: runner, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 1}); err != nil {
		t.Fatalf("lease superseded job: %v", err)
	}
	// A dependent in another run, gated on the superseded job's success.
	if err := st.InsertRun(ctx, model.Run{ID: depRun, Repo: repo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	dep := pgITJob(depRun, depJob, repo)
	dep.Condition = "success()"
	dep.Needs = []string{oldQueued}
	if err := st.InsertJob(ctx, dep); err != nil {
		t.Fatal(err)
	}

	newRun := pgITNewID(t)
	newJob := pgITNewID(t)
	contracts := map[string]ArtifactContract{"dist": {Name: "dist", Paths: []string{"out/"}, Required: true, Retention: time.Hour}}
	next := InsertCompiledRunRequest{
		Run:       model.Run{ID: newRun, Repo: repo, ConcurrencyGroup: "grp", Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs:      map[string]model.Job{newJob: pgITJob(newRun, newJob, repo)},
		Deps:      map[string][]string{newJob: {}},
		Contracts: map[string]map[string]ArtifactContract{newJob: contracts},
		Supersede: &SupersedePolicy{RepoID: pgITRepoID, ConcurrencyGroup: "grp"},
		Quota:     &QuotaReservation{RepoKey: pgITRepoID, JobCount: 1},
		WebhookClaim: &WebhookClaim{
			Forge: "github", DeliveryID: "del-new", RunID: newRun,
		},
	}
	if err := st.InsertCompiledRun(ctx, next); err != nil {
		t.Fatalf("atomic enqueue (supersede policy): %v", err)
	}

	// The new run, its job (with authoritative empty deps) and contracts
	// committed together with the delivery claim.
	if run, err := st.GetRun(ctx, newRun); err != nil || run.Status != model.StatusQueued {
		t.Fatalf("new run = %+v err=%v", run, err)
	}
	j, err := st.GetJob(ctx, newJob)
	if err != nil {
		t.Fatalf("new job: %v", err)
	}
	if len(j.Needs) != 0 {
		t.Fatalf("Deps entry was not authoritative: needs=%v", j.Needs)
	}
	got, ok, err := st.GetJobContracts(ctx, newJob)
	if err != nil || !ok || !got["dist"].Required || got["dist"].Name != "dist" {
		t.Fatalf("contracts = %v ok=%v err=%v", got, ok, err)
	}
	if _, found, err := st.FindDelivery(ctx, "github", "del-new"); err != nil || !found {
		t.Fatalf("delivery claim missing: found=%v err=%v", found, err)
	}

	// Supersession cancelled the old run, its jobs and released the running
	// job's runner slot and quota slot in the same commit.
	for _, id := range []string{oldQueued, oldRunning} {
		j, err := st.GetJob(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if j.Status != model.StatusCancelled || !strings.Contains(j.Error, "superseded by run "+newRun) {
			t.Fatalf("superseded job %s = %s/%q", id, j.Status, j.Error)
		}
		if j.LeaseRunnerID != "" || j.LeaseTokenHash != nil || j.LeaseExpiresAt != nil {
			t.Fatalf("superseded job %s kept lease state: %+v", id, j)
		}
	}
	if prev, err := st.GetRun(ctx, oldRun); err != nil || prev.Status != model.StatusCancelled || prev.FinishedAt == nil {
		t.Fatalf("superseded run = %+v err=%v", prev, err)
	}
	if ri, err := st.GetRunner(ctx, runner); err != nil {
		t.Fatalf("runner after supersession: %v", err)
	} else if len(ri.ActiveJobs) != 0 || ri.Busy || ri.CurrentJob != "" {
		t.Fatalf("runner after supersession = %+v err=%v, want released slot", ri, err)
	}
	running, queued, err := st.QuotaCounts(ctx, pgITRepoID, "")
	if err != nil {
		t.Fatal(err)
	}
	if running != 0 || queued != 1 {
		t.Fatalf("quota after supersession = %d/%d, want 0/1 (successor only)", running, queued)
	}
	// The supersession audit trail is durable.
	audit, err := st.ReadAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	supersededAudits := 0
	for _, e := range audit {
		if e.Action == "job.superseded" {
			supersededAudits++
		}
	}
	if supersededAudits != 2 {
		t.Fatalf("job.superseded audits = %d, want 2", supersededAudits)
	}
	// The superseded job's dependent was recomputed to blocked.
	if d, err := st.GetJob(ctx, depJob); err != nil || d.Status != model.StatusBlocked || d.DependencyStatus != model.StatusCancelled {
		t.Fatalf("dependent = %+v err=%v, want blocked/cancelled", d, err)
	}

	// Injected conflict 1: a replayed delivery ID rolls the whole enqueue
	// back with no partial rows (quota included).
	dupRun := pgITNewID(t)
	dupJob := pgITNewID(t)
	dup := InsertCompiledRunRequest{
		Run:          model.Run{ID: dupRun, Repo: repo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs:         map[string]model.Job{dupJob: pgITJob(dupRun, dupJob, repo)},
		Quota:        &QuotaReservation{RepoKey: pgITRepoID, JobCount: 1},
		WebhookClaim: &WebhookClaim{Forge: "github", DeliveryID: "del-new", RunID: dupRun},
	}
	if err := st.InsertCompiledRun(ctx, dup); !errors.Is(err, ErrDeliveryDuplicate) {
		t.Fatalf("replayed delivery = %v, want ErrDeliveryDuplicate", err)
	}
	if _, err := st.GetRun(ctx, dupRun); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replayed enqueue leaked a run: %v", err)
	}
	if _, err := st.GetJob(ctx, dupJob); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replayed enqueue leaked a job: %v", err)
	}
	if running, queued, err = st.QuotaCounts(ctx, pgITRepoID, ""); err != nil || running != 0 || queued != 1 {
		t.Fatalf("quota after rollback = %d/%d err=%v, want 0/1", running, queued, err)
	}

	// Injected conflict 2: crossing the queue-depth limit inside the
	// transaction rolls back run, jobs and reservation atomically.
	overRun := pgITNewID(t)
	overJob := pgITNewID(t)
	over := InsertCompiledRunRequest{
		Run:   model.Run{ID: overRun, Repo: repo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs:  map[string]model.Job{overJob: pgITJob(overRun, overJob, repo)},
		Quota: &QuotaReservation{RepoKey: pgITRepoID, JobCount: 1, RepoQueueDepth: 1},
	}
	err = st.InsertCompiledRun(ctx, over)
	var qe *QuotaExceededError
	if !errors.As(err, &qe) || qe.Reason != "REPO_QUOTA" {
		t.Fatalf("over-quota enqueue = %v, want REPO_QUOTA", err)
	}
	if _, err := st.GetRun(ctx, overRun); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected enqueue leaked a run: %v", err)
	}
	if running, queued, err = st.QuotaCounts(ctx, pgITRepoID, ""); err != nil || running != 0 || queued != 1 {
		t.Fatalf("quota after limit rollback = %d/%d err=%v, want 0/1", running, queued, err)
	}
}

// TestPostgresIntegrationAcquireLeaseAtomicConcurrency proves the atomic
// claim has exactly one winner under concurrent claims of one job.
func TestPostgresIntegrationAcquireLeaseAtomicConcurrency(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)

	const claims = 8
	runners := make([]string, claims)
	for i := range runners {
		runners[i] = pgITNewID(t)
		pgITSeedRunner(t, st, runners[i], 1, 0, 0)
	}
	type outcome struct {
		runner int
		err    error
	}
	results := make(chan outcome, claims)
	var wg sync.WaitGroup
	for i := 0; i < claims; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runners[i], TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 1})
			results <- outcome{i, err}
		}(i)
	}
	wg.Wait()
	close(results)
	winners := []int{}
	for r := range results {
		switch {
		case r.err == nil:
			winners = append(winners, r.runner)
		case errors.Is(r.err, ErrLeaseConflict), errors.Is(r.err, ErrNoCapacity):
		default:
			t.Fatalf("unexpected concurrent claim error: %v", r.err)
		}
	}
	if len(winners) != 1 {
		t.Fatalf("concurrent claims produced %d winners, want exactly 1", len(winners))
	}
	j, err := st.GetJob(ctx, jobID)
	if err != nil || j.Status != model.StatusRunning || j.LeaseRunnerID != runners[winners[0]] {
		t.Fatalf("leased job = %+v err=%v", j, err)
	}
	active := 0
	for _, id := range runners {
		ri, err := st.GetRunner(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		active += len(ri.ActiveJobs)
	}
	if active != 1 {
		t.Fatalf("runner slots held = %d, want 1", active)
	}
}

// TestPostgresIntegrationAcquireLeaseAtomicAttemptsRates proves attempts
// increment once per claim, started_at is stamped on the first lease only,
// and the live runner rates are frozen into the job.
func TestPostgresIntegrationAcquireLeaseAtomicAttemptsRates(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID, runnerID := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)
	pgITSeedRunner(t, st, runnerID, 1, 2.5, 120)

	claim := LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 1}
	first, err := st.AcquireLeaseAtomic(ctx, claim)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if first.Attempts != 1 || first.StartedAt == nil {
		t.Fatalf("first claim attempts/started_at = %d/%v", first.Attempts, first.StartedAt)
	}
	if first.CostRate != 2.5 || first.PowerWatts != 120 {
		t.Fatalf("frozen rates = %v/%v, want 2.5/120", first.CostRate, first.PowerWatts)
	}
	originalStart := *first.StartedAt

	// Requeue and release the runner slot, then claim again: attempts grows,
	// started_at is preserved.
	first.Status = model.StatusQueued
	first.LeaseRunnerID = ""
	first.LeaseTokenHash = nil
	first.LeaseExpiresAt = nil
	if err := st.UpdateJob(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := st.ReleaseRunnerJob(ctx, runnerID, jobID, model.StatusFailure); err != nil {
		t.Fatalf("release runner job: %v", err)
	}
	claim.Generation = 2
	second, err := st.AcquireLeaseAtomic(ctx, claim)
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if second.Attempts != 2 {
		t.Fatalf("attempts after re-claim = %d, want 2", second.Attempts)
	}
	if second.StartedAt == nil || !second.StartedAt.Equal(originalStart) {
		t.Fatalf("started_at after re-claim = %v, want %v", second.StartedAt, originalStart)
	}
}

// TestPostgresIntegrationAcquireLeaseAtomicPredicates proves the SQL claim
// enforces disabled/draining, zero capacity, environment concurrency and the
// quota predicates without committing partial state.
func TestPostgresIntegrationAcquireLeaseAtomicPredicates(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	// disabled runner
	runA, jobA, disabled := pgITNewID(t), pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runA, jobA, pgITRepo)
	if err := st.UpsertRunner(ctx, model.Runner{ID: disabled, Capacity: 1, Disabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobA, RunnerID: disabled, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 1}); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("disabled runner claim = %v, want ErrNoCapacity", err)
	}
	if j, _ := st.GetJob(ctx, jobA); j.Status != model.StatusQueued || j.LeaseRunnerID != "" {
		t.Fatalf("rejected disabled claim mutated the job: %+v", j)
	}

	// draining runner
	draining := pgITNewID(t)
	if err := st.UpsertRunner(ctx, model.Runner{ID: draining, Capacity: 1, Draining: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobA, RunnerID: draining, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 1}); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("draining runner claim = %v, want ErrNoCapacity", err)
	}

	// capacity 0 means "take no work"
	zero := pgITNewID(t)
	pgITSeedRunner(t, st, zero, 0, 0, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobA, RunnerID: zero, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 0}); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("zero-capacity runner claim = %v, want ErrNoCapacity", err)
	}

	// environment concurrency 1: exactly one of two concurrent claims wins
	envRun := pgITNewID(t)
	envJobA, envJobB := pgITNewID(t), pgITNewID(t)
	envJobs := map[string]model.Job{}
	for _, id := range []string{envJobA, envJobB} {
		j := pgITJob(envRun, id, pgITRepo)
		j.Environment = "prod"
		j.EnvironmentConcurrency = 1
		envJobs[id] = j
	}
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  model.Run{ID: envRun, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: envJobs,
	}); err != nil {
		t.Fatal(err)
	}
	envRunnerA, envRunnerB := pgITNewID(t), pgITNewID(t)
	pgITSeedRunner(t, st, envRunnerA, 1, 0, 0)
	pgITSeedRunner(t, st, envRunnerB, 1, 0, 0)
	envResults := make(chan error, 2)
	var wg sync.WaitGroup
	for i, jobID := range []string{envJobA, envJobB} {
		runnerID := []string{envRunnerA, envRunnerB}[i]
		wg.Add(1)
		go func(jobID, runnerID string) {
			defer wg.Done()
			_, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 1, Environment: "prod", EnvironmentConcurrency: 1, CanonRepoID: pgITRepoID})
			envResults <- err
		}(jobID, runnerID)
	}
	wg.Wait()
	close(envResults)
	envWinners, envRejected := 0, 0
	for err := range envResults {
		switch {
		case err == nil:
			envWinners++
		case errors.Is(err, ErrEnvConcurrency):
			envRejected++
		case errors.Is(err, ErrLeaseConflict), errors.Is(err, ErrNoCapacity):
		default:
			t.Fatalf("environment claim error: %v", err)
		}
	}
	if envWinners != 1 || envRejected != 1 {
		t.Fatalf("environment-concurrency = %d winners/%d rejected, want 1 winner and 1 ErrEnvConcurrency", envWinners, envRejected)
	}
	// The environment winner holds a repo running-quota slot (unlimited in
	// this phase); release it so the quota phase below starts from zero.
	envStored, listErr := st.ListJobsByRun(ctx, envRun)
	if listErr != nil {
		t.Fatal(listErr)
	}
	for _, j := range envStored {
		if j.Status == model.StatusRunning {
			if err := st.ReleaseRunnerJob(ctx, j.LeaseRunnerID, j.ID, model.StatusFailure); err != nil {
				t.Fatalf("release environment winner: %v", err)
			}
		}
	}

	// quota concurrency 1: the conditional queued->running transition rejects
	// the second claim and leaves its job untouched.
	quotaRun := pgITNewID(t)
	quotaJobA, quotaJobB := pgITNewID(t), pgITNewID(t)
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run: model.Run{ID: quotaRun, Repo: pgITRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{
			quotaJobA: pgITJob(quotaRun, quotaJobA, pgITRepo),
			quotaJobB: pgITJob(quotaRun, quotaJobB, pgITRepo),
		},
	}); err != nil {
		t.Fatal(err)
	}
	quotaRunner := pgITNewID(t)
	pgITSeedRunner(t, st, quotaRunner, 2, 0, 0)
	baseClaim := LeaseClaim{RunnerID: quotaRunner, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 2, RepoConcurrency: 1}
	firstClaim := baseClaim
	firstClaim.JobID = quotaJobA
	if _, err := st.AcquireLeaseAtomic(ctx, firstClaim); err != nil {
		t.Fatalf("first quota claim: %v", err)
	}
	secondClaim := baseClaim
	secondClaim.JobID = quotaJobB
	_, err := st.AcquireLeaseAtomic(ctx, secondClaim)
	var qe *QuotaExceededError
	if !errors.As(err, &qe) || !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("second quota claim = %v, want *QuotaExceededError", err)
	}
	if j, _ := st.GetJob(ctx, quotaJobB); j.Status != model.StatusQueued || j.LeaseRunnerID != "" {
		t.Fatalf("rejected quota job mutated: %+v", j)
	}
	ri, err := st.GetRunner(ctx, quotaRunner)
	if err != nil || len(ri.ActiveJobs) != 1 {
		t.Fatalf("runner active jobs = %v err=%v, want only the winner", ri.ActiveJobs, err)
	}
}

// TestPostgresIntegrationCompleteJob proves the completion transaction:
// required-artifact verification inside the transaction, receipt idempotency,
// dependent recomputation, runner counters and quota release.
func TestPostgresIntegrationCompleteJob(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo := pgITRepo

	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	depID := pgITNewID(t)
	runnerID := pgITNewID(t)
	job := pgITJob(runID, jobID, repo)
	dep := pgITJob(runID, depID, repo)
	dep.Condition = "success()"
	dep.Needs = []string{jobID}
	contracts := map[string]map[string]ArtifactContract{jobID: {"dist": {Name: "dist", Required: true}}}
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:       model.Run{ID: runID, Repo: repo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs:      map[string]model.Job{jobID: job, depID: dep},
		Contracts: contracts,
		Quota:     &QuotaReservation{RepoKey: pgITRepoID, JobCount: 2},
	}); err != nil {
		t.Fatal(err)
	}
	pgITSeedRunner(t, st, runnerID, 1, 0, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 1}); err != nil {
		t.Fatal(err)
	}
	receipt := model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID, ResultHash: "hash-1"}

	// A success without the required artifact fails closed inside the
	// transaction: the job stays running and no counter moves.
	err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", nil, receipt)
	if !errors.Is(err, ErrRequiredArtifactMissing) {
		t.Fatalf("completion without required artifact = %v, want ErrRequiredArtifactMissing", err)
	}
	if j, _ := st.GetJob(ctx, jobID); j.Status != model.StatusRunning {
		t.Fatalf("job after rejected completion = %s, want running", j.Status)
	}
	if ri, _ := st.GetRunner(ctx, runnerID); len(ri.ActiveJobs) != 1 || ri.Completed != 0 {
		t.Fatalf("runner after rejected completion = active=%v completed=%d", ri.ActiveJobs, ri.Completed)
	}

	// With the artifact row present the completion commits: job terminal,
	// lease cleared, runner counters updated, dependent recomputed, quota
	// running slot released.
	artifact := model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, JobKey: job.Key, Name: "dist", Size: 3, SHA256: strings.Repeat("a", 64), CreatedAt: time.Now().UTC(), LeaseGeneration: 1}
	stored, created, err := st.InsertArtifactOnce(ctx, artifact)
	if err != nil || !created || stored.ID != artifact.ID {
		t.Fatalf("artifact insert = %+v created=%v err=%v", stored, created, err)
	}
	outputs := map[string]string{"out": "1"}
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", outputs, receipt); err != nil {
		t.Fatalf("completion: %v", err)
	}
	j, err := st.GetJob(ctx, jobID)
	if err != nil || j.Status != model.StatusSuccess || j.FinishedAt == nil || j.LeaseRunnerID != "" || j.LeaseTokenHash != nil {
		t.Fatalf("completed job = %+v err=%v", j, err)
	}
	if j.Outputs["out"] != "1" {
		t.Fatalf("outputs not persisted: %v", j.Outputs)
	}
	ri, err := st.GetRunner(ctx, runnerID)
	if err != nil || ri.Completed != 1 || ri.Failed != 0 || len(ri.ActiveJobs) != 0 || ri.Busy {
		t.Fatalf("runner after completion = %+v err=%v", ri, err)
	}
	d, err := st.GetJob(ctx, depID)
	if err != nil || d.DependencyStatus != model.StatusSuccess || d.Status != model.StatusQueued {
		t.Fatalf("dependent = %+v err=%v, want queued/success", d, err)
	}
	if running, queued, err := st.QuotaCounts(ctx, pgITRepoID, ""); err != nil || running != 0 || queued != 1 {
		t.Fatalf("quota after completion = %d/%d err=%v, want 0/1", running, queued, err)
	}

	// Receipt idempotency: the exact replay is acknowledged without moving
	// counters, and a mismatched generation fails closed.
	if err := st.CompleteJob(ctx, jobID, 1, runnerID, model.StatusSuccess, "", outputs, receipt); err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	ri, _ = st.GetRunner(ctx, runnerID)
	if ri.Completed != 1 {
		t.Fatalf("runner completed after replay = %d, want 1", ri.Completed)
	}
	if err := st.CompleteJob(ctx, jobID, 2, runnerID, model.StatusSuccess, "", outputs, model.CompletionReceipt{JobID: jobID, Generation: 2, RunnerID: runnerID}); !errors.Is(err, ErrGenerationMismatch) {
		t.Fatalf("mismatched generation replay = %v, want ErrGenerationMismatch", err)
	}
	if err := st.CompleteJob(ctx, jobID, 1, pgITNewID(t), model.StatusSuccess, "", outputs, model.CompletionReceipt{JobID: jobID, Generation: 1, RunnerID: runnerID}); err == nil {
		t.Fatal("mismatched runner completion must fail")
	}

	// Failure path: a separate run whose dependent needs success() gets
	// blocked, and the runner failure counter moves.
	failRun := pgITNewID(t)
	failJob := pgITNewID(t)
	failDep := pgITNewID(t)
	failRunner := pgITNewID(t)
	fjob := pgITJob(failRun, failJob, repo)
	fdep := pgITJob(failRun, failDep, repo)
	fdep.Condition = "success()"
	fdep.Needs = []string{failJob}
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  model.Run{ID: failRun, Repo: repo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{failJob: fjob, failDep: fdep},
	}); err != nil {
		t.Fatal(err)
	}
	pgITSeedRunner(t, st, failRunner, 1, 0, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: failJob, RunnerID: failRunner, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 1}); err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteJob(ctx, failJob, 1, failRunner, model.StatusFailure, "boom", nil, model.CompletionReceipt{JobID: failJob, Generation: 1, RunnerID: failRunner}); err != nil {
		t.Fatalf("failure completion: %v", err)
	}
	if d, _ := st.GetJob(ctx, failDep); d.Status != model.StatusBlocked || d.DependencyStatus != model.StatusFailure {
		t.Fatalf("dependent of failed job = %+v, want blocked/failure", d)
	}
	if fri, _ := st.GetRunner(ctx, failRunner); fri.Failed != 1 || fri.Completed != 0 {
		t.Fatalf("runner after failed completion = %+v", fri)
	}
	if r, _ := st.GetRun(ctx, failRun); r.Status != model.StatusFailure {
		t.Fatalf("run after failed job = %s, want failure", r.Status)
	}
	// The run stays non-terminal while its queued dependent is unfinished:
	// the terminal-success job plus an unstarted queued job recompute to
	// "queued" (mirroring recomputeRunStatus).
	if r, _ := st.GetRun(ctx, runID); r.Status != model.StatusQueued {
		t.Fatalf("run with a queued dependent = %s, want queued", r.Status)
	}
}

// TestPostgresIntegrationCancelRunJobs proves the cancellation transaction
// releases runner slots and quota slots and leaves terminal jobs alone.
func TestPostgresIntegrationCancelRunJobs(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo := pgITRepo
	runID := pgITNewID(t)
	jobQueued := pgITNewID(t)
	jobRunning := pgITNewID(t)
	runnerID := pgITNewID(t)
	otherRun := pgITNewID(t)
	otherJob := pgITNewID(t)

	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run: model.Run{ID: runID, Repo: repo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{
			jobQueued:  pgITJob(runID, jobQueued, repo),
			jobRunning: pgITJob(runID, jobRunning, repo),
		},
		Quota: &QuotaReservation{RepoKey: pgITRepoID, JobCount: 2},
	}); err != nil {
		t.Fatal(err)
	}
	// The unrelated run reserves its own quota slot: cancelling runID must
	// leave it untouched.
	if err := st.InsertCompiledRun(ctx, InsertCompiledRunRequest{
		Run:  model.Run{ID: otherRun, Repo: repo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs: map[string]model.Job{otherJob: pgITJob(otherRun, otherJob, repo)},
		Quota: &QuotaReservation{
			RepoKey: pgITRepoID, JobCount: 1,
		},
	}); err != nil {
		t.Fatalf("seed unrelated run: %v", err)
	}
	pgITSeedRunner(t, st, runnerID, 1, 0, 0)
	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobRunning, RunnerID: runnerID, TokenHash: []byte("h"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), RunnerCapacity: 1}); err != nil {
		t.Fatal(err)
	}

	ids, err := st.CancelRunJobs(ctx, runID, "cancelled by test")
	if err != nil {
		t.Fatalf("CancelRunJobs: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("cancelled ids = %v, want 2", ids)
	}
	for _, id := range ids {
		j, err := st.GetJob(ctx, id)
		if err != nil || j.Status != model.StatusCancelled || j.Error != "cancelled by test" {
			t.Fatalf("cancelled job %s = %+v err=%v", id, j, err)
		}
	}
	if r, err := st.GetRun(ctx, runID); err != nil || r.Status != model.StatusCancelled || r.FinishedAt == nil {
		t.Fatalf("cancelled run = %+v err=%v", r, err)
	}
	if ri, err := st.GetRunner(ctx, runnerID); err != nil || len(ri.ActiveJobs) != 0 || ri.Busy || ri.CurrentJob != "" {
		t.Fatalf("runner after cancel = %+v err=%v", ri, err)
	}
	if running, queued, err := st.QuotaCounts(ctx, pgITRepoID, ""); err != nil || running != 0 || queued != 1 {
		t.Fatalf("quota after cancel = %d/%d err=%v, want 0/1 (other run queued)", running, queued, err)
	}
	// Re-cancelling a terminal run is a no-op.
	again, err := st.CancelRunJobs(ctx, runID, "again")
	if err != nil || len(again) != 0 {
		t.Fatalf("second cancel = %v err=%v, want no ids", again, err)
	}
	// The unrelated run is untouched.
	if j, _ := st.GetJob(ctx, otherJob); j.Status != model.StatusQueued {
		t.Fatalf("unrelated job = %s, want queued", j.Status)
	}
	if r, _ := st.GetRun(ctx, otherRun); r.Status != model.StatusQueued {
		t.Fatalf("unrelated run = %s, want queued", r.Status)
	}
}

// TestPostgresIntegrationOutboxClaimDisjoint proves concurrent claimers with
// SKIP LOCKED never see the same outbox row, and acks remove claimed rows.
func TestPostgresIntegrationOutboxClaimDisjoint(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	ids := map[string]bool{}
	base := time.Now().UTC()
	for i := 0; i < 6; i++ {
		id := pgITNewID(t)
		ids[id] = true
		if err := st.OutboxAppend(ctx, OutboxItem{ID: id, Kind: "integration", Payload: []byte(fmt.Sprintf(`{"n":%d}`, i)), CreatedAt: base.Add(time.Duration(i) * time.Millisecond)}); err != nil {
			t.Fatal(err)
		}
	}
	// FIFO order is preserved by OutboxPending.
	pending, err := st.OutboxPending(ctx)
	if err != nil || len(pending) != 6 {
		t.Fatalf("pending = %d err=%v, want 6", len(pending), err)
	}
	for i := 1; i < len(pending); i++ {
		if pending[i].CreatedAt.Before(pending[i-1].CreatedAt) {
			t.Fatalf("pending not in FIFO order: %v then %v", pending[i-1].CreatedAt, pending[i].CreatedAt)
		}
	}

	type claimResult struct {
		claimer string
		items   []OutboxItem
		err     error
	}
	results := make(chan claimResult, 2)
	var wg sync.WaitGroup
	for _, claimer := range []string{"claimer-a", "claimer-b"} {
		wg.Add(1)
		go func(claimer string) {
			defer wg.Done()
			items, err := st.ClaimOutbox(ctx, claimer, 3)
			results <- claimResult{claimer, items, err}
		}(claimer)
	}
	wg.Wait()
	close(results)
	claimers := map[string]string{}
	var claimed []OutboxItem
	for r := range results {
		if r.err != nil {
			t.Fatalf("ClaimOutbox: %v", r.err)
		}
		for _, it := range r.items {
			if prev, dup := claimers[it.ID]; dup {
				t.Fatalf("outbox row %s claimed by both %s and a peer", it.ID, prev)
			}
			claimers[it.ID] = r.claimer
			claimed = append(claimed, it)
			if !ids[it.ID] {
				t.Fatalf("unexpected outbox item %s", it.ID)
			}
		}
	}
	if len(claimed) != 6 {
		t.Fatalf("claimed rows = %d, want 6 (disjoint union)", len(claimed))
	}
	// Claimed rows are skipped by a fresh claim until the TTL expires.
	if extra, err := st.ClaimOutbox(ctx, "claimer-c", 10); err != nil || len(extra) != 0 {
		t.Fatalf("claim after claims = %d err=%v, want 0", len(extra), err)
	}
	// Release makes an un-dispatched row immediately claimable again, and a
	// foreign claimer cannot release it.
	target := claimed[0].ID
	if err := st.ReleaseOutboxClaim(ctx, target, "someone-else"); err != nil {
		t.Fatal(err)
	}
	if extra, err := st.ClaimOutbox(ctx, "claimer-d", 10); err != nil || len(extra) != 0 {
		t.Fatalf("foreign release must be ignored: claimed=%d err=%v", len(extra), err)
	}
	if err := st.ReleaseOutboxClaim(ctx, target, claimers[target]); err != nil {
		t.Fatal(err)
	}
	again, err := st.ClaimOutbox(ctx, "claimer-e", 10)
	if err != nil || len(again) != 1 || again[0].ID != target {
		t.Fatalf("re-claim after release = %+v err=%v, want %s", again, err, target)
	}
	// Acking removes the rows for good.
	for _, it := range claimed {
		if err := st.OutboxAck(ctx, it.ID); err != nil {
			t.Fatalf("ack %s: %v", it.ID, err)
		}
	}
	if rest, err := st.OutboxPending(ctx); err != nil || len(rest) != 0 {
		t.Fatalf("pending after acks = %d err=%v, want 0", len(rest), err)
	}
}

// TestPostgresIntegrationArtifactInsertOnce proves the digest-arbitrated
// idempotent artifact insert against the real unique index.
func TestPostgresIntegrationArtifactInsertOnce(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITEnqueueOne(t, st, runID, jobID, pgITRepo)

	digestA := strings.Repeat("a", 64)
	first := model.ArtifactRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, JobKey: "build", Name: "bin", Size: 3, SHA256: digestA, CreatedAt: time.Now().UTC(), LeaseGeneration: 1}
	stored, created, err := st.InsertArtifactOnce(ctx, first)
	if err != nil || !created || stored.ID != first.ID {
		t.Fatalf("first insert = %+v created=%v err=%v", stored, created, err)
	}
	// A second replica staging the same (job, generation, name) with the same
	// digest gets the stored record and no second row.
	replay := first
	replay.ID = pgITNewID(t)
	replay.Size = 99
	stored, created, err = st.InsertArtifactOnce(ctx, replay)
	if err != nil || created {
		t.Fatalf("same-digest insert = %+v created=%v err=%v, want stored record", stored, created, err)
	}
	if stored.ID != first.ID || stored.Size != first.Size {
		t.Fatalf("stored record overwritten: %+v", stored)
	}
	// A different digest fails closed without mutating the stored row.
	conflict := first
	conflict.ID = pgITNewID(t)
	conflict.SHA256 = strings.Repeat("b", 64)
	if _, _, err := st.InsertArtifactOnce(ctx, conflict); !errors.Is(err, ErrArtifactDigestConflict) {
		t.Fatalf("digest conflict = %v, want ErrArtifactDigestConflict", err)
	}
	listed, err := st.ListArtifacts(ctx, runID)
	if err != nil || len(listed) != 1 {
		t.Fatalf("artifacts after conflict = %d err=%v, want 1", len(listed), err)
	}
	if listed[0].SHA256 != digestA || listed[0].ID != first.ID {
		t.Fatalf("stored artifact mutated: %+v", listed[0])
	}
}

// TestPostgresIntegrationPendingSidecars proves the pending-sidecar table
// round trip, digest-conditioned consumption and pruning.
func TestPostgresIntegrationPendingSidecars(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	jobID := pgITNewID(t)
	digest1 := strings.Repeat("1", 64)
	digest2 := strings.Repeat("2", 64)

	if err := st.RememberPendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM, digest1); err != nil {
		t.Fatalf("remember: %v", err)
	}
	got, ok, err := st.PendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM)
	if err != nil || !ok || got != digest1 {
		t.Fatalf("pending = %q ok=%v err=%v, want %s", got, ok, err, digest1)
	}
	// A re-upload replaces the digest; consuming the stale digest must not
	// remove the newer row.
	if err := st.RememberPendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM, digest2); err != nil {
		t.Fatal(err)
	}
	if err := st.ConsumePendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM, digest1); err != nil {
		t.Fatal(err)
	}
	if got, ok, _ := st.PendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM); !ok || got != digest2 {
		t.Fatalf("stale consume removed the newest digest: %q ok=%v", got, ok)
	}
	if err := st.ConsumePendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM, digest2); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.PendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM); ok {
		t.Fatal("consumed sidecar still present")
	}
	// Kind-scoped rows and job cleanup.
	if err := st.RememberPendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSigstore, digest1); err != nil {
		t.Fatal(err)
	}
	if err := st.RememberPendingSidecar(ctx, jobID, "other", ArtifactSidecarKindSBOM, digest2); err != nil {
		t.Fatal(err)
	}
	if err := st.DeletePendingSidecars(ctx, jobID); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.PendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSigstore); ok {
		t.Fatal("DeletePendingSidecars left a row behind")
	}
	// Pruning by age removes only older rows.
	if err := st.RememberPendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM, digest1); err != nil {
		t.Fatal(err)
	}
	if n, err := st.PrunePendingSidecars(ctx, time.Now().UTC().Add(-time.Hour)); err != nil || n != 0 {
		t.Fatalf("past cutoff pruned %d err=%v, want 0", n, err)
	}
	if n, err := st.PrunePendingSidecars(ctx, time.Now().UTC().Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("future cutoff pruned %d err=%v, want 1", n, err)
	}
	// Validation fails closed on malformed keys and digests.
	if err := st.RememberPendingSidecar(ctx, jobID, "bin", "not-a-kind", digest1); err == nil {
		t.Fatal("invalid sidecar kind accepted")
	}
	if err := st.RememberPendingSidecar(ctx, jobID, "bin", ArtifactSidecarKindSBOM, "short"); err == nil {
		t.Fatal("invalid sidecar digest accepted")
	}
}

// TestPostgresIntegrationLogIdentitySequences proves the identity sequence is
// allocated by the database: concurrent appends receive monotonic sequence
// numbers regardless of the caller-supplied Seq.
func TestPostgresIntegrationLogIdentitySequences(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	pgITEnqueueOne(t, st, runID, pgITNewID(t), pgITRepo)

	const writers, lines = 8, 8
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < lines; i++ {
				e := model.LogEntry{RunID: runID, JobKey: "build", Step: "run", Line: fmt.Sprintf("line-%d-%d", w, i), CreatedAt: time.Now().UTC()}
				e.Seq = 9999 // must be ignored in favor of the database identity
				if err := st.AppendLog(ctx, e); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("append log: %v", err)
	}
	entries, err := st.ReadLogs(ctx, runID, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != writers*lines {
		t.Fatalf("log entries = %d, want %d", len(entries), writers*lines)
	}
	distinct := map[string]bool{}
	for i, e := range entries {
		if e.Seq == 9999 {
			t.Fatalf("caller-supplied Seq leaked into the identity column: %+v", e)
		}
		if i > 0 && e.Seq <= entries[i-1].Seq {
			t.Fatalf("sequence not strictly increasing at %d: %d <= %d", i, e.Seq, entries[i-1].Seq)
		}
		if distinct[e.Line] {
			t.Fatalf("duplicate log line %q", e.Line)
		}
		distinct[e.Line] = true
	}
	// A cursor read returns only the tail.
	after := entries[len(entries)/2].Seq
	tail, err := st.ReadLogs(ctx, runID, after, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(tail) != len(entries)-len(entries)/2-1 {
		t.Fatalf("tail entries = %d, want %d", len(tail), len(entries)-len(entries)/2-1)
	}
	for _, e := range tail {
		if e.Seq <= after {
			t.Fatalf("cursor read returned seq %d <= %d", e.Seq, after)
		}
	}
}
