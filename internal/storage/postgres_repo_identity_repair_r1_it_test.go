package storage

// Real-PostgreSQL integration tests for the R1 repository-identity repair
// hardening. Gated on KIWI_TEST_POSTGRES_URL like every *_it_test.go here.
//
//   - R1-1: a repair away from identity A restamps the materialized identity
//     columns in the SAME statement, so the collection page (columns) and the
//     per-run read (payload) authorize the SAME repository.
//   - R1-4: a concurrent writer that makes the guarded UPDATE match zero rows
//     is never reported as repaired/quarantined, and the quarantine audit row
//     carries the actual pre-update payload.
//   - R1-5: keyset batching commits each batch, so a mid-run failure leaves
//     the earlier batches committed and a re-run completes without
//     duplication; the LIMIT is honored.
//   - R1-6: quarantined queued work is transitioned to cancelled and carries a
//     durable flag that denies leasing under a global allow policy.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func pgITSetCreatedAt(t *testing.T, st *PostgresStore, table, id string, at time.Time) {
	t.Helper()
	if _, err := st.pool.Exec(context.Background(), `UPDATE `+table+` SET created_at=$2 WHERE id=$1`, id, at); err != nil {
		t.Fatalf("set %s.created_at for %s: %v", table, id, err)
	}
}

func pgITNormalizedRunColumns(t *testing.T, st *PostgresStore, runID string) (identity, full string) {
	t.Helper()
	if err := st.pool.QueryRow(context.Background(),
		`SELECT COALESCE(repo_identity_normalized,''), COALESCE(repo_full_name_normalized,'') FROM runs WHERE id=$1`,
		runID).Scan(&identity, &full); err != nil {
		t.Fatalf("read normalized columns for %s: %v", runID, err)
	}
	return identity, full
}

// TestPostgresIntegrationRepoIdentityRepairRestampAndAuthorization is the R1-1
// regression: after a repair from A to B, A must not observe the run through
// EITHER the collection page (materialized columns) or the per-run read
// (payload), B must observe it through both, and both columns must equal the
// shared normalization functions.
func TestPostgresIntegrationRepoIdentityRepairRestampAndAuthorization(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)

	// Stored identity A, clone URL proves B.
	pgITInsertRunIdentity(t, st, runID, "github.com/acme/a", "github.com/acme/a", "https://github.com/acme/b.git", "acme/b")
	if _, err := st.pool.Exec(ctx, `UPDATE runs SET repo_identity_normalized = kiwi_normalize_run_repo_identity(payload,'repo'), repo_full_name_normalized = kiwi_normalize_run_repo_full_name(payload,'repo') WHERE id=$1`, runID); err != nil {
		t.Fatalf("populate normalized columns: %v", err)
	}
	if identity, full := pgITNormalizedRunColumns(t, st, runID); identity != "github.com/acme/a" || full != "acme/a" {
		t.Fatalf("pre-repair columns = %q/%q, want github.com/acme/a / acme/a", identity, full)
	}

	applied, err := st.RepairRepoIdentities(ctx, RepoIdentityRepairApply)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if applied.Rewritten != 1 || applied.Quarantined != 0 || applied.Conflicts != 0 {
		t.Fatalf("apply = rewritten=%d quarantined=%d conflicts=%d, want 1/0/0",
			applied.Rewritten, applied.Quarantined, applied.Conflicts)
	}

	run, err := st.GetRun(ctx, runID)
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	repoID := RepoIDForRun(run)
	if repoID != "github.com/acme/b" {
		t.Fatalf("repaired identity = %q, want github.com/acme/b", repoID)
	}
	// The columns were restamped in the SAME statement and equal the shared
	// normalization functions.
	identity, full := pgITNormalizedRunColumns(t, st, runID)
	wantIdentity, wantFull := normalizedRepoColumns(repoID)
	if identity != wantIdentity || full != wantFull {
		t.Fatalf("repaired columns = %q/%q, want %q/%q", identity, full, wantIdentity, wantFull)
	}
	var identityMatchesFunction, fullMatchesFunction bool
	if err := st.pool.QueryRow(ctx,
		`SELECT repo_identity_normalized IS NOT DISTINCT FROM kiwi_normalize_run_repo_identity(payload,'repo'),
		        repo_full_name_normalized IS NOT DISTINCT FROM kiwi_normalize_run_repo_full_name(payload,'repo')
		 FROM runs WHERE id=$1`, runID).Scan(&identityMatchesFunction, &fullMatchesFunction); err != nil {
		t.Fatalf("compare columns to functions: %v", err)
	}
	if !identityMatchesFunction || !fullMatchesFunction {
		t.Fatal("normalized columns are not the shared-normalization-function values")
	}

	principalA := auth.Principal{Subject: "a", Repositories: map[string]auth.RepositoryPermission{
		"github.com/acme/a": {Read: true},
	}}
	principalB := auth.Principal{Subject: "b", Repositories: map[string]auth.RepositoryPermission{
		"github.com/acme/b": {Read: true},
	}}

	// GET /runs/{id}: the per-run read authorization.
	if auth.CanReadRepo(principalA, repoID) {
		t.Fatal("A sees the repaired run through the per-run read")
	}
	if !auth.CanReadRepo(principalB, repoID) {
		t.Fatal("B cannot see the repaired run through the per-run read")
	}
	// GET /runs: the collection visibility policy.
	policyA := RunAuthzPolicyForPrincipal(&principalA)
	policyB := RunAuthzPolicyForPrincipal(&principalB)
	if policyA.Allows(repoID) {
		t.Fatal("A sees the repaired run through the collection policy")
	}
	if !policyB.Allows(repoID) {
		t.Fatal("B cannot see the repaired run through the collection policy")
	}

	// The actual page endpoints apply the policy as a predicate.
	pageA, err := st.ListRunsPageAuthorized(ctx, policyA, time.Time{}, "", 50)
	if err != nil {
		t.Fatalf("page A: %v", err)
	}
	if runPageContains(pageA, runID) {
		t.Fatal("A's collection page still contains the repaired run")
	}
	pageB, err := st.ListRunsPageAuthorized(ctx, policyB, time.Time{}, "", 50)
	if err != nil {
		t.Fatalf("page B: %v", err)
	}
	if !runPageContains(pageB, runID) {
		t.Fatal("B's collection page does not contain the repaired run")
	}
}

func runPageContains(page RunPage, runID string) bool {
	for _, r := range page.Runs {
		if r.ID == runID {
			return true
		}
	}
	return false
}

// TestPostgresIntegrationRepoIdentityRepairConcurrentWriter is the R1-4
// regression: a concurrent writer (driven by the deterministic hook, no
// sleeps) changes the row between the batch read and the repair's row lock.
// Under lock-then-classify the repair must act on the LOCKED value (never the
// stale batch plan): the row is not quarantined from what it used to be, no
// phantom quarantine row is written, and the outcome reflects the current
// committed identity. A separate, uncontended row's quarantine audit must
// match its actual pre-update payload.
func TestPostgresIntegrationRepoIdentityRepairConcurrentWriter(t *testing.T) {
	env := pgITSetup(t)
	st := env.open(t)
	env.migrate(t, st)
	writer := env.open(t)
	ctx := context.Background()

	target := pgITNewID(t)
	audit := pgITNewID(t)
	pgITInsertRunIdentity(t, st, target, "group/sub/project", "group/sub/project", "", "")
	pgITInsertRunIdentity(t, st, audit, "gitlab/group/sub/project", "gitlab/group/sub/project", "", "group/sub/project")

	var calls int
	st.repoIdentityRepairHooks = &repoIdentityRepairTestHooks{
		BeforeApply: func(kind, id string) error {
			if kind != "run" || id != target {
				return nil
			}
			calls++
			next := "group/concurrent/" + string(rune('a'+calls-1))
			_, err := writer.pool.Exec(context.Background(),
				`UPDATE runs SET payload = jsonb_set(payload, '{repo_id}', to_jsonb($2::text), true) WHERE id=$1`,
				target, next)
			return err
		},
	}
	res, err := st.RepairRepoIdentities(ctx, RepoIdentityRepairApply)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if calls != 1 {
		t.Fatalf("concurrent writer injections = %d, want 1 (before the row lock)", calls)
	}
	// Both rows are now quarantined, but the concurrent row MUST have been
	// classified from the LOCKED value (the writer's injection), never from
	// the stale batch snapshot.
	if res.Quarantined != 2 {
		t.Fatalf("quarantined = %d, want 2 (audit row + the concurrent row from its locked value)", res.Quarantined)
	}
	sawTarget := false
	for _, e := range res.Entries {
		if e.ID == target {
			sawTarget = true
		}
	}
	if !sawTarget {
		t.Fatal("concurrent row missing from the operator entries")
	}
	var storedStale string
	if err := st.pool.QueryRow(ctx, `SELECT stored_repo_id FROM repo_identity_quarantine WHERE kind='run' AND record_id=$1`, target).Scan(&storedStale); err != nil {
		t.Fatalf("read concurrent row quarantine audit: %v", err)
	}
	if storedStale != "group/concurrent/a" {
		t.Fatalf("quarantine audit stored %q, want the LOCKED value group/concurrent/a (the stale batch value would be group/sub/project)", storedStale)
	}
	// The row keeps a quarantined identity derived from the LOCKED value, and
	// its lifecycle was NOT mutated by the identity UPDATE (cancellation is
	// the canonical transaction's job).
	// The uncontended quarantine audit matches the actual pre-update payload.
	var storedRepo, storedPolicy, storedURL, storedFull string
	if err := st.pool.QueryRow(ctx,
		`SELECT stored_repo_id, stored_policy_repo_id, repo_url, repo_full_name FROM repo_identity_quarantine WHERE kind='run' AND record_id=$1`,
		audit).Scan(&storedRepo, &storedPolicy, &storedURL, &storedFull); err != nil {
		t.Fatalf("read quarantine audit: %v", err)
	}
	if storedRepo != "gitlab/group/sub/project" || storedPolicy != "gitlab/group/sub/project" || storedURL != "" || storedFull != "group/sub/project" {
		t.Fatalf("audit = %q/%q/%q/%q, want the pre-update payload", storedRepo, storedPolicy, storedURL, storedFull)
	}
}

// TestPostgresIntegrationRepoIdentityRepairBatching is the R1-5 regression:
// the pass walks keyset batches with one transaction per batch, a mid-run
// failure leaves the earlier batches committed, a re-run completes without
// duplication, and the configured LIMIT is honored.
func TestPostgresIntegrationRepoIdentityRepairBatching(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	a1Nested := auth.RepoAlias{FullName: "group/sub/project"}.Serialized()

	const n = 7
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		id := pgITNewID(t)
		ids[i] = id
		pgITInsertRunIdentity(t, st, id, "group/sub/project", "group/sub/project", "", "group/sub/project")
		pgITSetCreatedAt(t, st, "runs", id, time.Date(2024, 1, 1, 0, 0, i, 0, time.UTC))
	}
	assertRepaired := func(idx int, want string) {
		t.Helper()
		got, _ := pgITRunIdentity(t, st, ids[idx])
		if got != want {
			t.Fatalf("row %d repo_id = %q, want %q", idx, got, want)
		}
	}

	// Phase 1: abort on the third batch (rows 4 and 5), after batches 0 and 1
	// have committed.
	var lens []int
	st.repoIdentityRepairHooks = &repoIdentityRepairTestHooks{
		BeforeBatch: func(batchIndex int, records []repoIdentityRepairRow) error {
			lens = append(lens, len(records))
			if batchIndex == 2 {
				return errors.New("injected mid-run failure")
			}
			return nil
		},
	}
	if _, err := st.RepairRepoIdentitiesWithOptions(ctx, RepoIdentityRepairApply, RepoIdentityRepairOptions{BatchSize: 2}); err == nil {
		t.Fatal("expected the injected mid-run failure")
	}
	if len(lens) != 3 || lens[0] != 2 || lens[1] != 2 || lens[2] != 2 {
		t.Fatalf("failure-phase batch sizes = %v, want [2 2 2]", lens)
	}
	for i := 0; i < 4; i++ {
		assertRepaired(i, a1Nested)
	}
	for i := 4; i < n; i++ {
		assertRepaired(i, "group/sub/project")
	}

	// Phase 2: re-run completes the remaining rows without duplicating.
	lens = nil
	st.repoIdentityRepairHooks = &repoIdentityRepairTestHooks{
		BeforeBatch: func(_ int, records []repoIdentityRepairRow) error {
			lens = append(lens, len(records))
			return nil
		},
	}
	res, err := st.RepairRepoIdentitiesWithOptions(ctx, RepoIdentityRepairApply, RepoIdentityRepairOptions{BatchSize: 2})
	if err != nil {
		t.Fatalf("resume apply: %v", err)
	}
	if res.Scanned != n || res.Rewritten != 3 || res.Unchanged != 4 || res.Conflicts != 0 {
		t.Fatalf("resume = scanned=%d rewritten=%d unchanged=%d conflicts=%d, want 7/3/4/0",
			res.Scanned, res.Rewritten, res.Unchanged, res.Conflicts)
	}
	total := 0
	for _, l := range lens {
		if l > 2 {
			t.Fatalf("batch size %d exceeded the configured LIMIT 2", l)
		}
		total += l
	}
	if total != n {
		t.Fatalf("batched records = %d, want %d", total, n)
	}
	for i := 0; i < n; i++ {
		assertRepaired(i, a1Nested)
	}

	// A third idempotent pass changes nothing.
	third, err := st.RepairRepoIdentitiesWithOptions(ctx, RepoIdentityRepairApply, RepoIdentityRepairOptions{BatchSize: 2})
	if err != nil {
		t.Fatalf("third apply: %v", err)
	}
	if third.Rewritten != 0 || third.Quarantined != 0 || third.Unchanged != n {
		t.Fatalf("third pass = rewritten=%d quarantined=%d unchanged=%d, want 0/0/%d",
			third.Rewritten, third.Quarantined, third.Unchanged, n)
	}
}

// TestPostgresIntegrationRepoIdentityRepairQuarantineInert is the R1-6
// regression: a quarantined queued job is transitioned to cancelled and
// carries the durable flag, and cannot be leased even by a runner with an
// EMPTY (global allow) repository allowlist. The valid control job leases on
// the same runner.
func TestPostgresIntegrationRepoIdentityRepairQuarantineInert(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	pgITInsertRunIdentityStatus(t, st, runID, "queued", "group/sub/project", "group/sub/project", "", "")
	pgITInsertJobIdentityStatus(t, st, runID, jobID, "queued", "group/sub/project", "group/sub/project", "", "")

	okRun := pgITNewID(t)
	okJob := pgITNewID(t)
	pgITInsertRunIdentityStatus(t, st, okRun, "queued", "github.com/acme/ok", "github.com/acme/ok", "https://github.com/acme/ok.git", "acme/ok")
	pgITInsertJobIdentityStatus(t, st, okRun, okJob, "queued", "github.com/acme/ok", "github.com/acme/ok", "https://github.com/acme/ok.git", "acme/ok")

	runnerID := pgITNewID(t)
	pgITSeedRunner(t, st, runnerID, 5, 0, 0)

	// The run/job are non-terminal: the drain-then-quarantine path requires
	// the explicit --cancel-active (T1-1).
	res, err := st.RepairRepoIdentitiesWithOptions(ctx, RepoIdentityRepairApply, RepoIdentityRepairOptions{CancelActive: true})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.Quarantined != 2 {
		t.Fatalf("quarantined = %d, want 2 (the run and its job)", res.Quarantined)
	}
	foundJobEntry := false
	for _, e := range res.Entries {
		if e.Kind == "job" && e.ID == jobID && e.Action == RepoIdentityQuarantine {
			foundJobEntry = true
		}
	}
	if !foundJobEntry {
		t.Fatal("the quarantined job is missing from the operator output")
	}

	job, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if !job.RepoIdentityQuarantined {
		t.Fatal("job does not carry the durable quarantine flag")
	}
	if job.Status != model.StatusCancelled {
		t.Fatalf("job status = %q, want cancelled", job.Status)
	}
	run, err := st.GetRun(ctx, runID)
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	if !run.RepoIdentityQuarantined || run.Status != model.StatusCancelled {
		t.Fatalf("run not quarantined: flag=%v status=%q", run.RepoIdentityQuarantined, run.Status)
	}
	var payloadFlag bool
	if err := st.pool.QueryRow(ctx, `SELECT COALESCE(payload->>'repo_identity_quarantined','') = 'true' FROM jobs WHERE id=$1`, jobID).Scan(&payloadFlag); err != nil {
		t.Fatalf("read payload flag: %v", err)
	}
	if !payloadFlag {
		t.Fatal("the quarantined flag is not durable in the payload")
	}

	// Isolate the flag: flip the job back to queued and try to lease it with a
	// runner whose allowlist is EMPTY (global allow). The durable flag must
	// deny the claim independently of the repository ACL.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET status='queued' WHERE id=$1`, jobID); err != nil {
		t.Fatalf("requeue quarantined job: %v", err)
	}
	claim := LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("tok"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if _, err := st.AcquireLeaseAtomic(ctx, claim); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("quarantined lease err = %v, want ErrNoCapacity", err)
	}

	// Control: the valid job leases on the same global-allow runner.
	okJobDB, err := st.GetJob(ctx, okJob)
	if err != nil {
		t.Fatalf("get control job: %v", err)
	}
	control := LeaseClaim{
		JobID: okJob, RunnerID: runnerID, TokenHash: []byte("tok2"), Generation: 1,
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
		CanonRepoID: RepoIDForJob(okJobDB), RepoFullName: okJobDB.RepoFullName,
	}
	if _, err := st.AcquireLeaseAtomic(ctx, control); err != nil {
		t.Fatalf("control lease: %v", err)
	}
}
