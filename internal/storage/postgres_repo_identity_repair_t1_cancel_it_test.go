package storage

// T1-6(b) live-PostgreSQL regression for the explicit --cancel-active drain.
// It is FAIL-before at HEAD at COMPILE time: RepoIdentityRepairOptions.
// CancelActive is the new opt-in this task adds, so the pre-fix source cannot
// build this file. The behavioral assertions below fail at runtime against a
// build that has the option but not the drain (see the report).

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func pgITSeedQuotaRunning(t *testing.T, st *PostgresStore, key string, running int) {
	t.Helper()
	if _, err := st.pool.Exec(context.Background(),
		`INSERT INTO quota_reservations (key, running, queued) VALUES ($1,$2,0) ON CONFLICT (key) DO UPDATE SET running=$2, queued=0`, key, running); err != nil {
		t.Fatalf("seed quota %s: %v", key, err)
	}
}

// TestPostgresIntegrationRepairCancelActiveDrains is T1-6(b): with
// --cancel-active, an active row whose identity would change is FIRST
// cancelled through the canonical cancellation transaction (lease cleared,
// runner slot freed, reservation deleted, quota released under the OLD
// identity, dependents recomputed, audit appended) and ONLY THEN rewritten.
func TestPostgresIntegrationRepairCancelActiveDrains(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	const oldRepo = "github.com/acme/a"
	const newRepo = "github.com/acme/b"

	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	runnerID := pgITNewID(t)
	depRun := pgITNewID(t)
	depJob := pgITNewID(t)

	pgITInsertRunIdentityStatus(t, st, runID, "running", oldRepo, oldRepo, "https://github.com/acme/a.git", "acme/a")
	pgITInsertJobIdentityStatus(t, st, runID, jobID, "queued", oldRepo, oldRepo, "https://github.com/acme/b.git", "acme/b")
	pgITSeedRunner(t, st, runnerID, 4, 0, 0)

	if _, err := st.AcquireLeaseAtomic(ctx, LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("token"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatalf("lease under old identity: %v", err)
	}
	// The dependent waits on the cancelled job (payload needs + the
	// job_dependencies edge, exactly what recomputeDependentsTx reads).
	pgITInsertRunIdentityStatus(t, st, depRun, "running", oldRepo, oldRepo, "https://github.com/acme/a.git", "acme/a")
	// A provable canonical identity (URL evidence) so the dependent is Keep and
	// stays queued for the recompute; only its `needs` edge is added.
	pgITInsertJobIdentityStatus(t, st, depRun, depJob, "queued", oldRepo, oldRepo, "https://github.com/acme/a.git", "acme/a")
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET payload = jsonb_set(jsonb_set(payload, '{needs}', jsonb_build_array($2::text), true), '{status}', to_jsonb('queued'::text), true) WHERE id=$1`, depJob, jobID); err != nil {
		t.Fatalf("set dependent needs: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `INSERT INTO job_dependencies (job_id, depends_on) VALUES ($1,$2)`, depJob, jobID); err != nil {
		t.Fatalf("insert dependency edge: %v", err)
	}

	// Quota is charged under the OLD identity by the lease; seed a counter
	// under the NEW identity too, to prove the release uses OLD.
	var oldRunningBefore int
	if err := st.pool.QueryRow(ctx, `SELECT running FROM quota_reservations WHERE key=$1`, oldRepo).Scan(&oldRunningBefore); err != nil {
		t.Fatalf("read old quota before: %v", err)
	}
	if oldRunningBefore != 1 {
		t.Fatalf("old quota running = %d, want 1 after the lease", oldRunningBefore)
	}
	pgITSeedQuotaRunning(t, st, newRepo, 7)
	var reservationsBefore int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM job_resource_reservations WHERE job_id=$1`, jobID).Scan(&reservationsBefore); err != nil {
		t.Fatalf("count reservations before: %v", err)
	}
	if reservationsBefore != 1 {
		t.Fatalf("reservations before = %d, want 1", reservationsBefore)
	}

	res, err := st.RepairRepoIdentitiesWithOptions(ctx, RepoIdentityRepairApply, RepoIdentityRepairOptions{CancelActive: true})
	if err != nil {
		t.Fatalf("cancel-active repair: %v", err)
	}
	if res.Drained < 1 {
		t.Fatalf("drained = %d, want >= 1", res.Drained)
	}

	job, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	// THEN the identity was rewritten.
	if job.RepoID != newRepo || RepoIDForJob(job) != newRepo {
		t.Fatalf("identity after drain = %q/%q, want %q", job.RepoID, RepoIDForJob(job), newRepo)
	}
	if job.Status != model.StatusCancelled {
		t.Fatalf("job status = %q, want cancelled", job.Status)
	}

	// Lease columns cleared.
	var (
		leaseRunner string
		leaseHash   []byte
		leaseExp    *time.Time
	)
	if err := st.pool.QueryRow(ctx, `SELECT COALESCE(lease_runner_id,''), lease_token_hash, lease_expires_at FROM jobs WHERE id=$1`, jobID).
		Scan(&leaseRunner, &leaseHash, &leaseExp); err != nil {
		t.Fatalf("read lease columns: %v", err)
	}
	if leaseRunner != "" || len(leaseHash) != 0 || leaseExp != nil {
		t.Fatalf("lease columns not cleared: runner=%q hash=%v expires=%v", leaseRunner, leaseHash, leaseExp)
	}

	// Runner slot freed.
	ri, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner: %v", err)
	}
	if len(ri.ActiveJobs) != 0 || ri.Busy || ri.CurrentJob != "" {
		t.Fatalf("runner slot not released: active=%v busy=%v current=%q", ri.ActiveJobs, ri.Busy, ri.CurrentJob)
	}

	// Reservation deleted.
	var reservationsAfter int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM job_resource_reservations WHERE job_id=$1`, jobID).Scan(&reservationsAfter); err != nil {
		t.Fatalf("count reservations after: %v", err)
	}
	if reservationsAfter != 0 {
		t.Fatalf("resource reservation survived the drain: %d", reservationsAfter)
	}

	// Quota decremented under the OLD identity; the NEW identity is untouched.
	var oldRunning, newRunning int
	if err := st.pool.QueryRow(ctx, `SELECT COALESCE((SELECT running FROM quota_reservations WHERE key=$1),-1)`, oldRepo).Scan(&oldRunning); err != nil {
		t.Fatalf("read old quota: %v", err)
	}
	if err := st.pool.QueryRow(ctx, `SELECT COALESCE((SELECT running FROM quota_reservations WHERE key=$1),-1)`, newRepo).Scan(&newRunning); err != nil {
		t.Fatalf("read new quota: %v", err)
	}
	if oldRunning != 0 {
		t.Fatalf("old-identity quota running = %d, want 0 (released under OLD identity)", oldRunning)
	}
	if newRunning != 7 {
		t.Fatalf("new-identity quota running = %d, want 7 (must be untouched)", newRunning)
	}

	// Dependents recomputed.
	dep, err := st.GetJob(ctx, depJob)
	if err != nil {
		t.Fatalf("get dependent: %v", err)
	}
	if dep.DependencyStatus != model.StatusCancelled {
		t.Fatalf("dependent dependency_status = %q, want cancelled", dep.DependencyStatus)
	}

	// Audit appended for the cancellation.
	var audit int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE run_id=$1 AND action='job.cancelled'`, runID).Scan(&audit); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if audit == 0 {
		t.Fatal("no job.cancelled audit event appended by the drain")
	}
}
