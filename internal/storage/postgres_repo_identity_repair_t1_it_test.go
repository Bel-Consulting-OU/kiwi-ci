package storage

// T1-6(a)/(c) live-PostgreSQL regressions. Both are FAIL-before at HEAD:
//
//   - (a) a running job admitted under identity A must NOT be rewritten to B
//     by a default repair; the historical code rewrote it in place, so the
//     same lease could then resolve B-scoped tokens/cache/provenance.
//   - (c) quarantining a run must cancel its non-terminal child jobs; the
//     historical code left a queued child queued and leasable. The test
//     isolates the NEW parent-run lease predicate by clearing the child's own
//     durable flag before attempting the lease.
//
// Both use only APIs that exist at the pre-fix HEAD (plus the status-aware
// insert helpers), so the FAIL-before run is a real assertion failure rather
// than a compile error.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestPostgresIntegrationRepairActiveIdentityImmutable is T1-6(a): a RUNNING
// job under A with a valid lease, plus a default repair A->B, must leave the
// job's identity, lease and runner slot untouched and report the row as
// active_requires_drain. No B-scoped identity is resolvable for the row.
func TestPostgresIntegrationRepairActiveIdentityImmutable(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	runnerID := pgITNewID(t)

	// The run itself is canonical A (kept); the job is the active row whose
	// clone URL proves B.
	pgITInsertRunIdentityStatus(t, st, runID, "running", "github.com/acme/a", "github.com/acme/a", "https://github.com/acme/a.git", "acme/a")
	pgITInsertJobIdentityStatus(t, st, runID, jobID, "queued", "github.com/acme/a", "github.com/acme/a", "https://github.com/acme/b.git", "acme/b")
	pgITSeedRunner(t, st, runnerID, 4, 0, 0)

	claim := LeaseClaim{JobID: jobID, RunnerID: runnerID, TokenHash: []byte("token"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if _, err := st.AcquireLeaseAtomic(ctx, claim); err != nil {
		t.Fatalf("lease under A: %v", err)
	}

	res, err := st.RepairRepoIdentities(ctx, RepoIdentityRepairApply)
	if err != nil {
		t.Fatalf("default repair: %v", err)
	}

	job, err := st.GetJob(ctx, jobID)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if job.RepoID != "github.com/acme/a" || RepoIDForJob(job) != "github.com/acme/a" {
		t.Fatalf("running job identity changed: stored=%q resolved=%q, want A", job.RepoID, RepoIDForJob(job))
	}
	if job.Status != model.StatusRunning {
		t.Fatalf("job status = %q, want running (lease must survive)", job.Status)
	}
	if job.RepoIdentityQuarantined {
		t.Fatal("active row was quarantined by a default repair")
	}
	run, err := st.GetRun(ctx, runID)
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	if RepoIDForRun(run) != "github.com/acme/a" {
		t.Fatalf("run identity resolved %q, want A", RepoIDForRun(run))
	}

	// The lease columns are intact and the lease still heartbeats under A.
	var (
		leaseRunner string
		leaseGen    int64
		leaseExp    *time.Time
	)
	if err := st.pool.QueryRow(ctx, `SELECT COALESCE(lease_runner_id,''), lease_generation, lease_expires_at FROM jobs WHERE id=$1`, jobID).
		Scan(&leaseRunner, &leaseGen, &leaseExp); err != nil {
		t.Fatalf("read lease columns: %v", err)
	}
	if leaseRunner != runnerID || leaseGen != 1 || leaseExp == nil {
		t.Fatalf("lease columns changed: runner=%q gen=%d expires=%v", leaseRunner, leaseGen, leaseExp)
	}
	if err := st.HeartbeatLease(ctx, jobID, runnerID, 1, time.Now().UTC().Add(2*time.Hour)); err != nil {
		t.Fatalf("heartbeat under A failed after repair: %v", err)
	}
	// The runner slot was not freed: the running lease still owns it.
	ri, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner: %v", err)
	}
	found := false
	for _, id := range ri.ActiveJobs {
		if id == jobID {
			found = true
		}
	}
	if !found {
		t.Fatalf("runner active set lost the running job: %v", ri.ActiveJobs)
	}

	// The operator report classifies the row as active_requires_drain.
	reported := false
	for _, e := range res.Entries {
		if e.Kind == "job" && e.ID == jobID && e.Action.String() == "active_requires_drain" {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("job not reported active_requires_drain: %+v", res.Entries)
	}

	// Defense in depth: even after clearing the job's own identity to the new
	// value, NO row exposes B through the identity-resolution helpers, because
	// the repair never rewrote it.
	if RepoIDForJob(job) != "github.com/acme/a" {
		t.Fatal("a B-scoped identity became resolvable for the still-live lease")
	}
}

// TestPostgresIntegrationRepairRunQuarantineCascades is T1-6(c): a terminal
// (unprovable) run with queued child jobs must cancel every non-terminal
// child, and a requeued child must stay unleasable through the parent-run
// predicate even on a global-allow runner.
func TestPostgresIntegrationRepairRunQuarantineCascades(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	childA := pgITNewID(t)
	childB := pgITNewID(t)

	// The run is TERMINAL but unprovable -> quarantine_terminal. Its children
	// are queued with a PROVABLE canonical identity (Keep), so only the
	// cascade can make them terminal.
	pgITInsertRunIdentityStatus(t, st, runID, "success", "group/sub/project", "group/sub/project", "", "")
	pgITInsertJobIdentityStatus(t, st, runID, childA, "queued", "github.com/acme/one", "github.com/acme/one", "https://github.com/acme/one.git", "acme/one")
	pgITInsertJobIdentityStatus(t, st, runID, childB, "queued", "github.com/acme/two", "github.com/acme/two", "https://github.com/acme/two.git", "acme/two")

	runnerID := pgITNewID(t)
	pgITSeedRunner(t, st, runnerID, 5, 0, 0) // empty allowlist = global allow

	if _, err := st.RepairRepoIdentities(ctx, RepoIdentityRepairApply); err != nil {
		t.Fatalf("repair: %v", err)
	}

	run, err := st.GetRun(ctx, runID)
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	if !run.RepoIdentityQuarantined {
		t.Fatal("run not quarantined")
	}
	for _, id := range []string{childA, childB} {
		j, err := st.GetJob(ctx, id)
		if err != nil {
			t.Fatalf("get child %s: %v", id, err)
		}
		if j.Status != model.StatusCancelled {
			t.Fatalf("child %s status = %q, want cancelled (run quarantine must cascade)", id, j.Status)
		}
	}

	// Isolate the NEW parent-run predicate: strip the child's own durable
	// flag and requeue it, so only the parent run's quarantined/terminal
	// state can deny the lease.
	if _, err := st.pool.Exec(ctx, `UPDATE jobs SET status='queued', payload = payload - 'repo_identity_quarantined' WHERE id=$1`, childA); err != nil {
		t.Fatalf("isolate child: %v", err)
	}
	var flag bool
	if err := st.pool.QueryRow(ctx, `SELECT COALESCE(payload->>'repo_identity_quarantined','') = 'true' FROM jobs WHERE id=$1`, childA).Scan(&flag); err != nil {
		t.Fatalf("read child flag: %v", err)
	}
	if flag {
		t.Fatal("fixture failed to clear the child's own quarantine flag")
	}
	claim := LeaseClaim{JobID: childA, RunnerID: runnerID, TokenHash: []byte("tok"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if _, err := st.AcquireLeaseAtomic(ctx, claim); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("queued child of a quarantined run leased: err=%v, want ErrNoCapacity", err)
	}
	// The NON-atomic claim carries the same parent-run predicate.
	if _, err := st.AcquireLease(ctx, childA, runnerID, []byte("tok"), 1, time.Now().UTC().Add(time.Hour)); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("non-atomic claim leased a child of a quarantined run: err=%v, want ErrLeaseConflict", err)
	}

	// Control: the same global-allow runner leases a queued job in a healthy
	// run, proving the denial above comes from the parent run.
	okRun := pgITNewID(t)
	okJob := pgITNewID(t)
	pgITInsertRunIdentityStatus(t, st, okRun, "running", "github.com/acme/ok", "github.com/acme/ok", "", "")
	pgITInsertJobIdentityStatus(t, st, okRun, okJob, "queued", "github.com/acme/ok", "github.com/acme/ok", "https://github.com/acme/ok.git", "acme/ok")
	control := LeaseClaim{JobID: okJob, RunnerID: runnerID, TokenHash: []byte("tok2"), Generation: 1, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if _, err := st.AcquireLeaseAtomic(ctx, control); err != nil {
		t.Fatalf("control lease failed: %v", err)
	}
}

// TestPostgresIntegrationRepairQuarantineKeepsRawOriginal is the live half of
// T1-4: whitespace variants of an unprovable stored identity become DISTINCT
// reserved identities (the hash input is raw) while the quarantine table keeps
// each raw original verbatim.
func TestPostgresIntegrationRepairQuarantineKeepsRawOriginal(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()

	variants := []string{"group/sub/project", " group/sub/project", "group/sub/project "}
	ids := make([]string, len(variants))
	for i, v := range variants {
		id := pgITNewID(t)
		ids[i] = id
		pgITInsertRunIdentityStatus(t, st, id, "success", v, v, "", "")
	}

	if _, err := st.RepairRepoIdentities(ctx, RepoIdentityRepairApply); err != nil {
		t.Fatalf("repair: %v", err)
	}

	seen := map[string]string{}
	for i, id := range ids {
		got, _ := pgITRunIdentity(t, st, id)
		if want := QuarantinedRepoIdentity(variants[i]); got != want {
			t.Fatalf("variant %q repaired to %q, want raw-value identity %q", variants[i], got, want)
		}
		if prev, ok := seen[got]; ok {
			t.Fatalf("whitespace variants %q and %q collapsed to one identity", prev, variants[i])
		}
		seen[got] = variants[i]

		var storedOriginal string
		if err := st.pool.QueryRow(ctx, `SELECT stored_repo_id FROM repo_identity_quarantine WHERE kind='run' AND record_id=$1`, id).Scan(&storedOriginal); err != nil {
			t.Fatalf("read quarantine original for %q: %v", variants[i], err)
		}
		if storedOriginal != variants[i] {
			t.Fatalf("quarantine table original = %q, want the raw %q", storedOriginal, variants[i])
		}
	}
}
