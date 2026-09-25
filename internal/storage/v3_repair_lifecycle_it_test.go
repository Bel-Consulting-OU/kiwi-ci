package storage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func v3SeedRun(t *testing.T, st *PostgresStore, runID, repoID, url, full string) {
	t.Helper()
	run := model.Run{ID: runID, RepoID: repoID, Repo: url, RepoFullName: full, Status: model.StatusSuccess, CreatedAt: time.Now().UTC()}
	if err := st.InsertRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
}

func v3SeedChild(t *testing.T, st *PostgresStore, jobID, runID, repoID, url, full string, status model.Status) {
	runnerID := pgITNewID(t)
	t.Helper()
	job := model.Job{ID: jobID, RunID: runID, Key: "build", Status: status, RepoID: repoID, RepoURL: url, RepoFullName: full, CreatedAt: time.Now().UTC()}
	_ = runnerID
	var lease *time.Time
	if status == model.StatusRunning {
		exp := time.Now().UTC().Add(time.Hour)
		lease = &exp
		job.LeaseRunnerID = runnerID
		job.LeaseGeneration = 1
		job.LeaseExpiresAt = lease
	}
	if _, err := st.pool.Exec(context.Background(), `INSERT INTO jobs (id, run_id, key, status, lease_runner_id, lease_generation, lease_expires_at, created_at, payload) VALUES ($1,$2,'build',$3,$4,$5,$6,now(),$7)`,
		jobID, runID, string(status), nullText(job.LeaseRunnerID), job.LeaseGeneration, lease, v3JSON(t, job)); err != nil {
		t.Fatal(err)
	}
}

// TestPostgresIntegrationRepairTerminalRunWithActiveChildrenRequiresDrain pins
// finding 5: a terminal run that still owns non-terminal children must be
// classified active_requires_drain, so a plain --apply cannot cascade a
// cancellation the operator did not request.
func TestPostgresIntegrationRepairTerminalRunWithActiveChildrenRequiresDrain(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	for _, child := range []model.Status{model.StatusQueued, model.StatusRunning, model.StatusWaitingApproval} {
		runID := pgITNewID(t)
		v3SeedRun(t, st, runID, "github.com/acme/old", "https://github.com/acme/new.git", "acme/new")
		v3SeedChild(t, st, pgITNewID(t), runID, "github.com/acme/old", "https://github.com/acme/new.git", "acme/new", child)

		report, err := st.RepairRepoIdentitiesWithOptions(ctx, RepoIdentityRepairReport, RepoIdentityRepairOptions{})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, e := range report.Entries {
			if e.Kind == "run" && e.ID == runID && e.Action == RepoIdentityActiveRequiresDrain {
				found = true
			}
		}
		if !found {
			t.Fatalf("child=%s: terminal run with an active child was not reported active_requires_drain", child)
		}
		// Plain apply must not rewrite the run or cancel the child.
		if _, err := st.RepairRepoIdentitiesWithOptions(ctx, RepoIdentityRepairApply, RepoIdentityRepairOptions{}); err != nil {
			t.Fatal(err)
		}
		var stored string
		if err := st.pool.QueryRow(ctx, `SELECT COALESCE(payload->>'repo_id','') FROM runs WHERE id=$1`, runID).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if stored != "github.com/acme/old" {
			t.Fatalf("child=%s: plain apply rewrote an active-requires-drain run to %q", child, stored)
		}
		var childStatus string
		if err := st.pool.QueryRow(ctx, `SELECT status FROM jobs WHERE run_id=$1`, runID).Scan(&childStatus); err != nil {
			t.Fatal(err)
		}
		if childStatus != string(child) {
			t.Fatalf("child=%s: plain apply changed the child status to %q", child, childStatus)
		}
	}
}

// TestPostgresIntegrationRepairConcurrentIdentityChangeIsNotCancelled pins
// finding 6: a concurrent writer that changes the identity after the batch
// read must not have its row cancelled by the stale plan.
func TestPostgresIntegrationRepairConcurrentIdentityChangeIsNotCancelled(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	v3SeedRun(t, st, runID, "github.com/acme/new", "https://github.com/acme/new.git", "acme/new")
	v3SeedChild(t, st, jobID, runID, "github.com/acme/old", "https://github.com/acme/new.git", "acme/new", model.StatusRunning)

	prev := st.repoIdentityRepairHooks
	// BeforeBatch fires AFTER the batch snapshot is read and BEFORE the row is
	// locked, which is exactly the window the finding describes: the stale
	// batch entry wants a repair, but the committed row has moved on.
	st.repoIdentityRepairHooks = &repoIdentityRepairTestHooks{
		BeforeBatch: func(batchIndex int, records []repoIdentityRepairRow) error {
			for _, r := range records {
				if r.id != jobID {
					continue
				}
				_, err := st.pool.Exec(ctx, `UPDATE jobs SET payload = jsonb_set(payload,'{repo_id}',to_jsonb('github.com/acme/new'::text),true) WHERE id=$1`, jobID)
				return err
			}
			return nil
		},
	}
	t.Cleanup(func() { st.repoIdentityRepairHooks = prev })

	if _, err := st.RepairRepoIdentitiesWithOptions(ctx, RepoIdentityRepairApply, RepoIdentityRepairOptions{CancelActive: true}); err != nil {
		t.Fatal(err)
	}
	var status, repoID string
	if err := st.pool.QueryRow(ctx, `SELECT status, COALESCE(payload->>'repo_id','') FROM jobs WHERE id=$1`, jobID).Scan(&status, &repoID); err != nil {
		t.Fatal(err)
	}
	if repoID != "github.com/acme/new" {
		t.Fatalf("concurrently changed identity was overwritten: %q", repoID)
	}
	if status == string(model.StatusCancelled) {
		t.Fatal("a concurrently changed row was cancelled from a stale plan")
	}
}

// TestPostgresIntegrationSnapshotCapEnforcedAtCommit pins finding 7: the cap
// holds under concurrent commits because it is enforced inside the
// transactional insert under the job row lock.
func TestPostgresIntegrationSnapshotCapEnforcedAtCommit(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	runID := pgITNewID(t)
	jobID := pgITNewID(t)
	v3SeedRun(t, st, runID, "github.com/acme/x", "https://github.com/acme/x.git", "acme/x")
	lease := time.Now().UTC().Add(time.Hour)
	runnerID := pgITNewID(t)
	job := model.Job{ID: jobID, RunID: runID, Key: "build", Status: model.StatusRunning, LeaseRunnerID: runnerID, LeaseGeneration: 3, LeaseExpiresAt: &lease, CreatedAt: time.Now().UTC()}
	if _, err := st.pool.Exec(ctx, `INSERT INTO jobs (id, run_id, key, status, lease_runner_id, lease_generation, lease_expires_at, created_at, payload) VALUES ($1,$2,'build','running',$3,3,$4,now(),$5)`, jobID, runID, runnerID, lease, v3JSON(t, job)); err != nil {
		t.Fatal(err)
	}
	insert := func() error {
		return st.InsertSnapshotForLease(ctx, jobID, runnerID, 3, 2, model.SnapshotRecord{ID: pgITNewID(t), RunID: runID, JobID: jobID, CreatedAt: time.Now().UTC()})
	}
	if err := insert(); err != nil {
		t.Fatal(err)
	}
	if err := insert(); err != nil {
		t.Fatal(err)
	}
	if err := insert(); !errors.Is(err, ErrSnapshotCapReached) {
		t.Fatalf("third snapshot = %v, want ErrSnapshotCapReached", err)
	}
}

// TestPostgresIntegrationCacheManifestReplacementUpdatesCreatedAt pins
// finding 9: the indexed created_at column follows a replacement.
func TestPostgresIntegrationCacheManifestReplacementUpdatesCreatedAt(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	rec := CacheManifestRecord{Repo: "github.com/acme/x", TrustDomain: "trusted", LogicalKey: "k1", BlobSHA256: strings.Repeat("a", 64), BlobSize: 1, CreatedAt: time.Now().UTC().Add(-time.Hour), Envelope: []byte("{}")}
	if err := st.PutCacheManifest(ctx, rec); err != nil {
		t.Fatal(err)
	}
	newer := rec
	newer.CreatedAt = time.Now().UTC()
	newer.BlobSHA256 = strings.Repeat("b", 64)
	if err := st.PutCacheManifest(ctx, newer); err != nil {
		t.Fatal(err)
	}
	var col time.Time
	if err := st.pool.QueryRow(ctx, `SELECT created_at FROM cache_manifests WHERE repo=$1 AND trust_domain=$2 AND logical_key=$3`, rec.Repo, rec.TrustDomain, rec.LogicalKey).Scan(&col); err != nil {
		t.Fatal(err)
	}
	if !col.Equal(newer.CreatedAt) {
		t.Fatalf("created_at = %v, want the replacement timestamp %v", col, newer.CreatedAt)
	}
}

// v3JSON marshals a value for a raw payload insert.
func v3JSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
