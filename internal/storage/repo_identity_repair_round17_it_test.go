package storage

// Coverage round: repository-identity repair arms. The apply pass's
// missing-row conflict, its test hooks, the operator env batch size and the
// drain/guarded-update/quarantine error returns are each driven against a
// real throwaway database.

import (
	"context"
	"errors"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

var errRepoIdentityHook = errors.New("seam: repo identity hook refused")

// TestPostgresIntegrationRepoIdentityRepairMissingRowAndHooks covers the
// conflict classification for a row that vanished before it could be locked
// and both test-hook refusals.
func TestPostgresIntegrationRepoIdentityRepairMissingRowAndHooks(t *testing.T) {
	ctx := context.Background()

	t.Run("row disappeared before the lock", func(t *testing.T) {
		st := pgITStore(t)
		tx, err := st.pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		result := &RepoIdentityRepairResult{}
		table := newRepoIdentityRepairTables()[0]
		row := repoIdentityRepairRow{id: pgITNewID(t), repoID: "group/sub/project"}
		if err := st.applyRepoIdentityRecord(ctx, tx, table, row, false, result); err != nil {
			t.Fatalf("apply missing row: %v", err)
		}
		if result.Conflicts != 1 || result.Rewritten != 0 || result.Quarantined != 0 {
			t.Fatalf("result = %+v, want one conflict and no repair", result)
		}
		if len(result.Entries) != 1 || result.Entries[0].Action != RepoIdentityConflict {
			t.Fatalf("entries = %+v, want one conflict entry", result.Entries)
		}
	})

	t.Run("before batch hook refuses", func(t *testing.T) {
		st := pgITStore(t)
		pgITInsertRunIdentity(t, st, pgITNewID(t), "group/sub/project", "group/sub/project", "", "group/sub/project")
		st.repoIdentityRepairHooks = &repoIdentityRepairTestHooks{
			BeforeBatch: func(int, []repoIdentityRepairRow) error { return errRepoIdentityHook },
		}
		if _, err := st.RepairRepoIdentities(ctx, RepoIdentityRepairReport); !errors.Is(err, errRepoIdentityHook) {
			t.Fatalf("report with a refusing batch hook = %v, want the hook error", err)
		}
	})

	t.Run("before apply hook refuses", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITInsertRunIdentity(t, st, runID, "group/sub/project", "group/sub/project", "", "group/sub/project")
		st.repoIdentityRepairHooks = &repoIdentityRepairTestHooks{
			BeforeApply: func(string, string) error { return errRepoIdentityHook },
		}
		if _, err := st.RepairRepoIdentities(ctx, RepoIdentityRepairApply); !errors.Is(err, errRepoIdentityHook) {
			t.Fatalf("apply with a refusing record hook = %v, want the hook error", err)
		}
		// The refusal happens before the guarded UPDATE: the row is untouched.
		if got, _ := pgITRunIdentity(t, st, runID); got != "group/sub/project" {
			t.Fatalf("hook refusal still rewrote the row to %q", got)
		}
	})

	t.Run("env batch size", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITInsertRunIdentity(t, st, runID, "group/sub/project", "group/sub/project", "", "group/sub/project")
		t.Setenv("KIWI_REPO_IDENTITY_REPAIR_BATCH_SIZE", "2")
		res, err := st.RepairRepoIdentities(ctx, RepoIdentityRepairApply)
		if err != nil || res.Rewritten != 1 {
			t.Fatalf("apply with the env batch size = %+v, %v", res, err)
		}
	})

	t.Run("no pool", func(t *testing.T) {
		if _, err := (&PostgresStore{}).RepairRepoIdentities(ctx, RepoIdentityRepairReport); !errors.Is(err, ErrRepoIdentityRepairRequiresPool) {
			t.Fatalf("repair without a pool = %v, want ErrRepoIdentityRepairRequiresPool", err)
		}
	})
}

// TestPostgresIntegrationRepoIdentityRepairDrainArms covers the drain,
// guarded-update and quarantine-insert error returns with real rows and
// trigger-injected write failures.
func TestPostgresIntegrationRepoIdentityRepairDrainArms(t *testing.T) {
	ctx := context.Background()

	t.Run("job drain error", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		// The run stays canonical (kept), so the repair reaches the job row.
		pgITInsertRunIdentity(t, st, runID, "github.com/acme/repo", "github.com/acme/repo", "https://github.com/acme/repo.git", "acme/repo")
		pgITInsertJobIdentityStatus(t, st, runID, jobID, "queued", "group/sub/project", "group/sub/project", "", "group/sub/project")
		pgITBoomOp(t, st, "jobs", "UPDATE")
		if _, err := st.RepairRepoIdentitiesWithOptions(ctx, RepoIdentityRepairApply, RepoIdentityRepairOptions{CancelActive: true}); err == nil {
			t.Fatal("repair with a failing job cancellation succeeded")
		}
	})

	t.Run("run child drain error", func(t *testing.T) {
		st := pgITStore(t)
		runID, jobID := pgITNewID(t), pgITNewID(t)
		pgITInsertRunIdentityStatus(t, st, runID, "queued", "group/sub/project", "group/sub/project", "", "group/sub/project")
		pgITInsertJobIdentityStatus(t, st, runID, jobID, "queued", "group/sub/project", "group/sub/project", "", "group/sub/project")
		pgITBoomOp(t, st, "jobs", "UPDATE")
		if _, err := st.RepairRepoIdentitiesWithOptions(ctx, RepoIdentityRepairApply, RepoIdentityRepairOptions{CancelActive: true}); err == nil {
			t.Fatal("repair with a failing child cancellation succeeded")
		}
	})

	t.Run("guarded update error", func(t *testing.T) {
		st := pgITStore(t)
		runID := pgITNewID(t)
		pgITInsertRunIdentity(t, st, runID, "group/sub/project", "group/sub/project", "", "group/sub/project")
		pgITBoomOp(t, st, "runs", "UPDATE")
		if _, err := st.RepairRepoIdentities(ctx, RepoIdentityRepairApply); err == nil {
			t.Fatal("repair with a failing guarded update succeeded")
		}
	})

	t.Run("quarantine insert error", func(t *testing.T) {
		st := pgITStore(t)
		// First pass creates the quarantine table and quarantines one row.
		pgITInsertRunIdentity(t, st, pgITNewID(t), "group/sub/project", "group/sub/project", "", "")
		if _, err := st.RepairRepoIdentities(ctx, RepoIdentityRepairApply); err != nil {
			t.Fatalf("seed apply: %v", err)
		}
		// Second pass quarantines a fresh row and the log insert fails.
		pgITInsertRunIdentity(t, st, pgITNewID(t), "group/sub/project", "group/sub/project", "", "")
		pgITBoomOp(t, st, "repo_identity_quarantine", "INSERT")
		if _, err := st.RepairRepoIdentities(ctx, RepoIdentityRepairApply); err == nil {
			t.Fatal("repair with a failing quarantine insert succeeded")
		}
	})
}

// TestClassifyRepoIdentityActiveDrain pins the classification rule: a
// terminal rewrite/quarantine plan becomes an active drain while the run
// still owns non-terminal children, with a defaulted reason.
func TestClassifyRepoIdentityActiveDrain(t *testing.T) {
	rewrite := ClassifyRepoIdentity("group/sub/project", "", "group/sub/project", model.StatusQueued)
	if rewrite.Action != RepoIdentityActiveRequiresDrain || rewrite.Reason == "" {
		t.Fatalf("rewrite plan = %+v, want active drain with a reason", rewrite)
	}
	quarantine := ClassifyRepoIdentity("group/sub/project", "", "", model.StatusQueued)
	if quarantine.Action != RepoIdentityActiveRequiresDrain {
		t.Fatalf("quarantine plan = %+v, want active drain", quarantine)
	}
}
