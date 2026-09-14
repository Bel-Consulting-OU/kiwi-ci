package storage

import (
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// TestMemStoreDownstreamClaimExactlyOnce proves the claim-row semantics the
// exactly-once dispatch relies on: the link row is created once, and once a
// ChildRunID is recorded it can never be overwritten.
func TestMemStoreDownstreamClaimExactlyOnce(t *testing.T) {
	m := newMemStore()
	_ = m.InsertRun(ctx(), testRun)
	_ = m.InsertJob(ctx(), testJob)

	link := DownstreamLink{ParentJobID: testJob.ID, TargetRepo: "acme/child", TargetRef: "refs/heads/main", LaunchToken: "tok", CreatedAt: time.Now().UTC()}
	if err := m.InsertDownstreamLink(ctx(), link); err != nil {
		t.Fatalf("InsertDownstreamLink: %v", err)
	}
	// Re-insert with a different token must keep the original claim.
	dup := link
	dup.LaunchToken = "other-token"
	if err := m.InsertDownstreamLink(ctx(), dup); err != nil {
		t.Fatalf("re-InsertDownstreamLink: %v", err)
	}
	got, ok, err := m.GetDownstreamLink(ctx(), link.ParentJobID, link.TargetRepo, link.TargetRef)
	if err != nil || !ok {
		t.Fatalf("GetDownstreamLink: ok=%v err=%v", ok, err)
	}
	if got.LaunchToken != "tok" {
		t.Fatalf("launch token overwritten: %q", got.LaunchToken)
	}
	if got.ChildRunID != "" {
		t.Fatalf("fresh link must have empty ChildRunID, got %q", got.ChildRunID)
	}
	// First mark wins; a second mark for another child is ignored.
	if err := m.MarkDownstreamLaunched(ctx(), link.ParentJobID, link.TargetRepo, link.TargetRef, "child-1"); err != nil {
		t.Fatalf("MarkDownstreamLaunched: %v", err)
	}
	if err := m.MarkDownstreamLaunched(ctx(), link.ParentJobID, link.TargetRepo, link.TargetRef, "child-2"); err != nil {
		t.Fatalf("second MarkDownstreamLaunched: %v", err)
	}
	got, _, _ = m.GetDownstreamLink(ctx(), link.ParentJobID, link.TargetRepo, link.TargetRef)
	if got.ChildRunID != "child-1" {
		t.Fatalf("ChildRunID = %q, want child-1", got.ChildRunID)
	}
}

// TestMemStoreInsertGeneratedJobs proves generated fragments commit
// atomically in memory and refuse a missing parent.
func TestMemStoreInsertGeneratedJobs(t *testing.T) {
	m := newMemStore()
	child := testJob
	child.ID = "ffffffffffffffffffffffffffffffff"
	child.Key = "generated"
	child.DynamicDepth = 1
	if err := m.InsertGeneratedJobs(ctx(), testJob.ID, 1, map[string]model.Job{child.ID: child}, nil); !isNotFound(err) {
		t.Fatalf("missing parent = %v, want ErrNotFound", err)
	}
	_ = m.InsertRun(ctx(), testRun)
	_ = m.InsertJob(ctx(), testJob)
	if err := m.InsertGeneratedJobs(ctx(), testJob.ID, 1, map[string]model.Job{child.ID: child}, nil); err != nil {
		t.Fatalf("InsertGeneratedJobs: %v", err)
	}
	got, err := m.GetJob(ctx(), child.ID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if got.DynamicDepth != 1 || got.Key != "generated" {
		t.Fatalf("generated child = %+v", got)
	}
}

// TestMemStoreRecentUsage proves usage aggregation reads the persisted
// cost/energy fields within the trailing window only.
func TestMemStoreRecentUsage(t *testing.T) {
	m := newMemStore()
	now := time.Now().UTC()
	recent := testJob
	recent.ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
	recent.FinishedAt = &now
	recent.Cost = 2.5
	recent.EnergyWh = 30
	old := testJob
	old.ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac"
	oldFinished := now.Add(-25 * time.Hour)
	old.FinishedAt = &oldFinished
	old.Cost = 100
	old.EnergyWh = 1000
	_ = m.InsertRun(ctx(), testRun)
	_ = m.InsertJob(ctx(), recent)
	_ = m.InsertJob(ctx(), old)
	cost, energy, err := m.RecentUsage(ctx(), now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("RecentUsage: %v", err)
	}
	if cost != 2.5 || energy != 30 {
		t.Fatalf("RecentUsage = %g/%g, want 2.5/30", cost, energy)
	}
}

// TestMigration0003DownstreamLinks verifies the 0003 migration replaces the
// provisional 0001 downstream_links table with the claim contract.
func TestMigration0003DownstreamLinks(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0003_downstream_links.sql")
	if err != nil {
		t.Fatalf("read 0003: %v", err)
	}
	sql := string(raw)
	for _, want := range []string{
		`DROP TABLE IF EXISTS downstream_links`,
		`CREATE TABLE downstream_links`,
		`parent_job_id TEXT NOT NULL`,
		`target_repo TEXT NOT NULL`,
		`target_ref TEXT NOT NULL`,
		`launch_token TEXT NOT NULL`,
		`child_run_id TEXT NOT NULL`,
		`created_at TIMESTAMPTZ NOT NULL`,
		`PRIMARY KEY (parent_job_id, target_repo, target_ref)`,
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("0003_downstream_links.sql is missing %q", want)
		}
	}
	// The file follows the 0001/0002 no-argument batch style (one simple
	// protocol statement); it must split into at least one statement.
	stmts := migrations.SplitStatements(sql)
	if len(stmts) == 0 {
		t.Fatal("0003 has no statements after splitting")
	}
}

func isNotFound(err error) bool {
	return err != nil && err.Error() == ErrNotFound.Error()
}
