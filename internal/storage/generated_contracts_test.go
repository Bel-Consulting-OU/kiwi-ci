package storage

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage/migrations"
)

// TestMemStoreGeneratedContractFailureRollsBackJobs proves the generated-
// fragment contract writes ride the SAME transaction as the jobs: a
// contract failure (here: a malformed contract job ID, which the SQL path
// fails inside the transaction) leaves neither the fragment jobs nor the
// fragment contracts behind.
func TestMemStoreGeneratedContractFailureRollsBackJobs(t *testing.T) {
	m := newMemStore()
	seedRunAndJob(m)
	child := testJob
	child.ID = "ffffffffffffffffffffffffffffffff"
	child.Key = "generated"
	badContracts := map[string]map[string]ArtifactContract{
		"NOT-A-VALID-ID": {"dist": {Name: "dist", Required: true}},
	}
	_, _, err := m.InsertGeneratedFragmentTx(ctx(), GeneratedFragmentRequest{
		ParentJobID: testJob.ID, Depth: 1, FragmentID: "frag-bad-contract",
		Jobs: map[string]model.Job{child.ID: child}, Contracts: badContracts, Children: []GeneratedFragmentChild{{Key: child.Key, ID: child.ID}},
	}, nil)
	if err == nil {
		t.Fatal("malformed contract job id must fail the fragment")
	}
	if _, gerr := m.GetJob(ctx(), child.ID); !errors.Is(gerr, ErrNotFound) {
		t.Fatalf("contract failure leaked a job: %v", gerr)
	}
	if got, ok, _ := m.GetJobContracts(ctx(), child.ID); ok || got != nil {
		t.Fatalf("contract failure leaked contracts: %v", got)
	}
	if got, ok, _ := m.GetJobContracts(ctx(), "NOT-A-VALID-ID"); ok || got != nil {
		t.Fatalf("contract failure leaked contracts: %v", got)
	}
}

// TestMemStoreGeneratedContractsVisibleBeforeCompletion proves a generated
// job with a Required artifact has its contract row present immediately
// after the fragment commit — before any completion can run against it.
func TestMemStoreGeneratedContractsVisibleBeforeCompletion(t *testing.T) {
	m := newMemStore()
	seedRunAndJob(m)
	child := testJob
	child.ID = "ffffffffffffffffffffffffffffffff"
	child.Key = "generated"
	contracts := map[string]map[string]ArtifactContract{
		child.ID: {"dist": {Name: "dist", Required: true}},
	}
	if _, _, err := m.InsertGeneratedFragmentTx(ctx(), GeneratedFragmentRequest{
		ParentJobID: testJob.ID, Depth: 1, FragmentID: "frag-contracts",
		Jobs: map[string]model.Job{child.ID: child}, Contracts: contracts, Children: []GeneratedFragmentChild{{Key: child.Key, ID: child.ID}},
	}, nil); err != nil {
		t.Fatalf("InsertGeneratedFragmentTx: %v", err)
	}
	got, ok, err := m.GetJobContracts(ctx(), child.ID)
	if err != nil || !ok {
		t.Fatalf("contracts not stored with the fragment: ok=%v err=%v", ok, err)
	}
	if got["dist"].Name != "dist" || !got["dist"].Required {
		t.Fatalf("contract = %+v", got["dist"])
	}
}

// TestMemStoreDownstreamLaunchClaimAtomic proves the downstream launch
// claim processed inside InsertCompiledRun: the child run and the link
// update commit together, an already-launched link with the same stable
// child ID reports ErrDownstreamLaunched, and a conflicting child ID fails
// closed.
func TestMemStoreDownstreamLaunchClaimAtomic(t *testing.T) {
	m := newMemStore()
	seedRunAndJob(m)
	key := testJob.ID + "\x00acme/child\x00refs/heads/main"
	link := DownstreamLink{ParentJobID: testJob.ID, TargetRepo: "acme/child", TargetRef: "refs/heads/main", LaunchToken: "tok", Reserved: true, CreatedAt: time.Now().UTC()}
	if err := m.InsertDownstreamLink(ctx(), link); err != nil {
		t.Fatalf("InsertDownstreamLink: %v", err)
	}
	childRunID := "0123456789abcdef0123456789abcdef"
	stable := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	claim := &DownstreamLaunchClaim{LinkKey: key, StableChildID: stable}
	req := InsertCompiledRunRequest{
		Run:              model.Run{ID: childRunID, Repo: "https://github.com/acme/child", Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
		Jobs:             map[string]model.Job{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae": {ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", RunID: childRunID, Key: "child", Status: model.StatusQueued, CreatedAt: time.Now().UTC()}},
		DownstreamLaunch: claim,
	}
	if err := m.InsertCompiledRun(ctx(), req); err != nil {
		t.Fatalf("InsertCompiledRun with launch claim: %v", err)
	}
	got, ok, err := m.GetDownstreamLink(ctx(), testJob.ID, "acme/child", "refs/heads/main")
	if err != nil || !ok {
		t.Fatalf("link missing: ok=%v err=%v", ok, err)
	}
	if got.ChildRunID != childRunID || got.StableChildID != stable || got.Reserved {
		t.Fatalf("link = %+v, want launched with stable child id", got)
	}
	// Replaying the SAME enqueue (same stable child ID) reports already-
	// launched instead of inserting a duplicate run.
	dup := req
	dup.Run.ID = childRunID
	if err := m.InsertCompiledRun(ctx(), dup); !errors.Is(err, ErrDownstreamLaunched) {
		t.Fatalf("replayed launch = %v, want ErrDownstreamLaunched", err)
	}
	// A different child ID for the same link fails closed (claim lost).
	conflict := req
	conflict.Run.ID = "ffffffffffffffffffffffffffffffff"
	if err := m.InsertCompiledRun(ctx(), conflict); err == nil || errors.Is(err, ErrDownstreamLaunched) {
		t.Fatalf("conflicting child id = %v, want hard error", err)
	}
	// A launch claim against a missing link fails closed.
	missing := req
	missing.Run.ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
	missing.DownstreamLaunch = &DownstreamLaunchClaim{LinkKey: "missing\x00a/b\x00ref", StableChildID: stable}
	if err := m.InsertCompiledRun(ctx(), missing); err == nil {
		t.Fatal("missing link must fail the launch claim")
	}
}

// TestMemStoreScheduleIdentityRoundTrip proves the migration-0007 schedule
// identity fields persist through the ScheduleStore.
func TestMemStoreScheduleIdentityRoundTrip(t *testing.T) {
	m := newMemStore()
	sc := Schedule{
		ID: "sched-1", Repository: "acme/service", RepoID: "gitlab.example/acme/service",
		RepoURL: "https://gitlab.example/acme/service.git", Forge: "gitlab", Trusted: true,
		Spec: "version: 1", Enabled: true, CreatedAt: time.Now().UTC(),
	}
	if err := m.UpsertSchedule(ctx(), sc); err != nil {
		t.Fatalf("UpsertSchedule: %v", err)
	}
	list, err := m.ListSchedules(ctx())
	if err != nil {
		t.Fatalf("ListSchedules: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("schedules = %d, want 1", len(list))
	}
	got := list[0]
	if got.RepoID != sc.RepoID || got.RepoURL != sc.RepoURL || got.Forge != sc.Forge || !got.Trusted {
		t.Fatalf("schedule identity = %+v, want %+v", got, sc)
	}
}

// TestMigration0007ScheduleIdentity verifies the 0007 migration adds the
// schedule identity columns and the downstream stable-child column.
func TestMigration0007ScheduleIdentity(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0007_schedule_identity.sql")
	if err != nil {
		t.Fatalf("read 0007: %v", err)
	}
	sql := string(raw)
	for _, want := range []string{
		`ALTER TABLE schedules ADD COLUMN repo_id`,
		`ALTER TABLE schedules ADD COLUMN repo_url`,
		`ALTER TABLE schedules ADD COLUMN forge`,
		`ALTER TABLE schedules ADD COLUMN trusted`,
		`ALTER TABLE downstream_links ADD COLUMN stable_child_id`,
		`schedules_repo_id_idx`,
		`downstream_links_stable_child_idx`,
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("0007_schedule_identity.sql is missing %q", want)
		}
	}
	stmts := migrations.SplitStatements(sql)
	if len(stmts) != 1 {
		t.Fatalf("0007 has %d statements, want exactly 1 (one migration = one statement batch, matching the 0001-0006 convention)", len(stmts))
	}
}
