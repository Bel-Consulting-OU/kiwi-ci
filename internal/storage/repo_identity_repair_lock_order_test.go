package storage

// Hermetic pins for the X2-A lock order of the repository-identity repair.
// The behavioural proof is the real-PostgreSQL regression in
// postgres_repo_identity_repair_lock_order_it_test.go; these assert the SQL
// SHAPE so a future edit cannot quietly reintroduce a run lock that carries
// the hasActiveChildren EXISTS (i.e. touches jobs) or a child scan that is not
// deterministic and lock-first.

import (
	"strings"
	"testing"
)

func TestRepoIdentityRepairLockOrderSQLShape(t *testing.T) {
	tables := newRepoIdentityRepairTables()
	byKind := map[string]repoIdentityRepairTable{}
	for _, table := range tables {
		byKind[table.kind] = table
	}
	run, ok := byKind["run"]
	if !ok {
		t.Fatal("missing the run repair table")
	}
	job, ok := byKind["job"]
	if !ok {
		t.Fatal("missing the job repair table")
	}

	// The RUN row lock is a plain 7-column runs read: it must not reference
	// jobs at all (no EXISTS, no join), because any job lock it carried could
	// be taken before the child locks that precede it.
	if strings.Contains(strings.ToLower(run.lockedSQL), "jobs") {
		t.Fatalf("run lockedSQL references jobs, so the run lock could wait on a job row: %s", run.lockedSQL)
	}
	if !strings.Contains(run.lockedSQL, "FROM runs WHERE id=$1 FOR UPDATE") {
		t.Fatalf("run lockedSQL is not a FOR UPDATE lock of the run row: %s", run.lockedSQL)
	}
	if strings.Contains(run.lockedSQL, "EXISTS") {
		t.Fatalf("run lockedSQL still carries the hasActiveChildren EXISTS: %s", run.lockedSQL)
	}
	// The run batch scan still classifies a run's active children in REPORT
	// mode (nothing is locked there, so the EXISTS is safe and required).
	if strings.Count(run.batchSQL, "FROM jobs j WHERE j.run_id = runs.id") != 1 {
		t.Fatalf("run batchSQL lost its active-child EXISTS: %s", run.batchSQL)
	}

	// A JOB is locked on its own job row, never through a run.
	if !strings.Contains(job.lockedSQL, "FROM jobs WHERE id=$1 FOR UPDATE") {
		t.Fatalf("job lockedSQL is not a FOR UPDATE lock of the job row: %s", job.lockedSQL)
	}
	if strings.Contains(job.lockedSQL, "runs") {
		t.Fatalf("job lockedSQL references runs: %s", job.lockedSQL)
	}

	// The child scan locks the run's non-terminal children in deterministic
	// id order and never locks the run (so it always runs BEFORE the run
	// lock).
	if !strings.Contains(repoIdentityRepairChildLockSQL, "FROM jobs WHERE run_id=$1") {
		t.Fatalf("child lock SQL is not scoped to the run's jobs: %s", repoIdentityRepairChildLockSQL)
	}
	if !strings.Contains(repoIdentityRepairChildLockSQL, "ORDER BY id ASC FOR UPDATE") {
		t.Fatalf("child lock SQL is not deterministic and lock-taking: %s", repoIdentityRepairChildLockSQL)
	}
	if strings.Contains(repoIdentityRepairChildLockSQL, "runs") {
		t.Fatalf("child lock SQL references the run row, so it could invert the order: %s", repoIdentityRepairChildLockSQL)
	}
	if !strings.Contains(repoIdentityRepairChildLockSQL, repoIdentityRepairNonTerminalJobsSQL) {
		t.Fatalf("child lock SQL does not use the shared non-terminal predicate: %s", repoIdentityRepairChildLockSQL)
	}
}
