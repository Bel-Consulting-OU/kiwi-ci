package storage

// Real-PostgreSQL integration coverage for the downstream parent
// reverse-index lookup (DownstreamParentRunStore.ParentRunIDsForChild): the
// bounded, index-backed replacement for the old ListRuns(10000) parent scan.
// The second test EXPLAINs the exact production statement on a seeded volume
// and asserts it rides downstream_links_child_run_idx. Gated on
// KIWI_TEST_POSTGRES_URL like every *_it_test.go file.

import (
	"context"
	"crypto/md5"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestPostgresIntegrationParentRunIDsForChild(t *testing.T) {
	env := pgITSetup(t)
	st := env.open(t)
	env.migrate(t, st)
	ctx := context.Background()
	now := time.Now().UTC()

	parentA, parentB, childRun, otherChild := pgITNewID(t), pgITNewID(t), pgITNewID(t), pgITNewID(t)
	jobA, jobB := pgITNewID(t), pgITNewID(t)
	pgITRecSeedRun(t, st, parentA, model.StatusRunning, map[string]model.Job{jobA: pgITJob(parentA, jobA, pgITRepo)})
	pgITRecSeedRun(t, st, parentB, model.StatusRunning, map[string]model.Job{jobB: pgITJob(parentB, jobB, pgITRepo)})

	link := func(parentJob, targetRepo, child string) {
		t.Helper()
		if err := st.InsertDownstreamLink(ctx, DownstreamLink{
			ParentJobID: parentJob, TargetRepo: targetRepo, TargetRef: "refs/heads/main",
			LaunchToken: "tok", ChildRunID: child, CreatedAt: now,
		}); err != nil {
			t.Fatalf("InsertDownstreamLink(%s): %v", targetRepo, err)
		}
	}
	link(jobA, "acme/one", childRun)
	link(jobA, "acme/two", otherChild)
	link(jobB, "acme/three", childRun)
	// A second link of parent A to the same child must fold into one run ID.
	link(jobA, "acme/four", childRun)
	// A launched link whose parent job row is gone is dropped by the JOIN.
	if err := st.InsertDownstreamLink(ctx, DownstreamLink{
		ParentJobID: pgITNewID(t), TargetRepo: "acme/ghost", TargetRef: "refs/heads/main",
		LaunchToken: "tok", ChildRunID: childRun, CreatedAt: now,
	}); err != nil {
		t.Fatalf("InsertDownstreamLink(ghost): %v", err)
	}

	got, err := st.ParentRunIDsForChild(ctx, childRun)
	if err != nil {
		t.Fatalf("ParentRunIDsForChild: %v", err)
	}
	want := []string{parentA, parentB}
	sort.Strings(want)
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("ParentRunIDsForChild = %v; want %v ordered and distinct", got, want)
	}

	if got, err := st.ParentRunIDsForChild(ctx, otherChild); err != nil || len(got) != 1 || got[0] != parentA {
		t.Fatalf("other child = %v/%v; want [%s]", got, err, parentA)
	}
	if got, err := st.ParentRunIDsForChild(ctx, pgITNewID(t)); err != nil || len(got) != 0 {
		t.Fatalf("unknown child = %v/%v; want empty/nil", got, err)
	}
	if _, err := st.ParentRunIDsForChild(ctx, ""); err == nil {
		t.Fatal("empty child id must be rejected")
	}
}

// TestPostgresIntegrationParentRunIDsForChildUsesChildRunIndex seeds a
// production-scale downstream_links/jobs volume (12k+ filler runs/jobs/links,
// the shape that defeated the old 10k ListRuns scan), ANALYZEs the tables and
// EXPLAINs the exact production statement: the plan must resolve the child
// through downstream_links_child_run_idx, never a full enumeration.
func TestPostgresIntegrationParentRunIDsForChildUsesChildRunIndex(t *testing.T) {
	env := pgITSetup(t)
	st := env.open(t)
	env.migrate(t, st)
	ctx := context.Background()

	// Bulk-seed 12,000 filler runs/jobs/links plus two parent links to the
	// probed child. md5() yields canonical 32-hex IDs.
	if _, err := st.pool.Exec(ctx, `INSERT INTO runs (id, status, created_at, payload) SELECT md5('run'||i), 'success', now(), '{}'::jsonb FROM generate_series(1, 12000) AS i`); err != nil {
		t.Fatalf("seed runs: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `INSERT INTO jobs (id, run_id, key, status, created_at, payload) SELECT md5('job'||i), md5('run'||i), 'build', 'success', now(), '{}'::jsonb FROM generate_series(1, 12000) AS i`); err != nil {
		t.Fatalf("seed jobs: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `INSERT INTO downstream_links (parent_job_id, target_repo, target_ref, launch_token, child_run_id, created_at) SELECT md5('job'||i), 'acme/filler', 'refs/heads/main', 'tok', md5('filler-child'||i), now() FROM generate_series(1, 12000) AS i`); err != nil {
		t.Fatalf("seed links: %v", err)
	}
	probedChild := pgITNewID(t)
	if _, err := st.pool.Exec(ctx, `UPDATE downstream_links SET child_run_id=$1 WHERE parent_job_id IN (md5('job1'), md5('job2'))`, probedChild); err != nil {
		t.Fatalf("retarget links: %v", err)
	}
	// Fresh statistics so the planner estimates the child_run_id predicate
	// from the real data distribution (autovacuum has not necessarily run).
	if _, err := st.pool.Exec(ctx, `ANALYZE downstream_links`); err != nil {
		t.Fatalf("analyze downstream_links: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `ANALYZE jobs`); err != nil {
		t.Fatalf("analyze jobs: %v", err)
	}

	rows, err := st.pool.Query(ctx, "EXPLAIN (COSTS OFF) "+parentRunIDsForChildSQL, probedChild)
	if err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	defer rows.Close()
	var planLines []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("scan plan: %v", err)
		}
		planLines = append(planLines, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("plan rows: %v", err)
	}
	plan := strings.Join(planLines, "\n")
	t.Logf("EXPLAIN (COSTS OFF) %s -- $1=%s\n%s", parentRunIDsForChildSQL, probedChild, plan)
	if !strings.Contains(plan, "downstream_links_child_run_idx") {
		t.Fatalf("plan does not use downstream_links_child_run_idx:\n%s", plan)
	}

	// The probed child resolves exactly the two parent runs (md5('run1'),
	// md5('run2') for parent jobs md5('job1'), md5('job2')) through the
	// index; the 12k filler links are never enumerated.
	expect := []string{fmt.Sprintf("%x", md5.Sum([]byte("run1"))), fmt.Sprintf("%x", md5.Sum([]byte("run2")))}
	sort.Strings(expect)
	got, err := st.ParentRunIDsForChild(ctx, probedChild)
	if err != nil || len(got) != 2 || got[0] != expect[0] || got[1] != expect[1] {
		t.Fatalf("ParentRunIDsForChild = %v/%v; want %v", got, err, expect)
	}
}
