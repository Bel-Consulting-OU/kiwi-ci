package storage

// Real-PostgreSQL integration coverage for the test-history error and
// degenerate-input branches: missing relations (outage, not "empty
// history"), malformed persisted rows (JSONB that does not decode as the
// expected shape), empty identifiers and the bounded enumeration's query
// failures. Every case asserts the fail-closed outcome AND that a healthy
// read still works where the schema allows it.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestPostgresIntegrationTestHistoryMissingRelationErrors proves the scoped
// reads distinguish "no history" from "the relation is gone": a dropped
// relation surfaces an error on every entry point instead of silently
// reporting empty history.
func TestPostgresIntegrationTestHistoryMissingRelationErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("repos-relation", func(t *testing.T) {
		st := pgITStore(t)
		if _, err := st.pool.Exec(ctx, `DROP TABLE test_history_repos`); err != nil {
			t.Fatalf("drop test_history_repos: %v", err)
		}
		if v, stats, err := st.LoadRepoTestHistory(ctx, "github.com/kiwi-it/x"); err == nil || v != 0 || stats != nil {
			t.Fatalf("LoadRepoTestHistory after drop = (%d, %v, %v), want an error", v, stats, err)
		}
		if _, err := st.RebuildRepoTestHistory(ctx, "github.com/kiwi-it/x"); err == nil {
			t.Fatal("RebuildRepoTestHistory after drop must error")
		}
	})

	t.Run("aggregates-relation", func(t *testing.T) {
		st := pgITStore(t)
		repo, full := "github.com/kiwi-it/agg-drop", "kiwi-it/agg-drop"
		runID, jobID := pgITNewID(t), pgITNewID(t)
		base := time.Now().UTC().Truncate(time.Second)
		pgITHistoryRun(t, st, runID, jobID, repo, full, base)
		if _, err := st.InsertTestReportWithHistory(ctx, pgITHistoryReport(runID, pgITNewID(t), base, model.TestResult{Name: "t", Passed: true}), repo); err != nil {
			t.Fatal(err)
		}
		// The version row exists but the aggregate relation is gone: the
		// load must report the outage rather than a version-0 rebuild hint.
		if _, err := st.pool.Exec(ctx, `DROP TABLE test_history_aggregates`); err != nil {
			t.Fatalf("drop aggregates: %v", err)
		}
		if _, _, err := st.LoadRepoTestHistory(ctx, repo); err == nil {
			t.Fatal("LoadRepoTestHistory with a dropped aggregate relation must error")
		}
		if _, err := st.RebuildRepoTestHistory(ctx, repo); err == nil {
			t.Fatal("RebuildRepoTestHistory with a dropped aggregate relation must error")
		}
		if _, err := st.FlakyTestNames(ctx, []string{repo}, 10); err == nil {
			t.Fatal("FlakyTestNames with a dropped aggregate relation must error")
		}
	})

	t.Run("runs-relation", func(t *testing.T) {
		st := pgITStore(t)
		if _, err := st.pool.Exec(ctx, `DROP TABLE runs CASCADE`); err != nil {
			t.Fatalf("drop runs: %v", err)
		}
		if _, err := st.ResolveTestHistoryRepoIDs(ctx, "o/r", 10); err == nil {
			t.Fatal("ResolveTestHistoryRepoIDs after dropping runs must error")
		}
		if _, _, _, err := st.TestReportTotals(ctx, []string{"github.com/o/r"}, "o/r"); err == nil {
			t.Fatal("TestReportTotals after dropping runs must error")
		}
		if _, err := st.ListTestHistoryRepoIDs(ctx, 10); err == nil {
			t.Fatal("ListTestHistoryRepoIDs after dropping runs must error")
		}
	})
}

// TestPostgresIntegrationTestHistoryCorruptAggregateRows proves a persisted
// outcomes value that is valid JSONB but not the expected []bool is reported
// (never silently treated as an empty window), both by the read path and by
// the incremental fold that would rewrite it.
func TestPostgresIntegrationTestHistoryCorruptAggregateRows(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo, full := "github.com/kiwi-it/corrupt-agg", "kiwi-it/corrupt-agg"
	base := time.Now().UTC().Truncate(time.Second)
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITHistoryRun(t, st, runID, jobID, repo, full, base)
	if _, err := st.InsertTestReportWithHistory(ctx, pgITHistoryReport(runID, pgITNewID(t), base, model.TestResult{Name: "t", Passed: true}), repo); err != nil {
		t.Fatal(err)
	}
	// Plant a shape the fold cannot decode (an object where the window
	// expects an array of booleans).
	if _, err := st.pool.Exec(ctx, `UPDATE test_history_aggregates SET outcomes='{"bad":true}'::jsonb WHERE repo_id=$1 AND test_name='t'`, repo); err != nil {
		t.Fatalf("plant corrupt outcomes: %v", err)
	}
	if _, _, err := st.LoadRepoTestHistory(ctx, repo); err == nil {
		t.Fatal("LoadRepoTestHistory accepted a corrupt outcomes window")
	}
	// The incremental fold reads the same row FOR UPDATE and must fail
	// rather than fold on top of garbage.
	rep := pgITHistoryReport(runID, pgITNewID(t), base.Add(time.Second), model.TestResult{Name: "t", Passed: true})
	if _, err := st.InsertTestReportWithHistory(ctx, rep, repo); err == nil {
		t.Fatal("InsertTestReportWithHistory folded onto a corrupt outcomes window")
	}
	// The failed upload rolled back: no report row and no version bump.
	if n := pgITHistoryReportCount(t, st, rep.ID); n != 0 {
		t.Fatalf("failed fold persisted %d report row(s)", n)
	}
}

// TestPostgresIntegrationTestHistoryCorruptReportPayloadRebuild proves the
// explicit rebuild fails on a report payload that does not decode as
// model.TestReport instead of folding a partial report.
func TestPostgresIntegrationTestHistoryCorruptReportPayloadRebuild(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	repo, full := "github.com/kiwi-it/corrupt-rebuild", "kiwi-it/corrupt-rebuild"
	base := time.Now().UTC().Truncate(time.Second)
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITHistoryRun(t, st, runID, jobID, repo, full, base)
	if _, err := st.pool.Exec(ctx, `INSERT INTO test_results (id, run_id, job_key, created_at, payload) VALUES ($1, $2, 'build', $3, '{"cases":"boom"}'::jsonb)`,
		pgITNewID(t), runID, base); err != nil {
		t.Fatalf("plant corrupt report: %v", err)
	}
	if _, err := st.RebuildRepoTestHistory(ctx, repo); err == nil {
		t.Fatal("RebuildRepoTestHistory folded a corrupt report payload")
	}
}

// TestPostgresIntegrationTestHistoryEmptyIdentifiers pins the degenerate
// inputs that must answer without touching the database.
func TestPostgresIntegrationTestHistoryEmptyIdentifiers(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	if v, stats, err := st.LoadRepoTestHistory(ctx, "   "); err != nil || v != 0 || stats != nil {
		t.Fatalf("blank repository = (%d, %v, %v), want the empty answer", v, stats, err)
	}
	if _, err := st.RebuildRepoTestHistory(ctx, "  "); err == nil {
		t.Fatal("blank repository rebuild accepted")
	}
	if _, err := st.ResolveTestHistoryRepoIDs(ctx, "   ", 10); err != nil {
		t.Fatalf("blank query = %v, want the empty answer", err)
	}
	// Blank/nil repository sets answer empty without a query.
	if reports, tests, failures, err := st.TestReportTotals(ctx, []string{"", "  "}, "q"); err != nil || reports != 0 || tests != 0 || failures != 0 {
		t.Fatalf("blank id set = (%d, %d, %d, %v)", reports, tests, failures, err)
	}
	if names, err := st.FlakyTestNames(ctx, nil, 10); err != nil || names == nil || len(names) != 0 {
		t.Fatalf("nil id set = (%v, %v)", names, err)
	}
	// A non-positive limit is clamped (not an error, not an unbounded read):
	// no flaky rows exist yet, so the answer is empty either way.
	if names, err := st.FlakyTestNames(ctx, []string{"github.com/kiwi-it/none"}, 0); err != nil || len(names) != 0 {
		t.Fatalf("zero limit = (%v, %v)", names, err)
	}
	if ids, err := st.ListTestHistoryRepoIDs(ctx, 0); err != nil || len(ids) != 0 {
		t.Fatalf("empty enumeration = (%v, %v)", ids, err)
	}
}

// TestPostgresIntegrationTestHistoryListIDsRelationDrop covers the
// enumeration's per-page query failure: dropping the report relation makes
// the keyset query fail before any page can be considered complete.
func TestPostgresIntegrationTestHistoryListIDsRelationDrop(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	if _, err := st.pool.Exec(ctx, `DROP TABLE test_results CASCADE`); err != nil {
		t.Fatalf("drop test_results: %v", err)
	}
	if _, err := st.ListTestHistoryRepoIDs(ctx, 5); err == nil || !strings.Contains(err.Error(), "test_results") {
		t.Fatalf("enumeration after drop = %v, want a relation error", err)
	}
}
