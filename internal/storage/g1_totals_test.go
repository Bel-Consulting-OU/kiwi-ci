package storage

// G1-I: TestReportTotals must not cast its bigint SUMs to int4. Two reports
// each near the int32 ceiling used to make the aggregate click over the int4
// range and abort the whole totals query with 22003, losing every total for
// the repository. The sums stay bigint and narrow, clamped, at the API.

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestPostgresIntegrationTestReportTotalsBigCounts(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	const repoID = "github.com/kiwi-it/totals"
	const full = "kiwi-it/totals"
	base := time.Now().UTC().Truncate(time.Second)
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITHistoryRun(t, st, runID, jobID, repoID, full, base)
	for i := 0; i < 2; i++ {
		rep := model.TestReport{
			ID: pgITNewID(t), RunID: runID, JobKey: "build",
			Tests: math.MaxInt32, Cases: nil, CreatedAt: base.Add(time.Duration(i) * time.Second),
		}
		if _, err := st.InsertTestReportWithHistory(ctx, rep, repoID); err != nil {
			t.Fatalf("insert big report %d: %v", i, err)
		}
	}
	reports, tests, failures, err := st.TestReportTotals(ctx, []string{repoID}, "")
	if err != nil {
		t.Fatalf("TestReportTotals with near-max counts = %v", err)
	}
	if reports != 2 {
		t.Fatalf("reports = %d, want 2", reports)
	}
	if int64(tests) != 2*int64(math.MaxInt32) {
		t.Fatalf("tests total = %d, want %d (pre-fix the ::int cast raised 22003)", tests, 2*int64(math.MaxInt32))
	}
	if failures != 0 {
		t.Fatalf("failures = %d, want 0", failures)
	}
}

func TestMemStoreTestReportTotalsBigCounts(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	const repoID = "github.com/acme/totals"
	base := time.Now().UTC().Truncate(time.Second)
	const runID = "ccccccccccccccccccccccccccccccc0"
	if err := m.InsertRun(ctx, model.Run{ID: runID, PolicyRepoID: repoID, RepoID: repoID, Repo: "https://github.com/acme/totals.git", RepoFullName: "acme/totals", Status: model.StatusQueued, CreatedAt: base}); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	for i := 0; i < 2; i++ {
		rep := model.TestReport{
			ID: pgITNewID(t), RunID: runID, JobKey: "build",
			Tests: math.MaxInt32, CreatedAt: base.Add(time.Duration(i) * time.Second),
		}
		if _, err := m.InsertTestReportWithHistory(ctx, rep, repoID); err != nil {
			t.Fatalf("insert big report %d: %v", i, err)
		}
	}
	_, tests, _, err := m.TestReportTotals(ctx, []string{repoID}, "")
	if err != nil {
		t.Fatalf("mem TestReportTotals = %v", err)
	}
	if int64(tests) != 2*int64(math.MaxInt32) {
		t.Fatalf("mem tests total = %d, want %d", tests, 2*int64(math.MaxInt32))
	}
}
