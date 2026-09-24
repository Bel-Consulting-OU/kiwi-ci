package storage

// G1-E: the incremental history fold must be order-insensitive relative to
// the created_at/id rebuild. Committing a report whose created_at precedes an
// already-folded report must not leave the live aggregates drifted from what
// a rebuild (or a restart with a repair) produces. Both the PostgreSQL and
// the in-memory store must rebuild in that case and agree.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

// g1HistoryExpected folds reports in canonical (created_at,id) order into the
// reference testintel history for repoID and returns it as a stats map (the
// same persisted JSON shape LoadRepoTestHistory decodes).
func g1HistoryExpected(t *testing.T, repoID string, reports []model.TestReport) map[string]testintel.TestStat {
	t.Helper()
	ordered := append([]model.TestReport(nil), reports...)
	for i := 0; i < len(ordered); i++ {
		for j := i + 1; j < len(ordered); j++ {
			si, sj := ordered[i], ordered[j]
			if si.CreatedAt.After(sj.CreatedAt) || (si.CreatedAt.Equal(sj.CreatedAt) && si.ID > sj.ID) {
				ordered[i], ordered[j] = ordered[j], ordered[i]
			}
		}
	}
	h := testintel.NewHistory()
	for _, rep := range ordered {
		for _, c := range rep.Cases {
			if c.Skipped {
				continue
			}
			h.Record(repoID, rep.JobKey, c.Class, c.Name, c.Duration, c.Passed, rep.CreatedAt)
		}
	}
	path := filepath.Join(t.TempDir(), "expected-history.json")
	if err := h.Save(path); err != nil {
		t.Fatalf("save expected history: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]testintel.TestStat{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestMemStoreHistoryOutOfOrderFoldMatchesRebuild is the in-memory half.
func TestMemStoreHistoryOutOfOrderFoldMatchesRebuild(t *testing.T) {
	ctx := context.Background()
	m := newMemStore()
	const repoID = "github.com/acme/widget"
	base := time.Now().UTC().Truncate(time.Second)
	const runID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0"
	if err := m.InsertRun(ctx, model.Run{ID: runID, PolicyRepoID: repoID, RepoID: repoID, Repo: "https://github.com/acme/widget.git", RepoFullName: "acme/widget", Status: model.StatusQueued, CreatedAt: base}); err != nil {
		t.Fatalf("seed run: %v", err)
	}
	newer := pgITHistoryReport(runID, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0", base.Add(time.Minute),
		model.TestResult{Name: "t", Duration: 10, Passed: true})
	older := pgITHistoryReport(runID, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1", base,
		model.TestResult{Name: "t", Duration: 1, Passed: false})
	// Commit NEWER first, then the OLDER report: the arrival order is the
	// reverse of the canonical created_at order.
	for _, rep := range []model.TestReport{newer, older} {
		if _, err := m.InsertTestReportWithHistory(ctx, rep, repoID); err != nil {
			t.Fatalf("insert report %s: %v", rep.ID, err)
		}
	}
	want := g1HistoryExpected(t, repoID, []model.TestReport{newer, older})
	if got := memHistoryStats(t, m, repoID); !reflect.DeepEqual(want, got) {
		t.Fatalf("out-of-order incremental fold diverged from the canonical fold:\nwant %+v\ngot  %+v", want, got)
	}
	if _, err := m.RebuildRepoTestHistory(ctx, repoID); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if got := memHistoryStats(t, m, repoID); !reflect.DeepEqual(want, got) {
		t.Fatalf("mem rebuild diverged from the canonical fold:\nwant %+v\ngot  %+v", want, got)
	}
}

func memHistoryStats(t *testing.T, m *memStore, repoID string) map[string]testintel.TestStat {
	t.Helper()
	_, stats, err := m.LoadRepoTestHistory(context.Background(), repoID)
	if err != nil {
		t.Fatalf("load repo history: %v", err)
	}
	out := map[string]testintel.TestStat{}
	if len(stats) == 0 {
		return out
	}
	if err := json.Unmarshal(stats, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestPostgresIntegrationHistoryOutOfOrderFoldMatchesRebuild is the live-PG
// half: the same reverse-order commit must produce the canonical fold.
func TestPostgresIntegrationHistoryOutOfOrderFoldMatchesRebuild(t *testing.T) {
	st := pgITStore(t)
	ctx := context.Background()
	const repoID = "github.com/kiwi-it/order"
	const full = "kiwi-it/order"
	base := time.Now().UTC().Truncate(time.Second)
	runID, jobID := pgITNewID(t), pgITNewID(t)
	pgITHistoryRun(t, st, runID, jobID, repoID, full, base)
	newer := pgITHistoryReport(runID, pgITNewID(t), base.Add(time.Minute),
		model.TestResult{Name: "t", Duration: 10, Passed: true})
	older := pgITHistoryReport(runID, pgITNewID(t), base,
		model.TestResult{Name: "t", Duration: 1, Passed: false})
	for _, rep := range []model.TestReport{newer, older} {
		if _, err := st.InsertTestReportWithHistory(ctx, rep, repoID); err != nil {
			t.Fatalf("insert report %s: %v", rep.ID, err)
		}
	}
	want := g1HistoryExpected(t, repoID, []model.TestReport{newer, older})
	if got := pgITHistoryStats(t, st, repoID); !reflect.DeepEqual(want, got) {
		t.Fatalf("out-of-order incremental fold diverged from the canonical fold:\nwant %+v\ngot  %+v", want, got)
	}
	if _, err := st.RebuildRepoTestHistory(ctx, repoID); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if got := pgITHistoryStats(t, st, repoID); !reflect.DeepEqual(want, got) {
		t.Fatalf("SQL rebuild diverged from the canonical fold:\nwant %+v\ngot  %+v", want, got)
	}
}
