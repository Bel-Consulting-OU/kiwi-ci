package server

// Real-PostgreSQL integration test for the DB-mode state gauges. Gated on
// KIWI_TEST_POSTGRES_URL via pgITServerSetup (skipped when unset, and in
// -short mode).
//
// It seeds the shared metrics dataset straight into the store (133 runs, 137
// jobs, 3 runners), scrapes /metrics through the real HTTP handler and proves
// the exposition equals the memory-mode exposition for the same data — with
// more runs than the old ListRuns(100) window and with jobs inside terminal
// runs, which the old DB path dropped.

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

func TestIntegrationMetricsPostgresServerAggregatesMatchMemory(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	ctx := context.Background()

	runs, jobs, runners := metricsStateDataset()
	for _, r := range runs {
		if err := st.InsertRun(ctx, r); err != nil {
			t.Fatalf("insert run %s: %v", r.ID, err)
		}
	}
	for _, j := range jobs {
		if err := st.InsertJob(ctx, j); err != nil {
			t.Fatalf("insert job %s: %v", j.ID, err)
		}
	}
	for _, r := range runners {
		if err := st.UpsertRunner(ctx, r); err != nil {
			t.Fatalf("upsert runner %s: %v", r.ID, err)
		}
	}

	w := pgITDo(t, s, http.MethodGet, "/metrics", "token", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("db metrics = %d: %s", w.Code, w.Body.String())
	}
	dbLines := stateGaugeLines(w.Body.String())
	if want := metricsStateExpectedLines(); !slices.Equal(dbLines, want) {
		t.Fatalf("db state gauges mismatch\ngot:  %v\nwant: %v", dbLines, want)
	}

	// Memory mode renders exactly the same state exposition for the same
	// data: DB and memory values agree, so the metric no longer changes
	// meaning with the backend.
	memSrv := New("token")
	memSrv.mu.Lock()
	for _, r := range runs {
		memSrv.runs[r.ID] = r
	}
	for _, j := range jobs {
		memSrv.jobs[j.ID] = j
	}
	for _, r := range runners {
		memSrv.runners[r.ID] = r
	}
	memSrv.mu.Unlock()
	memLines := stateGaugeLines(metricsScrapeBody(t, memSrv))
	if !slices.Equal(dbLines, memLines) {
		t.Fatalf("db/memory parity broken\ndb:  %v\nmem: %v", dbLines, memLines)
	}

	// The old DB source (ListRuns(100)) would have reported zero failure
	// runs; the aggregate reports all 30 across the whole table.
	listed, err := st.ListRuns(ctx, 100)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	sampled := map[model.Status]int{}
	for _, r := range listed {
		sampled[r.Status]++
	}
	if len(listed) != 100 || sampled[model.StatusFailure] != 0 {
		t.Fatalf("sampled view = %d runs, %d failures; want 100 runs / 0 failures (the regression case)",
			len(listed), sampled[model.StatusFailure])
	}
	if !slices.Contains(dbLines, `kiwi_runs{status="failure"} 30`) {
		t.Fatalf("aggregate failure runs missing from %v", dbLines)
	}
}
