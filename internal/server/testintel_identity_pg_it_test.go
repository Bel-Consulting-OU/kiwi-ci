package server

// Real-PostgreSQL integration test for the D4-B/D4-C ingestion boundary: a
// lease-authenticated /tests submission carrying an oversized testcase
// identity or an impossible numeric relation is rejected by the shared
// validator BEFORE any SQL statement, so no test_results row and no
// test_history_aggregates row can ever carry an unindexable key or garbage
// counters. A boundary-valid report still commits.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

// pgITUploadRawReport uploads one arbitrary report for a leased task.
func pgITUploadRawReport(t *testing.T, s *Server, runnerID string, task Task, rep model.TestReport) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"runner_id": runnerID, "lease_token": task.LeaseToken, "lease_generation": task.LeaseGeneration, "report": rep,
	})
	if err != nil {
		t.Fatal(err)
	}
	return pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/tests", "token", string(raw), nil)
}

func TestPostgresIntegrationServerRejectsReportIdentityAndNumbersBeforeSQL(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	runnerID := pgITRegisterRunner(t, s)
	run := pgITSubmit(t, s, pgITServerPipeline)
	task := pgITNext(t, s, runnerID)
	runID := task.Job.RunID

	rejected := []struct {
		name   string
		rep    model.TestReport
		reason string
	}{
		{
			"oversized testcase name",
			model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: strings.Repeat("n", testintel.MaxTestNameBytes+1), Passed: true}}},
			"name budget",
		},
		{
			"oversized testcase class",
			model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: "t", Class: strings.Repeat("c", testintel.MaxTestClassBytes+1), Passed: true}}},
			"class budget",
		},
		{
			"impossible counter relation",
			model.TestReport{Tests: 1, Failures: 1, Errors: 1},
			"failures+errors",
		},
		{
			"absurd duration",
			model.TestReport{Tests: 1, Duration: 1e18},
			"report duration",
		},
	}
	for _, tc := range rejected {
		w := pgITUploadRawReport(t, s, runnerID, task, tc.rep)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 400: %s", tc.name, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), tc.reason) {
			t.Fatalf("%s rejection = %q, want reason %q", tc.name, w.Body.String(), tc.reason)
		}
	}
	// Nothing reached SQL.
	ctx := context.Background()
	reports, err := st.ListTestReports(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 0 {
		t.Fatalf("rejected uploads wrote %d test_results rows, want 0", len(reports))
	}
	canonical := storage.RepoIDForRun(run)
	if canonical == "" {
		t.Fatal("submitted run has no canonical repository identity")
	}
	version, stats, err := st.LoadRepoTestHistory(ctx, canonical)
	if err != nil {
		t.Fatal(err)
	}
	if version != 0 || len(stats) != 0 {
		t.Fatalf("rejected uploads folded history: version=%d stats=%d", version, len(stats))
	}

	// Boundary-valid identity and counters commit normally.
	at := model.TestReport{Tests: 1, Cases: []model.TestResult{{Name: strings.Repeat("n", testintel.MaxTestNameBytes), Passed: false}}}
	if w := pgITUploadRawReport(t, s, runnerID, task, at); w.Code != http.StatusCreated {
		t.Fatalf("boundary report upload = %d: %s", w.Code, w.Body.String())
	}
	reports, err = st.ListTestReports(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 {
		t.Fatalf("boundary report rows = %d, want 1", len(reports))
	}
}
