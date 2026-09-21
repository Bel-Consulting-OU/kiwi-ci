package server

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestTestReportUploadRunLookupFailsClosed proves the report upload refuses
// to record the durable report OR any test history when the authoritative
// run lookup fails or the run is missing: the zero-valued run would key the
// history under an empty repository and merge unrelated repositories' test
// history. DB store error, missing DB row and missing memory run entry all
// fail the upload closed.
func TestTestReportUploadRunLookupFailsClosed(t *testing.T) {
	fault := errors.New("run read down")
	t.Run("db store error", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		s.DB = &fcStore{dbFakeStore: f, getRunErr: fault}
		w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok",
			fcReportBody("job-a", model.TestResult{Name: "t1", Passed: true}), hdrs)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("upload with failing GetRun = %d, want 503: %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), fault.Error()) {
			t.Fatalf("response leaked the raw store error: %q", w.Body.String())
		}
		f.mu.Lock()
		reports, version := len(f.reports), f.testHistoryVersion
		f.mu.Unlock()
		if reports != 0 || version != 0 {
			t.Fatalf("failed upload persisted reports=%d history_version=%d, want none", reports, version)
		}
	})
	t.Run("db run missing", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		f.mu.Lock()
		delete(f.runs, "run-c")
		f.mu.Unlock()
		w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok",
			fcReportBody("job-a", model.TestResult{Name: "t1", Passed: true}), hdrs)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("upload with missing run = %d, want 503: %s", w.Code, w.Body.String())
		}
		f.mu.Lock()
		reports, version := len(f.reports), f.testHistoryVersion
		f.mu.Unlock()
		if reports != 0 || version != 0 {
			t.Fatalf("missing-run upload persisted reports=%d history_version=%d, want none", reports, version)
		}
	})
	t.Run("memory run missing", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t)
		s.mu.Lock()
		delete(s.runs, "run-c")
		s.mu.Unlock()
		w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok",
			fcReportBody("job-a", model.TestResult{Name: "t1", Passed: true}), hdrs)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("memory upload with missing run = %d, want 503: %s", w.Code, w.Body.String())
		}
		s.mu.Lock()
		reports := len(s.reports)
		s.mu.Unlock()
		if reports != 0 {
			t.Fatalf("memory reports = %d, want 0", reports)
		}
		// The history fold (and its file commit) never ran.
		if _, err := os.Stat(filepath.Join(s.dataDir, testHistoryFile)); err == nil {
			t.Fatal("history file was committed for a report with no authoritative run")
		}
	})
}
