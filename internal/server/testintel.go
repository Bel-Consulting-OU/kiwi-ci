package server

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func (s *Server) uploadTestReport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RunnerID        string           `json:"runner_id"`
		LeaseToken      string           `json:"lease_token"`
		LeaseGeneration int64            `json:"lease_generation"`
		Report          model.TestReport `json:"report"`
	}
	if !decode(w, r, &in) {
		return
	}
	j, authErr := s.authorizeRunnerLease(r, in.RunnerID, in.LeaseToken, in.LeaseGeneration)
	if authErr != nil {
		s.writeLeaseAuthError(w, r, authErr)
		return
	}
	rep := in.Report
	id, err := newID()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	rep.ID = id
	rep.RunID = j.RunID
	rep.JobID = j.ID
	rep.JobKey = j.Key
	rep.CreatedAt = time.Now().UTC()
	repo := ""
	if s.DB != nil {
		if run, gerr := s.DB.GetRun(r.Context(), j.RunID); gerr == nil {
			repo = repoIDForRun(run)
		}
	} else {
		s.mu.Lock()
		if run, ok := s.runs[j.RunID]; ok {
			repo = repoIDForRun(run)
		}
		s.mu.Unlock()
	}
	for _, c := range rep.Cases {
		s.metricObserve("kiwi_test_duration_seconds", c.Duration, nil)
	}
	// The durable report commits FIRST; the test-history update follows in
	// the same flow so a failed history write can never lose the report.
	if s.DB != nil {
		if err := s.DB.InsertTestReport(r.Context(), rep); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		s.recordTestReportHistory(repo, rep)
		s.auditLocked("tests.uploaded", in.RunnerID, j.RunID, j.ID, "test report uploaded", map[string]string{"job": j.Key, "tests": strconv.Itoa(rep.Tests), "failures": strconv.Itoa(rep.Failures)})
		writeJSON(w, http.StatusCreated, rep)
		return
	}
	s.mu.Lock()
	s.reports[rep.ID] = rep
	perr := s.persistCheckedErrLocked("test.report")
	if perr != nil {
		// The report never became durable: remove the in-memory ghost so a
		// later successful persist cannot commit a report the runner was
		// told failed, and the retry stores exactly one.
		delete(s.reports, rep.ID)
		s.mu.Unlock()
		http.Error(w, perr.Error(), 500)
		return
	}
	s.mu.Unlock()
	s.recordTestReportHistory(repo, rep)
	s.auditLocked("tests.uploaded", in.RunnerID, j.RunID, j.ID, "test report uploaded", map[string]string{"job": j.Key, "tests": strconv.Itoa(rep.Tests), "failures": strconv.Itoa(rep.Failures)})
	writeJSON(w, http.StatusCreated, rep)
}

func (s *Server) listTestReports(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	if s.DB != nil {
		run, err := s.DB.GetRun(r.Context(), runID)
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		} else if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if !s.requireRunRead(w, r, run) {
			return
		}
		out, err := s.DB.ListTestReports(r.Context(), runID)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[runID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !s.requireRunRead(w, r, run) {
		return
	}
	out := []model.TestReport{}
	for _, rep := range s.reports {
		if rep.RunID == runID {
			out = append(out, rep)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	writeJSON(w, http.StatusOK, out)
}

// testIntelligence reports flaky-test history and report volume for one
// repository. The repo query parameter is required and accepts the
// human-readable full name, the canonical RepoID or the legacy canonical
// form: reports are keyed by run and matched through the run's canonical
// repository identity, so a control plane hosting many repositories — or
// two forges presenting the same bare name — never leaks cross-repo test
// history.
func (s *Server) testIntelligence(w http.ResponseWriter, r *http.Request) {
	repo := r.URL.Query().Get("repo")
	if repo == "" {
		http.Error(w, "repo query parameter is required (e.g. ?repo=owner/name)", http.StatusBadRequest)
		return
	}
	if !s.requireAction(w, r, auth.ActionRead, auth.CanonicalRepoID("", repo), false) {
		return
	}
	if !s.repoVisibleByName(r, repo) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	historyKeys := map[string]bool{repo: true}
	if s.DB != nil {
		s.syncTestHistoryDB(r.Context())
		reports, err := s.DB.ListTestReportsAll(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		filtered := make([]model.TestReport, 0, len(reports))
		for _, rep := range reports {
			run, gerr := s.DB.GetRun(r.Context(), rep.RunID)
			if gerr == nil && runMatchesRepoQuery(run, repo) {
				filtered = append(filtered, rep)
				historyKeys[repoIDForRun(run)] = true
			}
		}
		out := summarizeTestIntelligence(filtered)
		out["repo"] = repo
		s.mergeHistoryFlakyKeys(historyKeys, out)
		writeJSON(w, http.StatusOK, out)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	filtered := []model.TestReport{}
	for _, rep := range s.reports {
		if run, ok := s.runs[rep.RunID]; ok && runMatchesRepoQuery(run, repo) {
			filtered = append(filtered, rep)
			historyKeys[repoIDForRun(run)] = true
		}
	}
	out := summarizeTestIntelligence(filtered)
	out["repo"] = repo
	s.mergeHistoryFlakyKeys(historyKeys, out)
	writeJSON(w, http.StatusOK, out)
}

// runMatchesRepoQuery reports whether a test-intelligence query addresses a
// run's repository. The query may be the human-readable full name, the
// canonical RepoID, or the legacy host-less canonical form.
func runMatchesRepoQuery(run model.Run, query string) bool {
	query = strings.TrimSpace(query)
	if query == "" {
		return false
	}
	if query == run.RepoFullName || query == repoIDForRun(run) {
		return true
	}
	return query == auth.CanonicalRepoID("", run.RepoFullName)
}

// summarizeTestIntelligence computes the flaky-test summary from an explicit
// report list (both the DB and the in-memory path feed pre-filtered lists).
func summarizeTestIntelligence(reports []model.TestReport) map[string]any {
	history := map[string][]bool{}
	var tests, failures int
	for _, rep := range reports {
		tests += rep.Tests
		failures += rep.Failures
		for _, c := range rep.Cases {
			key := c.Name
			if c.Class != "" {
				key = c.Class + "." + c.Name
			}
			history[key] = append(history[key], c.Passed)
		}
	}
	flaky := []string{}
	for name, results := range history {
		var pass, fail bool
		for _, ok := range results {
			if ok {
				pass = true
			} else {
				fail = true
			}
		}
		if pass && fail {
			flaky = append(flaky, name)
		}
	}
	sort.Strings(flaky)
	return map[string]any{
		"reports":     len(reports),
		"total_tests": tests,
		"failures":    failures,
		"flaky_tests": flaky,
	}
}

// mergeHistoryFlaky unions the report-derived flaky set with the persisted
// history's flaky set for one repository key.
func (s *Server) mergeHistoryFlaky(repo string, out map[string]any) {
	existing, _ := out["flaky_tests"].([]string)
	seen := map[string]bool{}
	for _, name := range existing {
		seen[name] = true
	}
	for _, name := range s.flakyFromHistory(repo) {
		if !seen[name] {
			seen[name] = true
			existing = append(existing, name)
		}
	}
	sort.Strings(existing)
	out["flaky_tests"] = existing
}

// mergeHistoryFlakyKeys unions the persisted flaky set over every canonical
// history key a query matched.
func (s *Server) mergeHistoryFlakyKeys(keys map[string]bool, out map[string]any) {
	for key := range keys {
		s.mergeHistoryFlaky(key, out)
	}
}
