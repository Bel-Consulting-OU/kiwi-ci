package server

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func (s *Server) uploadTestReport(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	var in struct {
		RunnerID        string           `json:"runner_id"`
		LeaseToken      string           `json:"lease_token"`
		LeaseGeneration int64            `json:"lease_generation"`
		Report          model.TestReport `json:"report"`
	}
	if !decode(w, r, &in) {
		return
	}
	j, err := s.jobForLease(r.Context(), jobID)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !s.verifyRunnerIdentity(r, in.RunnerID) {
		http.Error(w, "runner identity mismatch", http.StatusForbidden)
		return
	}
	if !s.validActiveLease(j, in.RunnerID, in.LeaseToken, in.LeaseGeneration, time.Now().UTC()) {
		http.Error(w, "stale or invalid lease", http.StatusConflict)
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
	// Persistent test history: every uploaded case feeds the flaky/sharding
	// model, and the history file is the durable store in both modes.
	repo := ""
	if s.DB != nil {
		if run, gerr := s.DB.GetRun(r.Context(), j.RunID); gerr == nil {
			repo = run.RepoFullName
		}
	} else {
		s.mu.Lock()
		if run, ok := s.runs[j.RunID]; ok {
			repo = run.RepoFullName
		}
		s.mu.Unlock()
	}
	for _, c := range rep.Cases {
		s.metricObserve("kiwi_test_duration_seconds", c.Duration, nil)
	}
	s.recordTestReportHistory(repo, rep)
	if s.DB != nil {
		if err := s.DB.InsertTestReport(r.Context(), rep); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		s.auditLocked("tests.uploaded", in.RunnerID, j.RunID, j.ID, "test report uploaded", map[string]string{"job": j.Key, "tests": strconv.Itoa(rep.Tests), "failures": strconv.Itoa(rep.Failures)})
		writeJSON(w, http.StatusCreated, rep)
		return
	}
	s.mu.Lock()
	s.reports[rep.ID] = rep
	s.auditLocked("tests.uploaded", in.RunnerID, j.RunID, j.ID, "test report uploaded", map[string]string{"job": j.Key, "tests": strconv.Itoa(rep.Tests), "failures": strconv.Itoa(rep.Failures)})
	_ = s.persistLocked()
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, rep)
}

func (s *Server) listTestReports(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	if s.DB != nil {
		if _, err := s.DB.GetRun(r.Context(), runID); errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		} else if err != nil {
			http.Error(w, err.Error(), 500)
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
	if _, ok := s.runs[runID]; !ok {
		http.NotFound(w, r)
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
// repository. The repo query parameter is required: reports are keyed by
// run, and the run's RepoFullName scopes the aggregation so a control plane
// hosting many repositories never leaks cross-repo test history.
func (s *Server) testIntelligence(w http.ResponseWriter, r *http.Request) {
	repo := r.URL.Query().Get("repo")
	if repo == "" {
		http.Error(w, "repo query parameter is required (e.g. ?repo=owner/name)", http.StatusBadRequest)
		return
	}
	if s.DB != nil {
		reports, err := s.DB.ListTestReportsAll(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		filtered := make([]model.TestReport, 0, len(reports))
		for _, rep := range reports {
			run, gerr := s.DB.GetRun(r.Context(), rep.RunID)
			if gerr == nil && run.RepoFullName == repo {
				filtered = append(filtered, rep)
			}
		}
		out := summarizeTestIntelligence(filtered)
		out["repo"] = repo
		s.mergeHistoryFlaky(repo, out)
		writeJSON(w, http.StatusOK, out)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	filtered := []model.TestReport{}
	for _, rep := range s.reports {
		if run, ok := s.runs[rep.RunID]; ok && run.RepoFullName == repo {
			filtered = append(filtered, rep)
		}
	}
	out := summarizeTestIntelligence(filtered)
	out["repo"] = repo
	s.mergeHistoryFlaky(repo, out)
	writeJSON(w, http.StatusOK, out)
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
// history's flaky set for a repository.
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
