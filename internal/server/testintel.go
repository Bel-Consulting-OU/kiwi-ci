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

// testIntelligence is the v0.1 foundation for flaky-test history: it reports
// tests whose outcome changed across runs, plus report volume and totals.
func (s *Server) testIntelligence(w http.ResponseWriter, r *http.Request) {
	if s.DB != nil {
		reports, err := s.DB.ListTestReportsAll(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, http.StatusOK, summarizeTestIntelligence(reports))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	history := map[string][]bool{}
	totals := map[string]model.TestReport{}
	var tests, failures int
	for _, rep := range s.reports {
		tests += rep.Tests
		failures += rep.Failures
		for _, c := range rep.Cases {
			key := c.Name
			if c.Class != "" {
				key = c.Class + "." + c.Name
			}
			history[key] = append(history[key], c.Passed)
		}
		totals[rep.ID] = rep
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
	writeJSON(w, http.StatusOK, map[string]any{
		"reports":     len(s.reports),
		"total_tests": tests,
		"failures":    failures,
		"flaky_tests": flaky,
	})
}

// summarizeTestIntelligence computes the flaky-test summary from an explicit
// report list (the DB path).
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
