package server

import (
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/kiwici/kiwi/internal/model"
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
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[jobID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !validLease(j, in.RunnerID, in.LeaseToken, in.LeaseGeneration) {
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
	}
	rep := in.Report
	rep.ID = newID()
	rep.RunID = j.RunID
	rep.JobID = j.ID
	rep.JobKey = j.Key
	rep.CreatedAt = time.Now().UTC()
	s.reports[rep.ID] = rep
	s.auditLocked("tests.uploaded", in.RunnerID, j.RunID, j.ID, "test report uploaded", map[string]string{"job": j.Key, "tests": strconv.Itoa(rep.Tests), "failures": strconv.Itoa(rep.Failures)})
	_ = s.persistLocked()
	writeJSON(w, http.StatusCreated, rep)
}

func (s *Server) listTestReports(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
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
func (s *Server) testIntelligence(w http.ResponseWriter, _ *http.Request) {
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
