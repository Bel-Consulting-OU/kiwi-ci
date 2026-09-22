package server

// E5-B endpoint half: the shared validator is authoritative for DIRECT /tests
// submissions too. Contradictory counters, oversized counters and undeclared
// failing cases are refused with 400 before any store call, a boundary-valid
// report is accepted, and nothing reaches the durable state on a refusal.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// e5RawUploadBody renders a /tests body with an EXACT client-supplied report
// (counters included), so the endpoint's validator — not the transport — is
// what accepts or refuses it.
func e5RawUploadBody(jobID string, rep map[string]any) string {
	b, _ := json.Marshal(map[string]any{
		"runner_id": "runner-a", "lease_token": "cache-lease-token", "lease_generation": 5,
		"report": rep,
	})
	return string(b)
}

// TestE5EndpointRejectsContradictoryDirectReports pins each contradiction at
// the HTTP boundary and proves the refusal is fail-closed: no report and no
// history are stored.
func TestE5EndpointRejectsContradictoryDirectReports(t *testing.T) {
	bad := []struct {
		name   string
		report map[string]any
		want   string
	}{
		{
			"failure and skip counters individually inside tests but summing over it",
			map[string]any{"tests": 10, "failures": 8, "skipped": 8},
			"failures+errors+skipped",
		},
		{
			"64-bit counter over the SQL int range",
			map[string]any{"tests": 3_000_000_000},
			"tests=3000000000",
		},
		{
			"fewer declared tests than materialized cases",
			map[string]any{"tests": 1, "cases": []map[string]any{{"name": "a", "passed": true}, {"name": "b", "passed": true}}},
			"materialized cases exceed the declared tests counter",
		},
		{
			"failing case with no failures declared",
			map[string]any{"tests": 1, "cases": []map[string]any{{"name": "a", "passed": false}}},
			"materialized failing cases exceed failures+errors",
		},
		{
			"skipped case with no skipped counter",
			map[string]any{"tests": 1, "cases": []map[string]any{{"name": "a", "skipped": true}}},
			"materialized skipped cases exceed the skipped counter",
		},
		{
			"case both passed and skipped",
			map[string]any{"tests": 1, "skipped": 1, "cases": []map[string]any{{"name": "a", "passed": true, "skipped": true}}},
			"both passed and skipped",
		},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
			w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", e5RawUploadBody("job-a", tc.report), hdrs)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("upload = %d, want 400: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("body = %q, want the reason %q", w.Body.String(), tc.want)
			}
			s.mu.Lock()
			reports := len(s.reports)
			s.mu.Unlock()
			if reports != 0 {
				t.Fatalf("refused report was persisted: %d reports", reports)
			}
			if flaky := s.flakyFromHistory("github.com/o/repo-a"); len(flaky) != 0 {
				t.Fatalf("refused report reached the history: %v", flaky)
			}
		})
	}

	// Boundary-valid: counters summing to exactly tests and cases explaining
	// the counters are accepted.
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
	boundary := e5RawUploadBody("job-a", map[string]any{
		"tests": 3, "failures": 1, "errors": 0, "skipped": 1, "duration": 1.5,
		"cases": []map[string]any{
			{"name": "ok", "class": "C", "duration": 0.5, "passed": true},
			{"name": "bad", "class": "C", "duration": 0.5, "passed": false},
			{"name": "skip", "class": "C", "duration": 0.5, "skipped": true},
		},
	})
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", boundary, hdrs)
	if w.Code != http.StatusCreated {
		t.Fatalf("boundary-valid upload = %d, want 201: %s", w.Code, w.Body.String())
	}
	var stored model.TestReport
	if err := json.Unmarshal(w.Body.Bytes(), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Tests != 3 || stored.Failures != 1 || stored.Skipped != 1 {
		t.Fatalf("stored counters = %+v", stored)
	}
}
