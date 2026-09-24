package server

// G1-B: the memory/fs-mode deterministic report identity must be scoped by
// the authoritative (job, lease generation) just like the durable delivery
// table. Two jobs that reuse one delivery_id must store two reports, not have
// the second silently dropped (pre-fix: 200 returning the FIRST job's report
// body) or refused as a conflict. DB mode already keys the receipt by
// (job_id, lease_generation, delivery_id) and must keep storing both.

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// g1SeedLeasedJob installs one running job with a valid lease into the
// fs/memory server state and returns its lease headers. Unlike seedCacheJob
// it lets a test own the job/run/runner IDs and the lease generation.
func g1SeedLeasedJob(t *testing.T, s *Server, jobID, runID, runnerID, repoURL, repoFullName string, gen int64) map[string]string {
	t.Helper()
	raw := "g1-token-" + jobID
	exp := time.Now().UTC().Add(time.Hour)
	s.mu.Lock()
	s.runs[runID] = model.Run{ID: runID, Repo: repoURL, RepoFullName: repoFullName, Status: model.StatusRunning}
	s.jobs[jobID] = model.Job{ID: jobID, RunID: runID, Key: "build", RepoURL: repoURL, RepoFullName: repoFullName,
		Status: model.StatusRunning, Trusted: true, LeaseRunnerID: runnerID,
		LeaseTokenHash: hashLeaseToken(s.leaseKey, raw), LeaseGeneration: gen, LeaseExpiresAt: &exp}
	s.runners[runnerID] = model.Runner{ID: runnerID, Name: runnerID, Capacity: 1}
	s.mu.Unlock()
	return map[string]string{"X-Kiwi-Runner-ID": runnerID, "X-Kiwi-Lease-Token": raw, "X-Kiwi-Lease-Generation": strconv.FormatInt(gen, 10)}
}

// TestMemoryReportDeliveryScopedByJob pins the cross-job collision in fs
// mode, for both identical and different reused content.
func TestMemoryReportDeliveryScopedByJob(t *testing.T) {
	const shared = "shared-delivery-id"
	casesA := []model.TestResult{{Name: "A", Class: "C", Duration: 1, Passed: true}}
	casesB := []model.TestResult{{Name: "B", Class: "C", Duration: 2, Passed: true}}
	for _, tc := range []struct {
		name  string
		cases []model.TestResult
	}{
		{"identical content", casesA},
		{"different content", casesB},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			hdrsA := g1SeedLeasedJob(t, s, "job-a", "run-a", "runner-a", "https://github.com/o/repo.git", "o/repo", 5)
			hdrsB := g1SeedLeasedJob(t, s, "job-b", "run-b", "runner-b", "https://github.com/o/repo.git", "o/repo", 5)
			bodyA, _ := explicitDeliveryBody("job-a", "runner-a", "g1-token-job-a", 5, shared, casesA...)
			bodyB, _ := explicitDeliveryBody("job-b", "runner-b", "g1-token-job-b", 5, shared, tc.cases...)
			if w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", bodyA, hdrsA); w.Code != http.StatusCreated {
				t.Fatalf("job A upload = %d: %s", w.Code, w.Body.String())
			}
			if w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-b/tests", "runner-tok", bodyB, hdrsB); w.Code != http.StatusCreated {
				t.Fatalf("job B upload = %d, want 201 (pre-fix 200 replay of job A or 409): %s", w.Code, w.Body.String())
			}
			s.mu.Lock()
			got := make([]model.TestReport, 0, len(s.reports))
			for _, rep := range s.reports {
				got = append(got, rep)
			}
			s.mu.Unlock()
			if len(got) != 2 {
				t.Fatalf("stored reports = %d, want 2 (job B's report was dropped)", len(got))
			}
			byJob := map[string]bool{}
			for _, rep := range got {
				byJob[rep.JobID] = true
				if rep.RunID == "run-a" && rep.JobID != "job-a" {
					t.Fatalf("report attributed to the wrong job: %+v", rep)
				}
			}
			if !byJob["job-a"] || !byJob["job-b"] {
				t.Fatalf("stored reports do not cover both jobs: %v", byJob)
			}
		})
	}
}

// TestDBReportDeliveryScopedByJob pins DB parity: the durable delivery
// receipt is keyed by (job, generation, delivery ID), so both jobs store.
func TestDBReportDeliveryScopedByJob(t *testing.T) {
	s, f, _, hdrsA := cacheFixture(t)
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	f.mu.Lock()
	f.runs["run-b"] = model.Run{ID: "run-b", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Status: model.StatusRunning}
	f.jobs["job-b"] = model.Job{ID: "job-b", RunID: "run-b", Key: "build", RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a",
		Status: model.StatusRunning, Trusted: true, LeaseRunnerID: "runner-b",
		LeaseTokenHash: hashLeaseToken(s.leaseKey, "cache-lease-token"), LeaseGeneration: 5, LeaseExpiresAt: &exp}
	f.runners["runner-b"] = model.Runner{ID: "runner-b", Name: "runner-b", Capacity: 1}
	f.mu.Unlock()
	hdrsB := map[string]string{"X-Kiwi-Runner-ID": "runner-b", "X-Kiwi-Lease-Token": "cache-lease-token", "X-Kiwi-Lease-Generation": "5"}

	const shared = "shared-delivery-id"
	bodyA, _ := explicitDeliveryBody("job-a", "runner-a", "cache-lease-token", 5, shared, model.TestResult{Name: "A", Passed: true})
	bodyB, _ := explicitDeliveryBody("job-b", "runner-b", "cache-lease-token", 5, shared, model.TestResult{Name: "B", Passed: true})
	if w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-a/tests", "runner-tok", bodyA, hdrsA); w.Code != http.StatusCreated {
		t.Fatalf("db job A upload = %d: %s", w.Code, w.Body.String())
	}
	if w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/job-b/tests", "runner-tok", bodyB, hdrsB); w.Code != http.StatusCreated {
		t.Fatalf("db job B upload = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	byJob := map[string]bool{}
	for _, rep := range f.reports {
		byJob[rep.JobID] = true
	}
	f.mu.Unlock()
	if !byJob["job-a"] || !byJob["job-b"] {
		t.Fatalf("db stored reports do not cover both jobs: %v", byJob)
	}
}
