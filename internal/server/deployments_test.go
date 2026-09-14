package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

const deploymentPipeline = `version: 1
jobs:
  deploy:
    runtime: container
    image: ubuntu@sha256:` + pinnedImage + `
    environment:
      name: production
    deployment:
      canary:
        - run: echo canary
      verify:
        - run: echo verify
      rollback:
        - run: echo rollback
    steps:
      - run: echo deploy
`

// grantDeployments enables the deployments capability via the admission
// seam (deployments are denied by default pending repository policy).
func grantDeployments(s *Server) {
	caps := policy.DefaultTrustedCapabilities()
	caps.Deployments = true
	s.AdmissionCapabilities = &caps
}

// leaseDeploymentJob enqueues a run with deployments granted and leases its
// job.
func leaseDeploymentJob(t *testing.T, s *Server, c *testClient) (runID, jobID, runnerID, token string, generation int64) {
	t.Helper()
	run, err := s.enqueue(SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: deploymentPipeline, Trusted: true})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runID = run.ID
	runnerID = registerRunner(t, c, "deployer", nil)
	w := c.do(http.MethodPost, "/api/v1/runners/"+runnerID+"/next", map[string]any{}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("next: %d %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	return runID, task.Job.ID, runnerID, task.LeaseToken, task.LeaseGeneration
}

func TestDeploymentLifecycle(t *testing.T) {
	s := New("secret")
	grantDeployments(s)
	c := newTestClient(t, s.Handler(), "secret")
	runID, jobID, runnerID, token, gen := leaseDeploymentJob(t, s, c)

	// The lease created the deployment record automatically.
	s.mu.Lock()
	d, ok := s.deployments[jobID]
	s.mu.Unlock()
	if !ok {
		t.Fatal("no deployment record after lease")
	}
	if d.Environment != "production" || d.Status != model.StatusRunning || d.StartedAt == nil {
		t.Fatalf("record wrong: %+v", d)
	}

	// GET /api/v1/runs/{id}/deployments lists it.
	w := c.do(http.MethodGet, "/api/v1/runs/"+runID+"/deployments", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var out []model.Deployment
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].JobID != jobID {
		t.Fatalf("deployments listed wrong: %+v", out)
	}

	// Completion updates the record status.
	w = c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", Complete{RunnerID: runnerID, LeaseToken: token, LeaseGeneration: gen, Status: model.StatusSuccess}, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("complete: %d %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	d = s.deployments[jobID]
	s.mu.Unlock()
	if d.Status != model.StatusSuccess || d.FinishedAt == nil {
		t.Fatalf("deployment not updated on completion: %+v", d)
	}

	// The explicit record endpoint is idempotent.
	w = c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/deployments", nil, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("explicit record: %d %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	n := len(s.deployments)
	s.mu.Unlock()
	if n != 1 {
		t.Fatalf("deployment records = %d, want 1 (idempotent)", n)
	}
}

func TestDeploymentRecordRejectsNonEnvironmentJob(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	_, jobID, _, _, _ := leaseNativeJob(t, c, testPipeline)
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/deployments", nil, nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("want 409, got %d %s", w.Code, w.Body.String())
	}
}

func TestDeploymentCreatedAtOrdered(t *testing.T) {
	s := New("secret")
	grantDeployments(s)
	c := newTestClient(t, s.Handler(), "secret")
	_, jobID, _, _, _ := leaseDeploymentJob(t, s, c)
	s.mu.Lock()
	s.deployments[jobID+"x"] = model.Deployment{ID: jobID + "x", RunID: s.deployments[jobID].RunID, CreatedAt: time.Now().UTC().Add(-time.Hour)}
	s.mu.Unlock()
	runID := ""
	s.mu.Lock()
	runID = s.deployments[jobID].RunID
	s.mu.Unlock()
	w := c.do(http.MethodGet, "/api/v1/runs/"+runID+"/deployments", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d", w.Code)
	}
	var out []model.Deployment
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0].CreatedAt.After(out[1].CreatedAt) {
		t.Fatalf("deployments not sorted by created_at: %+v", out)
	}
}

const sharedEnvPipeline = `version: 1
jobs:
  deploy:
    runtime: container
    image: ubuntu@sha256:` + pinnedImage + `
    environment:
      name: shared
      concurrency: 1
    steps:
      - run: echo hi
`

// TestEnvironmentConcurrencyScopedToRepo verifies the concurrency key is
// repo+environment: the same environment name in different repositories does
// not contend, but two jobs in the same repository do.
func TestEnvironmentConcurrencyScopedToRepo(t *testing.T) {
	s := New("secret")
	grantDeployments(s)
	c := newTestClient(t, s.Handler(), "secret")
	for _, repo := range []string{"https://github.com/acme/one.git", "https://github.com/acme/two.git"} {
		if _, err := s.enqueue(SubmitRun{RepoURL: repo, Ref: "main", Pipeline: sharedEnvPipeline, Trusted: true}); err != nil {
			t.Fatalf("enqueue %s: %v", repo, err)
		}
	}
	r1 := registerRunner(t, c, "r1", nil)
	r2 := registerRunner(t, c, "r2", nil)
	// Both runners lease: same environment name, different repos.
	for _, id := range []string{r1, r2} {
		w := c.do(http.MethodPost, "/api/v1/runners/"+id+"/next", map[string]any{}, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("next for %s: %d %s", id, w.Code, w.Body.String())
		}
	}
	// A second job in repo one must wait: same repo+environment is at
	// capacity.
	if _, err := s.enqueue(SubmitRun{RepoURL: "https://github.com/acme/one.git", Ref: "main", Pipeline: sharedEnvPipeline, Trusted: true}); err != nil {
		t.Fatal(err)
	}
	r3 := registerRunner(t, c, "r3", nil)
	w := c.do(http.MethodPost, "/api/v1/runners/"+r3+"/next", map[string]any{}, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("same-repo environment must be locked, got %d", w.Code)
	}
	s.mu.Lock()
	var reason string
	for _, j := range s.jobs {
		if j.RepoURL == "https://github.com/acme/one.git" && j.LeaseRunnerID == "" {
			reason = j.QueueReason
		}
	}
	s.mu.Unlock()
	if reason != "ENVIRONMENT_LOCKED" {
		t.Fatalf("queue reason = %q, want ENVIRONMENT_LOCKED", reason)
	}
}
