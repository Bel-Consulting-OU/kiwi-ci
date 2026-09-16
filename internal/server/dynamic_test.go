package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
)

const generatePipeline = `version: 1
jobs:
  gen:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    generate:
      path: generated.yaml
      max_jobs: 16
      max_depth: 2
    steps:
      - run: echo generate
`

func boolPtr(b bool) *bool { return &b }

// trustedGenerateServer builds a persistent server whose policy grants
// generate_child_graph (and cross_repo_trigger) for repo o/r, and enqueues a
// trusted run of generatePipeline, returning the server and the run.
func trustedGenerateServer(t *testing.T) (*Server, model.Run) {
	t.Helper()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{
		Repositories: map[string]policy.RepoPolicy{
			"o/r": {GenerateChildGraph: boolPtr(true), CrossRepoTrigger: boolPtr(true)},
		},
	}
	run, err := s.enqueue(SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: generatePipeline, Trusted: true,
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	return s, run
}

// leaseRunJob registers a runner and leases the first job of the run.
func leaseRunJob(t *testing.T, s *Server) (string, Task) {
	t.Helper()
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token", `{"name":"r1","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":2}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, s, http.MethodPost, "/api/v1/runners/"+ri.ID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next: %d %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	return ri.ID, task
}

func TestDynamicGenerateHappyPath(t *testing.T) {
	s, run := trustedGenerateServer(t)
	runnerID, task := leaseRunJob(t, s)
	frag := `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo child"}]}},"deps":{}}`
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", frag, leaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated {
		t.Fatalf("generated = %d: %s", w.Code, w.Body.String())
	}
	var res generatedResponse
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Depth != 1 || len(res.JobIDs) != 1 || res.JobIDs[0] == "" {
		t.Fatalf("bad response: %+v", res)
	}
	s.mu.Lock()
	child, ok := s.jobs[res.JobIDs[0]]
	s.mu.Unlock()
	if !ok {
		t.Fatal("child job not inserted")
	}
	if child.RunID != run.ID || child.DynamicDepth != 1 {
		t.Fatalf("child run/depth = %s/%d", child.RunID, child.DynamicDepth)
	}
	if len(child.Needs) != 1 || child.Needs[0] != task.Job.ID {
		t.Fatalf("child needs = %v, want [parent]", child.Needs)
	}
	if child.Status != model.StatusQueued {
		t.Fatalf("child status = %s", child.Status)
	}
	// The child's stored pipeline compiles back to the child job so the
	// runner can reconstruct its steps.
	if cj, ok := compileJobFromPipeline(child); !ok || len(cj.Job.Steps) != 1 {
		t.Fatalf("child pipeline does not recompile: %+v", cj)
	}
}

func TestDynamicGenerateDepthLimit(t *testing.T) {
	s, _ := trustedGenerateServer(t)
	_, task := leaseRunJob(t, s)
	s.mu.Lock()
	parent := s.jobs[task.Job.ID]
	parent.DynamicDepth = 2
	s.jobs[task.Job.ID] = parent
	s.mu.Unlock()
	frag := `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo child"}]}},"deps":{}}`
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", frag, leaseHeaders(task, runnerIDFor(s, task.Job.ID)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("depth-3 generation = %d, want 400: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "depth") {
		t.Fatalf("rejection should mention depth: %s", w.Body.String())
	}
}

func runnerIDFor(s *Server, jobID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[jobID]
	if !ok {
		return ""
	}
	return j.LeaseRunnerID
}

func TestDynamicGenerateRejectsFragmentTooLarge(t *testing.T) {
	s, _ := trustedGenerateServer(t)
	runnerID, task := leaseRunJob(t, s)
	var b strings.Builder
	b.WriteString(`{"jobs":{`)
	for i := 0; i < 129; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"j` + string(rune('a'+i%26)) + jsonInt(i) + `":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo x"}]}`)
	}
	b.WriteString(`},"deps":{}}`)
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", b.String(), leaseHeaders(task, runnerID))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("129-job fragment = %d, want 400: %s", w.Code, w.Body.String())
	}
}

func jsonInt(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func TestDynamicGenerateRejectsUnknownDeps(t *testing.T) {
	s, _ := trustedGenerateServer(t)
	runnerID, task := leaseRunJob(t, s)
	frag := `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo child"}]}},"deps":{"child-a":["nope"]}}`
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", frag, leaseHeaders(task, runnerID))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown dep = %d, want 400: %s", w.Code, w.Body.String())
	}
}

func TestDynamicGenerateTrustReduction(t *testing.T) {
	s, _ := trustedGenerateServer(t)
	// Narrow the parent's admission caps to a single-secret allowlist so
	// children must inherit the reduction.
	restricted := policy.DefaultTrustedCapabilities()
	restricted.Secrets = map[string]bool{"allowed-secret": true}
	s.AdmissionCapabilities = &restricted
	s.mu.Lock()
	s.runs = map[string]model.Run{}
	s.jobs = map[string]model.Job{}
	s.mu.Unlock()
	run, err := s.enqueue(SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: generatePipeline, Trusted: true,
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	_ = run
	runnerID, task := leaseRunJob(t, s)
	frag := `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo child","secrets":["forbidden-secret"]}]}},"deps":{}}`
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", frag, leaseHeaders(task, runnerID))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("secret over parent caps = %d, want 400: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "secret") {
		t.Fatalf("rejection should mention the secret: %s", w.Body.String())
	}
}

func TestDynamicGenerateRequiresLease(t *testing.T) {
	s, _ := trustedGenerateServer(t)
	runnerID, task := leaseRunJob(t, s)
	frag := `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo child"}]}},"deps":{}}`
	hdrs := leaseHeaders(task, runnerID)
	hdrs["X-Kiwi-Lease-Token"] = "wrong-token"
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", frag, hdrs)
	if w.Code != http.StatusConflict {
		t.Fatalf("bad lease = %d, want 409: %s", w.Code, w.Body.String())
	}
}

func TestDynamicGenerateDBMode(t *testing.T) {
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{
		Repositories: map[string]policy.RepoPolicy{
			"o/r": {GenerateChildGraph: boolPtr(true)},
		},
	}
	if _, err := s.enqueue(SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: generatePipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID, task := leaseRunJob(t, s)
	frag := `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo child"}]}},"deps":{}}`
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", frag, leaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated {
		t.Fatalf("db generated = %d: %s", w.Code, w.Body.String())
	}
	var res generatedResponse
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	child, ok := f.jobs[res.JobIDs[0]]
	f.mu.Unlock()
	if !ok || child.DynamicDepth != 1 {
		t.Fatalf("child not inserted through DynamicStore: %+v", child)
	}
	_ = runnerID
	// The parent's lease must still be valid for a second fragment.
	w = doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", `{"jobs":{"child-b":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo b"}]}},"deps":{}}`, leaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated {
		t.Fatalf("db second fragment = %d: %s", w.Code, w.Body.String())
	}
}

func TestDynamicGenerateRejectedWithoutCapability(t *testing.T) {
	// A parent admitted while the policy granted generate_child_graph loses
	// the capability when the policy is removed: the endpoint re-derives
	// the child ceiling from stored caps ∩ current policy.
	s, _ := trustedGenerateServer(t)
	_, task := leaseRunJob(t, s)
	runnerID := runnerIDFor(s, task.Job.ID)
	s.Policy = &policy.Config{}
	frag := `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo child"}]}},"deps":{}}`
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", frag, leaseHeaders(task, runnerID))
	if w.Code != http.StatusForbidden {
		t.Fatalf("no-capability generation = %d, want 403: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "capabilities") {
		t.Fatalf("rejection should mention capabilities: %s", w.Body.String())
	}
}
