package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

func registerRunner(t *testing.T, c *testClient, name string, extra map[string]any) string {
	t.Helper()
	body := map[string]any{"name": name, "capacity": 1, "labels": []string{"native", "container"}, "protocol_min": 3, "protocol_max": 3}
	for k, v := range extra {
		body[k] = v
	}
	w := c.do(http.MethodPost, "/api/v1/runners/register", body, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var reg struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reg); err != nil {
		t.Fatal(err)
	}
	return reg.ID
}

const regionPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: ubuntu@sha256:` + pinnedImage + `
    placement:
      regions: [east]
    steps:
      - run: echo hi
`

func TestRegionFiltering(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: regionPipeline}, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	// The job carries its placement regions.
	s.mu.Lock()
	var regions []string
	for _, j := range s.jobs {
		regions = j.PlacementRegions
	}
	s.mu.Unlock()
	if len(regions) != 1 || regions[0] != "east" {
		t.Fatalf("placement regions = %v, want [east]", regions)
	}

	west := registerRunner(t, c, "west", map[string]any{"region": "west"})
	// A runner outside the region gets no lease.
	w = c.do(http.MethodPost, "/api/v1/runners/"+west+"/next", map[string]any{}, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("west runner: %d %s", w.Code, w.Body.String())
	}
	// The queue reason explains it.
	s.mu.Lock()
	var reason string
	for _, j := range s.jobs {
		reason = j.QueueReason
	}
	s.mu.Unlock()
	if reason != "REGION_UNAVAILABLE" {
		t.Fatalf("queue reason = %q, want REGION_UNAVAILABLE", reason)
	}

	east := registerRunner(t, c, "east", map[string]any{"region": "east"})
	w = c.do(http.MethodPost, "/api/v1/runners/"+east+"/next", map[string]any{}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("east runner: %d %s", w.Code, w.Body.String())
	}
}

func TestRunnerDrainDisableEnable(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: testPipeline}, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	id := registerRunner(t, c, "r1", nil)

	// Lease a job, then disable the runner mid-flight.
	w = c.do(http.MethodPost, "/api/v1/runners/"+id+"/next", map[string]any{}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("next: %d %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}

	w = c.do(http.MethodPost, "/api/v1/runners/"+id+"/disable", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", w.Code, w.Body.String())
	}
	// The active job was cancelled with "runner disabled".
	s.mu.Lock()
	j := s.jobs[task.Job.ID]
	r := s.runners[id]
	s.mu.Unlock()
	if j.Status != "cancelled" || j.Error != "runner disabled" {
		t.Fatalf("job after disable: %s %q", j.Status, j.Error)
	}
	if len(r.ActiveJobs) != 0 || r.Busy {
		t.Fatalf("runner still busy after disable: %+v", r)
	}
	if !r.Disabled {
		t.Fatal("runner not marked disabled")
	}

	// A disabled runner gets no leases.
	w = c.do(http.MethodPost, "/api/v1/runners/"+id+"/next", map[string]any{}, nil)
	if w.Code != http.StatusNoContent || w.Header().Get("X-Kiwi-Disabled") != "true" {
		t.Fatalf("disabled next: %d header=%q", w.Code, w.Header().Get("X-Kiwi-Disabled"))
	}

	// Re-registering cannot clear the flag.
	id2 := registerRunner(t, c, "r1", map[string]any{"id": id})
	if id2 != id {
		t.Fatalf("re-register changed id: %q -> %q", id, id2)
	}
	s.mu.Lock()
	r = s.runners[id]
	s.mu.Unlock()
	if !r.Disabled {
		t.Fatal("re-registration cleared disabled flag")
	}

	// Enable restores service.
	w = c.do(http.MethodPost, "/api/v1/runners/"+id+"/enable", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	r = s.runners[id]
	s.mu.Unlock()
	if r.Disabled || r.Draining {
		t.Fatalf("enable did not clear flags: %+v", r)
	}

	// Drain: no new work, header advertises the state.
	w = c.do(http.MethodPost, "/api/v1/runners/"+id+"/drain", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("drain: %d %s", w.Code, w.Body.String())
	}
	w = c.do(http.MethodPost, "/api/v1/runners/"+id+"/next", map[string]any{}, nil)
	if w.Code != http.StatusNoContent || w.Header().Get("X-Kiwi-Draining") != "true" {
		t.Fatalf("draining next: %d header=%q", w.Code, w.Header().Get("X-Kiwi-Draining"))
	}

	// Unknown runner.
	w = c.do(http.MethodPost, "/api/v1/runners/nope/drain", nil, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown runner drain: %d", w.Code)
	}
}

func TestRunnerAdminAuth(t *testing.T) {
	s := New("secret")
	s.AdminToken = "admin"
	c := newTestClient(t, s.Handler(), "secret")
	// The runner token must not drain/disable runners.
	w := c.do(http.MethodPost, "/api/v1/runners/whatever/drain", nil, nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("runner token passed admin gate: %d", w.Code)
	}
	// The admin token may.
	cAdmin := newTestClient(t, s.Handler(), "admin")
	w = cAdmin.do(http.MethodPost, "/api/v1/runners/whatever/drain", nil, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("admin drain on unknown runner: %d %s", w.Code, w.Body.String())
	}
}

func TestRunnerSelfDrainRegistration(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	// A runner registering with draining=true stays draining across
	// re-registration (kiwi runner --drain semantics).
	id := registerRunner(t, c, "drainer", map[string]any{"draining": true})
	s.mu.Lock()
	r := s.runners[id]
	s.mu.Unlock()
	if !r.Draining {
		t.Fatal("draining flag not recorded at registration")
	}
	registerRunner(t, c, "drainer", map[string]any{"id": id, "draining": false})
	s.mu.Lock()
	r = s.runners[id]
	s.mu.Unlock()
	if !r.Draining {
		t.Fatal("re-registration cleared draining flag")
	}
}
