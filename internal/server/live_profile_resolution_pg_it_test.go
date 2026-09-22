package server

// Real-PostgreSQL integration test for the server-side live-profile
// resolution: a per-runner bearer runner bound through runner_profile_links
// leases under the LIVE profile, a capacity edit is honored by the NEXT lease
// without re-registration, and the fleet queue explainer evaluates the
// edited live profile. Gated on KIWI_TEST_POSTGRES_URL via the shared
// pgITServer* helpers.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITLiveProfileNext polls with the runner's OWN per-runner bearer
// credential (the shared dev token is disabled once per-runner tokens exist).
func pgITLiveProfileNext(t *testing.T, s *Server, runnerID, bearer string) Task {
	t.Helper()
	w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", bearer, "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("next %s = %d %s", runnerID, w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatalf("decode task: %v", err)
	}
	return task
}

// TestIntegrationLeaseLiveRunnerIDProfileServerPostgres drives the
// production DB-mode topology: a bearer runner bound through
// runner_profile_links leases under the LIVE profile, a capacity edit takes
// effect on the NEXT lease without re-registration, and the queue explainer
// evaluates the edited live profile.
func TestIntegrationLeaseLiveRunnerIDProfileServerPostgres(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	s.RequireProfiles = true
	ctx := context.Background()
	runnerID := pgITServerRandomHex(t, 32)
	rivalID := pgITServerRandomHex(t, 32)
	if err := s.ProvisionRunnerTokensDB(ctx, map[string]string{
		runnerID: auth.TokenDigest("token-a"),
		rivalID:  auth.TokenDigest("token-b"),
	}); err != nil {
		t.Fatal(err)
	}
	pgITBindingProfile(t, s, model.RunnerProfile{ID: "live", Labels: []string{"container"}, Capabilities: []string{"container"}, MaxCapacity: 1})
	pgITBindingRunner(t, s, "live", runnerID)

	ri := pgITRegisterBearer(t, s, "token-a",
		`{"id":"`+runnerID+`","name":"ra","protocol_min":3,"protocol_max":3,"labels":["snapshot"],"capacity":8}`)
	if ri.Capacity != 1 || len(ri.Labels) != 1 || ri.Labels[0] != "container" {
		t.Fatalf("registration did not apply the bound profile: %+v", ri)
	}
	// A second, unprofiled runner drives the fleet explainer misses.
	rival := pgITRegisterBearer(t, s, "token-b",
		`{"id":"`+rivalID+`","name":"rb","protocol_min":3,"protocol_max":3,"labels":["rival"],"capacity":1}`)

	pgITServerAwaitLeadership(t, s)
	run1 := pgITSubmit(t, s, pgITServerPipeline)
	task1 := pgITLiveProfileNext(t, s, runnerID, "token-a")
	if task1.Job.RunID != run1.ID {
		t.Fatalf("first lease run = %s, want %s", task1.Job.RunID, run1.ID)
	}
	// Capacity 1 from the live profile: the next poll takes nothing.
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token-a", "", nil); w.Code != http.StatusNoContent {
		t.Fatalf("full-runner next = %d, want 204: %s", w.Code, w.Body.String())
	}

	// Edit the live profile: capacity 2. The NEXT lease must honor the edit
	// without any re-registration.
	pgITBindingProfile(t, s, model.RunnerProfile{ID: "live", Labels: []string{"container"}, Capabilities: []string{"container"}, MaxCapacity: 2})
	run2 := pgITSubmit(t, s, pgITServerPipeline)
	task2 := pgITLiveProfileNext(t, s, runnerID, "token-a")
	if task2.Job.RunID != run2.ID {
		t.Fatalf("post-edit lease run = %s, want %s (live profile capacity edit)", task2.Job.RunID, run2.ID)
	}
	got, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatal(err)
	}
	if eff := s.Sched.EffectiveRunner(ctx, got); eff.Capacity != 2 {
		t.Fatalf("effective capacity after edit = %d, want 2", eff.Capacity)
	}

	// The explainer evaluates the edited LIVE profile: rename the profile's
	// labels, submit a job requiring the new label, and let the rival's
	// lease miss run the fleet pass. The bound runner's live profile now
	// satisfies the label, so the fleet reason is RUNNER_CAPACITY (two
	// running jobs against the live capacity 2); the registration snapshot's
	// stale label would have produced NO_COMPATIBLE_RUNNER instead.
	pgITBindingProfile(t, s, model.RunnerProfile{ID: "live", Labels: []string{"container", "renamed"}, Capabilities: []string{"container"}, MaxCapacity: 2})
	run3 := pgITSubmit(t, s, `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    runner: [renamed]
    steps:
      - run: echo hi
`)
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/"+rival.ID+"/next", "token-b", "", nil); w.Code != http.StatusNoContent {
		t.Fatalf("rival next = %d, want 204", w.Code)
	}
	if reason := pgITJobQueueReason(t, s, run3.ID); reason != "RUNNER_CAPACITY" {
		t.Fatalf("edited-label reason = %q, want RUNNER_CAPACITY (the live profile satisfies the label)", reason)
	}
}
