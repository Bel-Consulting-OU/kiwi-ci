package server

// Real-PostgreSQL integration test for resource-capacity admission driven
// end to end over the HTTP handlers: an operator creates a capacity-bearing
// runner profile, a runner linked to it may not lease beyond its memory
// capacity, the blocked job waits with the explainable RUNNER_CAPACITY
// reason, a job above the capacity is explained as NO_COMPATIBLE_RUNNER, and
// completing the running job releases the reservation so the waiter leases.
// Gated on KIWI_TEST_POSTGRES_URL like every *_it_test.go here.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const pgITResourcePipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    resources:
      memory: 5GiB
    steps:
      - run: echo hi
`

const pgITResourceOverPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    resources:
      memory: 16GiB
    steps:
      - run: echo hi
`

// TestIntegrationResourceAdmissionServerEndToEnd (D2-B): the whole stack
// honors a profile's memory capacity.
func TestIntegrationResourceAdmissionServerEndToEnd(t *testing.T) {
	s, st := pgITServer(t, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	// The untrusted memory ceiling is the ADMISSION bound for untrusted
	// requests; raise it above the runner's capacity so the oversubscription
	// scenario is exercised by resource admission instead of being rejected
	// at enqueue (the default 4 GiB ceiling is covered by the ceiling tests).
	s.UntrustedMemoryCeiling = 16 << 30
	serial := "res-serial-" + pgITServerRandomHex(t, 8)
	profileID := "res-prof-" + pgITServerRandomHex(t, 6)

	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runner-profiles", "token",
		`{"id":"`+profileID+`","labels":["container"],"capabilities":["container"],"max_capacity":8,"max_memory":8589934592}`, nil); w.Code != http.StatusCreated {
		t.Fatalf("create profile = %d %s", w.Code, w.Body.String())
	}
	if w := pgITDo(t, s, http.MethodPut, "/api/v1/runner-profiles/"+profileID+"/cert/"+serial, "token", "{}", nil); w.Code != http.StatusOK {
		t.Fatalf("bind profile = %d %s", w.Code, w.Body.String())
	}
	w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"res-runner","cert_serial":"`+serial+`","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":8}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("register = %d %s", w.Code, w.Body.String())
	}
	var runner model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &runner); err != nil {
		t.Fatal(err)
	}
	// The profile's capacities are the runner's live scheduling attributes:
	// the registration snapshot is resolved through the linked profile on
	// every scheduling decision (the claim re-reads the profile inside its
	// transaction, see storage.AcquireLeaseAtomic).
	got, err := st.GetRunner(context.Background(), runner.ID)
	if err != nil {
		t.Fatal(err)
	}
	eff := s.Sched.EffectiveRunner(context.Background(), got)
	if eff.ResourceCapacity.Memory != 8<<30 {
		t.Fatalf("effective runner resource capacity = %+v, want memory 8GiB (from the live profile)", eff.ResourceCapacity)
	}

	runA := pgITSubmit(t, s, pgITResourcePipeline)
	runB := pgITSubmit(t, s, pgITResourcePipeline)
	runOver := pgITSubmit(t, s, pgITResourceOverPipeline)

	// The first 5 GiB job leases and reserves exactly 5 GiB.
	taskA := pgITNext(t, s, runner.ID)
	if taskA.Job.MemoryRequest != 5<<30 {
		t.Fatalf("leased job memory request = %d, want 5GiB", taskA.Job.MemoryRequest)
	}
	if taskA.Job.RunID != runA.ID {
		t.Fatalf("leased run = %s, want %s", taskA.Job.RunID, runA.ID)
	}
	reserved, err := st.RunnerReservedResources(context.Background(), runner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Memory != 5<<30 {
		t.Fatalf("reserved memory = %d, want 5GiB", reserved.Memory)
	}

	// The second 5 GiB job cannot fit the remaining 3 GiB: it waits with the
	// explainable RUNNER_CAPACITY reason; the 16 GiB job can never fit the
	// 8 GiB capacity and is explained as NO_COMPATIBLE_RUNNER.
	for i := 0; i < 2; i++ {
		if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/"+runner.ID+"/next", "token", "", nil); w.Code != http.StatusNoContent {
			t.Fatalf("oversubscribed next = %d, want 204: %s", w.Code, w.Body.String())
		}
	}
	if reason := pgITJobQueueReason(t, s, runB.ID); reason != "RUNNER_CAPACITY" {
		t.Fatalf("second job reason = %q, want RUNNER_CAPACITY", reason)
	}
	if reason := pgITJobQueueReason(t, s, runOver.ID); reason != "NO_COMPATIBLE_RUNNER" {
		t.Fatalf("over-capacity job reason = %q, want NO_COMPATIBLE_RUNNER", reason)
	}
	reserved, err = st.RunnerReservedResources(context.Background(), runner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Memory != 5<<30 {
		t.Fatalf("reserved memory after rejected leases = %d, want 5GiB (no oversubscription)", reserved.Memory)
	}

	// Completion releases the reservation and the waiter leases.
	completeBody, _ := json.Marshal(map[string]any{"runner_id": runner.ID, "lease_token": taskA.LeaseToken, "lease_generation": taskA.LeaseGeneration, "status": "success"})
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+taskA.Job.ID+"/complete", "token", string(completeBody), nil); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d %s", w.Code, w.Body.String())
	}
	reserved, err = st.RunnerReservedResources(context.Background(), runner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Memory != 0 {
		t.Fatalf("reserved memory after completion = %d, want 0", reserved.Memory)
	}
	taskB := pgITNext(t, s, runner.ID)
	if taskB.Job.RunID != runB.ID {
		t.Fatalf("second lease run = %s, want %s", taskB.Job.RunID, runB.ID)
	}
	reserved, err = st.RunnerReservedResources(context.Background(), runner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Memory != 5<<30 {
		t.Fatalf("reserved memory after second lease = %d, want 5GiB", reserved.Memory)
	}
}

// pgITJobQueueReason reads the first job's persisted queue_reason for a run.
func pgITJobQueueReason(t *testing.T, s *Server, runID string) string {
	t.Helper()
	w := pgITDo(t, s, http.MethodGet, "/api/v1/runs/"+runID+"/jobs", "token", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list jobs = %d %s", w.Code, w.Body.String())
	}
	var jobs []struct {
		QueueReason string `json:"queue_reason"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &jobs); err != nil {
		t.Fatalf("decode jobs: %v", err)
	}
	if len(jobs) == 0 {
		t.Fatalf("run %s has no jobs", runID)
	}
	return jobs[0].QueueReason
}
