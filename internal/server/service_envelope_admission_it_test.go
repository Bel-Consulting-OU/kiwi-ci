package server

// Real-PostgreSQL integration test for the aggregate service-envelope
// reservation driven end to end over the HTTP handlers: a job declaring
// services reserves its own request PLUS the executor's fair-split service
// envelope in the durable ledger, a runner with room for the job alone does
// not take it, a job without services is unchanged, and completion releases
// the single row. Gated on KIWI_TEST_POSTGRES_URL like every *_it_test.go
// here.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// pgITEnvelopeServicesPipeline declares one service on a 5 GiB job: the
// executor's fair split allocates min(5GiB, 2GiB) = 2 GiB to that service, so
// the scheduler must reserve 7 GiB.
const pgITEnvelopeServicesPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    resources:
      memory: 5GiB
    services:
      - name: db
        image: postgres:16
    steps:
      - run: echo hi
`

// pgITEnvelopePlainPipeline is the same job without services: its reservation
// is exactly its own 7 GiB request.
const pgITEnvelopePlainPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    resources:
      memory: 7GiB
    steps:
      - run: echo hi
`

// TestIntegrationResourceAdmissionServiceEnvelopeServerPostgres: the full DB
// stack reserves job+services in one row, refuses the aggregate-only fit,
// keeps the no-services charge unchanged, and releases on completion.
func TestIntegrationResourceAdmissionServiceEnvelopeServerPostgres(t *testing.T) {
	env := pgITServerSetup(t)
	s, st := pgITServerWithEnv(t, env, t.TempDir())
	pgITServerAwaitLeadership(t, s)
	// Untrusted ceilings are the admission bound; raise the memory ceiling
	// above the runner's capacity so resource admission decides.
	s.UntrustedMemoryCeiling = 16 << 30
	serial := "env-serial-" + pgITServerRandomHex(t, 8)
	profileID := "env-prof-" + pgITServerRandomHex(t, 6)
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runner-profiles", "token",
		`{"id":"`+profileID+`","labels":["container"],"capabilities":["container"],"max_capacity":8,"max_memory":8589934592}`, nil); w.Code != http.StatusCreated {
		t.Fatalf("create profile = %d %s", w.Code, w.Body.String())
	}
	if w := pgITDo(t, s, http.MethodPut, "/api/v1/runner-profiles/"+profileID+"/cert/"+serial, "token", "{}", nil); w.Code != http.StatusOK {
		t.Fatalf("bind profile = %d %s", w.Code, w.Body.String())
	}
	w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"env-runner","cert_serial":"`+serial+`","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":8}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("register = %d %s", w.Code, w.Body.String())
	}
	var runner model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &runner); err != nil {
		t.Fatal(err)
	}

	runSvcA := pgITSubmit(t, s, pgITEnvelopeServicesPipeline)
	runSvcB := pgITSubmit(t, s, pgITEnvelopeServicesPipeline)
	runPlain := pgITSubmit(t, s, pgITEnvelopePlainPipeline)

	// The 5 GiB job with one 2 GiB service envelope leases and reserves 7 GiB
	// in ONE row; the stamped envelope travels to the runner.
	taskA := pgITNext(t, s, runner.ID)
	if taskA.Job.RunID != runSvcA.ID {
		t.Fatalf("leased run = %s, want %s", taskA.Job.RunID, runSvcA.ID)
	}
	if taskA.Job.ServiceEnvelopeRequest.Memory != 2<<30 {
		t.Fatalf("leased envelope memory = %d, want the fair-split 2GiB", taskA.Job.ServiceEnvelopeRequest.Memory)
	}
	if rows := pgITReservationRows(t, env); rows != 1 {
		t.Fatalf("ledger rows after aggregate lease = %d, want 1 (job + services share one row)", rows)
	}
	reserved, err := st.RunnerReservedResources(context.Background(), runner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Memory != 7<<30 {
		t.Fatalf("reserved memory = %d, want the 7GiB aggregate (5GiB job + 2GiB services)", reserved.Memory)
	}

	// The second service job (7 GiB aggregate) and the plain 7 GiB job both
	// exceed the remaining 1 GiB: no lease is issued.
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/runners/"+runner.ID+"/next", "token", "", nil); w.Code != http.StatusNoContent {
		t.Fatalf("oversubscribed next = %d, want 204: %s", w.Code, w.Body.String())
	}
	if reason := pgITJobQueueReason(t, s, runSvcB.ID); reason != "RUNNER_CAPACITY" {
		t.Fatalf("second service job reason = %q, want RUNNER_CAPACITY", reason)
	}
	if reason := pgITJobQueueReason(t, s, runPlain.ID); reason != "RUNNER_CAPACITY" {
		t.Fatalf("plain job reason = %q, want RUNNER_CAPACITY", reason)
	}
	reserved, err = st.RunnerReservedResources(context.Background(), runner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Memory != 7<<30 {
		t.Fatalf("reserved memory after refusals = %d, want 7GiB (no oversubscription)", reserved.Memory)
	}

	// Completion deletes the single row; the plain job then leases and
	// reserves EXACTLY its own 7 GiB (no services -> zero envelope).
	completeBody, _ := json.Marshal(map[string]any{"runner_id": runner.ID, "lease_token": taskA.LeaseToken, "lease_generation": taskA.LeaseGeneration, "status": "success"})
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+taskA.Job.ID+"/complete", "token", string(completeBody), nil); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d %s", w.Code, w.Body.String())
	}
	if rows := pgITReservationRows(t, env); rows != 0 {
		t.Fatalf("ledger rows after completion = %d, want 0", rows)
	}
	// The service job B is older than the plain job and leases first.
	taskB := pgITNext(t, s, runner.ID)
	if taskB.Job.RunID != runSvcB.ID {
		t.Fatalf("second lease run = %s, want %s", taskB.Job.RunID, runSvcB.ID)
	}
	reserved, err = st.RunnerReservedResources(context.Background(), runner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Memory != 7<<30 {
		t.Fatalf("reserved memory after second service lease = %d, want 7GiB", reserved.Memory)
	}
	completeBodyB, _ := json.Marshal(map[string]any{"runner_id": runner.ID, "lease_token": taskB.LeaseToken, "lease_generation": taskB.LeaseGeneration, "status": "success"})
	if w := pgITDo(t, s, http.MethodPost, "/api/v1/jobs/"+taskB.Job.ID+"/complete", "token", string(completeBodyB), nil); w.Code != http.StatusNoContent {
		t.Fatalf("complete second service job = %d %s", w.Code, w.Body.String())
	}
	taskPlain := pgITNext(t, s, runner.ID)
	if taskPlain.Job.RunID != runPlain.ID {
		t.Fatalf("plain lease run = %s, want %s", taskPlain.Job.RunID, runPlain.ID)
	}
	if taskPlain.Job.ServiceEnvelopeRequest != (model.ResourceCapacity{}) {
		t.Fatalf("plain job envelope = %+v, want zero", taskPlain.Job.ServiceEnvelopeRequest)
	}
	reserved, err = st.RunnerReservedResources(context.Background(), runner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reserved.Memory != 7<<30 {
		t.Fatalf("plain reserved memory = %d, want exactly its own 7GiB", reserved.Memory)
	}
}
