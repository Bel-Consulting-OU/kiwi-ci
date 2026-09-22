package server

// Aggregate service-envelope admission on the fs/dev path (E-envelope): the
// memory-mode lease path must charge a running job's own request PLUS the
// aggregate service envelope stamped at enqueue (model.Job.
// ReservedResources), exactly like the SQL claim transaction and the
// scheduler's pre-filter. The envelope is what bounds aggregate host usage
// when the runner cannot establish a job-scoped parent cgroup, so a runner
// with room for the job alone but not for job+services is not admitted.
// A job without services keeps the pre-envelope charge (its own request
// only), and the fs and DB explainers agree on the reasons.

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// fsEnvelopePipeline declares one service on a 5 GiB job: the fair-split
// envelope is 2 GiB (one full per-service default), so the aggregate the
// runner must hold is 7 GiB.
const fsEnvelopePipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    resources:
      memory: 5GiB
    services:
      - name: db
        image: postgres:16
    steps:
      - run: echo hi
`

// fsEnvelopeOverPipeline declares one service on a 7 GiB job: the envelope is
// 2 GiB, so the 9 GiB aggregate is permanently above the 8 GiB runner.
const fsEnvelopeOverPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    resources:
      memory: 7GiB
    services:
      - name: db
        image: postgres:16
    steps:
      - run: echo hi
`

// fsEnvelopePlainPipeline is the same job without services: the reservation
// is exactly its own 2 GiB request.
const fsEnvelopePlainPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    resources:
      memory: 2GiB
    steps:
      - run: echo hi
`

// TestMemoryServiceEnvelopeAggregateReserved: the fs lease path charges
// job+services to the runner (7 GiB for a 5 GiB job with one 2 GiB service
// envelope), so neither a second identical job nor a plain 2 GiB job fits the
// remaining 1 GiB; after completion releases the aggregate, the plain job
// reserves exactly its own request (the no-services charge is unchanged).
func TestMemoryServiceEnvelopeAggregateReserved(t *testing.T) {
	s, runnerID := fsResourceServer(t)
	first := fsSubmitResource(t, s, "fs/env-a", fsEnvelopePipeline)
	second := fsSubmitResource(t, s, "fs/env-b", fsEnvelopePipeline)
	plain := fsSubmitResource(t, s, "fs/env-plain", fsEnvelopePlainPipeline)

	taskA := fsLeaseOne(t, s, runnerID)
	if taskA.Job.ID != first {
		t.Fatalf("first lease = %s, want %s", taskA.Job.ID, first)
	}
	if taskA.Job.MemoryRequest != 5<<30 {
		t.Fatalf("first lease own memory = %d, want 5GiB", taskA.Job.MemoryRequest)
	}
	// The enqueue stamping derived the executor's fair split: one service
	// gets min(remaining/1, 2 GiB) = 2 GiB.
	envelope := taskA.Job.ServiceEnvelopeRequest
	if envelope.Memory != 2<<30 {
		t.Fatalf("envelope memory = %d, want 2GiB (fair split of the 5GiB envelope)", envelope.Memory)
	}
	if got := fsReservedMemory(s, runnerID); got != 7<<30 {
		t.Fatalf("reserved after service lease = %d, want 7GiB (5GiB job + 2GiB services)", got)
	}

	// Neither waiter fits the remaining 1 GiB: the second service job's own
	// 5 GiB and the plain job's 2 GiB both exceed it, so no lease is issued
	// although job slots are free.
	fsBlockedNext(t, s, runnerID)
	if got := fsJob(t, s, second).QueueReason; got != "RUNNER_CAPACITY" {
		t.Fatalf("second service job reason = %q, want RUNNER_CAPACITY", got)
	}
	if got := fsJob(t, s, plain).QueueReason; got != "RUNNER_CAPACITY" {
		t.Fatalf("plain job reason = %q, want RUNNER_CAPACITY", got)
	}
	if got := fsReservedMemory(s, runnerID); got != 7<<30 {
		t.Fatalf("reserved after refusals = %d, want 7GiB", got)
	}

	// Completion releases the aggregate (one derived reservation covering
	// job+services, no separate row to strand); the oldest waiter (the second
	// service job) then leases with the same aggregate charge.
	if code := fsComplete(t, s, runnerID, taskA, "success"); code != http.StatusNoContent {
		t.Fatalf("complete first service job = %d", code)
	}
	if got := fsReserved(s, runnerID); got != (model.ResourceCapacity{}) {
		t.Fatalf("reserved after completion = %+v, want zero", got)
	}
	taskB := fsLeaseOne(t, s, runnerID)
	if taskB.Job.ID != second {
		t.Fatalf("second lease = %s, want %s", taskB.Job.ID, second)
	}
	if got := fsReservedMemory(s, runnerID); got != 7<<30 {
		t.Fatalf("reserved after second service lease = %d, want 7GiB", got)
	}
	if code := fsComplete(t, s, runnerID, taskB, "success"); code != http.StatusNoContent {
		t.Fatalf("complete second service job = %d", code)
	}

	// The plain job now leases and reserves ONLY its own 2 GiB: the
	// no-services path carries a zero envelope and is unchanged.
	taskPlain := fsLeaseOne(t, s, runnerID)
	if taskPlain.Job.ID != plain {
		t.Fatalf("plain lease = %s, want %s", taskPlain.Job.ID, plain)
	}
	if taskPlain.Job.ServiceEnvelopeRequest != (model.ResourceCapacity{}) {
		t.Fatalf("plain job envelope = %+v, want zero", taskPlain.Job.ServiceEnvelopeRequest)
	}
	if got := fsReservedMemory(s, runnerID); got != 2<<30 {
		t.Fatalf("reserved after plain lease = %d, want exactly its own 2GiB", got)
	}
	if code := fsComplete(t, s, runnerID, taskPlain, "success"); code != http.StatusNoContent {
		t.Fatalf("complete plain = %d", code)
	}
	if got := fsReserved(s, runnerID); got != (model.ResourceCapacity{}) {
		t.Fatalf("reserved after all completions = %+v, want zero", got)
	}
}

// TestMemoryServiceEnvelopeReasonParityWithDBMode: for the SAME logical data
// (8 GiB runner profile, a 7 GiB aggregate reservation, a service waiter whose
// 5+2 GiB does not fit the remaining 1 GiB, and a 7+2 GiB job whose aggregate
// is permanently above the capacity), the fs path and the DB-mode explainer
// report the same reasons: RUNNER_CAPACITY for the waiter and
// NO_COMPATIBLE_RUNNER for the over-capacity aggregate. Both use the aggregate
// request (own + service envelope) for the decision.
func TestMemoryServiceEnvelopeReasonParityWithDBMode(t *testing.T) {
	fsSrv, runnerID := fsResourceServer(t)
	fsSubmitResource(t, fsSrv, "fs/env-par-a", fsEnvelopePipeline)
	waitJob := fsSubmitResource(t, fsSrv, "fs/env-par-wait", fsEnvelopePipeline)
	overJob := fsSubmitResource(t, fsSrv, "fs/env-par-over", fsEnvelopeOverPipeline)
	fsLeaseOne(t, fsSrv, runnerID)
	fsBlockedNext(t, fsSrv, runnerID)
	waitReason := fsJob(t, fsSrv, waitJob).QueueReason
	overReason := fsJob(t, fsSrv, overJob).QueueReason
	if waitReason != "RUNNER_CAPACITY" || overReason != "NO_COMPATIBLE_RUNNER" {
		t.Fatalf("fs reasons = %q/%q, want RUNNER_CAPACITY/NO_COMPATIBLE_RUNNER", waitReason, overReason)
	}

	// DB mode over the fake store with the same fixture: profile 8 GiB,
	// 7 GiB reserved (job+services), a 5+2 GiB waiter and a 7+2 GiB job.
	f := &reservationFakeStore{dbFakeStore: newDBFakeStore(), reserved: model.ResourceCapacity{Memory: 7 << 30}}
	dbSrv := New("token")
	if err := dbSrv.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.profiles["env-par-prof"] = model.RunnerProfile{ID: "env-par-prof", MaxCapacity: 8, MaxMemory: 8 << 30}
	f.certProfiles["env-par-serial"] = "env-par-prof"
	f.runners["env-par-runner"] = model.Runner{ID: "env-par-runner", Name: "env-par-runner", Capacity: 8, CertSerial: "env-par-serial"}
	f.runs["env-par-run"] = model.Run{ID: "env-par-run", Status: model.StatusQueued}
	f.jobs["env-par-wait"] = model.Job{ID: "env-par-wait", RunID: "env-par-run", Key: "wait", Status: model.StatusQueued,
		MemoryRequest: 5 << 30, ServiceEnvelopeRequest: model.ResourceCapacity{Memory: 2 << 30}, CreatedAt: time.Now().UTC()}
	f.jobs["env-par-over"] = model.Job{ID: "env-par-over", RunID: "env-par-run", Key: "over", Status: model.StatusQueued,
		MemoryRequest: 7 << 30, ServiceEnvelopeRequest: model.ResourceCapacity{Memory: 2 << 30}, CreatedAt: time.Now().UTC().Add(time.Second)}
	f.mu.Unlock()
	if w := doJSON(t, dbSrv, http.MethodPost, "/api/v1/runners/env-par-runner/next", "token", ""); w.Code != http.StatusNoContent {
		t.Fatalf("db next = %d: %s", w.Code, w.Body.String())
	}
	dbWait, dbOver := f.queueReason("env-par-wait"), f.queueReason("env-par-over")
	if dbWait != waitReason || dbOver != overReason {
		t.Fatalf("parity: fs %q/%q vs db %q/%q", waitReason, overReason, dbWait, dbOver)
	}
}

// TestServiceEnvelopeStampedForTrustedAndUntrustedJobs: the envelope stamp is
// derived from the EFFECTIVE compiled job — for untrusted jobs after the
// server-side ceilings were filled, which is exactly what the runner executes
// (the signed CompiledJobPayload.EffectiveJob) — and for trusted jobs from the
// declared resources unchanged. The stamp itself is trust-agnostic: both
// classes get the aggregate.
func TestServiceEnvelopeStampedForTrustedAndUntrustedJobs(t *testing.T) {
	s := New("tok")
	mk := func(resources pipeline.Resources) pipeline.CompiledJob {
		cj := pipeline.CompiledJob{ID: "build", BaseID: "build"}
		cj.Job.Runtime = "container"
		cj.Job.Resources = resources
		cj.Job.Services = []pipeline.Service{{Name: "db", Image: "postgres:16"}}
		return cj
	}
	// Fair split of one service: min(job cpu, 2), min(job memory, 2GiB),
	// min(job pids, 256).
	trustedJob, err := s.applyUntrustedResourceCeilings(mk(pipeline.Resources{CPU: 3, Memory: 6 << 30, PIDs: 300}), true)
	if err != nil {
		t.Fatal(err)
	}
	var tj model.Job
	applyCompiledJobFields(&tj, trustedJob, time.Now())
	if tj.ServiceEnvelopeRequest != (model.ResourceCapacity{CPU: 2, Memory: 2 << 30, PIDs: 256}) {
		t.Fatalf("trusted envelope = %+v, want the declared-resource fair split {cpu:2 memory:2GiB pids:256}", tj.ServiceEnvelopeRequest)
	}
	if tj.CPURequest != 3 || tj.MemoryRequest != 6<<30 || tj.PIDsRequest != 300 {
		t.Fatalf("trusted own request = %v/%d/%d, want the declared resources", tj.CPURequest, tj.MemoryRequest, tj.PIDsRequest)
	}

	// Untrusted: the ceilings fill cpu=2, pids=256 and the disk bound, so the
	// envelope derives from the FILLED envelope (cpu 2, memory 3GiB, pids
	// 256), not from the declared CPU/PIDs of zero.
	untrustedJob, err := s.applyUntrustedResourceCeilings(mk(pipeline.Resources{Memory: 3 << 30}), false)
	if err != nil {
		t.Fatal(err)
	}
	var uj model.Job
	applyCompiledJobFields(&uj, untrustedJob, time.Now())
	if uj.ServiceEnvelopeRequest != (model.ResourceCapacity{CPU: 2, Memory: 2 << 30, PIDs: 256}) {
		t.Fatalf("untrusted envelope = %+v, want the ceiling-filled fair split {cpu:2 memory:2GiB pids:256}", uj.ServiceEnvelopeRequest)
	}
	if uj.CPURequest != 2 || uj.PIDsRequest != 256 {
		t.Fatalf("untrusted own request = cpu %v pids %d, want the filled ceilings", uj.CPURequest, uj.PIDsRequest)
	}
}

// TestMemoryServiceEnvelopeStampedAtEnqueue: the enqueue stamping itself — the
// persisted job payload carries the executor's aggregate envelope (re-planning
// the effective job through the executor's own planner yields the same
// values), and a job without services carries the zero value.
func TestMemoryServiceEnvelopeStampedAtEnqueue(t *testing.T) {
	s, _ := fsResourceServer(t)
	svcJob := fsSubmitResource(t, s, "fs/env-stamp", fsEnvelopePipeline)
	plainJob := fsSubmitResource(t, s, "fs/env-stamp-plain", fsEnvelopePlainPipeline)

	svc := fsJob(t, s, svcJob)
	if svc.ServiceEnvelopeRequest.Memory != 2<<30 || svc.ServiceEnvelopeRequest.CPU != 2 || svc.ServiceEnvelopeRequest.PIDs != 256 {
		t.Fatalf("stamped envelope = %+v, want the executor's fair split {cpu:2 memory:2GiB pids:256}", svc.ServiceEnvelopeRequest)
	}
	// The stamped envelope IS the executor's own computation: re-planning the
	// signed effective job through executor.ServiceEnvelopeRequest must
	// reproduce it exactly (one planner behind admission and execution).
	raw, err := json.Marshal(svc.CompiledJobPayload.EffectiveJob)
	if err != nil {
		t.Fatal(err)
	}
	var cj pipeline.CompiledJob
	if err := json.Unmarshal(raw, &cj); err != nil {
		t.Fatal(err)
	}
	req, err := executor.ServiceEnvelopeRequest(cj.Job.Resources, cj.Job.Services)
	if err != nil {
		t.Fatalf("executor planner on the effective job: %v", err)
	}
	want := model.ResourceCapacity{CPU: req.CPU, Memory: int64(req.Memory), PIDs: req.PIDs}
	if svc.ServiceEnvelopeRequest != want {
		t.Fatalf("stamped envelope = %+v, executor planner = %+v", svc.ServiceEnvelopeRequest, want)
	}
	if plain := fsJob(t, s, plainJob); plain.ServiceEnvelopeRequest != (model.ResourceCapacity{}) {
		t.Fatalf("plain job envelope = %+v, want zero", plain.ServiceEnvelopeRequest)
	}
}
