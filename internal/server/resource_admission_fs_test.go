package server

// fs/dev-mode resource capacity admission (E4-A): the actual Server.next()
// path must honor the runner's configured resource capacity exactly like the
// SQL claim (storage.AcquireLeaseAtomic + reserveResourcesTx) and the
// in-memory stores. The memory-mode ledger is DERIVED: a reservation exists
// while the job is RUNNING and is charged against the runner it currently
// holds, so every terminal path releases it by construction — completion,
// cancellation, lease expiry/requeue, queue timeout and runner
// revoke/disable. These tests pin the admission and each release path, plus
// the fleet-global reasons the fs path reports for a blocked job.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

const fsResourcePipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    resources:
      memory: 5GiB
    steps:
      - run: echo hi
`

const fsResourceOverPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    resources:
      memory: 16GiB
    steps:
      - run: echo hi
`

// fsResourceServer builds a memory-mode server with one runner whose live
// profile carries an 8 GiB memory capacity and 8 job slots.
func fsResourceServer(t *testing.T) (*Server, string) {
	t.Helper()
	s := adminProfileServer(t)
	serial := "fs-res-serial"
	createProfile(t, s, model.RunnerProfile{
		ID: "fs-res-prof", Labels: []string{"container"}, Capabilities: []string{"container"},
		MaxCapacity: 8, MaxMemory: 8 << 30,
	})
	bindSerial(t, s, "fs-res-prof", serial)
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "runner-tok",
		`{"name":"fs-res-runner","cert_serial":"`+serial+`","protocol_min":3,"protocol_max":3}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var ri model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &ri); err != nil {
		t.Fatal(err)
	}
	// The untrusted memory ceiling is the enqueue bound; raise it above the
	// runner's capacity so admission (not the ceiling) decides.
	s.UntrustedMemoryCeiling = 16 << 30
	return s, ri.ID
}

// fsReservedLocked sums the resources the runner currently holds (caller
// holds s.mu): the memory-mode reservation ledger the fs admission charges
// against. Each running job charges its TOTAL reservation — own request plus
// the aggregate service envelope (model.Job.ReservedResources) — the same
// computation the production derived sum in next() uses.
func fsReservedLocked(s *Server, runnerID string) model.ResourceCapacity {
	var out model.ResourceCapacity
	for _, j := range s.jobs {
		if j.Status != model.StatusRunning || j.LeaseRunnerID != runnerID {
			continue
		}
		out = model.AddResourceCapacity(out, j.ReservedResources())
	}
	return out
}

// fsReserved returns the runner's reserved resources under s.mu.
func fsReserved(s *Server, runnerID string) model.ResourceCapacity {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fsReservedLocked(s, runnerID)
}

// fsReservedMemory returns only the reserved memory (the dimension these
// tests vary; untrusted admission fills the other dimensions with their
// default ceilings).
func fsReservedMemory(s *Server, runnerID string) int64 {
	return fsReserved(s, runnerID).Memory
}

// fsSubmitResource submits one run with the given pipeline and returns the
// run's first job ID. repoPath is the forge full name (owner/repo); the URL
// derives from it so the identity check sees one consistent repository.
func fsSubmitResource(t *testing.T, s *Server, repoPath, pipeline string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"repo_url": "https://github.com/" + repoPath + ".git", "repo_full_name": repoPath, "ref": "main", "pipeline": pipeline,
	})
	if err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "admin-tok", string(body))
	if w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	var run model.Run
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if j.RunID == run.ID {
			return j.ID
		}
	}
	t.Fatalf("run %s has no jobs", run.ID)
	return ""
}

// fsJob returns a copy of one job.
func fsJob(t *testing.T, s *Server, jobID string) model.Job {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[jobID]
	if !ok {
		t.Fatalf("job %s missing", jobID)
	}
	return j
}

// fsLeaseOne leases one task through the real HTTP path and returns it.
func fsLeaseOne(t *testing.T, s *Server, runnerID string) Task {
	t.Helper()
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "runner-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("next = %d: %s", w.Code, w.Body.String())
	}
	var task Task
	if err := json.Unmarshal(w.Body.Bytes(), &task); err != nil {
		t.Fatal(err)
	}
	return task
}

// fsBlockedNext asserts a lease miss through the HTTP path.
func fsBlockedNext(t *testing.T, s *Server, runnerID string) {
	t.Helper()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "runner-tok", ""); w.Code != http.StatusNoContent {
		t.Fatalf("blocked next = %d, want 204: %s", w.Code, w.Body.String())
	}
}

// fsComplete submits one completion for a leased task.
func fsComplete(t *testing.T, s *Server, runnerID string, task Task, status string) int {
	t.Helper()
	body := `{"runner_id":"` + runnerID + `","lease_token":"` + task.LeaseToken +
		`","lease_generation":` + strconv.FormatInt(task.LeaseGeneration, 10) + `,"status":"` + status + `"}`
	w := doJSON(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/complete", "runner-tok", body)
	return w.Code
}

// TestMemoryRunnerResourceCapacityCannotBeOverAdmitted (E4-A): a runner with
// an 8 GiB memory capacity leases one 5 GiB job and must refuse the second
// (5+5 > 8) although two job slots remain; a 16 GiB job above the configured
// capacity is refused for good. Before the fix the fs path leased the second
// job: it only counted slots.
func TestMemoryRunnerResourceCapacityCannotBeOverAdmitted(t *testing.T) {
	s, runnerID := fsResourceServer(t)
	fsSubmitResource(t, s, "fs/res-a", fsResourcePipeline)
	jobB := fsSubmitResource(t, s, "fs/res-b", fsResourcePipeline)
	jobOver := fsSubmitResource(t, s, "fs/res-over", fsResourceOverPipeline)

	taskA := fsLeaseOne(t, s, runnerID)
	if taskA.Job.MemoryRequest != 5<<30 {
		t.Fatalf("first lease memory = %d, want 5GiB", taskA.Job.MemoryRequest)
	}

	// The second 5 GiB job does not fit the remaining 3 GiB.
	fsBlockedNext(t, s, runnerID)
	if got := fsJob(t, s, jobB).QueueReason; got != "RUNNER_CAPACITY" {
		t.Fatalf("second job reason = %q, want RUNNER_CAPACITY", got)
	}
	if got := fsJob(t, s, jobOver).QueueReason; got != "NO_COMPATIBLE_RUNNER" {
		t.Fatalf("over-capacity job reason = %q, want NO_COMPATIBLE_RUNNER", got)
	}
	// Only the first lease's 5 GiB is charged: the refused candidates never
	// reserved anything.
	if got := fsReservedMemory(s, runnerID); got != 5<<30 {
		t.Fatalf("reserved memory after refusals = %d, want 5GiB", got)
	}

	// Completion releases the reservation; a replayed completion is
	// idempotent, and the waiter then leases.
	if code := fsComplete(t, s, runnerID, taskA, "success"); code != http.StatusNoContent {
		t.Fatalf("complete = %d", code)
	}
	if got := fsReserved(s, runnerID); got != (model.ResourceCapacity{}) {
		t.Fatalf("reserved after completion = %+v, want zero", got)
	}
	if code := fsComplete(t, s, runnerID, taskA, "success"); code != http.StatusNoContent && code != http.StatusConflict {
		t.Fatalf("replayed complete = %d", code)
	}
	if got := fsLeaseOne(t, s, runnerID).Job.ID; got != jobB {
		t.Fatalf("second lease = %s, want %s", got, jobB)
	}
	if got := fsReservedMemory(s, runnerID); got != 5<<30 {
		t.Fatalf("reserved memory after second lease = %d, want 5GiB", got)
	}
}

// TestMemoryRunnerResourceReleasedOnEveryTerminalPath (E4-A): the fs
// reservation is derived from the RUNNING set, so completion, run
// cancellation, lease expiry and runner disable each release it; a waiting
// job leases afterwards.
func TestMemoryRunnerResourceReleasedOnEveryTerminalPath(t *testing.T) {
	t.Run("completion", func(t *testing.T) {
		s, runnerID := fsResourceServer(t)
		fsSubmitResource(t, s, "fs/fin-a", fsResourcePipeline)
		jobB := fsSubmitResource(t, s, "fs/fin-b", fsResourcePipeline)
		task := fsLeaseOne(t, s, runnerID)
		if code := fsComplete(t, s, runnerID, task, "success"); code != http.StatusNoContent {
			t.Fatalf("complete = %d", code)
		}
		if got := fsReserved(s, runnerID); got != (model.ResourceCapacity{}) {
			t.Fatalf("reserved after completion = %+v, want zero", got)
		}
		if got := fsLeaseOne(t, s, runnerID).Job.ID; got != jobB {
			t.Fatalf("waiter leased %s, want %s", got, jobB)
		}
	})

	t.Run("failure completion", func(t *testing.T) {
		s, runnerID := fsResourceServer(t)
		fsSubmitResource(t, s, "fs/finf-a", fsResourcePipeline)
		jobB := fsSubmitResource(t, s, "fs/finf-b", fsResourcePipeline)
		task := fsLeaseOne(t, s, runnerID)
		if code := fsComplete(t, s, runnerID, task, "failure"); code != http.StatusNoContent {
			t.Fatalf("complete = %d", code)
		}
		if got := fsReserved(s, runnerID); got != (model.ResourceCapacity{}) {
			t.Fatalf("reserved after failure = %+v, want zero", got)
		}
		if got := fsLeaseOne(t, s, runnerID).Job.ID; got != jobB {
			t.Fatalf("waiter leased %s, want %s", got, jobB)
		}
	})

	t.Run("run cancellation", func(t *testing.T) {
		s, runnerID := fsResourceServer(t)
		fsSubmitResource(t, s, "fs/can-a", fsResourcePipeline)
		jobB := fsSubmitResource(t, s, "fs/can-b", fsResourcePipeline)
		task := fsLeaseOne(t, s, runnerID)
		if w := doJSON(t, s, http.MethodPost, "/api/v1/runs/"+task.Job.RunID+"/cancel", "admin-tok", "{}"); w.Code != http.StatusOK {
			t.Fatalf("cancel = %d %s", w.Code, w.Body.String())
		}
		if got := fsJob(t, s, task.Job.ID).Status; got != model.StatusCancelled {
			t.Fatalf("cancelled job status = %s, want cancelled", got)
		}
		if got := fsReserved(s, runnerID); got != (model.ResourceCapacity{}) {
			t.Fatalf("reserved after cancellation = %+v, want zero", got)
		}
		if got := fsLeaseOne(t, s, runnerID).Job.ID; got != jobB {
			t.Fatalf("waiter leased %s, want %s", got, jobB)
		}
	})

	t.Run("lease expiry requeue", func(t *testing.T) {
		s, runnerID := fsResourceServer(t)
		fsSubmitResource(t, s, "fs/exp-a", fsResourcePipeline)
		fsSubmitResource(t, s, "fs/exp-b", fsResourcePipeline)
		task := fsLeaseOne(t, s, runnerID)
		// Expire the lease: the next poll's recovery requeues the job and
		// releases its reservation before candidate selection.
		s.mu.Lock()
		j := s.jobs[task.Job.ID]
		past := time.Now().UTC().Add(-time.Minute)
		j.LeaseExpiresAt = &past
		s.jobs[task.Job.ID] = j
		s.mu.Unlock()
		if got := fsReservedMemory(s, runnerID); got != 5<<30 {
			t.Fatalf("reserved memory before recovery = %d, want 5GiB (still running)", got)
		}
		// The expired lease is recovered (requeued and its reservation
		// released) in the same poll, which then leases one 5 GiB job — the
		// requeued job (oldest) or the waiter. Leasing at all proves the
		// release: with both charged, 10 GiB > the 8 GiB capacity.
		recovered := fsLeaseOne(t, s, runnerID)
		if recovered.Job.MemoryRequest != 5<<30 {
			t.Fatalf("recovered lease memory request = %d, want 5GiB", recovered.Job.MemoryRequest)
		}
		if got := fsReservedMemory(s, runnerID); got != 5<<30 {
			t.Fatalf("reserved memory after requeue+lease = %d, want exactly one 5GiB lease", got)
		}
	})

	t.Run("runner disable revoke", func(t *testing.T) {
		s, runnerID := fsResourceServer(t)
		fsSubmitResource(t, s, "fs/dis-a", fsResourcePipeline)
		jobB := fsSubmitResource(t, s, "fs/dis-b", fsResourcePipeline)
		fsLeaseOne(t, s, runnerID)
		if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/disable", "admin-tok", "{}"); w.Code != http.StatusOK {
			t.Fatalf("disable = %d %s", w.Code, w.Body.String())
		}
		if got := fsReserved(s, runnerID); got != (model.ResourceCapacity{}) {
			t.Fatalf("reserved after disable = %+v, want zero", got)
		}
		if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/enable", "admin-tok", "{}"); w.Code != http.StatusOK {
			t.Fatalf("enable = %d %s", w.Code, w.Body.String())
		}
		if got := fsLeaseOne(t, s, runnerID).Job.ID; got != jobB {
			t.Fatalf("waiter leased %s, want %s", got, jobB)
		}
	})
}

// TestMemoryResourceReasonParityWithDBMode (E4-A): for the SAME logical data
// (8 GiB runner profile, 5 GiB held, a 5 GiB waiter and a 16 GiB
// over-capacity job), the fs path and the DB-mode explainer report the same
// reasons: RUNNER_CAPACITY for the waiter and NO_COMPATIBLE_RUNNER for the
// job above the configured capacity.
func TestMemoryResourceReasonParityWithDBMode(t *testing.T) {
	fsSrv, runnerID := fsResourceServer(t)
	fsSubmitResource(t, fsSrv, "fs/par-a", fsResourcePipeline)
	jobWait := fsSubmitResource(t, fsSrv, "fs/par-b", fsResourcePipeline)
	jobOver := fsSubmitResource(t, fsSrv, "fs/par-over", fsResourceOverPipeline)
	fsLeaseOne(t, fsSrv, runnerID)
	fsBlockedNext(t, fsSrv, runnerID)
	waitReason := fsJob(t, fsSrv, jobWait).QueueReason
	overReason := fsJob(t, fsSrv, jobOver).QueueReason
	if waitReason != "RUNNER_CAPACITY" || overReason != "NO_COMPATIBLE_RUNNER" {
		t.Fatalf("fs reasons = %q/%q, want RUNNER_CAPACITY/NO_COMPATIBLE_RUNNER", waitReason, overReason)
	}

	// DB mode over the fake store with the same fixture: profile 8 GiB,
	// 5 GiB reserved, one 5 GiB waiter and one 16 GiB job.
	f := &reservationFakeStore{dbFakeStore: newDBFakeStore(), reserved: model.ResourceCapacity{Memory: 5 << 30}}
	dbSrv := New("token")
	if err := dbSrv.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.profiles["par-prof"] = model.RunnerProfile{ID: "par-prof", MaxCapacity: 8, MaxMemory: 8 << 30}
	f.certProfiles["par-serial"] = "par-prof"
	f.runners["par-runner"] = model.Runner{ID: "par-runner", Name: "par-runner", Capacity: 8, CertSerial: "par-serial"}
	f.runs["par-run"] = model.Run{ID: "par-run", Status: model.StatusQueued}
	f.jobs["par-wait"] = model.Job{ID: "par-wait", RunID: "par-run", Key: "wait", Status: model.StatusQueued, MemoryRequest: 5 << 30, CreatedAt: time.Now().UTC()}
	f.jobs["par-over"] = model.Job{ID: "par-over", RunID: "par-run", Key: "over", Status: model.StatusQueued, MemoryRequest: 16 << 30, CreatedAt: time.Now().UTC().Add(time.Second)}
	f.mu.Unlock()
	if w := doJSON(t, dbSrv, http.MethodPost, "/api/v1/runners/par-runner/next", "token", ""); w.Code != http.StatusNoContent {
		t.Fatalf("db next = %d: %s", w.Code, w.Body.String())
	}
	dbWait, dbOver := f.queueReason("par-wait"), f.queueReason("par-over")
	if dbWait != waitReason || dbOver != overReason {
		t.Fatalf("parity: fs %q/%q vs db %q/%q", waitReason, overReason, dbWait, dbOver)
	}
}
