package server

// Fleet-global queue reasons (E4-C): a persisted queue reason is a
// fleet-level diagnostic, so it must be computed against ALL active
// effective runner profiles, never against the single runner that happened
// to poll. A job another runner can take must not be pinned with
// NO_COMPATIBLE_RUNNER, and a degenerate (single-runner) evaluation must not
// overwrite a fleet-level diagnostic.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/queue"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// fleetListFailStore makes the runner listing fail while every other store
// operation works, so the degraded-fleet contract is observable.
type fleetListFailStore struct {
	*dbFakeStore
	listRunnersErr error
}

func (f *fleetListFailStore) ListRunners(ctx context.Context) ([]model.Runner, error) {
	return nil, f.listRunnersErr
}

var _ storage.Store = (*fleetListFailStore)(nil)

// TestQueueReasonFleetGlobalJobFitsAnotherRunner (E4-C): runner A cannot
// take a GPU job, runner B can. While A polls, the persisted reason must not
// be NO_COMPATIBLE_RUNNER, and it must stay stable across repeated A polls
// (before the fix A's view was persisted).
func TestQueueReasonFleetGlobalJobFitsAnotherRunner(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.runners["fleet-a"] = model.Runner{ID: "fleet-a", Name: "a", Labels: []string{"container"}, Capacity: 1}
	f.runners["fleet-b"] = model.Runner{ID: "fleet-b", Name: "b", Labels: []string{"gpu", "container"}, Capacity: 1}
	f.runs["fleet-run"] = model.Run{ID: "fleet-run", Status: model.StatusQueued}
	// A stale, runner-local diagnostic is already persisted (the job payload
	// is where the store keeps it; queue_reason mirrors the same value): the
	// fleet-global pass must clear it.
	f.jobs["fleet-gpu"] = model.Job{ID: "fleet-gpu", RunID: "fleet-run", Key: "gpu", Status: model.StatusQueued, RequiredLabels: []string{"gpu"}, QueueReason: string(queue.NoCompatibleRunner), CreatedAt: time.Now().UTC()}
	f.queueReasons["fleet-gpu"] = string(queue.NoCompatibleRunner)
	f.mu.Unlock()

	for i := 0; i < 2; i++ {
		w := doJSON(t, s, http.MethodPost, "/api/v1/runners/fleet-a/next", "token", "")
		if w.Code != http.StatusNoContent {
			t.Fatalf("poll %d: %d %s", i, w.Code, w.Body.String())
		}
		if got := f.queueReason("fleet-gpu"); got == string(queue.NoCompatibleRunner) {
			t.Fatalf("poll %d pinned the job with NO_COMPATIBLE_RUNNER although runner B fits: %q", i, got)
		}
		if got := f.queueReason("fleet-gpu"); got != string(queue.None) {
			t.Fatalf("poll %d reason = %q, want cleared (runner B fits)", i, got)
		}
	}
}

// TestQueueReasonFleetGlobalCapacityIsRunnerCapacity (E4-C): every
// compatible runner is out of slots, so the fleet reason is RUNNER_CAPACITY —
// not NO_COMPATIBLE_RUNNER and not a per-runner artifact.
func TestQueueReasonFleetGlobalCapacityIsRunnerCapacity(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.runners["fleet-a"] = model.Runner{ID: "fleet-a", Name: "a", Labels: []string{"container"}, Capacity: 1, ActiveJobs: []string{"busy-a"}}
	f.runners["fleet-b"] = model.Runner{ID: "fleet-b", Name: "b", Labels: []string{"container"}, Capacity: 1, ActiveJobs: []string{"busy-b"}}
	f.runs["fleet-run"] = model.Run{ID: "fleet-run", Status: model.StatusQueued}
	f.jobs["fleet-wait"] = model.Job{ID: "fleet-wait", RunID: "fleet-run", Key: "wait", Status: model.StatusQueued, CreatedAt: time.Now().UTC()}
	f.mu.Unlock()

	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/fleet-a/next", "token", ""); w.Code != http.StatusNoContent {
		t.Fatalf("next = %d %s", w.Code, w.Body.String())
	}
	if got := f.queueReason("fleet-wait"); got != string(queue.RunnerCapacity) {
		t.Fatalf("reason = %q, want RUNNER_CAPACITY (every compatible runner is full)", got)
	}
}

// TestQueueReasonFleetGlobalGenuinelyIncompatible (E4-C): with no runner
// matching the labels, and with the request above every runner's configured
// resource capacity, the reason is NO_COMPATIBLE_RUNNER.
func TestQueueReasonFleetGlobalGenuinelyIncompatible(t *testing.T) {
	f := &reservationFakeStore{dbFakeStore: newDBFakeStore()}
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.profiles["cap-prof"] = model.RunnerProfile{ID: "cap-prof", MaxCapacity: 2, MaxMemory: 4 << 30}
	f.certProfiles["cap-serial"] = "cap-prof"
	f.runners["cap-runner"] = model.Runner{ID: "cap-runner", Name: "cap", Labels: []string{"container"}, Capacity: 2, CertSerial: "cap-serial"}
	f.runs["cap-run"] = model.Run{ID: "cap-run", Status: model.StatusQueued}
	f.jobs["cap-label"] = model.Job{ID: "cap-label", RunID: "cap-run", Key: "label", Status: model.StatusQueued, RequiredLabels: []string{"fpga"}, CreatedAt: time.Now().UTC()}
	f.jobs["cap-over"] = model.Job{ID: "cap-over", RunID: "cap-run", Key: "over", Status: model.StatusQueued, MemoryRequest: 8 << 30, CreatedAt: time.Now().UTC().Add(time.Second)}
	f.mu.Unlock()

	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/cap-runner/next", "token", ""); w.Code != http.StatusNoContent {
		t.Fatalf("next = %d %s", w.Code, w.Body.String())
	}
	if got := f.queueReason("cap-label"); got != string(queue.NoCompatibleRunner) {
		t.Fatalf("label reason = %q, want NO_COMPATIBLE_RUNNER", got)
	}
	if got := f.queueReason("cap-over"); got != string(queue.NoCompatibleRunner) {
		t.Fatalf("over-capacity reason = %q, want NO_COMPATIBLE_RUNNER (permanently above the fleet)", got)
	}
}

// TestQueueReasonFleetListingFailureKeepsOnlyJobScopedReasons (E4-C): when
// the fleet cannot be listed, the pass may still persist job-scoped reasons
// (dependencies) but must not write a fleet-scoped diagnostic from the single
// polling runner — and must not clobber an existing one.
func TestQueueReasonFleetListingFailureKeepsOnlyJobScopedReasons(t *testing.T) {
	inner := newDBFakeStore()
	f := &fleetListFailStore{dbFakeStore: inner, listRunnersErr: errors.New("runner listing down")}
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	inner.mu.Lock()
	inner.runners["solo"] = model.Runner{ID: "solo", Name: "solo", Labels: []string{"container"}, Capacity: 1}
	inner.runs["solo-run"] = model.Run{ID: "solo-run", Status: model.StatusQueued}
	inner.jobs["solo-dep"] = model.Job{ID: "solo-dep", RunID: "solo-run", Key: "dep", Status: model.StatusQueued, Needs: []string{"missing"}, CreatedAt: time.Now().UTC()}
	// A previously persisted fleet-level diagnostic must survive the
	// degraded pass untouched (the payload carries it; the projection
	// mirrors it).
	inner.jobs["solo-gpu"] = model.Job{ID: "solo-gpu", RunID: "solo-run", Key: "gpu", Status: model.StatusQueued, RequiredLabels: []string{"gpu"}, QueueReason: string(queue.NoCompatibleRunner), CreatedAt: time.Now().UTC()}
	inner.jobs["solo-fresh"] = model.Job{ID: "solo-fresh", RunID: "solo-run", Key: "fresh", Status: model.StatusQueued, RequiredLabels: []string{"fpga"}, CreatedAt: time.Now().UTC()}
	inner.queueReasons["solo-gpu"] = string(queue.NoCompatibleRunner)
	inner.mu.Unlock()

	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/solo/next", "token", ""); w.Code != http.StatusNoContent {
		t.Fatalf("next = %d %s", w.Code, w.Body.String())
	}
	if got := inner.queueReason("solo-dep"); got != string(queue.WaitingDependency) {
		t.Fatalf("dependency reason = %q, want WAITING_DEPENDENCY (job-scoped, still persisted)", got)
	}
	if got := inner.queueReason("solo-gpu"); got != string(queue.NoCompatibleRunner) {
		t.Fatalf("existing fleet diagnostic = %q, want it preserved unmodified", got)
	}
	if got := inner.queueReason("solo-fresh"); got != string(queue.None) {
		t.Fatalf("fresh job reason = %q, want empty (no runner-local fleet claim)", got)
	}
}

// TestMemoryQueueReasonIsFleetGlobal (E4-C, fs mode): the in-memory explainer
// uses the same fleet-global evaluation. Runner A (container only) polls for
// a GPU job runner B can take: no runner-local NO_COMPATIBLE_RUNNER may be
// persisted, the result is stable across A's polls, and B then leases it.
func TestMemoryQueueReasonIsFleetGlobal(t *testing.T) {
	s := New("token")
	regA := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"fleet-a","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`)
	if regA.Code != http.StatusOK {
		t.Fatalf("register a: %d %s", regA.Code, regA.Body.String())
	}
	var runnerA model.Runner
	if err := json.Unmarshal(regA.Body.Bytes(), &runnerA); err != nil {
		t.Fatal(err)
	}
	regB := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"fleet-b","protocol_min":3,"protocol_max":3,"labels":["gpu","container"],"capacity":1}`)
	if regB.Code != http.StatusOK {
		t.Fatalf("register b: %d %s", regB.Code, regB.Body.String())
	}
	var runnerB model.Runner
	if err := json.Unmarshal(regB.Body.Bytes(), &runnerB); err != nil {
		t.Fatal(err)
	}
	pipe := `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    runner: [gpu]
    steps:
      - run: echo hi
`
	body, _ := json.Marshal(map[string]any{"repo_url": "https://github.com/fleet/repo.git", "repo_full_name": "fleet/repo", "ref": "main", "pipeline": pipe})
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", string(body)); w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	jobID := ""
	for id := range s.jobs {
		jobID = id
	}
	s.mu.Unlock()

	// A polls twice: the job is leasable by the fleet (runner B), so no
	// runner-local NO_COMPATIBLE_RUNNER may appear or persist.
	for i := 0; i < 2; i++ {
		if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerA.ID+"/next", "token", ""); w.Code != http.StatusNoContent {
			t.Fatalf("A poll %d = %d %s", i, w.Code, w.Body.String())
		}
		if got := fsJob(t, s, jobID).QueueReason; got != "" {
			t.Fatalf("A poll %d reason = %q, want none (runner B fits)", i, got)
		}
	}
	// B leases it through the normal path.
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerB.ID+"/next", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("B next = %d %s", w.Code, w.Body.String())
	}
}

// TestMemoryQueueReasonGenuinelyIncompatible (E4-C, fs mode): no runner has
// the label, so the fleet reason is NO_COMPATIBLE_RUNNER.
func TestMemoryQueueReasonGenuinelyIncompatible(t *testing.T) {
	s := New("token")
	w := doJSON(t, s, http.MethodPost, "/api/v1/runners/register", "token",
		`{"name":"fleet-a","protocol_min":3,"protocol_max":3,"labels":["container"],"capacity":1}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var runner model.Runner
	if err := json.Unmarshal(w.Body.Bytes(), &runner); err != nil {
		t.Fatal(err)
	}
	pipe := `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:` + pinnedImageDigest + `
    runner: [fpga]
    steps:
      - run: echo hi
`
	body, _ := json.Marshal(map[string]any{"repo_url": "https://github.com/fleet/none.git", "repo_full_name": "fleet/none", "ref": "main", "pipeline": pipe})
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runs", "token", string(body)); w.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runner.ID+"/next", "token", ""); w.Code != http.StatusNoContent {
		t.Fatalf("next = %d %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if j.QueueReason != string(queue.NoCompatibleRunner) {
			t.Fatalf("label-incompatible reason = %q, want NO_COMPATIBLE_RUNNER", j.QueueReason)
		}
	}
}

// TestMemoryQueueReasonTableIsFleetGlobal relocates the reason-branch table
// that used to pin the removed per-runner explainer (applyQueueReasonsLocked)
// onto the fleet-global memory path. The per-runner premise is gone — a
// verdict describes the fleet, not the polling runner — so this evaluates the
// same fixtures through applyQueueReasonsMemoryLocked: every code the removed
// function assigned is still assigned for a single-runner fleet, and the
// stale-reason clearing is preserved.
func TestMemoryQueueReasonTableIsFleetGlobal(t *testing.T) {
	s := New("shared-dev-tok")
	now := time.Now().UTC()
	runner := model.Runner{ID: "runner-1", Labels: []string{"linux"}, Region: "eu", Capacity: 4}

	// A stale annotation on a job that is now leasable must be cleared.
	jobs := map[string]model.Job{
		"approval": {ID: "approval", RunID: "run-1", Status: model.StatusWaitingApproval, CreatedAt: now},
		"dep-wait": {ID: "dep-wait", RunID: "run-1", Status: model.StatusQueued, Needs: []string{"upstream"}, Condition: "success()", CreatedAt: now},
		"label":    {ID: "label", RunID: "run-1", Status: model.StatusQueued, RequiredLabels: []string{"gpu"}, CreatedAt: now},
		"region":   {ID: "region", RunID: "run-1", Status: model.StatusQueued, PlacementRegions: []string{"us"}, CreatedAt: now},
		"ready":    {ID: "ready", RunID: "run-1", Status: model.StatusQueued, CreatedAt: now, QueueReason: string(queue.WaitingDependency)},
		"running":  {ID: "running", RunID: "run-1", Status: model.StatusRunning, CreatedAt: now},
		"upstream": {ID: "upstream", RunID: "run-1", Status: model.StatusQueued, CreatedAt: now},
	}
	// The environment-capacity fixture: one running plus one queued job in
	// the same (repo, environment) with concurrency 1.
	jobs["env-running"] = model.Job{ID: "env-running", RunID: "run-1", Status: model.StatusRunning, Environment: "prod", EnvironmentConcurrency: 1, RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r", CreatedAt: now}
	jobs["env-blocked"] = model.Job{ID: "env-blocked", RunID: "run-1", Status: model.StatusQueued, Environment: "prod", EnvironmentConcurrency: 1, RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r", CreatedAt: now}
	s.jobs = jobs

	s.mu.Lock()
	s.applyQueueReasonsMemoryLocked(runner)
	s.mu.Unlock()

	want := map[string]queue.ReasonCode{
		"approval":    queue.WaitingApproval,
		"dep-wait":    queue.WaitingDependency,
		"label":       queue.NoCompatibleRunner,
		"region":      queue.RegionUnavailable,
		"ready":       queue.None,
		"running":     queue.None,
		"upstream":    queue.None,
		"env-running": queue.None,
		"env-blocked": queue.EnvironmentLocked,
	}
	for id, code := range want {
		if got := queue.ReasonCode(fsJob(t, s, id).QueueReason); got != code {
			t.Errorf("job %s reason = %q, want %q", id, got, code)
		}
	}
}

// TestMemoryQueueReasonRequiresOneRunnerWithAllLabels keeps the removed
// per-runner "labels are an exact subset" assertion under fleet semantics: a
// partial match by one runner PLUS a partial match by another must not make
// the job leasable, because one runner must satisfy every required label;
// once a single runner carries them all, the stale diagnostic clears.
func TestMemoryQueueReasonRequiresOneRunnerWithAllLabels(t *testing.T) {
	s := New("shared-dev-tok")
	now := time.Now().UTC()
	s.jobs = map[string]model.Job{
		"both":   {ID: "both", RunID: "run-1", Status: model.StatusQueued, RequiredLabels: []string{"linux", "gpu"}, CreatedAt: now},
		"subset": {ID: "subset", RunID: "run-1", Status: model.StatusQueued, RequiredLabels: []string{"linux"}, CreatedAt: now},
	}
	linuxOnly := model.Runner{ID: "linux-only", Labels: []string{"linux"}, Capacity: 1}
	gpuOnly := model.Runner{ID: "gpu-only", Labels: []string{"gpu"}, Capacity: 1}
	s.runners = map[string]model.Runner{linuxOnly.ID: linuxOnly, gpuOnly.ID: gpuOnly}

	s.mu.Lock()
	s.applyQueueReasonsMemoryLocked(linuxOnly)
	s.mu.Unlock()
	if got := fsJob(t, s, "both").QueueReason; got != string(queue.NoCompatibleRunner) {
		t.Fatalf("two partial label matches: reason = %q, want NO_COMPATIBLE_RUNNER", got)
	}
	if got := fsJob(t, s, "subset").QueueReason; got != "" {
		t.Fatalf("satisfied labels reason = %q, want none", got)
	}

	// One runner carrying every required label clears the stale diagnostic.
	s.mu.Lock()
	linuxOnly.Labels = []string{"linux", "gpu"}
	s.runners[linuxOnly.ID] = linuxOnly
	s.applyQueueReasonsMemoryLocked(linuxOnly)
	s.mu.Unlock()
	if got := fsJob(t, s, "both").QueueReason; got != "" {
		t.Fatalf("full label match reason = %q, want none", got)
	}
}

// fleetReservationStore adds PER-RUNNER reservation sums to the fake store so
// a fleet can have one runner with room and another without.
type fleetReservationStore struct {
	*dbFakeStore
	reserved map[string]model.ResourceCapacity
}

func (f *fleetReservationStore) RunnerReservedResources(ctx context.Context, runnerID string) (model.ResourceCapacity, error) {
	return f.reserved[runnerID], nil
}

func (f *fleetReservationStore) ListResourceReservations(ctx context.Context, runnerID string) ([]storage.ResourceReservation, error) {
	return nil, nil
}

var _ storage.ResourceReservationStore = (*fleetReservationStore)(nil)

// TestQueueReasonFleetGlobalResourceCapacity (E4-C): the fleet reason sees
// RESOURCE capacity, not only job-count capacity. A job above runner A's
// remaining memory but inside runner B's is leasable by the fleet (no
// runner-local RUNNER_CAPACITY); when both runners lack the room it is
// RUNNER_CAPACITY; when the request exceeds every runner's configured
// capacity it is NO_COMPATIBLE_RUNNER.
func TestQueueReasonFleetGlobalResourceCapacity(t *testing.T) {
	f := &fleetReservationStore{dbFakeStore: newDBFakeStore(), reserved: map[string]model.ResourceCapacity{"res-a": {Memory: 6 << 30}, "res-b": {}}}
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	for _, id := range []string{"res-a", "res-b"} {
		prof := "prof-" + id
		f.profiles[prof] = model.RunnerProfile{ID: prof, MaxCapacity: 8, MaxMemory: 8 << 30}
		f.certProfiles["serial-"+id] = prof
		f.runners[id] = model.Runner{ID: id, Name: id, Capacity: 8, CertSerial: "serial-" + id}
	}
	f.runs["res-run"] = model.Run{ID: "res-run", Status: model.StatusQueued}
	f.jobs["res-wait"] = model.Job{ID: "res-wait", RunID: "res-run", Key: "wait", Status: model.StatusQueued, MemoryRequest: 5 << 30, CreatedAt: time.Now().UTC()}
	f.jobs["res-over"] = model.Job{ID: "res-over", RunID: "res-run", Key: "over", Status: model.StatusQueued, MemoryRequest: 16 << 30, CreatedAt: time.Now().UTC().Add(time.Second)}
	f.mu.Unlock()

	// Runner A is out of memory (6+5 > 8) but runner B has room: no reason.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/res-a/next", "token", ""); w.Code != http.StatusNoContent {
		t.Fatalf("next = %d %s", w.Code, w.Body.String())
	}
	if got := f.queueReason("res-wait"); got != string(queue.None) {
		t.Fatalf("reason while runner B has room = %q, want none", got)
	}
	if got := f.queueReason("res-over"); got != string(queue.NoCompatibleRunner) {
		t.Fatalf("over-capacity reason = %q, want NO_COMPATIBLE_RUNNER", got)
	}

	// Now both runners are out of memory: RUNNER_CAPACITY.
	f.mu.Lock()
	f.reserved["res-b"] = model.ResourceCapacity{Memory: 6 << 30}
	f.mu.Unlock()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/res-a/next", "token", ""); w.Code != http.StatusNoContent {
		t.Fatalf("next = %d %s", w.Code, w.Body.String())
	}
	if got := f.queueReason("res-wait"); got != string(queue.RunnerCapacity) {
		t.Fatalf("reason when the whole fleet lacks room = %q, want RUNNER_CAPACITY", got)
	}
}
