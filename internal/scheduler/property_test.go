package scheduler

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// Property tests drive the SQL-backed scheduler with randomized event
// sequences against the behavioral fakeStore and check the control-plane
// invariants after every single event. Sequences use math/rand with fixed
// seeds so failures reproduce exactly.

type propWorld struct {
	t       *testing.T
	ctx     context.Context
	store   *fakeStore
	sched   *DBScheduler
	rng     *rand.Rand
	runners []string
	runIDs  []string
	prev    map[string]model.Job
	prevGen map[string]int64
	now     time.Time
}

func propNewWorld(t *testing.T, seed int64) *propWorld {
	t.Helper()
	store := newFakeStore()
	store.setLeader(true, nil)
	sched := NewDB(store, 45*time.Second, nil, nil)
	if err := sched.InitErr(); err != nil {
		t.Fatalf("leadership init: %v", err)
	}
	rng := rand.New(rand.NewSource(seed))
	w := &propWorld{
		t:       t,
		ctx:     context.Background(),
		store:   store,
		sched:   sched,
		rng:     rng,
		prev:    map[string]model.Job{},
		prevGen: map[string]int64{},
		now:     time.Now().UTC().Truncate(time.Second),
	}
	for i := 0; i < 3; i++ {
		cap := 1 + rng.Intn(3)
		id := fmt.Sprintf("runner%d", i)
		store.putRunner(model.Runner{ID: id, Capacity: cap, Labels: []string{"linux"}})
		w.runners = append(w.runners, id)
	}
	runID := fmt.Sprintf("run%d", seed)
	store.putRun(model.Run{ID: runID, Status: model.StatusQueued, CreatedAt: w.now})
	w.runIDs = append(w.runIDs, runID)
	for _, j := range propDAG(w, runID) {
		store.putJob(j)
	}
	return w
}

// propDAG builds a small deterministic dependency graph: a -> b,c;
// b,c -> d; d -> f; c -> e; e -> f. Conditions and environments are random.
func propDAG(w *propWorld, runID string) []model.Job {
	needs := map[string][]string{
		"a": {}, "b": {"a"}, "c": {"a"}, "d": {"b", "c"},
		"e": {"c"}, "f": {"d", "e"},
	}
	conditions := []string{"", "success()", "always()", "failure()"}
	envs := []string{"", "staging", "prod"}
	out := make([]model.Job, 0, len(needs))
	keys := make([]string, 0, len(needs))
	for k := range needs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		env := envs[w.rng.Intn(len(envs))]
		concurrency := 0
		if env != "" {
			concurrency = 1 + w.rng.Intn(2)
		}
		out = append(out, model.Job{
			ID:                     runID + "-" + key,
			RunID:                  runID,
			Key:                    key,
			Needs:                  needs[key],
			Condition:              conditions[w.rng.Intn(len(conditions))],
			Status:                 model.StatusQueued,
			CreatedAt:              w.now,
			Priority:               w.rng.Intn(5),
			Environment:            env,
			EnvironmentConcurrency: concurrency,
		})
	}
	return out
}

func (w *propWorld) jobs() map[string]model.Job {
	out := map[string]model.Job{}
	for _, runID := range w.runIDs {
		jobs, err := w.store.ListJobsByRun(w.ctx, runID)
		if err != nil {
			w.t.Fatalf("ListJobsByRun: %v", err)
		}
		for _, j := range jobs {
			out[j.ID] = j
		}
	}
	return out
}

func (w *propWorld) sortedRunning() []model.Job {
	var out []model.Job
	for _, j := range w.jobs() {
		if j.Status == model.StatusRunning {
			out = append(out, j)
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i].ID < out[k].ID })
	return out
}

func (w *propWorld) step() {
	switch w.rng.Intn(6) {
	case 0:
		w.opLease()
	case 1:
		w.opHeartbeat()
	case 2:
		w.opComplete()
	case 3:
		w.opCancelRun()
	case 4:
		w.opRecover()
	case 5:
		w.opEnqueue()
	}
	w.now = w.now.Add(time.Duration(w.rng.Intn(90)) * time.Second)
}

func (w *propWorld) opLease() {
	runner := w.runners[w.rng.Intn(len(w.runners))]
	_, _, _, err := w.sched.Lease(w.ctx, runner, w.now)
	if err != nil && !errors.Is(err, ErrNoJobs) {
		w.t.Fatalf("Lease returned unexpected error: %v", err)
	}
}

func (w *propWorld) opHeartbeat() {
	running := w.sortedRunning()
	if len(running) == 0 {
		return
	}
	j := running[w.rng.Intn(len(running))]
	_, _ = w.sched.Heartbeat(w.ctx, j.ID, j.LeaseRunnerID, j.LeaseTokenHash, j.LeaseGeneration, w.now.Add(time.Minute))
}

func (w *propWorld) opComplete() {
	running := w.sortedRunning()
	if len(running) == 0 {
		return
	}
	j := running[w.rng.Intn(len(running))]
	statuses := []model.Status{model.StatusSuccess, model.StatusFailure, model.StatusCancelled}
	status := statuses[w.rng.Intn(len(statuses))]
	if err := w.sched.Complete(w.ctx, j.ID, j.LeaseGeneration, j.LeaseRunnerID, status, "prop error", map[string]string{"out": "1"}, fmt.Sprintf("hash%d", w.rng.Int())); err != nil {
		w.t.Fatalf("Complete returned unexpected error: %v", err)
	}
	w.assertCompletionIdempotent(j.ID, j.LeaseGeneration, j.LeaseRunnerID)
}

func (w *propWorld) opCancelRun() {
	runID := w.runIDs[w.rng.Intn(len(w.runIDs))]
	// Record running jobs so publication through the stale lease can be
	// attempted after the cancellation.
	var stale []model.Job
	for _, j := range w.jobs() {
		if j.RunID == runID && j.Status == model.StatusRunning {
			stale = append(stale, j)
		}
	}
	if err := w.sched.CancelRun(w.ctx, runID, "prop cancel"); err != nil {
		w.t.Fatalf("CancelRun returned unexpected error: %v", err)
	}
	for _, j := range stale {
		w.assertCancelledBlocksPublication(j)
	}
}

func (w *propWorld) opRecover() {
	if err := w.sched.RecoverExpired(w.ctx, w.now.Add(24*time.Hour)); err != nil && !errors.Is(err, ErrNotLeader) {
		w.t.Fatalf("RecoverExpired returned unexpected error: %v", err)
	}
}

func (w *propWorld) opEnqueue() {
	n := len(w.runIDs)
	runID := fmt.Sprintf("run%d-x%d", w.now.UnixNano(), n)
	run := model.Run{ID: runID, Status: model.StatusQueued, CreatedAt: w.now, ConcurrencyGroup: fmt.Sprintf("group%d", w.rng.Intn(3))}
	jobs := propDAG(w, runID)
	jobMap := map[string]model.Job{}
	deps := map[string][]string{}
	for _, j := range jobs {
		jobMap[j.ID] = j
		deps[j.ID] = j.Needs
	}
	if err := w.sched.Enqueue(w.ctx, run, jobMap, deps, w.rng.Intn(2) == 0); err != nil {
		w.t.Fatalf("Enqueue returned unexpected error: %v", err)
	}
	w.runIDs = append(w.runIDs, runID)
}

// assertCompletionIdempotent replays a completion for a finished generation:
// it must be a no-op (duplicate receipt) or a rejected stale lease, and it
// must never mutate the job a second time.
func (w *propWorld) assertCompletionIdempotent(jobID string, generation int64, runnerID string) {
	before, ok := w.store.job(jobID)
	if !ok {
		return
	}
	err := w.store.CompleteJob(w.ctx, jobID, generation, runnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: jobID, Generation: generation, RunnerID: runnerID, ResultHash: "replay"})
	if err != nil && !errors.Is(err, storage.ErrGenerationMismatch) {
		w.t.Fatalf("replayed CompleteJob returned unexpected error: %v", err)
	}
	after, _ := w.store.job(jobID)
	if before.Status != after.Status || before.Error != after.Error || before.Attempts != after.Attempts {
		w.t.Fatalf("replayed completion mutated job %s: %s/%s/%d -> %s/%s/%d", jobID, before.Status, before.Error, before.Attempts, after.Status, after.Error, after.Attempts)
	}
}

// assertCancelledBlocksPublication verifies the lease-invalidation path: a
// cancelled job cannot publish a completion, and its lease fields are wiped.
func (w *propWorld) assertCancelledBlocksPublication(stale model.Job) {
	err := w.store.CompleteJob(w.ctx, stale.ID, stale.LeaseGeneration, stale.LeaseRunnerID, model.StatusSuccess, "", map[string]string{"sneaky": "1"}, model.CompletionReceipt{JobID: stale.ID, Generation: stale.LeaseGeneration, RunnerID: stale.LeaseRunnerID, ResultHash: "sneaky"})
	if !errors.Is(err, storage.ErrGenerationMismatch) && !errors.Is(err, storage.ErrLeaseConflict) {
		w.t.Fatalf("cancelled job %s published a completion: %v", stale.ID, err)
	}
	cur, ok := w.store.job(stale.ID)
	if !ok {
		return
	}
	if cur.Status == model.StatusSuccess {
		w.t.Fatalf("cancelled job %s was flipped to success by a stale completion", stale.ID)
	}
	if cur.LeaseRunnerID != "" || cur.LeaseTokenHash != nil || cur.LeaseExpiresAt != nil {
		w.t.Fatalf("cancelled job %s kept lease state: runner=%q token=%v expires=%v", stale.ID, cur.LeaseRunnerID, cur.LeaseTokenHash, cur.LeaseExpiresAt)
	}
}

// assertInvariants checks every control-plane invariant after one event.
func (w *propWorld) assertInvariants() {
	jobs := w.jobs()

	// One active generation per job: a job is leased by at most one runner,
	// a running job is held by exactly one, and a queued job by none.
	hold := map[string]int{}
	runnerJobs := map[string][]string{}
	for _, rid := range w.runners {
		r, err := w.store.GetRunner(w.ctx, rid)
		if err != nil {
			w.t.Fatalf("GetRunner(%s): %v", rid, err)
		}
		runnerJobs[rid] = r.ActiveJobs
		cap := r.Capacity
		if cap < 1 {
			cap = 1
		}
		if len(r.ActiveJobs) > cap {
			w.t.Fatalf("runner %s capacity %d exceeded: %d active", rid, cap, len(r.ActiveJobs))
		}
		for _, id := range r.ActiveJobs {
			hold[id]++
			if hold[id] > 1 {
				w.t.Fatalf("job %s is actively leased by more than one runner", id)
			}
		}
	}
	for id, j := range jobs {
		switch j.Status {
		case model.StatusRunning:
			if hold[id] != 1 {
				w.t.Fatalf("running job %s is held by %d runners", id, hold[id])
			}
		case model.StatusQueued:
			if hold[id] != 0 {
				w.t.Fatalf("queued job %s is held by %d runners", id, hold[id])
			}
		}
		if j.LeaseGeneration < w.prevGen[id] {
			w.t.Fatalf("job %s lease generation went backwards: %d -> %d", id, w.prevGen[id], j.LeaseGeneration)
		}
	}

	// Terminal jobs never become running without a rerun (attempts++).
	for id, j := range jobs {
		if p, ok := w.prev[id]; ok && p.Status.Terminal() && !j.Status.Terminal() {
			if j.Attempts <= p.Attempts {
				w.t.Fatalf("job %s left terminal state %s for %s without a rerun (attempts %d -> %d)", id, p.Status, j.Status, p.Attempts, j.Attempts)
			}
		}
	}

	// A running job's dependencies must all be terminal and permitted by
	// the unified condition gate.
	for id, j := range jobs {
		if j.Status != model.StatusRunning {
			continue
		}
		ready, outcome := DependencyOutcome(j.Needs, nil, func(dep string) (model.Status, bool) {
			d, ok := jobs[dep]
			return d.Status, ok
		})
		if !ready {
			w.t.Fatalf("running job %s has non-terminal dependencies", id)
		}
		if !ConditionAllows(j.Condition, outcome) {
			w.t.Fatalf("running job %s has dependency outcome %s not permitted by condition %q", id, outcome, j.Condition)
		}
	}

	// Environment concurrency is never exceeded: a running job targeting a
	// limited environment can only run when the other active jobs in that
	// environment are below the limit.
	for id, j := range jobs {
		if j.Status != model.StatusRunning {
			continue
		}
		if j.Environment != "" && j.EnvironmentConcurrency > 0 {
			if EnvironmentAtCapacity(j, jobs) {
				w.t.Fatalf("running job %s exceeds environment %q concurrency %d", id, j.Environment, j.EnvironmentConcurrency)
			}
		}
	}

	w.prev = jobs
	for id, j := range jobs {
		w.prevGen[id] = j.LeaseGeneration
	}
}

// TestPropertySchedulerRandomSequences drives 300 fixed-seed randomized
// event sequences (40 events each) over lease, heartbeat, completion,
// cancellation, recovery and enqueue, asserting every invariant above after
// every single event.
func TestPropertySchedulerRandomSequences(t *testing.T) {
	const (
		sequences = 300
		events    = 40
	)
	for seed := int64(0); seed < sequences; seed++ {
		w := propNewWorld(t, seed)
		for i := 0; i < events; i++ {
			w.step()
			w.assertInvariants()
		}
	}
}

// TestPropertyCancelledJobCannotPublish deterministically exercises the
// cancellation -> publication path end to end and asserts the full lease
// invalidation contract.
func TestPropertyCancelledJobCannotPublish(t *testing.T) {
	w := propNewWorld(t, 42)
	runner := w.runners[0]
	for i := 0; i < 8; i++ {
		_, _, _, err := w.sched.Lease(w.ctx, runner, w.now)
		if err != nil && !errors.Is(err, ErrNoJobs) {
			t.Fatalf("Lease: %v", err)
		}
		w.now = w.now.Add(time.Minute)
	}
	running := w.sortedRunning()
	if len(running) == 0 {
		t.Fatal("expected at least one leased job")
	}
	leased := running[0]
	runID := leased.RunID
	if err := w.sched.CancelRun(w.ctx, runID, "deterministic cancel"); err != nil {
		t.Fatalf("CancelRun: %v", err)
	}
	// Publication through the stale lease must be rejected.
	w.assertCancelledBlocksPublication(leased)
	// Publication with a bumped generation must also be rejected.
	err := w.store.CompleteJob(w.ctx, leased.ID, leased.LeaseGeneration+1, leased.LeaseRunnerID, model.StatusSuccess, "", nil, model.CompletionReceipt{JobID: leased.ID, Generation: leased.LeaseGeneration + 1, RunnerID: leased.LeaseRunnerID, ResultHash: "bump"})
	if !errors.Is(err, storage.ErrGenerationMismatch) {
		t.Fatalf("bumped-generation completion was accepted: %v", err)
	}
	// No new receipts exist for the cancelled job.
	if _, ok, _ := w.store.HasCompletionReceipt(w.ctx, leased.ID, leased.LeaseGeneration, leased.LeaseRunnerID); ok {
		t.Fatal("cancelled job has a completion receipt")
	}
	w.assertInvariants()
}

func propRandomCapabilities(rng *rand.Rand) policy.Capabilities {
	names := []string{"CI_TOKEN", "DEPLOY_KEY", "NPM_TOKEN"}
	var secrets map[string]bool
	if rng.Intn(2) == 0 {
		secrets = map[string]bool{}
		for _, n := range names {
			if rng.Intn(2) == 0 {
				secrets[n] = true
			}
		}
	}
	var oidc []string
	if rng.Intn(2) == 0 {
		oidc = []string{}
		for _, a := range []string{"https://api.example.com", "sts.amazonaws.com"} {
			if rng.Intn(2) == 0 {
				oidc = append(oidc, a)
			}
		}
	}
	var labels []string
	if rng.Intn(2) == 0 {
		labels = []string{}
		for _, l := range []string{"linux", "gpu", "arm64"} {
			if rng.Intn(2) == 0 {
				labels = append(labels, l)
			}
		}
	}
	return policy.Capabilities{
		NativeExecution:    rng.Intn(2) == 0,
		Container:          rng.Intn(2) == 0,
		Tart:               rng.Intn(2) == 0,
		Network:            pipeline.NetworkPolicy(rng.Intn(4)),
		Secrets:            secrets,
		OIDC:               oidc,
		Deployments:        rng.Intn(2) == 0,
		CacheRead:          rng.Intn(2) == 0,
		CacheWrite:         rng.Intn(2) == 0,
		RunnerLabels:       labels,
		GenerateChildGraph: rng.Intn(2) == 0,
		CrossRepoTrigger:   rng.Intn(2) == 0,
	}
}

func propNetRank(p pipeline.NetworkPolicy) int {
	switch p {
	case pipeline.NetworkPolicyNone:
		return 0
	case pipeline.NetworkPolicyServicesOnly:
		return 1
	default:
		return 2
	}
}

// TestPropertyCapabilitiesMonotone checks 200 random capability pairs: the
// Intersect result never grants more than either input (least privilege),
// and the untrusted Effective floor can never be lifted above
// DefaultUntrustedCapabilities.
func TestPropertyCapabilitiesMonotone(t *testing.T) {
	const pairs = 200
	floor := policy.DefaultUntrustedCapabilities()
	for seed := int64(0); seed < pairs; seed++ {
		rng := rand.New(rand.NewSource(seed))
		a, b := propRandomCapabilities(rng), propRandomCapabilities(rng)
		got := policy.Intersect(a, b)

		booleans := []struct {
			name                    string
			va, vb, vg              bool
		}{
			{"NativeExecution", a.NativeExecution, b.NativeExecution, got.NativeExecution},
			{"Container", a.Container, b.Container, got.Container},
			{"Tart", a.Tart, b.Tart, got.Tart},
			{"Deployments", a.Deployments, b.Deployments, got.Deployments},
			{"CacheRead", a.CacheRead, b.CacheRead, got.CacheRead},
			{"CacheWrite", a.CacheWrite, b.CacheWrite, got.CacheWrite},
			{"GenerateChildGraph", a.GenerateChildGraph, b.GenerateChildGraph, got.GenerateChildGraph},
			{"CrossRepoTrigger", a.CrossRepoTrigger, b.CrossRepoTrigger, got.CrossRepoTrigger},
		}
		for _, f := range booleans {
			if f.vg && !(f.va && f.vb) {
				t.Fatalf("seed %d: Intersect granted %s beyond both inputs", seed, f.name)
			}
		}
		if rg, ra, rb := propNetRank(got.Network), propNetRank(a.Network), propNetRank(b.Network); rg > ra || rg > rb {
			t.Fatalf("seed %d: Intersect network %v exceeds an input (%v, %v)", seed, got.Network, a.Network, b.Network)
		}
		for k := range got.Secrets {
			if a.Secrets != nil && !a.Secrets[k] {
				t.Fatalf("seed %d: Intersect grants secret %q absent from input a", seed, k)
			}
			if b.Secrets != nil && !b.Secrets[k] {
				t.Fatalf("seed %d: Intersect grants secret %q absent from input b", seed, k)
			}
		}
		for _, audience := range []string{"https://api.example.com", "sts.amazonaws.com", "https://other.example.net"} {
			if got.OIDCAllows(audience) && (!a.OIDCAllows(audience) || !b.OIDCAllows(audience)) {
				t.Fatalf("seed %d: Intersect allows OIDC audience %q denied by an input", seed, audience)
			}
		}
		for _, l := range got.RunnerLabels {
			if !containsStringProp(a.RunnerLabels, l) || !containsStringProp(b.RunnerLabels, l) {
				t.Fatalf("seed %d: Intersect grants runner label %q absent from an input", seed, l)
			}
		}

		// Untrusted floor: Effective(false) must be a subset of the floor.
		eff := got.Effective(false)
		effBools := []struct {
			name          string
			veff, vfloor  bool
		}{
			{"NativeExecution", eff.NativeExecution, floor.NativeExecution},
			{"Container", eff.Container, floor.Container},
			{"Tart", eff.Tart, floor.Tart},
			{"Deployments", eff.Deployments, floor.Deployments},
			{"CacheRead", eff.CacheRead, floor.CacheRead},
			{"CacheWrite", eff.CacheWrite, floor.CacheWrite},
			{"GenerateChildGraph", eff.GenerateChildGraph, floor.GenerateChildGraph},
			{"CrossRepoTrigger", eff.CrossRepoTrigger, floor.CrossRepoTrigger},
		}
		for _, f := range effBools {
			if f.veff && !f.vfloor {
				t.Fatalf("seed %d: Effective(false) lifted %s above the untrusted floor", seed, f.name)
			}
		}
		if propNetRank(eff.Network) > propNetRank(floor.Network) {
			t.Fatalf("seed %d: Effective(false) network %v lifted above floor %v", seed, eff.Network, floor.Network)
		}
		if eff.Secrets == nil || len(eff.Secrets) != 0 {
			t.Fatalf("seed %d: Effective(false) secrets must be an empty allowlist, got %v", seed, eff.Secrets)
		}
		if eff.OIDC == nil || len(eff.OIDC) != 0 {
			t.Fatalf("seed %d: Effective(false) OIDC must be an empty allowlist, got %v", seed, eff.OIDC)
		}
		for _, audience := range []string{"sts.amazonaws.com", "https://api.example.com"} {
			if eff.OIDCAllows(audience) {
				t.Fatalf("seed %d: Effective(false) allows OIDC audience %q", seed, audience)
			}
		}
	}
}

// TestPropertyEnvironmentAtCapacityMath pins the environment concurrency
// helper's boundary arithmetic used by the scheduler lease path.
func TestPropertyEnvironmentAtCapacityMath(t *testing.T) {
	mk := func(id, env string, status model.Status) model.Job {
		return model.Job{ID: id, Environment: env, Status: status, EnvironmentConcurrency: 2}
	}
	jobs := map[string]model.Job{
		"a": mk("a", "staging", model.StatusRunning),
		"b": mk("b", "staging", model.StatusRunning),
		"c": mk("c", "staging", model.StatusQueued),
		"d": mk("d", "prod", model.StatusRunning),
		"e": mk("e", "", model.StatusRunning),
	}
	if !EnvironmentAtCapacity(jobs["c"], jobs) {
		t.Fatal("staging at concurrency 2 with two active jobs must be at capacity")
	}
	if !EnvironmentAtCapacity(jobs["a"], jobs) {
		t.Fatal("a running staging job observes one other active job, at limit")
	}
	if EnvironmentAtCapacity(jobs["d"], jobs) {
		t.Fatal("prod has only one active job, must not be at capacity")
	}
	if EnvironmentAtCapacity(jobs["e"], jobs) {
		t.Fatal("an empty environment must never be at capacity")
	}
}

func containsStringProp(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}
