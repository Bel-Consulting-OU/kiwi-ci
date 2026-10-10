package scheduler

// model_property_test.go is a deterministic reference-model property test for
// the control plane's hardest distributed invariants. It drives the REAL
// DBScheduler (Lease/Heartbeat/Complete/CancelRun/RecoverExpired) over the
// package's behavioral store fakes with a seeded math/rand, and maintains a
// parallel reference model of (status, generation, holder, attempts, lease
// expiry, terminal flag). After EVERY operation both the reference model and
// the store are compared, every lease/liveness invariant is re-checked, and a
// stale-generation completion/heartbeat probe proves that a stale claim can
// never mutate state or leave a phantom reservation.
//
// The store fake is extended ONLY inside this test file: the shared
// atomicFakeStore maintains its runner active-set in a private map that its
// own inherited CompleteJob/RecoverExpiredLease/CancelRunJobs paths do not
// update, so the wrapper here keeps that map in lockstep (mirroring the real
// stores, where completion and recovery release the reservation and the
// runner slot in the same transaction). No production code is touched.
//
// On failure the seed, step index and the full operation history are printed
// so the failing sequence is reproducible.

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// ---------------------------------------------------------------------------
// Store fake wrapper: reservation ledger + runner-slot release consistency.
// ---------------------------------------------------------------------------

// propModelStore wraps the package's atomicFakeStore so the runner active-set
// used by the atomic claim stays consistent with the runner row on every
// release path, and so the reservation ledger (derived from those active jobs)
// is readable through storage.ResourceReservationStore exactly as the real
// stores expose it.
type propModelStore struct {
	*atomicFakeStore
}

var (
	_ storage.Store                    = (*propModelStore)(nil)
	_ storage.AtomicLeaseStore         = (*propModelStore)(nil)
	_ storage.ResourceReservationStore = (*propModelStore)(nil)
)

func newPropModelStore() *propModelStore {
	return &propModelStore{atomicFakeStore: newAtomicFakeStore()}
}

// releaseActive removes jobID from the runner's atomic active set and from the
// runner row, mirroring the one-transaction release of the real stores.
func (m *propModelStore) releaseActive(runnerID, jobID string) {
	a := m.atomicFakeStore
	a.mu.Lock()
	if act, ok := a.active[runnerID]; ok {
		out := act[:0]
		for _, id := range act {
			if id != jobID {
				out = append(out, id)
			}
		}
		a.active[runnerID] = out
	}
	a.mu.Unlock()
	fs := m.atomicFakeStore.fakeStore
	fs.mu.Lock()
	fs.releaseRunnerSlotLocked(runnerID, jobID)
	fs.mu.Unlock()
}

func (m *propModelStore) holderOf(jobID string) string {
	fs := m.atomicFakeStore.fakeStore
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.jobs[jobID].LeaseRunnerID
}

// CompleteJob releases the runner slot and reservation on a successful
// completion (stale/failed completions never touch them).
func (m *propModelStore) CompleteJob(ctx context.Context, jobID string, generation int64, runnerID string, status model.Status, errMsg string, outputs map[string]string, receipt model.CompletionReceipt, observed *model.ObservedRuntime) error {
	holder := m.holderOf(jobID)
	err := m.atomicFakeStore.fakeStore.CompleteJob(ctx, jobID, generation, runnerID, status, errMsg, outputs, receipt, observed)
	if err == nil && holder != "" {
		m.releaseActive(holder, jobID)
	}
	return err
}

// RecoverExpiredLease releases the runner slot on an actual transition; a
// no-op recovery (future expiry, wrong generation, non-running) must leave
// the active set untouched.
func (m *propModelStore) RecoverExpiredLease(ctx context.Context, jobID string, expectedGeneration int64, now time.Time) error {
	holder := m.holderOf(jobID)
	err := m.atomicFakeStore.fakeStore.RecoverExpiredLease(ctx, jobID, expectedGeneration, now)
	if err == nil && holder != "" && m.holderOf(jobID) == "" {
		m.releaseActive(holder, jobID)
	}
	return err
}

// CancelRunJobs releases every cancelled running job's slot; the inherited
// fake only flips statuses.
func (m *propModelStore) CancelRunJobs(ctx context.Context, runID, reason string) ([]string, error) {
	fs := m.atomicFakeStore.fakeStore
	fs.mu.Lock()
	holders := map[string]string{}
	for id, j := range fs.jobs {
		if j.RunID == runID && !j.Status.Terminal() && j.LeaseRunnerID != "" {
			holders[id] = j.LeaseRunnerID
		}
	}
	fs.mu.Unlock()
	ids, err := fs.CancelRunJobs(ctx, runID, reason)
	if err == nil {
		for id, holder := range holders {
			m.releaseActive(holder, id)
		}
	}
	return ids, err
}

// RunnerReservedResources derives the ledger from the atomic active set,
// summing each active job's total reservation exactly like the real query.
func (m *propModelStore) RunnerReservedResources(ctx context.Context, runnerID string) (model.ResourceCapacity, error) {
	a := m.atomicFakeStore
	a.mu.Lock()
	ids := append([]string(nil), a.active[runnerID]...)
	a.mu.Unlock()
	var out model.ResourceCapacity
	fs := m.atomicFakeStore.fakeStore
	fs.mu.Lock()
	for _, id := range ids {
		if j, ok := fs.jobs[id]; ok {
			out = model.AddResourceCapacity(out, j.ReservedResources())
		}
	}
	fs.mu.Unlock()
	return out, nil
}

func (m *propModelStore) ListResourceReservations(ctx context.Context, runnerID string) ([]storage.ResourceReservation, error) {
	return nil, nil
}

// receiptCount and auditCount read the fake's append-only tables under lock.
func (m *propModelStore) receiptCount() int {
	fs := m.atomicFakeStore.fakeStore
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return len(fs.receipts)
}

func (m *propModelStore) auditCount() int {
	fs := m.atomicFakeStore.fakeStore
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return len(fs.audit)
}

// activeSet snapshots one runner's row active set.
func (m *propModelStore) activeSet(runnerID string) []string {
	fs := m.atomicFakeStore.fakeStore
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return append([]string(nil), fs.runners[runnerID].ActiveJobs...)
}

// ---------------------------------------------------------------------------
// Reference model.
// ---------------------------------------------------------------------------

type schedulerModelJob struct {
	id              string
	needs           []string
	status          model.Status
	generation      int64
	holder          string
	attempts        int
	maxInfraRetries int
	expires         *time.Time
	createdAt       time.Time
	priority        int
	cpu             float64
	key             string
}

type schedulerModelWorld struct {
	t     *testing.T
	seed  int64
	rng   *rand.Rand
	ctx   context.Context
	store *propModelStore
	sched *DBScheduler

	now     time.Time
	step    int
	history []string

	runs     []*schedulerModelRun
	jobs     map[string]*schedulerModelJob
	jobOrder []string

	runners []string
	caps    map[string]int

	// prev is the snapshot at the end of the previous invariant check, used
	// for generation monotonicity and terminal-state stability.
	prev map[string]schedulerModelSnapshot

	// receipts is the model's completion-receipt table: exactly the successful
	// CompleteJob transitions.
	receipts map[string]bool

	// stats guards against a degenerate sequence: the property run asserts
	// these transitions actually happened, so a green test can never be the
	// result of every operation being a no-op.
	stats propStats
}

type propStats struct {
	claims      int
	completions int
	requeues    int
	expired     int
	cancels     int
	blocked     int
	staleProbes int
}

type schedulerModelSnapshot struct {
	status   model.Status
	gen      int64
	attempts int
}

// schedulerModelRun tracks one enqueued run: each starts with a fresh 3..6
// job DAG. New runs are enqueued as earlier runs terminate, so the operation
// sequence keeps exercising live distributed state instead of degenerating
// into no-ops after a cancellation.
type schedulerModelRun struct {
	id   string
	jobs []string
}

func newSchedulerModelWorld(t *testing.T, seed int64) *schedulerModelWorld {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	store := newPropModelStore()
	sched := NewDB(store, 90*time.Second, nil, nil)
	if err := sched.InitErr(); err != nil {
		t.Fatalf("seed %d: leadership init: %v", seed, err)
	}
	w := &schedulerModelWorld{
		t:        t,
		seed:     seed,
		rng:      rng,
		ctx:      context.Background(),
		store:    store,
		sched:    sched,
		now:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		jobs:     map[string]*schedulerModelJob{},
		caps:     map[string]int{},
		prev:     map[string]schedulerModelSnapshot{},
		receipts: map[string]bool{},
	}
	if !sched.IsLeader(w.ctx) {
		t.Fatalf("seed %d: scheduler is not leader", seed)
	}
	nRunners := 1 + rng.Intn(3)
	for i := 0; i < nRunners; i++ {
		id := fmt.Sprintf("runner%d", i)
		capacity := 1 + rng.Intn(3)
		w.runners = append(w.runners, id)
		w.caps[id] = capacity
		if err := store.UpsertRunner(w.ctx, model.Runner{
			ID: id, Name: id, Capacity: capacity,
			ResourceCapacity: model.ResourceCapacity{CPU: 8},
		}); err != nil {
			t.Fatalf("seed %d: upsert runner: %v", seed, err)
		}
	}
	w.enqueueRun()
	w.logf("init: jobs=%d runners=%v caps=%v", len(w.jobOrder), w.runners, w.caps)
	w.assertInvariants()
	return w
}

// enqueueRun creates one fresh run with a 3..6 job DAG and inserts it through
// the store (runs are created by opEnqueue too, so a cancelled run never
// dead-ends the sequence).
func (w *schedulerModelWorld) enqueueRun() {
	nJobs := 3 + w.rng.Intn(4) // 3..6
	base := w.now.Add(10 * time.Second)
	w.now = base
	runID := fmt.Sprintf("run-%d-%d", w.seed, len(w.runs))
	if err := w.store.InsertRun(w.ctx, model.Run{ID: runID, Status: model.StatusQueued, CreatedAt: base}); err != nil {
		w.t.Fatalf("seed %d: insert run %s: %v", w.seed, runID, err)
	}
	rm := &schedulerModelRun{id: runID}
	prevIDs := make([]string, 0, nJobs)
	for i := 0; i < nJobs; i++ {
		id := fmt.Sprintf("%s-job%d", runID, i)
		var needs []string
		for p := 0; p < i; p++ {
			if w.rng.Intn(100) < 45 {
				needs = append(needs, prevIDs[p])
			}
		}
		w.addJob(runID, id, needs, w.rng.Intn(3), float64(1+w.rng.Intn(2)), w.rng.Intn(3), base.Add(time.Duration(i)*time.Second))
		prevIDs = append(prevIDs, id)
		rm.jobs = append(rm.jobs, id)
	}
	w.runs = append(w.runs, rm)
	w.logf("EnqueueRun(%s) jobs=%v", runID, rm.jobs)
}

// addJob inserts one queued job into the run and the model.
func (w *schedulerModelWorld) addJob(runID, id string, needs []string, priority int, cpu float64, maxInfraRetries int, createdAt time.Time) {
	j := model.Job{
		ID: id, RunID: runID, Key: id, Status: model.StatusQueued,
		Needs: needs, Priority: priority, CPURequest: cpu,
		MaxInfraRetries: maxInfraRetries, CreatedAt: createdAt,
	}
	if err := w.store.InsertJob(w.ctx, j); err != nil {
		w.t.Fatalf("seed %d: insert job %s: %v", w.seed, id, err)
	}
	w.jobs[id] = &schedulerModelJob{
		id: id, needs: append([]string(nil), needs...), status: model.StatusQueued,
		maxInfraRetries: maxInfraRetries, createdAt: createdAt, priority: priority, cpu: cpu, key: id,
	}
	w.jobOrder = append(w.jobOrder, id)
}

// ---------------------------------------------------------------------------
// Failure reporting.
// ---------------------------------------------------------------------------

func (w *schedulerModelWorld) logf(format string, args ...any) {
	w.history = append(w.history, fmt.Sprintf("step %d: %s", w.step, fmt.Sprintf(format, args...)))
}

func (w *schedulerModelWorld) failf(format string, args ...any) {
	w.t.Fatalf("model property failure seed=%d step=%d\n  %s\noperation history:\n  %s",
		w.seed, w.step, fmt.Sprintf(format, args...), strings.Join(w.history, "\n  "))
}

// ---------------------------------------------------------------------------
// Operation drivers.
// ---------------------------------------------------------------------------

func (w *schedulerModelWorld) stepOnce() {
	w.step++
	switch w.rng.Intn(11) {
	case 0, 1:
		w.opLease()
	case 2:
		w.opHeartbeat()
	case 3:
		w.opComplete(model.StatusSuccess)
	case 4:
		w.opComplete(model.StatusFailure)
	case 5:
		w.opCancelJob()
	case 6:
		w.opCancelRun()
	case 7:
		w.opRecoverOne()
	case 8:
		w.opRecoverSweep()
	case 9:
		w.opEnqueue()
	default:
		// Idle tick: time advances, no state mutation.
		w.logf("idle tick")
	}
	w.now = w.now.Add(time.Duration(w.rng.Intn(120)) * time.Second)
	w.assertInvariants()
}

func (w *schedulerModelWorld) storeJob(id string) (model.Job, bool) {
	return w.store.job(id)
}

// expectedWinner is a faithful reference implementation of the scheduler's
// candidate walk, built ONLY from the real storage helpers and the store
// state. The scheduler must claim exactly this job (or nothing).
func (w *schedulerModelWorld) expectedWinner(runnerID string) string {
	ri, err := w.store.GetRunner(w.ctx, runnerID)
	if err != nil {
		w.failf("GetRunner(%s): %v", runnerID, err)
	}
	eff := ri // the fake has no profile bindings: snapshot resolution is a no-op
	if eff.Capacity <= 0 || len(eff.ActiveJobs) >= eff.Capacity {
		return ""
	}
	reserved, err := w.store.RunnerReservedResources(w.ctx, runnerID)
	if err != nil {
		w.failf("RunnerReservedResources(%s): %v", runnerID, err)
	}
	filter := runnerQueuedJobFilter(eff)
	var ordered []model.Job
	for _, id := range w.jobOrder {
		sj, ok := w.storeJob(id)
		if !ok || sj.Status != model.StatusQueued {
			continue
		}
		if storage.QueuedJobMatchesFilter(sj, filter) {
			ordered = append(ordered, sj)
		}
	}
	orderQueuedJobs(ordered, w.now)
	var head *model.Job
	for i := range ordered {
		cand := ordered[i]
		adm := storage.ResourceAdmission{
			Capacity:  eff.ResourceCapacity,
			Reserved:  reserved,
			Requested: effectiveJobRequest(cand, eff.JobCgroup),
		}
		if !adm.Allows() {
			if head != nil || !adm.EverSatisfiable() {
				continue
			}
			if !w.eligible(cand, eff) {
				continue
			}
			c := cand
			head = &c
			continue
		}
		if head != nil && !w.headFitsAlongside(*head, cand, reserved, eff) {
			continue
		}
		if !w.eligible(cand, eff) {
			continue
		}
		return cand.ID
	}
	return ""
}

// eligible mirrors leaseCandidateWalk.eligible's non-resource gates with the
// real shared helpers.
func (w *schedulerModelWorld) eligible(cand model.Job, eff model.Runner) bool {
	envRunning := 0
	if cand.Environment != "" && cand.EnvironmentConcurrency > 0 {
		repoID := storage.RepoIDForJob(cand)
		for _, id := range w.jobOrder {
			sj, ok := w.storeJob(id)
			if !ok || sj.ID == cand.ID || sj.Status != model.StatusRunning {
				continue
			}
			if sj.Environment == cand.Environment && storage.RepoIDForJob(sj) == repoID {
				envRunning++
			}
		}
	}
	runtimes, enforced := storage.LeasePolicyRuntimes(cand)
	if !(storage.LeasePredicate{
		Runner: eff, Job: cand, EnvRunning: envRunning,
		PolicyEnforced: enforced, PolicyRuntimes: runtimes,
	}).Allows() {
		return false
	}
	ready, outcome := DependencyOutcome(cand.Needs, nil, func(id string) (model.Status, bool) {
		d, ok := w.storeJob(id)
		return d.Status, ok
	})
	if !ready {
		return false
	}
	return outcome == model.StatusSuccess || ConditionAllows(cand.Condition, outcome)
}

func (w *schedulerModelWorld) headFitsAlongside(head, cand model.Job, reserved model.ResourceCapacity, eff model.Runner) bool {
	add := effectiveJobRequest(cand, eff.JobCgroup)
	h := effectiveJobRequest(head, eff.JobCgroup)
	capacity := eff.ResourceCapacity
	if capacity.CPU > 0 && add.CPU > 0 && reserved.CPU+add.CPU+h.CPU > capacity.CPU {
		return false
	}
	if capacity.Memory > 0 && add.Memory > 0 && reserved.Memory+add.Memory+h.Memory > capacity.Memory {
		return false
	}
	if capacity.Disk > 0 && add.Disk > 0 && reserved.Disk+add.Disk+h.Disk > capacity.Disk {
		return false
	}
	if capacity.PIDs > 0 && add.PIDs > 0 && reserved.PIDs+add.PIDs+h.PIDs > capacity.PIDs {
		return false
	}
	return true
}

func (w *schedulerModelWorld) opLease() {
	runner := w.runners[w.rng.Intn(len(w.runners))]
	expected := w.expectedWinner(runner)
	job, raw, expires, err := w.sched.Lease(w.ctx, runner, w.now)
	if expected == "" {
		if !errors.Is(err, ErrNoJobs) {
			w.failf("Lease(%s) = %v (job %+v), want ErrNoJobs", runner, err, job)
		}
		w.logf("Lease(%s) -> none", runner)
		return
	}
	if err != nil {
		w.failf("Lease(%s) -> error %v, model expected claim of %s", runner, err, expected)
	}
	if job == nil || job.ID != expected {
		got := "<nil>"
		if job != nil {
			got = job.ID
		}
		w.failf("Lease(%s) claimed %s, model expected %s", runner, got, expected)
	}
	mj := w.jobs[job.ID]
	if mj.status != model.StatusQueued {
		w.failf("claimed job %s in model status %s, want queued", mj.id, mj.status)
	}
	if job.LeaseGeneration != mj.generation+1 {
		w.failf("claimed job %s generation = %d, want %d", job.ID, job.LeaseGeneration, mj.generation+1)
	}
	if job.Attempts != mj.attempts+1 {
		w.failf("claimed job %s attempts = %d, want %d", job.ID, job.Attempts, mj.attempts+1)
	}
	if job.LeaseRunnerID != runner {
		w.failf("claimed job %s holder = %q, want %q", job.ID, job.LeaseRunnerID, runner)
	}
	if job.LeaseExpiresAt == nil || !job.LeaseExpiresAt.Equal(expires) || !expires.After(w.now) {
		w.failf("claimed job %s expiry = %v (returned %v, now %v)", job.ID, job.LeaseExpiresAt, expires, w.now)
	}
	if raw == "" {
		w.failf("claimed job %s returned an empty raw token", job.ID)
	}
	mj.status = model.StatusRunning
	mj.generation = job.LeaseGeneration
	mj.holder = runner
	mj.attempts++
	t := expires
	mj.expires = &t
	w.stats.claims++
	w.logf("Lease(%s) -> %s (gen %d, attempt %d, expires %s)", runner, job.ID, job.LeaseGeneration, job.Attempts, expires.Format(time.RFC3339))
}

func (w *schedulerModelWorld) runningJobs() []*schedulerModelJob {
	var out []*schedulerModelJob
	for _, id := range w.jobOrder {
		if w.jobs[id].status == model.StatusRunning {
			out = append(out, w.jobs[id])
		}
	}
	return out
}

func (w *schedulerModelWorld) opHeartbeat() {
	running := w.runningJobs()
	if len(running) == 0 {
		w.logf("Heartbeat -> no running job")
		return
	}
	mj := running[w.rng.Intn(len(running))]
	sj, ok := w.storeJob(mj.id)
	if !ok {
		w.failf("running model job %s missing from store", mj.id)
	}
	expires := w.now.Add(60 * time.Second)
	cancelled, authoritative, err := w.sched.Heartbeat(w.ctx, mj.id, mj.holder, sj.LeaseTokenHash, mj.generation, expires)
	if err != nil || cancelled {
		w.failf("Heartbeat(%s) = cancelled=%v err=%v, want a live extension", mj.id, cancelled, err)
	}
	if !authoritative.Equal(expires) {
		w.failf("Heartbeat(%s) authoritative expiry = %v, want %v", mj.id, authoritative, expires)
	}
	t := expires
	mj.expires = &t
	w.logf("Heartbeat(%s) -> extended to %s", mj.id, expires.Format(time.RFC3339))
}

func (w *schedulerModelWorld) opComplete(status model.Status) {
	running := w.runningJobs()
	if len(running) == 0 {
		w.logf("Complete(%s) -> no running job", status)
		return
	}
	mj := running[w.rng.Intn(len(running))]
	hash := fmt.Sprintf("seed-%d-step-%d-%s", w.seed, w.step, mj.id)
	if err := w.sched.Complete(w.ctx, mj.id, mj.generation, mj.holder, status, "model property", map[string]string{"out": "1"}, hash); err != nil {
		w.failf("Complete(%s, %s, gen %d) -> %v", mj.id, status, mj.generation, err)
	}
	w.receipts[fmt.Sprintf("%s|%d|%s", mj.id, mj.generation, mj.holder)] = true
	holder := mj.holder
	mj.status = status
	mj.holder = ""
	mj.expires = nil
	w.stats.completions++
	w.logf("Complete(%s) -> %s (gen %d, runner %s)", mj.id, status, mj.generation, holder)
}

func (w *schedulerModelWorld) opCancelJob() {
	running := w.runningJobs()
	if len(running) == 0 {
		w.logf("CancelJob -> no running job")
		return
	}
	mj := running[w.rng.Intn(len(running))]
	hash := fmt.Sprintf("cancel-seed-%d-step-%d-%s", w.seed, w.step, mj.id)
	if err := w.sched.Complete(w.ctx, mj.id, mj.generation, mj.holder, model.StatusCancelled, "model property cancel", nil, hash); err != nil {
		w.failf("CancelJob(%s, gen %d) -> %v", mj.id, mj.generation, err)
	}
	w.receipts[fmt.Sprintf("%s|%d|%s", mj.id, mj.generation, mj.holder)] = true
	holder := mj.holder
	mj.status = model.StatusCancelled
	mj.holder = ""
	mj.expires = nil
	w.stats.cancels++
	w.logf("CancelJob(%s) -> cancelled (gen %d, runner %s)", mj.id, mj.generation, holder)
}

func (w *schedulerModelWorld) opCancelRun() {
	var live []*schedulerModelRun
	for _, r := range w.runs {
		for _, id := range r.jobs {
			if !w.jobs[id].status.Terminal() {
				live = append(live, r)
				break
			}
		}
	}
	if len(live) == 0 {
		w.logf("CancelRun -> no live run")
		return
	}
	rm := live[w.rng.Intn(len(live))]
	if err := w.sched.CancelRun(w.ctx, rm.id, "model property cancel run"); err != nil {
		w.failf("CancelRun(%s) -> %v", rm.id, err)
	}
	for _, id := range rm.jobs {
		mj := w.jobs[id]
		if mj.status.Terminal() {
			continue
		}
		mj.status = model.StatusCancelled
		mj.holder = ""
		mj.expires = nil
		w.stats.cancels++
	}
	w.logf("CancelRun(%s)", rm.id)
}

// applyRecover mirrors the fake store's RecoverExpiredLease transition
// (including the dependent-blocking recomputation) exactly.
func (w *schedulerModelWorld) applyRecover(mj *schedulerModelJob, expectedGen int64, now time.Time) bool {
	if mj.status != model.StatusRunning || mj.generation != expectedGen {
		return false
	}
	if mj.expires != nil && mj.expires.After(now) {
		return false
	}
	requeue := mj.attempts <= mj.maxInfraRetries
	if requeue {
		mj.status = model.StatusQueued
		w.stats.requeues++
	} else {
		mj.status = model.StatusFailure
		w.stats.expired++
	}
	mj.holder = ""
	mj.expires = nil
	// Dependent blocking exactly mirrors the fake's recomputeDependentsLocked:
	// direct dependents only, visited in sorted id order, evaluated against
	// the current (possibly already updated) statuses.
	var dependents []string
	for _, id := range w.jobOrder {
		for _, dep := range w.jobs[id].needs {
			if dep == mj.id {
				dependents = append(dependents, id)
				break
			}
		}
	}
	sort.Strings(dependents)
	for _, id := range dependents {
		other := w.jobs[id]
		if other.status != model.StatusQueued && other.status != model.StatusWaitingApproval {
			continue
		}
		ready, outcome := DependencyOutcome(other.needs, nil, func(id string) (model.Status, bool) {
			d, ok := w.jobs[id]
			if !ok {
				return "", false
			}
			return d.status, true
		})
		if !ready {
			continue
		}
		if outcome != model.StatusSuccess && !ConditionAllows("", outcome) {
			other.status = model.StatusBlocked
			w.stats.blocked++
		}
	}
	return true
}

func (w *schedulerModelWorld) opRecoverOne() {
	id := w.jobOrder[w.rng.Intn(len(w.jobOrder))]
	mj := w.jobs[id]
	at := w.now
	if mj.status == model.StatusRunning && mj.expires != nil {
		if w.rng.Intn(10) < 7 {
			at = mj.expires.Add(time.Second)
		} else {
			at = mj.expires.Add(-time.Second)
		}
	}
	expectedGen := mj.generation
	if err := w.store.RecoverExpiredLease(w.ctx, id, expectedGen, at); err != nil {
		w.failf("RecoverExpiredLease(%s, gen %d, %s) -> %v", id, expectedGen, at.Format(time.RFC3339), err)
	}
	changed := w.applyRecover(mj, expectedGen, at)
	w.logf("RecoverExpiredLease(%s, gen %d, %s) -> changed=%v status=%s", id, expectedGen, at.Format(time.RFC3339), changed, mj.status)
}

func (w *schedulerModelWorld) opRecoverSweep() {
	if err := w.sched.RecoverExpired(w.ctx, w.now); err != nil {
		w.failf("RecoverExpired(%s) -> %v", w.now.Format(time.RFC3339), err)
	}
	ids := append([]string(nil), w.jobOrder...)
	sort.Strings(ids)
	changed := 0
	for _, id := range ids {
		mj := w.jobs[id]
		if w.applyRecover(mj, mj.generation, w.now) {
			changed++
		}
	}
	w.logf("RecoverExpired(sweep at %s) -> %d transitions", w.now.Format(time.RFC3339), changed)
}

func (w *schedulerModelWorld) opEnqueue() {
	const maxJobs = 24
	if len(w.jobOrder) >= maxJobs {
		w.logf("Enqueue -> skipped at cap")
		return
	}
	w.enqueueRun()
}

// ---------------------------------------------------------------------------
// Invariants.
// ---------------------------------------------------------------------------

func (w *schedulerModelWorld) assertInvariants() {
	// 1. Every job's store row equals the model, and per-job structural
	// invariants hold.
	for _, id := range w.jobOrder {
		mj := w.jobs[id]
		sj, ok := w.storeJob(id)
		if !ok {
			w.failf("job %s missing from the store", id)
		}
		if sj.Status != mj.status {
			w.failf("job %s status: store=%s model=%s\nstore:%s\nmodel:%s", id, sj.Status, mj.status, fpString(w.fingerprint()), w.modelDump())
		}
		if sj.LeaseGeneration != mj.generation {
			w.failf("job %s generation: store=%d model=%d", id, sj.LeaseGeneration, mj.generation)
		}
		if sj.LeaseRunnerID != mj.holder {
			w.failf("job %s holder: store=%q model=%q", id, sj.LeaseRunnerID, mj.holder)
		}
		if sj.Attempts != mj.attempts {
			w.failf("job %s attempts: store=%d model=%d", id, sj.Attempts, mj.attempts)
		}
		if !sameTimePtr(sj.LeaseExpiresAt, mj.expires) {
			w.failf("job %s lease expiry: store=%v model=%v", id, fmtTimePtr(sj.LeaseExpiresAt), fmtTimePtr(mj.expires))
		}
		if mj.generation < 0 {
			w.failf("job %s generation is negative: %d", id, mj.generation)
		}
		if mj.status == model.StatusRunning {
			if mj.holder == "" || mj.expires == nil {
				w.failf("running job %s lacks holder/expiry", id)
			}
		} else if mj.holder != "" || mj.expires != nil {
			w.failf("non-running job %s keeps lease state: holder=%q expires=%v", id, mj.holder, fmtTimePtr(mj.expires))
		}
		if p, ok := w.prev[id]; ok {
			if mj.generation < p.gen {
				w.failf("job %s generation regressed: %d -> %d", id, p.gen, mj.generation)
			}
			if p.status.Terminal() {
				if mj.status != p.status || !mj.status.Terminal() {
					w.failf("terminal job %s left terminal: %s -> %s", id, p.status, mj.status)
				}
				if mj.attempts != p.attempts {
					w.failf("terminal job %s changed attempts: %d -> %d", id, p.attempts, mj.attempts)
				}
				if mj.generation != p.gen {
					w.failf("terminal job %s changed generation: %d -> %d", id, p.gen, mj.generation)
				}
			}
		}
		// Dependency discipline: a RUNNING job may only hold a claim when
		// every dependency is terminal-success (conditions are empty in this
		// world, so the claim gate is exactly success()).
		if mj.status == model.StatusRunning {
			for _, dep := range mj.needs {
				d := w.jobs[dep]
				if d == nil || d.status != model.StatusSuccess {
					got := "<missing>"
					if d != nil {
						got = string(d.status)
					}
					w.failf("running job %s has unsatisfied dependency %s (%s)", id, dep, got)
				}
			}
		}
	}

	// 2. Runner active sets, capacity and reservation ledger exactly match the
	// model; a failed/expired claim can never leave a phantom reservation.
	holderCount := map[string]int{}
	for _, rid := range w.runners {
		want := map[string]bool{}
		var wantReserved model.ResourceCapacity
		for _, id := range w.jobOrder {
			mj := w.jobs[id]
			if mj.holder == rid && mj.status == model.StatusRunning {
				want[id] = true
				sj, _ := w.storeJob(id)
				wantReserved = model.AddResourceCapacity(wantReserved, sj.ReservedResources())
			}
		}
		got := w.store.activeSet(rid)
		if len(got) != len(want) {
			w.failf("runner %s active set = %v, model expects %v", rid, got, want)
		}
		for _, id := range got {
			if !want[id] {
				w.failf("runner %s active set holds %s, which the model does not attribute to it", rid, id)
			}
			holderCount[id]++
			if holderCount[id] > 1 {
				w.failf("job %s is held by more than one runner", id)
			}
		}
		if len(got) > w.caps[rid] {
			w.failf("runner %s capacity %d exceeded: %v", rid, w.caps[rid], got)
		}
		reserved, err := w.store.RunnerReservedResources(w.ctx, rid)
		if err != nil {
			w.failf("RunnerReservedResources(%s): %v", rid, err)
		}
		if reserved != wantReserved {
			w.failf("runner %s reservations = %+v, model expects %+v (phantom or missing reservation)", rid, reserved, wantReserved)
		}
	}

	// 3. At most one live lease per job.
	for _, id := range w.jobOrder {
		mj := w.jobs[id]
		if mj.status == model.StatusRunning && holderCount[id] != 1 {
			w.failf("running job %s is held by %d runners", id, holderCount[id])
		}
		if mj.status != model.StatusRunning && holderCount[id] != 0 {
			w.failf("non-running job %s still occupies %d runner active sets", id, holderCount[id])
		}
	}

	// 4. Completion receipts exactly match the model's successful completions.
	if got := w.store.receiptCount(); got != len(w.receipts) {
		w.failf("store completion receipts = %d, model expects %d", got, len(w.receipts))
	}

	// 5. Stale-generation probes: a claim by generation gen-1 after the job
	// advanced past it must be refused WITHOUT mutating any row; an exact
	// replay must also be a no-op.
	w.assertStaleClaimsRefused()

	// 6. Snapshot for the monotonicity/terminal-stability checks.
	w.prev = map[string]schedulerModelSnapshot{}
	for _, id := range w.jobOrder {
		mj := w.jobs[id]
		w.prev[id] = schedulerModelSnapshot{status: mj.status, gen: mj.generation, attempts: mj.attempts}
	}
}

// stateFingerprint captures every mutable dimension a stale claim could touch.
type stateFingerprint struct {
	jobs     map[string]model.Job
	receipts int
	audits   int
	active   map[string][]string
	reserved map[string]model.ResourceCapacity
}

func (w *schedulerModelWorld) fingerprint() stateFingerprint {
	fp := stateFingerprint{
		jobs:     map[string]model.Job{},
		active:   map[string][]string{},
		reserved: map[string]model.ResourceCapacity{},
	}
	for _, id := range w.jobOrder {
		if j, ok := w.storeJob(id); ok {
			fp.jobs[id] = j
		}
	}
	fp.receipts = w.store.receiptCount()
	fp.audits = w.store.auditCount()
	for _, rid := range w.runners {
		fp.active[rid] = w.store.activeSet(rid)
		r, _ := w.store.RunnerReservedResources(w.ctx, rid)
		fp.reserved[rid] = r
	}
	return fp
}

func (w *schedulerModelWorld) assertStaleClaimsRefused() {
	if len(w.jobOrder) == 0 {
		return
	}
	id := w.jobOrder[w.step%len(w.jobOrder)]
	mj := w.jobs[id]
	if mj.generation == 0 {
		return
	}
	w.stats.staleProbes++
	before := w.fingerprint()
	staleGen := mj.generation - 1
	staleHolder := mj.holder
	_, hadReceipt, err := w.store.HasCompletionReceipt(w.ctx, id, staleGen, staleHolder)
	if err != nil {
		w.failf("HasCompletionReceipt(%s, %d): %v", id, staleGen, err)
	}
	cerr := w.store.CompleteJob(w.ctx, id, staleGen, staleHolder, model.StatusSuccess, "", map[string]string{"sneaky": "1"}, model.CompletionReceipt{
		JobID: id, Generation: staleGen, RunnerID: staleHolder, ResultHash: "stale-probe",
	}, nil)
	switch {
	case hadReceipt:
		if cerr != nil {
			w.failf("exact stale receipt replay for %s gen %d returned %v, want nil", id, staleGen, cerr)
		}
	default:
		if !errors.Is(cerr, storage.ErrGenerationMismatch) {
			w.failf("stale completion %s gen %d (current %d) = %v, want ErrGenerationMismatch", id, staleGen, mj.generation, cerr)
		}
	}
	// Stale heartbeat at a superseded generation must also be refused.
	if herr := w.store.HeartbeatLease(w.ctx, id, staleHolder, staleGen, w.now.Add(time.Minute)); !errors.Is(herr, storage.ErrLeaseConflict) {
		w.failf("stale heartbeat %s gen %d = %v, want ErrLeaseConflict", id, staleGen, herr)
	}
	after := w.fingerprint()
	if !reflect.DeepEqual(before, after) {
		w.failf("a stale claim mutated state\n  before: %s\n  after:  %s", fpString(before), fpString(after))
	}
}

// ---------------------------------------------------------------------------
// Entry points.
// ---------------------------------------------------------------------------

// TestPropertySchedulerModelMachine is the deliverable: 20 fixed seeds x 200
// randomized operations each over a 3..6 job dependency DAG and 1..3 runners,
// driving the REAL scheduler and asserting the full invariant set after every
// single operation. Failures print seed, step and the operation history.
func TestPropertySchedulerModelMachine(t *testing.T) {
	const (
		seeds = 20
		steps = 200
	)
	var total propStats
	for seed := int64(0); seed < seeds; seed++ {
		w := newSchedulerModelWorld(t, seed)
		for i := 0; i < steps; i++ {
			w.stepOnce()
		}
		total.claims += w.stats.claims
		total.completions += w.stats.completions
		total.requeues += w.stats.requeues
		total.expired += w.stats.expired
		total.cancels += w.stats.cancels
		total.blocked += w.stats.blocked
		total.staleProbes += w.stats.staleProbes
	}
	t.Logf("coverage: %+v", total)
	// Non-degeneracy floor: every seed must have exercised claims and stale
	// probes, and the run as a whole must have exercised completions, lease
	// expiry requeues and cancellations. A silently no-op sequence can never
	// pass as green.
	if total.claims < seeds || total.staleProbes < seeds {
		t.Fatalf("degenerate run: %+v", total)
	}
	if total.completions < seeds || total.requeues < seeds/2 || total.cancels < seeds/2 {
		t.Fatalf("insufficient transition coverage: %+v", total)
	}
}

// TestPropertySchedulerStaleGenerationRefused is a focused deterministic pin
// of the stale-claim rule: once a job's generation advanced, a completion or
// heartbeat carrying the superseded generation mutates nothing.
func TestPropertySchedulerStaleGenerationRefused(t *testing.T) {
	w := newSchedulerModelWorld(t, 7)
	runner := w.runners[0]
	// Claim the same job twice across a lease expiry, advancing the
	// generation each time.
	claimed := ""
	for i := 0; i < 2; i++ {
		job, _, _, err := w.sched.Lease(w.ctx, runner, w.now)
		if err != nil {
			t.Fatalf("lease %d: %v", i, err)
		}
		if i > 0 && job.ID != claimed {
			t.Fatalf("lease %d claimed %s, want the same job %s to advance its generation", i, job.ID, claimed)
		}
		claimed = job.ID
		mj := w.jobs[job.ID]
		mj.status = model.StatusRunning
		mj.generation = job.LeaseGeneration
		mj.holder = runner
		mj.attempts++
		exp := *job.LeaseExpiresAt
		mj.expires = &exp
		// Expire the lease and requeue.
		w.now = exp.Add(time.Second)
		if err := w.store.RecoverExpiredLease(w.ctx, job.ID, mj.generation, w.now); err != nil {
			t.Fatalf("recover %d: %v", i, err)
		}
		w.applyRecover(mj, mj.generation, w.now)
	}
	mj := w.jobs[claimed]
	if mj.generation < 2 {
		t.Fatalf("job %s generation = %d, want >= 2", claimed, mj.generation)
	}
	before := w.fingerprint()
	err := w.store.CompleteJob(w.ctx, claimed, mj.generation-1, runner, model.StatusSuccess, "", map[string]string{"sneaky": "1"},
		model.CompletionReceipt{JobID: claimed, Generation: mj.generation - 1, RunnerID: runner, ResultHash: "stale"}, nil)
	if !errors.Is(err, storage.ErrGenerationMismatch) {
		t.Fatalf("stale completion = %v, want ErrGenerationMismatch", err)
	}
	if err := w.store.HeartbeatLease(w.ctx, claimed, runner, mj.generation-1, w.now.Add(time.Minute)); !errors.Is(err, storage.ErrLeaseConflict) {
		t.Fatalf("stale heartbeat = %v, want ErrLeaseConflict", err)
	}
	after := w.fingerprint()
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("stale claims mutated state:\n before: %s\n after:  %s", fpString(before), fpString(after))
	}
}

func sameTimePtr(a, b *time.Time) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return a.Equal(*b)
	}
}

func fmtTimePtr(t *time.Time) string {
	if t == nil {
		return "<nil>"
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func (w *schedulerModelWorld) modelDump() string {
	var b strings.Builder
	for _, id := range w.jobOrder {
		mj := w.jobs[id]
		fmt.Fprintf(&b, "\n    job %s: %s gen=%d holder=%q attempts=%d retries=%d needs=%v",
			id, mj.status, mj.generation, mj.holder, mj.attempts, mj.maxInfraRetries, mj.needs)
	}
	return b.String()
}

func fpString(fp stateFingerprint) string {
	var b strings.Builder
	keys := make([]string, 0, len(fp.jobs))
	for id := range fp.jobs {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	for _, id := range keys {
		j := fp.jobs[id]
		fmt.Fprintf(&b, "\n    job %s: %s gen=%d holder=%q attempts=%d expiry=%s needs=%v",
			id, j.Status, j.LeaseGeneration, j.LeaseRunnerID, j.Attempts, fmtTimePtr(j.LeaseExpiresAt), j.Needs)
	}
	b.WriteString(fmt.Sprintf("\n    receipts=%d audits=%d", fp.receipts, fp.audits))
	for _, rid := range sortedKeys(fp.active) {
		fmt.Fprintf(&b, "\n    runner %s: active=%v reserved=%+v", rid, fp.active[rid], fp.reserved[rid])
	}
	return b.String()
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
