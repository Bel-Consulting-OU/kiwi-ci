package scheduler

// Real-PostgreSQL barrier tests for the heartbeat-vs-admin race: a heartbeat
// used to compose GetRunner -> LastSeen=now -> UpsertRunner, a whole-row
// read-modify-write that could write a pre-admin-change snapshot back after a
// concurrent disable/drain/profile edit committed. The heartbeat now uses the
// NARROW RunnerHeartbeatStore.TouchRunnerLastSeen capability, so the barrier
// tests below gate BOTH paths:
//
//   - the new path blocks inside TouchRunnerLastSeen (before it writes);
//   - the legacy implementation blocks inside GetRunner, after reading the
//     stale snapshot, and its later UpsertRunner then clobbers the admin
//     change — which is exactly what these tests fail on when the old path is
//     restored.
//
// Gated on KIWI_TEST_POSTGRES_URL like the other scheduler integration tests.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// heartbeatBarrierStore wraps a real store and gates both the legacy stale
// read (GetRunner) and the new narrow write (TouchRunnerLastSeen), so one
// test body drives the new implementation's barrier and still detects a
// regression to the old GetRunner -> UpsertRunner flow.
type heartbeatBarrierStore struct {
	*storage.PostgresStore
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

func newHeartbeatBarrierStore(st *storage.PostgresStore) *heartbeatBarrierStore {
	return &heartbeatBarrierStore{PostgresStore: st, reached: make(chan struct{}), release: make(chan struct{})}
}

// block signals the barrier once and waits for the test to release it.
func (b *heartbeatBarrierStore) block() {
	b.once.Do(func() { close(b.reached) })
	<-b.release
}

// GetRunner is the STALE READ the legacy heartbeat performed: it returns the
// snapshot taken BEFORE the barrier, so a heartbeat that later upserts that
// snapshot undoes whatever committed while it was suspended.
func (b *heartbeatBarrierStore) GetRunner(ctx context.Context, id string) (model.Runner, error) {
	r, err := b.PostgresStore.GetRunner(ctx, id)
	b.block()
	return r, err
}

// TouchRunnerLastSeen is the new narrow write; it blocks BEFORE writing, so
// an admin change committed during the wait is preserved.
func (b *heartbeatBarrierStore) TouchRunnerLastSeen(ctx context.Context, runnerID string) error {
	b.block()
	return b.PostgresStore.TouchRunnerLastSeen(ctx, runnerID)
}

// pgITSchedRepoID is the canonical repository identity of pgITSchedRepo: the
// form the runner ACL predicate compares against.
func pgITSchedRepoID() string {
	return storage.RepoIDFor("", pgITSchedRepo, "kiwi-it/repo")
}

// heartbeatRaceFixture leases one job to a fresh runner and returns the ids.
func heartbeatRaceFixture(t *testing.T, st *storage.PostgresStore, sched *DBScheduler, capacity int) (runnerID string, leased *model.Job) {
	t.Helper()
	ctx := context.Background()
	runnerID = pgITSchedID(t)
	if err := st.UpsertRunner(ctx, model.Runner{ID: runnerID, Name: runnerID, Capacity: capacity, Labels: []string{"container"}, AllowedRepositories: []string{pgITSchedRepoID()}}); err != nil {
		t.Fatalf("upsert runner: %v", err)
	}
	runID, jobID := pgITSchedID(t), pgITSchedID(t)
	if err := sched.Enqueue(ctx, model.Run{ID: runID, Repo: pgITSchedRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()}, map[string]model.Job{jobID: pgITSchedJob(runID, jobID)}, nil, false); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	leased, _, _, err := sched.Lease(ctx, runnerID, time.Now().UTC())
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	return runnerID, leased
}

// commitHeartbeat runs one DBScheduler.Heartbeat against the barriered store,
// waits for the heartbeat to reach its pre-write step, runs change, then
// releases the barrier and returns after the heartbeat completed.
func commitHeartbeat(t *testing.T, st *storage.PostgresStore, leased model.Job, runnerID string, change func()) {
	t.Helper()
	barrier := newHeartbeatBarrierStore(st)
	bsched := NewDB(barrier, time.Minute, nil, nil)
	done := make(chan error, 1)
	go func() {
		_, _, err := bsched.Heartbeat(context.Background(), leased.ID, runnerID, nil, leased.LeaseGeneration, time.Now().UTC().Add(time.Minute))
		done <- err
	}()
	select {
	case <-barrier.reached:
	case <-time.After(30 * time.Second):
		t.Fatal("heartbeat never reached its pre-write step")
	}
	change()
	close(barrier.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("heartbeat: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("heartbeat did not finish")
	}
}

// enqueueNextJob enqueues a second job so a post-change lease attempt has
// something to (not) claim.
func enqueueNextJob(t *testing.T, sched *DBScheduler) {
	t.Helper()
	runID, jobID := pgITSchedID(t), pgITSchedID(t)
	if err := sched.Enqueue(context.Background(), model.Run{ID: runID, Repo: pgITSchedRepo, Status: model.StatusQueued, CreatedAt: time.Now().UTC()}, map[string]model.Job{jobID: pgITSchedJob(runID, jobID)}, nil, false); err != nil {
		t.Fatalf("enqueue next job: %v", err)
	}
}

// TestIntegrationHeartbeatCannotUndoConcurrentRunnerDisable pins the P1
// kill-switch race: a heartbeat suspended before its liveness write must not
// resurrect a runner an admin disabled in the meantime, and the disabled
// runner must refuse new work.
func TestIntegrationHeartbeatCannotUndoConcurrentRunnerDisable(t *testing.T) {
	st := pgITSchedStore(t)
	ctx := context.Background()
	sched := pgITSchedLeader(t, st)
	runnerID, leased := heartbeatRaceFixture(t, st, sched, 4)

	before := time.Now().UTC()
	commitHeartbeat(t, st, *leased, runnerID, func() {
		if _, err := st.DisableRunnerAndRevokeCert(ctx, runnerID, "", "test-admin"); err != nil {
			t.Fatalf("disable runner: %v", err)
		}
	})

	got, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner: %v", err)
	}
	if !got.Disabled {
		t.Fatal("heartbeat undid the concurrent runner disable")
	}
	if !got.LastSeen.After(before) {
		t.Fatalf("heartbeat did not refresh last-seen: %v (before %v)", got.LastSeen, before)
	}
	// The disabled runner must refuse new work.
	enqueueNextJob(t, sched)
	if _, _, _, err := sched.Lease(ctx, runnerID, time.Now().UTC()); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("lease for a disabled runner = %v, want ErrNoJobs", err)
	}
}

// TestIntegrationHeartbeatCannotUndoConcurrentRunnerDrain pins the drain
// variant: a heartbeat must not clear a concurrent drain, and a draining
// runner must refuse new work.
func TestIntegrationHeartbeatCannotUndoConcurrentRunnerDrain(t *testing.T) {
	st := pgITSchedStore(t)
	ctx := context.Background()
	sched := pgITSchedLeader(t, st)
	runnerID, leased := heartbeatRaceFixture(t, st, sched, 4)

	commitHeartbeat(t, st, *leased, runnerID, func() {
		cur, err := st.GetRunner(ctx, runnerID)
		if err != nil {
			t.Fatalf("get runner: %v", err)
		}
		cur.Draining = true
		if err := st.UpdateRunnerProfileFields(ctx, cur); err != nil {
			t.Fatalf("drain runner: %v", err)
		}
	})

	got, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner: %v", err)
	}
	if !got.Draining {
		t.Fatal("heartbeat undid the concurrent runner drain")
	}
	enqueueNextJob(t, sched)
	if _, _, _, err := sched.Lease(ctx, runnerID, time.Now().UTC()); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("lease for a draining runner = %v, want ErrNoJobs", err)
	}
}

// TestIntegrationHeartbeatCannotOverwriteConcurrentProfileEdit pins the
// profile variant: a heartbeat must not restore any profile/admin field from
// its pre-edit snapshot.
func TestIntegrationHeartbeatCannotOverwriteConcurrentProfileEdit(t *testing.T) {
	st := pgITSchedStore(t)
	ctx := context.Background()
	sched := pgITSchedLeader(t, st)
	runnerID, leased := heartbeatRaceFixture(t, st, sched, 4)

	commitHeartbeat(t, st, *leased, runnerID, func() {
		cur, err := st.GetRunner(ctx, runnerID)
		if err != nil {
			t.Fatalf("get runner: %v", err)
		}
		cur.Name = "admin-renamed"
		cur.Region = "eu-west-9"
		cur.Labels = []string{"admin-label"}
		if err := st.UpdateRunnerProfileFields(ctx, cur); err != nil {
			t.Fatalf("profile edit: %v", err)
		}
	})

	got, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner: %v", err)
	}
	if got.Name != "admin-renamed" || got.Region != "eu-west-9" || len(got.Labels) != 1 || got.Labels[0] != "admin-label" {
		t.Fatalf("heartbeat overwrote the concurrent profile edit: %+v", got)
	}
}

// TestIntegrationHeartbeatCannotRestoreOldCapacity pins the capacity
// variant: a heartbeat must not restore a pre-reduction capacity, and the
// reduced capacity must gate new work.
func TestIntegrationHeartbeatCannotRestoreOldCapacity(t *testing.T) {
	st := pgITSchedStore(t)
	ctx := context.Background()
	sched := pgITSchedLeader(t, st)
	runnerID, leased := heartbeatRaceFixture(t, st, sched, 4)

	commitHeartbeat(t, st, *leased, runnerID, func() {
		cur, err := st.GetRunner(ctx, runnerID)
		if err != nil {
			t.Fatalf("get runner: %v", err)
		}
		cur.Capacity = 1
		if err := st.UpdateRunnerProfileFields(ctx, cur); err != nil {
			t.Fatalf("capacity reduction: %v", err)
		}
	})

	got, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner: %v", err)
	}
	if got.Capacity != 1 {
		t.Fatalf("heartbeat restored the old capacity: %d, want 1", got.Capacity)
	}
	// One job is already running, so capacity 1 admits no new work.
	if len(got.ActiveJobs) != 1 {
		t.Fatalf("active jobs = %v, want the one leased job", got.ActiveJobs)
	}
	enqueueNextJob(t, sched)
	if _, _, _, err := sched.Lease(ctx, runnerID, time.Now().UTC()); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("lease at capacity 1 with one running job = %v, want ErrNoJobs", err)
	}
}

// TestIntegrationHeartbeatCannotRestoreOldRepoACL pins the repository-ACL
// variant: a heartbeat must not restore a pre-narrowing allowlist, and the
// narrowed ACL must gate new work.
func TestIntegrationHeartbeatCannotRestoreOldRepoACL(t *testing.T) {
	st := pgITSchedStore(t)
	ctx := context.Background()
	sched := pgITSchedLeader(t, st)
	runnerID, leased := heartbeatRaceFixture(t, st, sched, 4)

	commitHeartbeat(t, st, *leased, runnerID, func() {
		cur, err := st.GetRunner(ctx, runnerID)
		if err != nil {
			t.Fatalf("get runner: %v", err)
		}
		cur.AllowedRepositories = []string{"github.com/other/repo"}
		if err := st.UpdateRunnerProfileFields(ctx, cur); err != nil {
			t.Fatalf("repo ACL narrowing: %v", err)
		}
	})

	got, err := st.GetRunner(ctx, runnerID)
	if err != nil {
		t.Fatalf("get runner: %v", err)
	}
	if len(got.AllowedRepositories) != 1 || got.AllowedRepositories[0] != "github.com/other/repo" {
		t.Fatalf("heartbeat restored the old repository ACL: %v", got.AllowedRepositories)
	}
	enqueueNextJob(t, sched)
	if _, _, _, err := sched.Lease(ctx, runnerID, time.Now().UTC()); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("lease for a runner whose ACL excludes the repository = %v, want ErrNoJobs", err)
	}
}
