package scheduler

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// atomicFakeStore wraps a fakeStore and implements the capacity-atomic
// lease semantics: the job claim and the runner slot update commit or fail
// together, and an over-capacity runner yields ErrNoCapacity with the job
// left queued.
type atomicFakeStore struct {
	*fakeStore
	mu       sync.Mutex
	capacity map[string]int
	active   map[string][]string
}

func newAtomicFakeStore() *atomicFakeStore {
	a := &atomicFakeStore{
		fakeStore: newFakeStore(),
		capacity:  map[string]int{},
		active:    map[string][]string{},
	}
	a.leaderOK = true
	return a
}

var _ storage.AtomicLeaseStore = (*atomicFakeStore)(nil)

func (a *atomicFakeStore) AcquireLeaseAtomic(ctx context.Context, jobID, runnerID string, tokenHash []byte, generation int64, expiresAt time.Time, runnerCapacity int) (model.Job, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.capacity[runnerID]; !ok {
		a.capacity[runnerID] = runnerCapacity
	}
	cap := a.capacity[runnerID]
	if cap <= 0 {
		cap = runnerCapacity
	}
	if cap > 0 && len(a.active[runnerID]) >= cap {
		return model.Job{}, storage.ErrNoCapacity
	}
	j, err := a.fakeStore.AcquireLease(ctx, jobID, runnerID, tokenHash, generation, expiresAt)
	if err != nil {
		return model.Job{}, err
	}
	// Mirror the SQL atomic lease: the runner's active set is updated in
	// the same critical section as the job claim.
	a.active[runnerID] = append(a.active[runnerID], jobID)
	if ri, rerr := a.fakeStore.GetRunner(ctx, runnerID); rerr == nil {
		ri.ActiveJobs = append([]string(nil), a.active[runnerID]...)
		ri.Busy = cap > 0 && len(ri.ActiveJobs) >= cap
		if len(ri.ActiveJobs) > 0 {
			ri.CurrentJob = ri.ActiveJobs[0]
		}
		_ = a.fakeStore.UpsertRunner(ctx, ri)
	}
	return j, nil
}

func (a *atomicFakeStore) jobStatus(jobID string) (model.Status, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	j, err := a.fakeStore.GetJob(context.Background(), jobID)
	if err != nil {
		return "", ""
	}
	return j.Status, j.LeaseRunnerID
}

// TestLeaseCapacityAtomicOverCapacity proves two concurrent leases against
// a capacity-1 runner yield exactly one success and one ErrNoCapacity, and
// the loser's job is never claimed.
func TestLeaseCapacityAtomicOverCapacity(t *testing.T) {
	st := newAtomicFakeStore()
	now := time.Now().UTC()
	_ = st.InsertRun(context.Background(), model.Run{ID: "run1", Status: model.StatusQueued, CreatedAt: now})
	for i := 0; i < 2; i++ {
		_ = st.InsertJob(context.Background(), model.Job{
			ID: fmt.Sprintf("job%d", i), RunID: "run1", Key: fmt.Sprintf("k%d", i),
			Status: model.StatusQueued, RequiredLabels: []string{"container"},
			CreatedAt: now.Add(time.Duration(i) * time.Second),
		})
	}
	_ = st.UpsertRunner(context.Background(), model.Runner{ID: "runner1", Name: "r1", Labels: []string{"container"}, Capacity: 1})
	s := NewDB(st, time.Minute, nil, nil)
	if !s.IsLeader(context.Background()) {
		t.Fatal("not leader")
	}
	type result struct {
		job *model.Job
		err error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j, _, _, err := s.Lease(context.Background(), "runner1", time.Now().UTC())
			results <- result{j, err}
		}()
	}
	wg.Wait()
	close(results)
	var won, overCapacity int
	var leasedJobID string
	for r := range results {
		switch {
		case r.err == nil:
			won++
			leasedJobID = r.job.ID
		case errors.Is(r.err, ErrNoJobs):
			overCapacity++
		default:
			t.Fatalf("unexpected lease error: %v", r.err)
		}
	}
	if won != 1 || overCapacity != 1 {
		t.Fatalf("leases: won=%d overCapacity=%d, want 1/1", won, overCapacity)
	}
	// The runner row holds exactly one active job; the losing job stays
	// queued with no lease.
	ri, err := st.GetRunner(context.Background(), "runner1")
	if err != nil {
		t.Fatal(err)
	}
	if len(ri.ActiveJobs) != 1 {
		t.Fatalf("runner active jobs = %v, want exactly 1", ri.ActiveJobs)
	}
	for _, id := range []string{"job0", "job1"} {
		status, leaseRunner := st.jobStatus(id)
		if id == leasedJobID {
			if status != model.StatusRunning || leaseRunner != "runner1" {
				t.Fatalf("winner job %s = %s/%s", id, status, leaseRunner)
			}
			continue
		}
		if status != model.StatusQueued || leaseRunner != "" {
			t.Fatalf("loser job %s = %s/%s, want queued with no lease", id, status, leaseRunner)
		}
	}
}
