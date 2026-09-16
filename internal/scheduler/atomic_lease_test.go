package scheduler

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	quotas   map[string]int
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

// AcquireLeaseAtomic mirrors the SQL claim: the shared lease predicate
// (storage.LeasePredicate) gates the claim, the job claim and the runner
// active-set update commit together, and the runner's capacity can be
// pinned by the test through the capacity map.
func (a *atomicFakeStore) AcquireLeaseAtomic(ctx context.Context, claim storage.LeaseClaim) (model.Job, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.capacity[claim.RunnerID]; !ok {
		a.capacity[claim.RunnerID] = claim.RunnerCapacity
	}
	cap := a.capacity[claim.RunnerID]
	ri, err := a.fakeStore.GetRunner(ctx, claim.RunnerID)
	if err != nil {
		return model.Job{}, storage.ErrNoCapacity
	}
	eff := ri
	if ri.CertSerial != "" {
		if p, linked, perr := a.fakeStore.ProfileForSerial(ctx, ri.CertSerial); perr != nil {
			return model.Job{}, perr
		} else if linked {
			eff = storage.ResolveRunnerProfile(ri, p, true)
		}
	}
	if eff.Disabled || eff.Draining || cap <= 0 || len(a.active[claim.RunnerID]) >= cap {
		return model.Job{}, storage.ErrNoCapacity
	}
	j, err := a.fakeStore.GetJob(ctx, claim.JobID)
	if err != nil {
		return model.Job{}, err
	}
	envRunning := 0
	if claim.Environment != "" && claim.EnvironmentConcurrency > 0 {
		all, _ := a.fakeStore.ListJobsByEnvironment(ctx, claim.RepoURL, claim.Environment)
		for _, other := range all {
			if other.ID != claim.JobID && other.Status == model.StatusRunning {
				envRunning++
			}
		}
	}
	runtimes, enforced := storage.LeasePolicyRuntimes(j)
	eff.Capacity = cap
	eff.ActiveJobs = append([]string(nil), a.active[claim.RunnerID]...)
	if !(storage.LeasePredicate{Runner: eff, Job: j, EnvRunning: envRunning, PolicyEnforced: enforced, PolicyRuntimes: runtimes}).Allows() {
		if claim.Environment != "" && claim.EnvironmentConcurrency > 0 && envRunning >= claim.EnvironmentConcurrency {
			return model.Job{}, storage.ErrEnvConcurrency
		}
		return model.Job{}, storage.ErrNoCapacity
	}
	if claim.RepoURL != "" {
		if m := a.fakeQuotas(); m != nil {
			keys := []string{claim.RepoURL}
			if team := repoTeamKey(claim.RepoURL); team != claim.RepoURL {
				keys = append(keys, team)
			}
			for i, key := range keys {
				limit := claim.RepoConcurrency
				if i > 0 {
					limit = claim.TeamConcurrency
				}
				if limit > 0 && float64(m[key]) >= limit {
					reason := "REPO_QUOTA"
					if i > 0 {
						reason = "TEAM_QUOTA"
					}
					return model.Job{}, &storage.QuotaExceededError{Reason: reason, Msg: "concurrency limit reached"}
				}
			}
			for _, key := range keys {
				m[key]++
			}
		}
	}
	leased, err := a.fakeStore.AcquireLease(ctx, claim.JobID, claim.RunnerID, claim.TokenHash, claim.Generation, claim.ExpiresAt)
	if err != nil {
		return model.Job{}, err
	}
	leased.CostRate = eff.CostPerHour
	leased.PowerWatts = eff.PowerWatts
	if err := a.fakeStore.UpdateJob(ctx, leased); err != nil {
		return model.Job{}, err
	}
	// Mirror the SQL atomic lease: the runner's active set is updated in
	// the same critical section as the job claim.
	a.active[claim.RunnerID] = append(a.active[claim.RunnerID], claim.JobID)
	if ri, rerr := a.fakeStore.GetRunner(ctx, claim.RunnerID); rerr == nil {
		ri.ActiveJobs = append([]string(nil), a.active[claim.RunnerID]...)
		ri.Busy = cap > 0 && len(ri.ActiveJobs) >= cap
		if len(ri.ActiveJobs) > 0 {
			ri.CurrentJob = ri.ActiveJobs[0]
		}
		_ = a.fakeStore.UpsertRunner(ctx, ri)
	}
	return leased, nil
}

// fakeQuotas is a lazily initialized in-memory running-counter map used by
// atomicFakeStore's conditional quota transition.
func (a *atomicFakeStore) fakeQuotas() map[string]int {
	if a.quotas == nil {
		a.quotas = map[string]int{}
	}
	return a.quotas
}

// repoTeamKey mirrors storage's team quota key derivation.
func repoTeamKey(repoURL string) string {
	u := repoURL
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if at := strings.Index(u, "@"); at >= 0 {
		u = u[at+1:]
	}
	slash := strings.Index(u, "/")
	if slash < 0 {
		return repoURL
	}
	rest := u[slash+1:]
	seg := rest
	if i := strings.Index(rest, "/"); i >= 0 {
		seg = rest[:i]
	}
	if seg == "" {
		return repoURL
	}
	return u[:slash] + "/" + seg
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
