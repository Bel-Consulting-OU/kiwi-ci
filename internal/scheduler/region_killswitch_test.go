package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// killStore extends the shared test fakeStore with the RunnerJobStore
// listing used by the runner disable kill switch.
type killStore struct {
	*fakeStore
}

func (k *killStore) ListJobsByRunner(ctx context.Context, runnerID string) ([]model.Job, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := []model.Job{}
	for _, j := range k.jobs {
		if j.Status == model.StatusRunning && j.LeaseRunnerID == runnerID {
			out = append(out, j)
		}
	}
	return out, nil
}

func TestLeaseSkipsRegionConstrainedJobsForRegionlessRunner(t *testing.T) {
	st := &killStore{fakeStore: newFakeStore()}
	st.leaderOK = true
	s := NewDB(st, DefaultLeaseDuration, nil, nil)
	ctx := context.Background()
	now := time.Now().UTC()

	st.mu.Lock()
	st.runs["run-1"] = model.Run{ID: "run-1", Repo: "https://github.com/o/r.git", RepoFullName: "o/r", Status: model.StatusQueued}
	st.jobs["job-1"] = model.Job{ID: "job-1", RunID: "run-1", Key: "build", Status: model.StatusQueued, RequiredLabels: []string{"container"}, PlacementRegions: []string{"eu-west"}, CreatedAt: now}
	st.runners["r-no-region"] = model.Runner{ID: "r-no-region", Name: "r", Capacity: 1, Labels: []string{"container"}}
	st.runners["r-eu"] = model.Runner{ID: "r-eu", Name: "r", Capacity: 1, Labels: []string{"container"}, Region: "eu-west"}
	st.mu.Unlock()

	// A runner without a region can never satisfy a region-constrained job.
	if _, _, _, err := s.Lease(ctx, "r-no-region", now); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("region-less runner lease: got %v, want ErrNoJobs", err)
	}
	// A runner in the allowed region leases it.
	if _, _, _, err := s.Lease(ctx, "r-eu", now); err != nil {
		t.Fatalf("matching-region runner lease: %v", err)
	}
}

func TestCancelJobsByRunnerRequeuesWithinBudget(t *testing.T) {
	st := &killStore{fakeStore: newFakeStore()}
	s := NewDB(st, DefaultLeaseDuration, nil, nil)
	ctx := context.Background()
	now := time.Now().UTC()
	exp := now.Add(time.Hour)

	st.mu.Lock()
	st.runs["run-1"] = model.Run{ID: "run-1", Repo: "https://github.com/o/r.git", RepoFullName: "o/r", Status: model.StatusRunning}
	st.jobs["job-retry"] = model.Job{ID: "job-retry", RunID: "run-1", Key: "a", Status: model.StatusRunning, Attempts: 1, MaxInfraRetries: 2,
		LeaseRunnerID: "runner-1", LeaseTokenHash: []byte{1}, LeaseGeneration: 2, LeaseExpiresAt: &exp}
	st.jobs["job-doomed"] = model.Job{ID: "job-doomed", RunID: "run-1", Key: "b", Status: model.StatusRunning, Attempts: 3, MaxInfraRetries: 2,
		LeaseRunnerID: "runner-1", LeaseTokenHash: []byte{1}, LeaseGeneration: 2, LeaseExpiresAt: &exp}
	st.runners["runner-1"] = model.Runner{ID: "runner-1", Name: "r", Capacity: 2, ActiveJobs: []string{"job-retry", "job-doomed"}}
	st.mu.Unlock()

	count, err := s.CancelJobsByRunner(ctx, "runner-1", "runner disabled")
	if err != nil {
		t.Fatalf("CancelJobsByRunner: %v", err)
	}
	if count != 2 {
		t.Fatalf("CancelJobsByRunner count = %d, want 2", count)
	}

	st.mu.Lock()
	retry := st.jobs["job-retry"]
	doomed := st.jobs["job-doomed"]
	audit := append([]model.AuditEvent(nil), st.audit...)
	st.mu.Unlock()

	if retry.Status != model.StatusQueued {
		t.Fatalf("job-retry status = %q, want queued", retry.Status)
	}
	if retry.Attempts != 2 {
		t.Fatalf("job-retry attempts = %d, want 2", retry.Attempts)
	}
	if retry.LeaseRunnerID != "" || retry.LeaseTokenHash != nil || retry.LeaseExpiresAt != nil {
		t.Fatalf("job-retry lease not invalidated: %+v", retry)
	}
	if doomed.Status != model.StatusCancelled {
		t.Fatalf("job-doomed status = %q, want cancelled", doomed.Status)
	}
	if doomed.Attempts != 4 {
		t.Fatalf("job-doomed attempts = %d, want 4", doomed.Attempts)
	}
	if doomed.LeaseRunnerID != "" || doomed.LeaseTokenHash != nil || doomed.LeaseExpiresAt != nil {
		t.Fatalf("job-doomed lease not invalidated: %+v", doomed)
	}
	var actions []string
	for _, e := range audit {
		actions = append(actions, e.Action)
	}
	if !containsString(actions, "job.runner_disabled_requeued") || !containsString(actions, "job.runner_disabled_cancelled") {
		t.Fatalf("audit missing kill-switch events: %v", actions)
	}
}

func TestCancelJobsByRunnerRequiresStoreSupport(t *testing.T) {
	s := NewDB(newFakeStore(), DefaultLeaseDuration, nil, nil)
	if _, err := s.CancelJobsByRunner(context.Background(), "r", "x"); err == nil {
		t.Fatal("expected error when the store cannot list jobs by runner")
	}
}

var _ = storage.ErrNotFound

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
