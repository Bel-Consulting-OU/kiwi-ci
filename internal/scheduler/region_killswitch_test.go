package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func TestLeaseSkipsRegionConstrainedJobsForRegionlessRunner(t *testing.T) {
	st := newFakeStore()
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

// revokeRunnerLeases is the runner-disable kill switch the scheduler used to
// wrap (DBScheduler.CancelJobsByRunner, removed as dead code): the disable
// path calls the store's transactional RecoveryStore.RevokeRunnerLeases
// directly, so the requeue-budget assertions live on the store contract.
func revokeRunnerLeases(ctx context.Context, st storage.Store, runnerID, reason string) (int, error) {
	rs, ok := st.(storage.RecoveryStore)
	if !ok {
		return 0, errors.New("scheduler: store does not support transactional runner lease revocation")
	}
	revoked, err := rs.RevokeRunnerLeases(ctx, runnerID, reason)
	if err != nil {
		return 0, err
	}
	return len(revoked), nil
}

func TestRevokeRunnerLeasesRequeuesWithinBudget(t *testing.T) {
	st := newFakeStore()
	ctx := context.Background()
	now := time.Now().UTC()
	exp := now.Add(time.Hour)

	st.mu.Lock()
	st.runs["run-1"] = model.Run{ID: "run-1", Repo: "https://github.com/o/r.git", RepoFullName: "o/r", Status: model.StatusRunning}
	st.jobs["job-retry"] = model.Job{ID: "job-retry", RunID: "run-1", Key: "a", Status: model.StatusRunning, RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r", Attempts: 1, MaxInfraRetries: 2,
		LeaseRunnerID: "runner-1", LeaseTokenHash: []byte{1}, LeaseGeneration: 2, LeaseExpiresAt: &exp}
	st.jobs["job-doomed"] = model.Job{ID: "job-doomed", RunID: "run-1", Key: "b", Status: model.StatusRunning, RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r", Attempts: 3, MaxInfraRetries: 2,
		LeaseRunnerID: "runner-1", LeaseTokenHash: []byte{1}, LeaseGeneration: 2, LeaseExpiresAt: &exp}
	st.runners["runner-1"] = model.Runner{ID: "runner-1", Name: "r", Capacity: 2, ActiveJobs: []string{"job-retry", "job-doomed"}}
	st.mu.Unlock()

	count, err := revokeRunnerLeases(ctx, st, "runner-1", "runner disabled")
	if err != nil {
		t.Fatalf("RevokeRunnerLeases: %v", err)
	}
	if count != 2 {
		t.Fatalf("RevokeRunnerLeases count = %d, want 2", count)
	}

	st.mu.Lock()
	retry := st.jobs["job-retry"]
	doomed := st.jobs["job-doomed"]
	audit := append([]model.AuditEvent(nil), st.audit...)
	runner := st.runners["runner-1"]
	revokes := append([]revokeCall(nil), st.revokeCalls...)
	releases := append([]releaseRunnerCall(nil), st.releaseRunnerCalls...)
	updates := append([]model.Job(nil), st.updateJobCalls...)
	st.mu.Unlock()

	// The disable path is ONE transactional RevokeRunnerLeases call with no
	// legacy per-job write.
	if len(releases) != 0 || len(updates) != 0 {
		t.Fatalf("legacy multi-step revocation writes used: release=%d update=%d", len(releases), len(updates))
	}
	if len(revokes) != 1 || revokes[0].RunnerID != "runner-1" {
		t.Fatalf("revoke calls = %+v, want one for runner-1", revokes)
	}
	if retry.Status != model.StatusQueued {
		t.Fatalf("job-retry status = %q, want queued", retry.Status)
	}
	// Attempts were charged by the lease, not by the kill switch: the
	// recovery path only reads the budget.
	if retry.Attempts != 1 {
		t.Fatalf("job-retry attempts = %d, want 1 (lease-time increment only)", retry.Attempts)
	}
	if retry.LeaseRunnerID != "" || retry.LeaseTokenHash != nil || retry.LeaseExpiresAt != nil {
		t.Fatalf("job-retry lease not invalidated: %+v", retry)
	}
	if doomed.Status != model.StatusCancelled {
		t.Fatalf("job-doomed status = %q, want cancelled", doomed.Status)
	}
	if doomed.Attempts != 3 {
		t.Fatalf("job-doomed attempts = %d, want 3 (lease-time increments only)", doomed.Attempts)
	}
	if doomed.LeaseRunnerID != "" || doomed.LeaseTokenHash != nil || doomed.LeaseExpiresAt != nil {
		t.Fatalf("job-doomed lease not invalidated: %+v", doomed)
	}
	if len(runner.ActiveJobs) != 0 || runner.Busy {
		t.Fatalf("runner after revocation = active=%v busy=%v, want empty", runner.ActiveJobs, runner.Busy)
	}
	// The revocation released the two running slots and re-reserved exactly
	// one queued slot for the requeued job.
	repoID := storage.RepoIDFor("", "https://github.com/o/r.git", "o/r")
	if running, queued, _ := st.QuotaCounts(ctx, repoID, ""); running != 0 || queued != 1 {
		t.Fatalf("quota after revocation = %d/%d, want 0/1", running, queued)
	}
	var actions []string
	for _, e := range audit {
		actions = append(actions, e.Action)
	}
	if !containsString(actions, "job.runner_disabled_requeued") || !containsString(actions, "job.runner_disabled_cancelled") {
		t.Fatalf("audit missing kill-switch events: %v", actions)
	}

	// A second replica racing the same revocation sees no leases and releases
	// nothing a second time.
	count, err = revokeRunnerLeases(ctx, st, "runner-1", "runner disabled")
	if err != nil || count != 0 {
		t.Fatalf("replayed revocation count/err = %d/%v, want 0/nil", count, err)
	}
	if running, queued, _ := st.QuotaCounts(ctx, repoID, ""); running != 0 || queued != 1 {
		t.Fatalf("quota after replayed revocation = %d/%d, want unchanged 0/1", running, queued)
	}
}

// legacyRecoveryStore hides the RecoveryStore methods by embedding only the
// storage.Store interface, so the fail-closed contract checks are reachable.
type legacyRecoveryStore struct {
	storage.Store
}

// TestRevokeRunnerLeasesRequiresStoreSupport: with the scheduler wrapper
// gone, the fail-closed guard is the type assertion every kill-switch caller
// performs; a store without the transactional contract never falls back to
// the retired multi-step sequence.
func TestRevokeRunnerLeasesRequiresStoreSupport(t *testing.T) {
	st := &legacyRecoveryStore{Store: newFakeStore()}
	if _, err := revokeRunnerLeases(context.Background(), st, "r", "x"); err == nil {
		t.Fatal("expected error when the store cannot revoke leases transactionally")
	}
	if _, ok := any(st).(storage.RecoveryStore); ok {
		t.Fatal("the fail-closed fixture unexpectedly implements RecoveryStore")
	}
}

func TestRecoverExpiredRequiresStoreSupport(t *testing.T) {
	inner := newFakeStore()
	inner.setLeader(true, nil)
	s := NewDB(&legacyRecoveryStore{Store: inner}, DefaultLeaseDuration, nil, nil)
	if err := s.RecoverExpired(context.Background(), time.Now().UTC()); err == nil {
		t.Fatal("expected error when the store cannot recover leases transactionally")
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
