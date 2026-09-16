package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// compiledJobWithRuntime builds a job whose compiled payload declares the
// given runtime capability, so the capability predicate has something to
// derive from.
func compiledJobWithRuntime(id, runID, repoURL, fullName, runtime string) model.Job {
	return model.Job{
		ID: id, RunID: runID, Key: "build", Status: model.StatusQueued,
		RepoURL: repoURL, RepoFullName: fullName,
		Priority:  0,
		CreatedAt: time.Now().UTC().Add(-time.Minute),
		CompiledJobPayload: &model.CompiledJobPayload{
			SchemaVersion: 1,
			EffectiveJob:  pipeline.CompiledJob{Job: pipeline.Job{Runtime: runtime}},
		},
	}
}

func leaseErr(t *testing.T, st *fakeStore, runnerID string) error {
	t.Helper()
	st.mu.Lock()
	st.leaderOK = true
	st.mu.Unlock()
	s := NewDB(st, time.Minute, nil, nil)
	_, _, _, err := s.Lease(context.Background(), runnerID, time.Now().UTC())
	return err
}

// TestLeaseSkipsReposOutsideRunnerAllowlist: a runner whose profile
// restricts repositories never leases a job whose canonical repo is not in
// the allowlist; the allowed repo leases normally.
func TestLeaseSkipsReposOutsideRunnerAllowlist(t *testing.T) {
	st := newFakeStore()
	st.mu.Lock()
	st.runners["r1"] = model.Runner{ID: "r1", Name: "r1", Capacity: 4, AllowedRepositories: []string{"github.com/o/allowed"}}
	st.jobs["j-foreign"] = compiledJobWithRuntime("j-foreign", "run-1", "https://github.com/o/other.git", "o/other", "container")
	st.mu.Unlock()
	if err := leaseErr(t, st, "r1"); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("foreign repo lease: got %v, want ErrNoJobs", err)
	}

	st.mu.Lock()
	st.jobs["j-ok"] = compiledJobWithRuntime("j-ok", "run-1", "https://github.com/o/allowed.git", "o/allowed", "container")
	st.mu.Unlock()
	if err := leaseErr(t, st, "r1"); err != nil {
		t.Fatalf("allowed repo lease: %v", err)
	}

	// An empty allowlist imposes no repository restriction.
	st2 := newFakeStore()
	st2.mu.Lock()
	st2.runners["r2"] = model.Runner{ID: "r2", Name: "r2", Capacity: 4}
	st2.jobs["j-any"] = compiledJobWithRuntime("j-any", "run-2", "https://gitlab.com/team/any.git", "team/any", "container")
	st2.mu.Unlock()
	if err := leaseErr(t, st2, "r2"); err != nil {
		t.Fatalf("unrestricted runner lease: %v", err)
	}
}

// TestLeaseSkipsCapabilityMismatch: the job's runtime capability must be in
// the runner's declared capabilities; an empty declared list keeps the
// check vacuous.
func TestLeaseSkipsCapabilityMismatch(t *testing.T) {
	st := newFakeStore()
	st.mu.Lock()
	st.runners["r1"] = model.Runner{ID: "r1", Name: "r1", Capacity: 4, Capabilities: []string{"native"}}
	st.jobs["j-container"] = compiledJobWithRuntime("j-container", "run-1", "https://github.com/o/r.git", "o/r", "container")
	st.mu.Unlock()
	if err := leaseErr(t, st, "r1"); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("container job on native-only runner: got %v, want ErrNoJobs", err)
	}

	st.mu.Lock()
	st.jobs["j-native"] = compiledJobWithRuntime("j-native", "run-1", "https://github.com/o/r.git", "o/r", "native")
	st.mu.Unlock()
	if err := leaseErr(t, st, "r1"); err != nil {
		t.Fatalf("native job on native runner: %v", err)
	}

	// Empty declared capabilities: no capability constraint.
	st2 := newFakeStore()
	st2.mu.Lock()
	st2.runners["r2"] = model.Runner{ID: "r2", Name: "r2", Capacity: 4}
	st2.jobs["j-any"] = compiledJobWithRuntime("j-any", "run-2", "https://github.com/o/r.git", "o/r", "tart")
	st2.mu.Unlock()
	if err := leaseErr(t, st2, "r2"); err != nil {
		t.Fatalf("runner without declared caps: %v", err)
	}

	// A job without a compiled payload has no derivable runtime: the
	// predicate does not constrain it.
	st3 := newFakeStore()
	st3.mu.Lock()
	st3.runners["r3"] = model.Runner{ID: "r3", Name: "r3", Capacity: 4, Capabilities: []string{"native"}}
	st3.jobs["j-legacy"] = model.Job{ID: "j-legacy", RunID: "run-3", Key: "b", Status: model.StatusQueued, RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r", CreatedAt: time.Now().UTC().Add(-time.Minute)}
	st3.mu.Unlock()
	if err := leaseErr(t, st3, "r3"); err != nil {
		t.Fatalf("payload-less job constrained by capability: %v", err)
	}
}

// TestLeaseCapacityZeroReceivesNothing: a runner whose profile yields
// capacity 0 never leases work (no legacy clamp).
func TestLeaseCapacityZeroReceivesNothing(t *testing.T) {
	st := newFakeStore()
	st.mu.Lock()
	st.runners["r0"] = model.Runner{ID: "r0", Name: "r0", Capacity: 0}
	st.jobs["j"] = compiledJobWithRuntime("j", "run-1", "https://github.com/o/r.git", "o/r", "native")
	st.mu.Unlock()
	if err := leaseErr(t, st, "r0"); !errors.Is(err, ErrNoJobs) {
		t.Fatalf("capacity-0 runner: got %v, want ErrNoJobs", err)
	}
}

// TestJobRuntimeCapabilityDerivation pins the payload-based extraction.
func TestJobRuntimeCapabilityDerivation(t *testing.T) {
	for _, tc := range []struct {
		runtime string
		want    string
	}{
		{"container", "container"},
		{"tart", "tart"},
		{"native", "native"},
		{"", ""},
		{"weird", ""},
	} {
		j := compiledJobWithRuntime("j", "run", "https://github.com/o/r.git", "o/r", tc.runtime)
		if got := jobRuntimeCapability(j); got != tc.want {
			t.Errorf("jobRuntimeCapability(%q) = %q, want %q", tc.runtime, got, tc.want)
		}
	}
	if got := jobRuntimeCapability(model.Job{ID: "j"}); got != "" {
		t.Errorf("payload-less job runtime = %q, want empty", got)
	}
}

// TestRepoHostDerivation pins the forge host extraction shared with the
// server's canonical repo IDs.
func TestRepoHostDerivation(t *testing.T) {
	for _, tc := range []struct{ url, want string }{
		{"https://github.com/o/r.git", "github.com"},
		{"https://gitlab.example.com/team/proj", "gitlab.example.com"},
		{"ssh://git@github.com/o/r.git", "github.com"},
		{"git@github.com:o/r.git", "github.com"},
	} {
		if got := repoHostFromURL(tc.url); got != tc.want {
			t.Errorf("repoHostFromURL(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

var _ = storage.ErrNotFound
