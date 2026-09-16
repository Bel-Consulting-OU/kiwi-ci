package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// regionParityTable is the canonical region-matching decision table shared
// by the DB scheduler and the server's memory-mode scheduler. The two
// implementations MUST agree on every row (see the identical
// regionParityTable in internal/server/region_parity_test.go) — this test
// pins the DB-scheduler side.
var regionParityTable = []struct {
	name         string
	runnerRegion string
	jobRegions   []string
	lease        bool
}{
	{"regionless runner, region-constrained job", "", []string{"eu-west"}, false},
	{"matching region", "eu-west", []string{"eu-west"}, true},
	{"non-matching region", "us-east", []string{"eu-west"}, false},
	{"unconstrained job, regionless runner", "", nil, true},
	{"unconstrained job, any runner", "eu-west", nil, true},
	{"multi-region match", "us-east", []string{"eu-west", "us-east"}, true},
}

// TestRegionParityTableDBMode runs the canonical region table against the
// DB scheduler: a runner whose region is EMPTY can never satisfy a
// region-constrained job (parity with memory mode).
func TestRegionParityTableDBMode(t *testing.T) {
	for _, tc := range regionParityTable {
		st := &killStore{fakeStore: newFakeStore()}
		st.leaderOK = true
		s := NewDB(st, DefaultLeaseDuration, nil, nil)
		ctx := context.Background()
		now := time.Now().UTC()
		runnerID := "runner-" + tc.name
		st.mu.Lock()
		st.runs["run-1"] = model.Run{ID: "run-1", Repo: "https://github.com/o/r.git", RepoFullName: "o/r", Status: model.StatusQueued}
		st.jobs["job-1"] = model.Job{ID: "job-1", RunID: "run-1", Key: "build", Status: model.StatusQueued, RequiredLabels: []string{"container"}, PlacementRegions: append([]string{}, tc.jobRegions...), CreatedAt: now}
		st.runners[runnerID] = model.Runner{ID: runnerID, Name: "r", Capacity: 1, Labels: []string{"container"}, Region: tc.runnerRegion}
		st.mu.Unlock()
		_, _, _, err := s.Lease(ctx, runnerID, now)
		if tc.lease && err != nil {
			t.Fatalf("%s: lease failed: %v", tc.name, err)
		}
		if !tc.lease && !errors.Is(err, ErrNoJobs) {
			t.Fatalf("%s: lease = %v, want ErrNoJobs", tc.name, err)
		}
	}
}
