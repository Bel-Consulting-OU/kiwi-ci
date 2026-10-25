package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestPlainLeasePersistsEngineIdentity drives the NON-atomic lease fallback
// (the scheduler branch for stores without AcquireLeaseAtomic /
// AcquireLeaseWithTTL) and pins that the lease-time interpreter identity is
// derived from the RUNNER's advertisement and persisted onto the durable
// job — the branch previously persisted rates but no engine identity, so a
// v2-job completion bridge could not distinguish a legacy drain lease from
// anything else on such stores.
func TestPlainLeasePersistsEngineIdentity(t *testing.T) {
	now := time.Now().UTC()

	// Current engine leasing a v3-stamped job → v3 identity.
	f := newFakeStore()
	f.setLeader(true, nil)
	f.putRunner(model.Runner{ID: "r-cur", Name: "r-cur", Capacity: 1, LastSeen: now,
		SupportedExecutionSemantics: []string{model.ExecutionSemanticsVersion}})
	f.putRun(model.Run{ID: "run-cur", Status: model.StatusQueued, CreatedAt: now})
	f.putJob(model.Job{ID: "job-cur", RunID: "run-cur", Key: "build", Status: model.StatusQueued,
		CreatedAt: now, ExecutionSemantics: model.ExecutionSemanticsVersion})
	s := NewDB(f, time.Minute, func() (string, error) { return "tok", nil }, testHash)
	s.LeaderKey = "test-key"
	if !s.IsLeader(context.Background()) {
		t.Fatal("expected leader")
	}
	j, _, _, err := s.Lease(context.Background(), "r-cur", now)
	if err != nil {
		t.Fatalf("Lease current: %v", err)
	}
	if j == nil || j.LeaseInterpreter != model.ExecutionSemanticsVersion {
		t.Fatalf("leased LeaseInterpreter = %+v, want current engine identity", j)
	}
	cur, _ := f.job("job-cur")
	if cur.LeaseInterpreter != model.ExecutionSemanticsVersion {
		t.Fatalf("persisted LeaseInterpreter = %q, want current engine identity (plain path must persist it)", cur.LeaseInterpreter)
	}

	// Legacy (unadvertised) engine leasing a v2-stamped job → legacy identity.
	f2 := newFakeStore()
	f2.setLeader(true, nil)
	f2.putRunner(model.Runner{ID: "r-old", Name: "r-old", Capacity: 1, LastSeen: now})
	f2.putRun(model.Run{ID: "run-old", Status: model.StatusQueued, CreatedAt: now})
	f2.putJob(model.Job{ID: "job-old", RunID: "run-old", Key: "build", Status: model.StatusQueued,
		CreatedAt: now, ExecutionSemantics: model.LegacyExecutionSemanticsVersion})
	s2 := NewDB(f2, time.Minute, func() (string, error) { return "tok2", nil }, testHash)
	s2.LeaderKey = "test-key"
	if !s2.IsLeader(context.Background()) {
		t.Fatal("expected leader")
	}
	j2, _, _, err := s2.Lease(context.Background(), "r-old", now)
	if err != nil {
		t.Fatalf("Lease legacy: %v", err)
	}
	if j2 == nil || j2.LeaseInterpreter != model.LegacyExecutionSemanticsVersion {
		t.Fatalf("leased LeaseInterpreter = %+v, want legacy identity", j2)
	}
	cur2, _ := f2.job("job-old")
	if cur2.LeaseInterpreter != model.LegacyExecutionSemanticsVersion {
		t.Fatalf("persisted LeaseInterpreter = %q, want legacy identity", cur2.LeaseInterpreter)
	}
}
