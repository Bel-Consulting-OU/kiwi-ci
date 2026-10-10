package storage

import (
	"context"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestMemStoreApproveJobIdempotentReplay pins docs/INVARIANTS.md I8 on the
// in-memory store mirror: repeating ApproveJob for an already-approved
// non-terminal job returns the stored job unchanged — the first approver is
// preserved and NO second approval.granted event is appended — while the
// first approval keeps its exact behavior.
func TestMemStoreApproveJobIdempotentReplay(t *testing.T) {
	m := newMemStore()
	ctx := context.Background()
	m.jobs["job-wait"] = model.Job{
		ID: "job-wait", RunID: "run-1", Key: "deploy",
		Status: model.StatusWaitingApproval, ApprovalRequired: true, Environment: "prod",
	}
	first, err := m.ApproveJob(ctx, "job-wait", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if first.ApprovedBy != "alice" || first.Status != model.StatusQueued {
		t.Fatalf("first approval = %+v, want alice/queued", first)
	}

	second, err := m.ApproveJob(ctx, "job-wait", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if second.ApprovedBy != "alice" || second.Status != model.StatusQueued {
		t.Fatalf("replayed approval = %+v, want the first approver alice preserved", second)
	}
	if n := m.approvalGrantedEventsLocked(); n != 1 {
		t.Fatalf("approval.granted events = %d, want exactly 1", n)
	}

	// A running job that was already approved replays identically.
	m.jobs["job-run"] = model.Job{
		ID: "job-run", RunID: "run-1", Key: "release",
		Status: model.StatusRunning, ApprovalRequired: true, ApprovedBy: "carol",
	}
	replayed, err := m.ApproveJob(ctx, "job-run", "dave")
	if err != nil {
		t.Fatal(err)
	}
	if replayed.ApprovedBy != "carol" || replayed.Status != model.StatusRunning {
		t.Fatalf("running replay = %+v, want carol/running untouched", replayed)
	}
	if n := m.approvalGrantedEventsLocked(); n != 1 {
		t.Fatalf("approval.granted events after running replay = %d, want still 1", n)
	}
}

// approvalGrantedEventsLocked counts the memStore's committed
// approval.granted events (test-only accessor kept off the retention API,
// which the scoped-events work is reshaping).
func (m *memStore) approvalGrantedEventsLocked() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.events {
		if e.Type == model.EventApprovalGranted {
			n++
		}
	}
	return n
}
