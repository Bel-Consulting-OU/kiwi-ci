package storage

// Unit coverage for the downstream parent reverse-index lookup
// (DownstreamParentRunStore.ParentRunIDsForChild) on the in-memory store and
// the fault-injection wrapper.

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// seedParentChildLink wires one parent job/run pair and its launched
// downstream link (childRunID) into the memory store.
func seedParentChildLink(m *memStore, runID, jobID, targetRepo, childRunID string) {
	now := time.Now().UTC()
	_ = m.InsertRun(ctx(), model.Run{ID: runID, Status: model.StatusRunning, CreatedAt: now})
	_ = m.InsertJob(ctx(), model.Job{ID: jobID, RunID: runID, Key: "build", Status: model.StatusSuccess, CreatedAt: now})
	_ = m.InsertDownstreamLink(ctx(), DownstreamLink{
		ParentJobID: jobID, TargetRepo: targetRepo, TargetRef: "refs/heads/main",
		LaunchToken: "tok", ChildRunID: childRunID, CreatedAt: now,
	})
}

// TestMemStoreParentRunIDsForChild pins the in-memory reverse-index
// semantics: distinct parent run IDs in deterministic (sorted) order,
// multiple links/parents folded, missing parent jobs skipped, unknown
// children empty and an empty child rejected.
func TestMemStoreParentRunIDsForChild(t *testing.T) {
	m := newMemStore()
	parentA := "11111111111111111111111111111111"
	parentB := "22222222222222222222222222222222"
	jobA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	jobB := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	child := "cccccccccccccccccccccccccccccccc"
	other := "dddddddddddddddddddddddddddddddd"
	seedParentChildLink(m, parentA, jobA, "acme/one", child)
	seedParentChildLink(m, parentB, jobB, "acme/two", child)
	// A second link of parent A to the same child (different target) must
	// fold into one run ID; a link to another child must not appear.
	_ = m.InsertDownstreamLink(ctx(), DownstreamLink{
		ParentJobID: jobA, TargetRepo: "acme/three", TargetRef: "refs/heads/main",
		LaunchToken: "tok", ChildRunID: child, CreatedAt: time.Now().UTC(),
	})
	_ = m.InsertDownstreamLink(ctx(), DownstreamLink{
		ParentJobID: jobA, TargetRepo: "acme/four", TargetRef: "refs/heads/main",
		LaunchToken: "tok", ChildRunID: other, CreatedAt: time.Now().UTC(),
	})
	// A link whose parent job is gone (the SQL JOIN drops it).
	_ = m.InsertDownstreamLink(ctx(), DownstreamLink{
		ParentJobID: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", TargetRepo: "acme/five", TargetRef: "refs/heads/main",
		LaunchToken: "tok", ChildRunID: child, CreatedAt: time.Now().UTC(),
	})

	got, err := m.ParentRunIDsForChild(ctx(), child)
	if err != nil {
		t.Fatalf("ParentRunIDsForChild: %v", err)
	}
	if len(got) != 2 || got[0] != parentA || got[1] != parentB {
		t.Fatalf("ParentRunIDsForChild(%s) = %v; want [%s %s]", child, got, parentA, parentB)
	}

	if got, err := m.ParentRunIDsForChild(ctx(), "99999999999999999999999999999999"); err != nil || len(got) != 0 {
		t.Fatalf("unknown child = %v/%v; want empty/nil", got, err)
	}
	if _, err := m.ParentRunIDsForChild(ctx(), ""); err == nil {
		t.Fatal("empty child id must be rejected")
	}
}

// TestFaultyStoreParentRunIDsForChild proves the wrapper passes the read
// through unchanged and fails closed with the typed missing-interface error
// when Inner lacks the contract.
func TestFaultyStoreParentRunIDsForChild(t *testing.T) {
	m := newMemStore()
	parent := "11111111111111111111111111111111"
	job := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	child := "cccccccccccccccccccccccccccccccc"
	seedParentChildLink(m, parent, job, "acme/one", child)

	f := &FaultyStore{Inner: m}
	got, err := f.ParentRunIDsForChild(ctx(), child)
	if err != nil || len(got) != 1 || got[0] != parent {
		t.Fatalf("FaultyStore pass-through = %v/%v; want [%s]", got, err, parent)
	}
	// The fault counter is write-only: the read must never consume it.
	f.FailAfter = 1
	f.Err = errors.New("injected")
	if _, err := f.ParentRunIDsForChild(ctx(), child); err != nil {
		t.Fatalf("fault-injected read = %v; want pass-through", err)
	}

	// A minimal Inner without the contract fails closed.
	bare := &FaultyStore{Inner: minimalStore{}}
	_, err = bare.ParentRunIDsForChild(ctx(), child)
	var missing *missingInnerInterfaceError
	if !errors.As(err, &missing) || !strings.Contains(err.Error(), "DownstreamParentRunStore") {
		t.Fatalf("missing inner contract = %v; want a typed missing-interface error", err)
	}
}

// minimalStore embeds the Store interface so it satisfies the base contract
// while exposing none of the optional extension interfaces (it models a
// legacy store that predates the reverse-index contract).
type minimalStore struct {
	Store
}

var _ Store = minimalStore{}
