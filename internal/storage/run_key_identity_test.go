package storage

// Run-scoped logical job identity (finding 7): model.Job.Key is the run's
// logical node identity (matrix/shard suffix included, so matrix variants
// stay distinct) and the memory store must refuse a generated fragment whose
// child key already exists in the run, exactly like the PostgreSQL
// transaction. These are the hermetic tests; the real-PostgreSQL admission
// and conditional-index tests live in postgres_run_key_conflict_it_test.go.

import (
	"errors"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// TestCheckGeneratedJobKeyConflicts pins the shared rule both stores call:
// requested keys are matched against the run's Key index in sorted Key order,
// a collision carries the run/key/existing-id, and matrix variants (distinct
// Keys sharing one BaseKey) never collide with each other.
func TestCheckGeneratedJobKeyConflicts(t *testing.T) {
	existing := map[string]string{"build[os=linux]": "11111111111111111111111111111111"}
	requested := map[string]model.Job{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1": {ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1", Key: "package"},
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2": {ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2", Key: "build[os=linux]", BaseKey: "build"},
	}
	err := CheckGeneratedJobKeyConflicts("run-1", requested, existing)
	var conflict *GeneratedJobKeyConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("collision error = %v, want *GeneratedJobKeyConflictError", err)
	}
	if conflict.RunID != "run-1" || conflict.Key != "build[os=linux]" || conflict.ExistingJobID != "11111111111111111111111111111111" {
		t.Fatalf("conflict = %+v", conflict)
	}
	if !errors.Is(err, ErrGeneratedJobKeyConflict) {
		t.Fatalf("errors.Is(ErrGeneratedJobKeyConflict) = false for %v", err)
	}
	// A free request (matrix siblings share BaseKey but not Key) passes.
	free := map[string]model.Job{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3": {ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3", Key: "build[os=mac]", BaseKey: "build"},
	}
	if err := CheckGeneratedJobKeyConflicts("run-1", free, existing); err != nil {
		t.Fatalf("matrix sibling refused: %v", err)
	}
	if err := CheckGeneratedJobKeyConflicts("run-1", nil, existing); err != nil {
		t.Fatalf("empty request refused: %v", err)
	}
	if err := CheckGeneratedJobKeyConflicts("run-1", requested, nil); err != nil {
		t.Fatalf("empty run refused: %v", err)
	}

	// GeneratedJobKeyIndex is run-scoped: the same Key in another run is not
	// part of the index, and the first id in sorted order wins for a
	// bug-created duplicate already present in the map.
	jobs := map[string]model.Job{
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1": {ID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1", RunID: "run-1", Key: "dup"},
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0": {ID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0", RunID: "run-1", Key: "dup"},
		"ccccccccccccccccccccccccccccccc1": {ID: "ccccccccccccccccccccccccccccccc1", RunID: "run-2", Key: "build[os=linux]"},
	}
	index := GeneratedJobKeyIndex("run-1", jobs)
	if len(index) != 1 || index["dup"] != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0" {
		t.Fatalf("index = %v, want deterministic first-id winner", index)
	}
}

// TestMemStoreGeneratedFragmentChildKeyConflict proves the memStore mirror of
// the SQL admission: a fragment child whose Key already identifies a run job
// fails closed with the shared typed error and inserts nothing (neither jobs
// nor receipt), while a free key is admitted.
func TestMemStoreGeneratedFragmentChildKeyConflict(t *testing.T) {
	m := newMemStore()
	generation := seedLeasedParentForGeneration(t, m)

	taken := testJob
	taken.ID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	taken.Key = "taken-key"
	if err := m.InsertJob(ctx(), taken); err != nil {
		t.Fatalf("seed existing run job: %v", err)
	}

	child := testJob
	child.ID = "ffffffffffffffffffffffffffffffff"
	child.Key = "taken-key"
	req := withGeneratedLease(GeneratedFragmentRequest{
		ParentJobID: testJob.ID, Depth: 1, FragmentID: "frag-key-conflict",
		Jobs:     map[string]model.Job{child.ID: child},
		Children: []GeneratedFragmentChild{{Key: child.Key, ID: child.ID}},
	}, generation)
	_, _, err := m.InsertGeneratedFragmentTx(ctx(), req, nil)
	if !errors.Is(err, ErrGeneratedJobKeyConflict) {
		t.Fatalf("colliding fragment = %v, want ErrGeneratedJobKeyConflict", err)
	}
	var conflict *GeneratedJobKeyConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("colliding fragment error = %v, want *GeneratedJobKeyConflictError", err)
	}
	if conflict.RunID != testRun.ID || conflict.Key != "taken-key" || conflict.ExistingJobID != taken.ID {
		t.Fatalf("conflict = %+v", conflict)
	}
	if _, gerr := m.GetJob(ctx(), child.ID); !errors.Is(gerr, ErrNotFound) {
		t.Fatalf("rejected fragment leaked a job: %v", gerr)
	}
	if _, found, _ := m.GetGeneratedFragment(ctx(), testJob.ID, GeneratedFragmentMutationSlotDefault); found {
		t.Fatal("rejected fragment left a receipt")
	}

	// A free key on the same run is admitted with its receipt.
	child.Key = "free-key"
	req.Jobs = map[string]model.Job{child.ID: child}
	if _, _, err := m.InsertGeneratedFragmentTx(ctx(), req, nil); err != nil {
		t.Fatalf("free-key fragment: %v", err)
	}
	if _, err := m.GetJob(ctx(), child.ID); err != nil {
		t.Fatalf("admitted fragment missing: %v", err)
	}
}
