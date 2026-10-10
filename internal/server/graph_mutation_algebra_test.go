package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Dynamic graph mutations are a deliberately constrained algebra, not
// arbitrary DAG editing: the only mutation surface is
// POST /api/v1/jobs/{id}/generated, which adds pre-expanded queued children of
// the generating parent. These tests pin the legality rules of
// docs/graph-mutations.md against the real admission path (handler, memory
// commit and the DB-fake transaction mirror):
//
//   - AddNode: children are queued jobs with an implicit parent edge (L1/L3).
//   - AddDependency: deps edges are confined to the fragment plus the
//     server-generated parent edge; the wire `needs` field cannot smuggle an
//     edge to an existing job (L4).
//   - AddConditionalNode: `if:` on a child is validated and persisted.
//   - Cycles stay rejected (L5).
//   - Committed nodes are never mutated and every new edge targets a new
//     queued node (L2/L3).
//   - SealSubgraph / CancelPendingSubgraph: completion or run cancellation
//     voids the lease, after which no further generation is possible.
//
// The same-slot replay-vs-conflict rule (L7), depth/count caps (L6) and
// run-scoped key uniqueness (L8) are already pinned by
// dynamic_receipt_test.go, dynamic_test.go, dynamic_flowcov_test.go,
// dynamic_key_conflict_test.go and the storage tests; this file references
// them instead of duplicating their fixtures.

// gmExistingJobID is a canonical 32-hex job id for the injected committed
// sibling the dependency-confinement tests try (and fail) to reference.
const gmExistingJobID = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"

// gmVictimKey is the run-scoped key of the injected sibling.
const gmVictimKey = "gm-sibling"

// gmTwoChildFragment declares a two-node fragment with one internal edge
// child-b -> child-a, so admission pins both AddNode and AddDependency.
const gmTwoChildFragment = `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo a"}]},"child-b":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo b"}]}},"deps":{"child-b":["child-a"]}}`

// gmConditionalFragment declares one child gated by a job-level `if:`.
const gmConditionalFragment = `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","if":"always()","steps":[{"run":"echo a"}]}},"deps":{}}`

// gmInvalidConditionFragment uses a condition the evaluator cannot run:
// admission must refuse the fragment before any child exists.
const gmInvalidConditionFragment = `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","if":"github.ref == 'refs/heads/main'","steps":[{"run":"echo a"}]}},"deps":{}}`

// gmNeedsSmuggleFragment puts a `needs:` list inside the fragment JOB body,
// naming an existing run job. Fragment edges are expressed only through the
// `deps` map; the job-body field must be ignored, never honored.
const gmNeedsSmuggleFragment = `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","needs":["gm-sibling"],"steps":[{"run":"echo a"}]}},"deps":{}}`

// gmCycleFragment declares child-a -> child-b and child-b -> child-a. The
// synthetic fragment spec must fail pipeline.Validate's cycle check.
const gmCycleFragment = `{"jobs":{"cyc-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo a"}]},"cyc-b":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo b"}]}},"deps":{"cyc-a":["cyc-b"],"cyc-b":["cyc-a"]}}`

// graphMutationFixture is one storage mode of the algebra tests: the server,
// its DB fake when in DB mode, and the leased generator task.
type graphMutationFixture struct {
	server   *Server
	fake     *dbFakeStore
	task     Task
	runnerID string
}

// graphMutationFixtures builds the memory and DB-fake fixtures, both with a
// policy that grants generate_child_graph for o/r and a leased generator job.
func graphMutationFixtures(t *testing.T) map[string]graphMutationFixture {
	t.Helper()
	memory := func() graphMutationFixture {
		s, _ := trustedGenerateServer(t)
		runnerID, task := leaseRunJob(t, s)
		return graphMutationFixture{server: s, task: task, runnerID: runnerID}
	}
	dbFake := func() graphMutationFixture {
		f := newDBFakeStore()
		s := trustedGenerateServerDB(t, f)
		runnerID, task := leaseRunJob(t, s)
		return graphMutationFixture{server: s, fake: f, task: task, runnerID: runnerID}
	}
	return map[string]graphMutationFixture{"memory": memory(), "dbFake": dbFake()}
}

// postFragment uploads one fragment exactly as the runner does.
func (fx graphMutationFixture) postFragment(t *testing.T, raw string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSONHeaders(t, fx.server, http.MethodPost,
		"/api/v1/jobs/"+fx.task.Job.ID+"/generated", "token",
		fragmentBody(t, raw), leaseHeaders(fx.task, fx.runnerID))
}

// jobs snapshots the store under its own lock.
func (fx graphMutationFixture) jobs() map[string]model.Job {
	out := map[string]model.Job{}
	if fx.fake != nil {
		fx.fake.mu.Lock()
		defer fx.fake.mu.Unlock()
		for id, j := range fx.fake.jobs {
			out[id] = j
		}
		return out
	}
	fx.server.mu.Lock()
	defer fx.server.mu.Unlock()
	for id, j := range fx.server.jobs {
		out[id] = j
	}
	return out
}

// inject seeds one committed run job directly into the store.
func (fx graphMutationFixture) inject(j model.Job) {
	if fx.fake != nil {
		fx.fake.mu.Lock()
		fx.fake.jobs[j.ID] = j
		fx.fake.mu.Unlock()
		return
	}
	fx.server.mu.Lock()
	fx.server.jobs[j.ID] = j
	fx.server.mu.Unlock()
}

// fragmentCount reports how many mutation receipts the store holds.
func (fx graphMutationFixture) fragmentCount() int {
	if fx.fake != nil {
		fx.fake.mu.Lock()
		defer fx.fake.mu.Unlock()
		return len(fx.fake.fragments)
	}
	fx.server.mu.Lock()
	defer fx.server.mu.Unlock()
	return len(fx.server.generatedFragments)
}

// gmNodeState is a comparable projection of one run job for before/after
// comparisons; the Needs slice is copied so in-place rewrites are visible.
type gmNodeState struct {
	Status model.Status
	Key    string
	Depth  int
	Needs  []string
	NodeID string
	Run    string
}

// gmNodeStates projects every job of the run.
func gmNodeStates(fx graphMutationFixture, runID string) map[string]gmNodeState {
	out := map[string]gmNodeState{}
	for id, j := range fx.jobs() {
		if j.RunID != runID {
			continue
		}
		out[id] = gmNodeState{
			Status: j.Status, Key: j.Key, Depth: j.DynamicDepth,
			Needs: append([]string(nil), j.Needs...), NodeID: j.ID, Run: j.RunID,
		}
	}
	return out
}

// gmChildrenByKey returns the run's generated children (dynamic depth > 0)
// keyed by logical job key.
func gmChildrenByKey(fx graphMutationFixture, runID string) map[string]model.Job {
	out := map[string]model.Job{}
	for _, j := range fx.jobs() {
		if j.RunID == runID && j.DynamicDepth > 0 {
			out[j.Key] = j
		}
	}
	return out
}

// gmSibling builds the committed run job the dependency-confinement tests try
// to reference.
func gmSibling(runID string, status model.Status) model.Job {
	return model.Job{
		ID: gmExistingJobID, RunID: runID, Key: gmVictimKey, BaseKey: gmVictimKey,
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Status: status, Needs: []string{"gm-upstream"},
	}
}

// TestGraphMutationAddNodeQueuesChildWithParentEdge pins AddNode and the
// implicit parent edge: every child of an admitted fragment is a QUEUED job of
// the parent's run at parent depth + 1, and its prerequisite set is exactly
// the generating parent plus the fragment-internal deps it declared.
func TestGraphMutationAddNodeQueuesChildWithParentEdge(t *testing.T) {
	for name, fx := range graphMutationFixtures(t) {
		t.Run(name, func(t *testing.T) {
			w := fx.postFragment(t, gmTwoChildFragment)
			if w.Code != http.StatusCreated {
				t.Fatalf("fragment = %d, want 201: %s", w.Code, w.Body.String())
			}
			var res generatedResponse
			if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
				t.Fatal(err)
			}
			if len(res.JobIDs) != 2 || len(res.Keys) != 2 {
				t.Fatalf("response = %+v, want two children", res)
			}
			kids := gmChildrenByKey(fx, fx.task.Job.RunID)
			a, okA := kids["child-a"]
			b, okB := kids["child-b"]
			if !okA || !okB {
				t.Fatalf("children = %v, want child-a and child-b", keysOf(kids))
			}
			for key, j := range kids {
				if j.Status != model.StatusQueued {
					t.Fatalf("child %s status = %s, want queued (L1: only queued nodes may be added)", key, j.Status)
				}
				if j.DynamicDepth != fx.task.Job.DynamicDepth+1 {
					t.Fatalf("child %s depth = %d, want parent depth + 1", key, j.DynamicDepth)
				}
			}
			if want := []string{fx.task.Job.ID}; !reflect.DeepEqual(a.Needs, want) {
				t.Fatalf("child-a needs = %v, want the implicit parent edge %v", a.Needs, want)
			}
			// The implicit parent edge comes first, then the declared deps.
			if want := []string{fx.task.Job.ID, a.ID}; !reflect.DeepEqual(b.Needs, want) {
				t.Fatalf("child-b needs = %v, want [parent, child-a]", b.Needs)
			}
			parent := fx.jobs()[fx.task.Job.ID]
			if parent.Status != model.StatusRunning || len(parent.Needs) != 0 {
				t.Fatalf("parent mutated by generation: status=%s needs=%v", parent.Status, parent.Needs)
			}
		})
	}
}

// TestGraphMutationAddDependencyStaysInsideFragment pins L3/L4: a `deps`
// entry may name only a declared fragment key. A dependency on the running
// generating parent's key or on an existing committed run job is refused
// whole (400, "unknown fragment job") and inserts nothing — there is no way
// to introduce an edge to an existing node.
func TestGraphMutationAddDependencyStaysInsideFragment(t *testing.T) {
	for name, fx := range graphMutationFixtures(t) {
		t.Run(name, func(t *testing.T) {
			fx.inject(gmSibling(fx.task.Job.RunID, model.StatusRunning))
			parent := fx.jobs()[fx.task.Job.ID]
			cases := map[string]string{
				"parent key":           parent.Key,
				"existing run job key": gmVictimKey,
			}
			for label, target := range cases {
				raw := fmt.Sprintf(`{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo a"}]}},"deps":{"child-a":[%q]}}`, target)
				w := fx.postFragment(t, raw)
				if w.Code != http.StatusBadRequest {
					t.Fatalf("%s dependency = %d, want 400: %s", label, w.Code, w.Body.String())
				}
				if !strings.Contains(w.Body.String(), "unknown fragment job") {
					t.Fatalf("%s rejection = %q, want the unknown-fragment-job refusal", label, w.Body.String())
				}
			}
			if kids := gmChildrenByKey(fx, fx.task.Job.RunID); len(kids) != 0 {
				t.Fatalf("rejected fragments inserted children: %v", keysOf(kids))
			}
			if n := fx.fragmentCount(); n != 0 {
				t.Fatalf("rejected fragments committed %d receipt(s), want 0", n)
			}
		})
	}
}

// TestGraphMutationFragmentJobNeedsFieldCannotSmuggleEdges pins the deps-only
// edge channel: a `needs:` list inside a fragment JOB body naming an existing
// run job is cleared before validation, so the admitted child carries only
// the implicit parent edge and the committed sibling gains no dependents.
func TestGraphMutationFragmentJobNeedsFieldCannotSmuggleEdges(t *testing.T) {
	for name, fx := range graphMutationFixtures(t) {
		t.Run(name, func(t *testing.T) {
			fx.inject(gmSibling(fx.task.Job.RunID, model.StatusSuccess))
			w := fx.postFragment(t, gmNeedsSmuggleFragment)
			if w.Code != http.StatusCreated {
				t.Fatalf("fragment with a job-body needs field = %d, want 201: %s", w.Code, w.Body.String())
			}
			child := gmChildrenByKey(fx, fx.task.Job.RunID)["child-a"]
			if want := []string{fx.task.Job.ID}; !reflect.DeepEqual(child.Needs, want) {
				t.Fatalf("child needs = %v, want only the implicit parent edge %v", child.Needs, want)
			}
			for _, need := range child.Needs {
				if need == gmExistingJobID {
					t.Fatalf("job-body needs field smuggled an edge to an existing job: %v", child.Needs)
				}
			}
			sibling := fx.jobs()[gmExistingJobID]
			if !reflect.DeepEqual(sibling.Needs, []string{"gm-upstream"}) {
				t.Fatalf("committed sibling rewired: needs = %v", sibling.Needs)
			}
		})
	}
}

// TestGraphMutationRejectsCycle pins L5: a fragment whose deps form a cycle
// (here a two-node cycle) fails pipeline.Validate's cycle check and commits
// nothing.
func TestGraphMutationRejectsCycle(t *testing.T) {
	for name, fx := range graphMutationFixtures(t) {
		t.Run(name, func(t *testing.T) {
			w := fx.postFragment(t, gmCycleFragment)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("cyclic fragment = %d, want 400: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "cycle") {
				t.Fatalf("cyclic rejection = %q, want the dependency-cycle error", w.Body.String())
			}
			if kids := gmChildrenByKey(fx, fx.task.Job.RunID); len(kids) != 0 {
				t.Fatalf("cyclic fragment inserted children: %v", keysOf(kids))
			}
			if n := fx.fragmentCount(); n != 0 {
				t.Fatalf("cyclic fragment committed %d receipt(s), want 0", n)
			}
		})
	}
}

// TestGraphMutationConditionalChild pins AddConditionalNode: a child `if:`
// condition accepted by the evaluator is persisted on the queued child, and a
// condition the evaluator cannot run is refused before admission (400).
func TestGraphMutationConditionalChild(t *testing.T) {
	for name, fx := range graphMutationFixtures(t) {
		t.Run(name, func(t *testing.T) {
			// Invalid condition first: it is refused before any receipt is
			// committed, so the parent's mutation slot stays free for the
			// valid fragment below.
			w := fx.postFragment(t, gmInvalidConditionFragment)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("invalid condition = %d, want 400: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "condition") {
				t.Fatalf("invalid-condition rejection = %q, want a condition error", w.Body.String())
			}
			if kids := gmChildrenByKey(fx, fx.task.Job.RunID); len(kids) != 0 {
				t.Fatalf("invalid condition inserted children: %v", keysOf(kids))
			}

			w = fx.postFragment(t, gmConditionalFragment)
			if w.Code != http.StatusCreated {
				t.Fatalf("conditional fragment = %d, want 201: %s", w.Code, w.Body.String())
			}
			child := gmChildrenByKey(fx, fx.task.Job.RunID)["child-a"]
			if child.Condition != "always()" {
				t.Fatalf("child condition = %q, want always()", child.Condition)
			}
		})
	}
}

// TestGraphMutationNeverMutatesCommittedNodes pins L2/L3: admitting a
// fragment leaves every pre-existing run job — running or terminal, parent
// included — byte-identical, and every new edge targets a node created by
// this fragment (the implicit parent edge may point at the running parent;
// fragment edges only at new queued children).
func TestGraphMutationNeverMutatesCommittedNodes(t *testing.T) {
	for name, fx := range graphMutationFixtures(t) {
		t.Run(name, func(t *testing.T) {
			runID := fx.task.Job.RunID
			fx.inject(gmSibling(runID, model.StatusRunning))
			terminal := gmSibling(runID, model.StatusSuccess)
			terminal.ID = "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2"
			terminal.Key = "gm-done"
			terminal.BaseKey = "gm-done"
			fx.inject(terminal)

			before := gmNodeStates(fx, runID)
			w := fx.postFragment(t, gmTwoChildFragment)
			if w.Code != http.StatusCreated {
				t.Fatalf("fragment = %d, want 201: %s", w.Code, w.Body.String())
			}
			after := gmNodeStates(fx, runID)
			for id, want := range before {
				got, ok := after[id]
				if !ok {
					t.Fatalf("pre-existing job %s disappeared", id)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("committed job %s mutated by generation: %+v -> %+v", id, want, got)
				}
			}
			// Every edge introduced by the fragment ends at a new queued
			// child; its only allowed sources are the parent and fragment
			// children created by the same admission.
			allowed := map[string]bool{fx.task.Job.ID: true}
			for id, j := range after {
				if _, existed := before[id]; !existed {
					allowed[id] = true
					if j.Status != model.StatusQueued {
						t.Fatalf("new node %s is %s, want queued", id, j.Status)
					}
				}
			}
			for id, j := range after {
				if _, existed := before[id]; existed {
					continue
				}
				for _, need := range j.Needs {
					if !allowed[need] {
						t.Fatalf("new node %s depends on %s outside the fragment plus implicit parent", id, need)
					}
				}
			}
		})
	}
}

// TestGraphMutationCompletedParentSealsGeneration pins SealSubgraph: after
// the generator completes, its lease is void and the mutation surface refuses
// both a new fragment and a replay of the committed one (409). The recorded
// children and receipt stay exactly as committed.
func TestGraphMutationCompletedParentSealsGeneration(t *testing.T) {
	for name, fx := range graphMutationFixtures(t) {
		t.Run(name, func(t *testing.T) {
			if w := fx.postFragment(t, replayFragmentA); w.Code != http.StatusCreated {
				t.Fatalf("first fragment = %d: %s", w.Code, w.Body.String())
			}
			kidsBefore := len(gmChildrenByKey(fx, fx.task.Job.RunID))
			fragsBefore := fx.fragmentCount()

			complete := fmt.Sprintf(`{"runner_id":%q,"lease_token":%q,"lease_generation":%d,"status":"success"}`,
				fx.runnerID, fx.task.LeaseToken, fx.task.LeaseGeneration)
			if w := doJSON(t, fx.server, http.MethodPost, "/api/v1/jobs/"+fx.task.Job.ID+"/complete", "token", complete); w.Code != http.StatusNoContent {
				t.Fatalf("completion = %d, want 204: %s", w.Code, w.Body.String())
			}

			// A different fragment is refused: the sealed parent has no lease.
			w := fx.postFragment(t, replayFragmentB)
			if w.Code != http.StatusConflict {
				t.Fatalf("fragment after completion = %d, want 409: %s", w.Code, w.Body.String())
			}
			// Even the committed fragment cannot replay without a live lease.
			w = fx.postFragment(t, replayFragmentA)
			if w.Code != http.StatusConflict {
				t.Fatalf("replay after completion = %d, want 409: %s", w.Code, w.Body.String())
			}
			if got := len(gmChildrenByKey(fx, fx.task.Job.RunID)); got != kidsBefore {
				t.Fatalf("children after seal = %d, want the committed %d", got, kidsBefore)
			}
			if got := fx.fragmentCount(); got != fragsBefore {
				t.Fatalf("receipts after seal = %d, want the committed %d", got, fragsBefore)
			}
		})
	}
}

// TestGraphMutationCancelRunSealsPendingSubgraph pins the cancellation
// semantics of the algebra: there is no targeted per-node cancel. The
// run-scoped cancel terminates every non-terminal job — queued generated
// children included — and seals further generation (409, nothing added).
func TestGraphMutationCancelRunSealsPendingSubgraph(t *testing.T) {
	for name, fx := range graphMutationFixtures(t) {
		t.Run(name, func(t *testing.T) {
			if w := fx.postFragment(t, replayFragmentA); w.Code != http.StatusCreated {
				t.Fatalf("first fragment = %d: %s", w.Code, w.Body.String())
			}
			kidsBefore := len(gmChildrenByKey(fx, fx.task.Job.RunID))
			fragsBefore := fx.fragmentCount()

			w := doJSON(t, fx.server, http.MethodPost, "/api/v1/runs/"+fx.task.Job.RunID+"/cancel", "token", "")
			if w.Code != http.StatusOK {
				t.Fatalf("cancel run = %d, want 200: %s", w.Code, w.Body.String())
			}
			for key, j := range gmChildrenByKey(fx, fx.task.Job.RunID) {
				if j.Status != model.StatusCancelled {
					t.Fatalf("pending child %s = %s, want cancelled by the run cancel", key, j.Status)
				}
			}
			// The cancelled parent has no lease: no further mutation.
			w = fx.postFragment(t, replayFragmentB)
			if w.Code != http.StatusConflict {
				t.Fatalf("fragment after cancel = %d, want 409: %s", w.Code, w.Body.String())
			}
			if got := len(gmChildrenByKey(fx, fx.task.Job.RunID)); got != kidsBefore {
				t.Fatalf("children after cancel = %d, want the committed %d", got, kidsBefore)
			}
			if got := fx.fragmentCount(); got != fragsBefore {
				t.Fatalf("receipts after cancel = %d, want the committed %d", got, fragsBefore)
			}
		})
	}
}

// keysOf returns the sorted logical keys of a job map for failure messages.
func keysOf(jobs map[string]model.Job) []string {
	out := make([]string, 0, len(jobs))
	for key := range jobs {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
