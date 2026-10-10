package server

// dynamic_graph_property_test.go is the deterministic property test for the
// generated-fragment admission graph: random child graphs (2..8 keys, with
// deliberately cyclic and structurally invalid variants) are pushed through
// the REAL admission path (Server.processGeneratedFragment, whose dependency
// checks are inline and whose acyclicity check is pipeline.Validate) and the
// pure graph recheck (verifyGeneratedFragmentGraph), asserting:
//
//   - cycles are rejected, acyclic graphs are admitted;
//   - duplicate edges, self edges and dep edges referencing keys outside the
//     fragment (including the parent's own key, another running job's key and
//     an existing terminal job's key) are rejected;
//   - a fragment key that collides with an existing run job key is refused
//     whole (storage.GeneratedJobKeyConflictError), because Key is the
//     run-scoped logical node identity;
//   - the depth / per-fragment count / per-run count caps are enforced;
//   - NO mutation may alter the prerequisite set of an existing node: a
//     rejected fragment leaves every pre-existing job (running, queued or
//     terminal) byte-identical, and an admitted fragment adds only NEW queued
//     children whose Needs reference the implicit parent plus new child jobs,
//     never an existing job ID.
//
// All randomness is seeded; failures print the seed.

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const dynPropChildImage = "alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func dynPropChildJob() pipeline.Job {
	return pipeline.Job{Runtime: "container", Image: dynPropChildImage, Steps: []pipeline.Step{{Run: "echo child"}}}
}

func dynPropKeys(n int) []string {
	keys := make([]string, 0, n)
	for i := 0; i < n; i++ {
		keys = append(keys, fmt.Sprintf("c%d", i))
	}
	return keys
}

func dynPropJobs(keys []string) map[string]pipeline.Job {
	jobs := make(map[string]pipeline.Job, len(keys))
	for _, k := range keys {
		jobs[k] = dynPropChildJob()
	}
	return jobs
}

func dynPropFragment(t *testing.T, jobs map[string]pipeline.Job, deps map[string][]string) generatedFragment {
	t.Helper()
	f := generatedFragment{Jobs: jobs, Deps: deps}
	id, err := f.Digest()
	if err != nil {
		t.Fatalf("fragment digest: %v", err)
	}
	f.FragmentID = id
	return f
}

// dynPropHasCycle reports whether the subgraph induced by the fragment's own
// keys contains a cycle (edges to unknown keys and self edges are ignored;
// those are rejected by earlier structural checks).
func dynPropHasCycle(keys []string, deps map[string][]string) bool {
	inFragment := map[string]bool{}
	for _, k := range keys {
		inFragment[k] = true
	}
	color := map[string]int{}
	var visit func(k string) bool
	visit = func(k string) bool {
		switch color[k] {
		case 1:
			return true
		case 2:
			return false
		}
		color[k] = 1
		for _, d := range deps[k] {
			if !inFragment[d] || d == k {
				continue
			}
			if visit(d) {
				return true
			}
		}
		color[k] = 2
		return false
	}
	for _, k := range keys {
		if visit(k) {
			return true
		}
	}
	return false
}

// dynPropJobFingerprint is a deep copy of the fields a fragment admission must
// never touch on an existing job (the prerequisite set above all).
type dynPropJobFingerprint struct {
	Status     model.Status
	Key        string
	Needs      []string
	Holder     string
	Generation int64
	Attempts   int
	Error      string
}

func dynPropSnapshot(s *Server) map[string]dynPropJobFingerprint {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]dynPropJobFingerprint, len(s.jobs))
	for id, j := range s.jobs {
		out[id] = dynPropJobFingerprint{
			Status: j.Status, Key: j.Key, Needs: append([]string(nil), j.Needs...),
			Holder: j.LeaseRunnerID, Generation: j.LeaseGeneration, Attempts: j.Attempts, Error: j.Error,
		}
	}
	return out
}

func dynPropReceipts(s *Server) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.generatedFragments)
}

// TestPropertyDynamicFragmentRandomGraphs pushes deliberately invalid random
// graphs (cycles, self edges, duplicate edges, edges outside the fragment,
// unknown deps keys, references to existing job keys) through the real
// admission path on ONE server: every case is rejected before any insertion,
// so the server state must be byte-identical after each case.
func TestPropertyDynamicFragmentRandomGraphs(t *testing.T) {
	s, task := fcDynamicServer(t)
	parent := fcStoredParent(t, s, task.Job.ID)
	ctx := context.Background()
	for seed := int64(0); seed < 48; seed++ {
		rng := rand.New(rand.NewSource(seed))
		n := 2 + rng.Intn(7) // 2..8
		keys := dynPropKeys(n)
		jobs := dynPropJobs(keys)
		deps := map[string][]string{}
		// Clean forward DAG base: key i may depend on earlier keys.
		for i := 1; i < n; i++ {
			for p := 0; p < i; p++ {
				if rng.Intn(100) < 40 {
					deps[keys[i]] = append(deps[keys[i]], keys[p])
				}
			}
		}
		var wantSub string
		switch seed % 6 {
		case 0: // guaranteed cycle: chain plus a closing backward edge
			deps = map[string][]string{}
			for i := 1; i < n; i++ {
				deps[keys[i]] = []string{keys[i-1]}
			}
			deps[keys[0]] = []string{keys[n-1]}
			if !dynPropHasCycle(keys, deps) {
				t.Fatalf("seed %d: generated graph is not cyclic: %v", seed, deps)
			}
			wantSub = "cycle"
		case 1: // self edge
			k := rng.Intn(n)
			deps[keys[k]] = append(deps[keys[k]], keys[k])
			wantSub = "itself"
		case 2: // duplicate edge
			i := 1 + rng.Intn(n-1)
			p := rng.Intn(i)
			deps[keys[i]] = append(deps[keys[i]], keys[p], keys[p])
			wantSub = "more than once"
		case 3: // edge to a key outside the fragment
			k := rng.Intn(n)
			deps[keys[k]] = append(deps[keys[k]], "ghost-"+keys[k])
			wantSub = "unknown fragment job"
		case 4: // deps entry for a key outside the fragment
			deps["ghost-key"] = nil
			wantSub = "unknown generated job"
		case 5: // edge to the existing parent (running) by key and by id
			k := rng.Intn(n)
			deps[keys[k]] = append(deps[keys[k]], parent.Key, parent.ID)
			wantSub = "unknown fragment job"
		}
		frag := dynPropFragment(t, jobs, deps)
		before := dynPropSnapshot(s)
		receiptsBefore := dynPropReceipts(s)
		_, err := s.processGeneratedFragment(ctx, parent, frag)
		if err == nil {
			t.Fatalf("seed %d: invalid fragment admitted: %+v", seed, frag)
		}
		if !strings.Contains(err.Error(), wantSub) {
			t.Fatalf("seed %d: rejection = %q, want %q", seed, err.Error(), wantSub)
		}
		after := dynPropSnapshot(s)
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("seed %d: rejected fragment mutated existing jobs:\n before=%v\n after=%v", seed, before, after)
		}
		if got := dynPropReceipts(s); got != receiptsBefore {
			t.Fatalf("seed %d: rejected fragment recorded a receipt: %d -> %d", seed, receiptsBefore, got)
		}
	}
}

// TestPropertyDynamicFragmentAcyclicAccepted generates random ACYCLIC
// fragments (strictly forward edges) and proves each is admitted as a whole:
// exactly the declared children appear as NEW queued jobs, every pre-existing
// job is byte-identical (status, prerequisite set, lease fields), and every
// stored dependency edge references only the implicit parent or the new
// children — never an existing job.
func TestPropertyDynamicFragmentAcyclicAccepted(t *testing.T) {
	for seed := int64(0); seed < 8; seed++ {
		rng := rand.New(rand.NewSource(seed))
		s, task := fcDynamicServer(t)
		parent := fcStoredParent(t, s, task.Job.ID)
		n := 2 + rng.Intn(7) // 2..8
		keys := dynPropKeys(n)
		jobs := dynPropJobs(keys)
		deps := map[string][]string{}
		edges := 0
		for i := 1; i < n; i++ {
			for p := 0; p < i; p++ {
				if rng.Intn(100) < 45 {
					deps[keys[i]] = append(deps[keys[i]], keys[p])
					edges++
				}
			}
		}
		if edges == 0 {
			// Force at least one edge so the prerequisite wiring is probed.
			deps[keys[n-1]] = []string{keys[0]}
		}
		if dynPropHasCycle(keys, deps) {
			t.Fatalf("seed %d: forward-edge graph must be acyclic: %v", seed, deps)
		}
		frag := dynPropFragment(t, jobs, deps)
		before := dynPropSnapshot(s)
		res, err := s.processGeneratedFragment(context.Background(), parent, frag)
		if err != nil {
			t.Fatalf("seed %d: acyclic fragment refused: %v", seed, err)
		}
		if res == nil || len(res.JobIDs) != n || len(res.Keys) != n {
			t.Fatalf("seed %d: response = %+v, want %d children", seed, res, n)
		}
		sort.Strings(res.Keys)
		wantKeys := append([]string(nil), keys...)
		sort.Strings(wantKeys)
		if !reflect.DeepEqual(res.Keys, wantKeys) {
			t.Fatalf("seed %d: child keys = %v, want %v", seed, res.Keys, wantKeys)
		}
		after := dynPropSnapshot(s)
		newIDs := map[string]bool{}
		for _, id := range res.JobIDs {
			if _, existed := before[id]; existed {
				t.Fatalf("seed %d: child id %s already existed", seed, id)
			}
			if newIDs[id] {
				t.Fatalf("seed %d: duplicate child id %s", seed, id)
			}
			newIDs[id] = true
		}
		if len(after) != len(before)+n {
			t.Fatalf("seed %d: job count %d -> %d, want +%d", seed, len(before), len(after), n)
		}
		// Every pre-existing job is untouched.
		for id, fp := range before {
			got, ok := after[id]
			if !ok {
				t.Fatalf("seed %d: pre-existing job %s disappeared", seed, id)
			}
			if !reflect.DeepEqual(fp, got) {
				t.Fatalf("seed %d: pre-existing job %s mutated:\n before=%+v\n after =%+v", seed, id, fp, got)
			}
		}
		// Every new child's stored prerequisite set is exactly the implicit
		// parent plus the declared fragment-internal deps (resolved to the
		// NEW child job IDs), and references no existing job.
		keyToID := map[string]string{}
		for i, k := range res.Keys {
			keyToID[k] = res.JobIDs[i]
		}
		s.mu.Lock()
		for i, id := range res.JobIDs {
			j, ok := s.jobs[id]
			if !ok {
				s.mu.Unlock()
				t.Fatalf("seed %d: child %s missing from the store", seed, id)
			}
			if j.RunID != parent.RunID || j.Status != model.StatusQueued || j.DynamicDepth != parent.DynamicDepth+1 {
				s.mu.Unlock()
				t.Fatalf("seed %d: child %s run/status/depth = %s/%s/%d", seed, id, j.RunID, j.Status, j.DynamicDepth)
			}
			wantNeeds := []string{parent.ID}
			for _, dep := range deps[res.Keys[i]] {
				wantNeeds = append(wantNeeds, keyToID[dep])
			}
			if !reflect.DeepEqual(j.Needs, wantNeeds) {
				s.mu.Unlock()
				t.Fatalf("seed %d: child %s needs = %v, want %v", seed, id, j.Needs, wantNeeds)
			}
			for _, dep := range j.Needs {
				if dep == parent.ID {
					continue
				}
				if !newIDs[dep] {
					s.mu.Unlock()
					t.Fatalf("seed %d: child %s depends on non-child job %s (prerequisite set of an existing node reachable)", seed, id, dep)
				}
			}
		}
		s.mu.Unlock()
	}
}

// TestPropertyDynamicFragmentKeyConflicts pins the run-scoped logical identity
// rule with an existing RUNNING job and an existing TERMINAL job: a child key
// colliding with either is refused whole (no rows, no receipt), and a dep edge
// pointing at an existing terminal job's key is refused as an unknown
// fragment job instead of silently resolving to that job.
func TestPropertyDynamicFragmentKeyConflicts(t *testing.T) {
	s, task := fcDynamicServer(t)
	parent := fcStoredParent(t, s, task.Job.ID)
	ctx := context.Background()

	// A terminal job already in the run, owned by the same run identity.
	s.mu.Lock()
	s.jobs["terminal-job"] = model.Job{
		ID: "terminal-job", RunID: parent.RunID, Key: "done-key",
		Status: model.StatusSuccess, Needs: []string{parent.ID},
	}
	s.mu.Unlock()

	snapshot := dynPropSnapshot(s)
	receipts := dynPropReceipts(s)

	// A child whose key collides with the running parent's key.
	parentKeyJobs := map[string]pipeline.Job{parent.Key: dynPropChildJob()}
	fragParentKey := dynPropFragment(t, parentKeyJobs, map[string][]string{})
	before := dynPropSnapshot(s)
	_, err := s.processGeneratedFragment(ctx, parent, fragParentKey)
	var conflict *storage.GeneratedJobKeyConflictError
	if !errors.As(err, &conflict) || conflict.Key != parent.Key {
		t.Fatalf("child key recycling the running parent key = %v, want GeneratedJobKeyConflictError", err)
	}
	if !reflect.DeepEqual(before, dynPropSnapshot(s)) {
		t.Fatal("refused parent-key collision mutated state")
	}

	// A child whose key collides with the existing TERMINAL job's key.
	terminalKeyJobs := map[string]pipeline.Job{"done-key": dynPropChildJob()}
	fragTerminalKey := dynPropFragment(t, terminalKeyJobs, map[string][]string{})
	_, terr := s.processGeneratedFragment(ctx, parent, fragTerminalKey)
	if !errors.As(terr, &conflict) || conflict.Key != "done-key" {
		t.Fatalf("child key recycling a terminal job key = %v, want GeneratedJobKeyConflictError", terr)
	}
	if !reflect.DeepEqual(snapshot, dynPropSnapshot(s)) {
		t.Fatal("refused terminal-key collision mutated state")
	}

	// A dep edge pointing at the existing terminal job's key: refused as an
	// unknown fragment key, never resolved to the existing job.
	edgeJobs := map[string]pipeline.Job{"c0": dynPropChildJob()}
	fragOutsideEdge := dynPropFragment(t, edgeJobs, map[string][]string{"c0": {"done-key"}})
	if _, err := s.processGeneratedFragment(ctx, parent, fragOutsideEdge); err == nil || !strings.Contains(err.Error(), "unknown fragment job") {
		t.Fatalf("edge to the existing terminal job key = %v, want unknown-fragment-job refusal", err)
	}
	if !reflect.DeepEqual(snapshot, dynPropSnapshot(s)) {
		t.Fatal("refused outside edge mutated state")
	}
	if got := dynPropReceipts(s); got != receipts {
		t.Fatalf("refusals recorded receipts: %d -> %d", receipts, got)
	}

	// Control: a valid two-node fragment is still admitted afterwards, and
	// the existing terminal job's prerequisite set is untouched.
	control := dynPropFragment(t, dynPropJobs([]string{"c0", "c1"}), map[string][]string{"c1": {"c0"}})
	res, cerr := s.processGeneratedFragment(ctx, parent, control)
	if cerr != nil {
		t.Fatalf("control fragment refused: %v", cerr)
	}
	if len(res.JobIDs) != 2 {
		t.Fatalf("control fragment created %d children, want 2", len(res.JobIDs))
	}
	after := dynPropSnapshot(s)
	for id, fp := range snapshot {
		if got := after[id]; !reflect.DeepEqual(fp, got) {
			t.Fatalf("accepted control fragment mutated pre-existing job %s:\n before=%+v\n after =%+v", id, fp, got)
		}
	}
	if after["terminal-job"].Key != "done-key" || len(after["terminal-job"].Needs) != 1 {
		t.Fatalf("terminal job prerequisite set changed: %+v", after["terminal-job"])
	}
}

// TestPropertyDynamicFragmentCaps is the depth/count-cap property over the
// pure graph recheck verifyGeneratedFragmentGraph: random child depths, child
// counts and run sizes against random parent generate envelopes. The expected
// decision is re-derived independently (global ceiling tightened by the
// parent's positive declared values; corrupt current-format payloads fail
// closed), so the test is not a mirror of the implementation.
func TestPropertyDynamicFragmentCaps(t *testing.T) {
	jobLimits := []int{0, 1, 2, 3, 5, 16, 127, 128, 1000}
	depthLimits := []int{0, 1, 2, 3, 10}
	for seed := int64(0); seed < 300; seed++ {
		rng := rand.New(rand.NewSource(seed))
		parent := model.Job{ID: "p"}
		kind := rng.Intn(4)
		maxJobs := jobLimits[rng.Intn(len(jobLimits))]
		maxDepth := depthLimits[rng.Intn(len(depthLimits))]
		switch kind {
		case 0: // legacy parent: no payload, global caps only
		case 1: // valid generated envelope
			parent.CompiledJobPayload = &model.CompiledJobPayload{
				SchemaVersion: 1,
				EffectiveJob:  []byte(fmt.Sprintf(`{"generate":{"max_jobs":%d,"max_depth":%d}}`, maxJobs, maxDepth)),
			}
		case 2: // corrupt current-format envelope
			parent.CompiledJobPayload = &model.CompiledJobPayload{
				SchemaVersion: 1,
				EffectiveJob:  []byte(`{"generate":{"max_jobs":"not-a-number"}}`),
			}
		case 3: // current-format payload without an effective job
			parent.CompiledJobPayload = &model.CompiledJobPayload{SchemaVersion: 1}
		}
		fresh := parent
		idMismatch := rng.Intn(10) == 0
		if idMismatch {
			fresh.ID = "other"
		}
		childDepth := rng.Intn(6)
		childCount := rng.Intn(200)
		runJobCount := rng.Intn(5000)
		err := verifyGeneratedFragmentGraph(parent, fresh, childDepth, runJobCount, childCount)
		if kind == 2 || kind == 3 {
			if err == nil {
				t.Fatalf("seed %d: corrupt current-format payload did not fail closed", seed)
			}
			continue
		}
		if idMismatch {
			if err == nil {
				t.Fatalf("seed %d: changed parent identity accepted", seed)
			}
			continue
		}
		jobsLimit := maxGeneratedJobsPerFragment
		if kind == 1 && maxJobs > 0 && maxJobs < jobsLimit {
			jobsLimit = maxJobs
		}
		depthLimit := maxDynamicDepth
		if kind == 1 && maxDepth > 0 && maxDepth < depthLimit {
			depthLimit = maxDepth
		}
		wantErr := childDepth > depthLimit || childCount > jobsLimit || runJobCount+childCount > maxJobsPerRun
		if wantErr && err == nil {
			t.Fatalf("seed %d: parent kind=%d maxJobs=%d maxDepth=%d childDepth=%d childCount=%d runJobs=%d accepted, want refusal",
				seed, kind, maxJobs, maxDepth, childDepth, childCount, runJobCount)
		}
		if !wantErr && err != nil {
			t.Fatalf("seed %d: parent kind=%d maxJobs=%d maxDepth=%d childDepth=%d childCount=%d runJobs=%d refused (%v), want acceptance",
				seed, kind, maxJobs, maxDepth, childDepth, childCount, runJobCount, err)
		}
	}
}
