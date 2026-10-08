package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// trustedGenerateServerDB builds a DB-mode server whose policy grants
// generate_child_graph for o/r and enqueues a trusted run of generatePipeline.
func trustedGenerateServerDB(t *testing.T, f *dbFakeStore) *Server {
	t.Helper()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{
		Repositories: map[string]policy.RepoPolicy{
			"o/r": {GenerateChildGraph: boolPtr(true), CrossRepoTrigger: boolPtr(true)},
		},
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: generatePipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	return s
}

const replayFragmentA = `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo a"}]}},"deps":{}}`
const replayFragmentB = `{"jobs":{"child-b":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo b"}]}},"deps":{}}`

// TestDynamicFragmentReplayIdempotent pins HIGH-15: a replayed upload with
// the same (parent, lease generation, fragment_id) returns 200 with the SAME
// children and inserts nothing — the lost-response path never duplicates.
func TestDynamicFragmentReplayIdempotent(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T) (*Server, model.Run, string, Task, func() int)
	}{
		{
			name: "memory",
			run: func(t *testing.T) (*Server, model.Run, string, Task, func() int) {
				s, run := trustedGenerateServer(t)
				runnerID, task := leaseRunJob(t, s)
				count := func() int {
					s.mu.Lock()
					defer s.mu.Unlock()
					n := 0
					for _, j := range s.jobs {
						if j.RunID == run.ID && j.ID != task.Job.ID {
							n++
						}
					}
					return n
				}
				return s, run, runnerID, task, count
			},
		},
		{
			name: "db",
			run: func(t *testing.T) (*Server, model.Run, string, Task, func() int) {
				f := newDBFakeStore()
				s := trustedGenerateServerDB(t, f)
				runnerID, task := leaseRunJob(t, s)
				count := func() int {
					f.mu.Lock()
					defer f.mu.Unlock()
					n := 0
					for _, j := range f.jobs {
						if j.RunID == task.Job.RunID && j.ID != task.Job.ID {
							n++
						}
					}
					return n
				}
				return s, model.Run{ID: task.Job.RunID}, runnerID, task, count
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _, runnerID, task, count := tc.run(t)
			body := fragmentBody(t, replayFragmentA)
			w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", body, leaseHeaders(task, runnerID))
			if w.Code != http.StatusCreated {
				t.Fatalf("first upload = %d: %s", w.Code, w.Body.String())
			}
			var first generatedResponse
			if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
				t.Fatal(err)
			}
			before := count()
			if before != len(first.JobIDs) {
				t.Fatalf("children = %d, response jobs = %d", before, len(first.JobIDs))
			}
			// Replay: 200 + identical children, zero new rows.
			w = doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", body, leaseHeaders(task, runnerID))
			if w.Code != http.StatusOK {
				t.Fatalf("replay = %d, want 200: %s", w.Code, w.Body.String())
			}
			var replay generatedResponse
			if err := json.Unmarshal(w.Body.Bytes(), &replay); err != nil {
				t.Fatal(err)
			}
			if !replay.Replayed {
				t.Fatalf("replay response not marked replayed: %s", w.Body.String())
			}
			if len(replay.JobIDs) != len(first.JobIDs) || len(replay.Keys) != len(first.Keys) {
				t.Fatalf("replay children = %v/%v, want %v/%v", replay.JobIDs, replay.Keys, first.JobIDs, first.Keys)
			}
			for i := range first.JobIDs {
				if replay.JobIDs[i] != first.JobIDs[i] || replay.Keys[i] != first.Keys[i] {
					t.Fatalf("replay children differ: %v vs %v", replay.JobIDs, first.JobIDs)
				}
			}
			if after := count(); after != before {
				t.Fatalf("replay inserted %d extra children (before=%d after=%d)", after-before, before, after)
			}
		})
	}
}

// TestDynamicFragmentDifferentIDConflicts: after one fragment for a parent
// job is committed in its mutation slot, a DIFFERENT fragment digest under
// the same parent is a nondeterministic generator retry: the server answers
// 409 with reason GENERATED_MUTATION_CONFLICT, inserts nothing, and exactly
// the first fragment's child set stays visible. The committed receipt still
// replays.
func TestDynamicFragmentDifferentIDConflicts(t *testing.T) {
	f := newDBFakeStore()
	s := trustedGenerateServerDB(t, f)
	runnerID, task := leaseRunJob(t, s)
	path := "/api/v1/jobs/" + task.Job.ID + "/generated"
	w := doJSONHeaders(t, s, http.MethodPost, path, "token", fragmentBody(t, replayFragmentA), leaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated {
		t.Fatalf("first = %d: %s", w.Code, w.Body.String())
	}
	var first generatedResponse
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	w = doJSONHeaders(t, s, http.MethodPost, path, "token", fragmentBody(t, replayFragmentB), leaseHeaders(task, runnerID))
	if w.Code != http.StatusConflict {
		t.Fatalf("different fragment = %d, want 409: %s", w.Code, w.Body.String())
	}
	var conflict generatedMutationConflictResponse
	if err := json.Unmarshal(w.Body.Bytes(), &conflict); err != nil {
		t.Fatalf("conflict body is not JSON: %v: %s", err, w.Body.String())
	}
	if conflict.Reason != generatedMutationConflictReason || conflict.Message == "" {
		t.Fatalf("conflict body = %+v", conflict)
	}
	for _, id := range first.JobIDs {
		if strings.Contains(w.Body.String(), id) {
			t.Fatalf("conflict response leaked committed child %s: %s", id, w.Body.String())
		}
	}
	f.mu.Lock()
	n := 0
	for _, j := range f.jobs {
		if j.RunID == task.Job.RunID && j.ID != task.Job.ID {
			n++
		}
	}
	f.mu.Unlock()
	if n != 1 {
		t.Fatalf("children = %d, want 1 (exactly the first fragment's child)", n)
	}
	// The committed slot receipt is intact: the original fragment replays.
	w = doJSONHeaders(t, s, http.MethodPost, path, "token", fragmentBody(t, replayFragmentA), leaseHeaders(task, runnerID))
	if w.Code != http.StatusOK {
		t.Fatalf("original replay after conflict = %d, want 200: %s", w.Code, w.Body.String())
	}
	var replay generatedResponse
	if err := json.Unmarshal(w.Body.Bytes(), &replay); err != nil {
		t.Fatal(err)
	}
	if !replay.Replayed || len(replay.JobIDs) != len(first.JobIDs) {
		t.Fatalf("original replay = %+v, first = %+v", replay, first)
	}
}

// TestDynamicFragmentDigestMismatchRejected: a fragment_id that is not the
// digest of the parsed body is rejected with 400 before any admission.
func TestDynamicFragmentDigestMismatchRejected(t *testing.T) {
	s, run := trustedGenerateServer(t)
	runnerID, task := leaseRunJob(t, s)
	body := fragmentBody(t, replayFragmentA)
	tampered := strings.Replace(body, `"fragment_id":"`, `"fragment_id":"00`, 1)
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", tampered, leaseHeaders(task, runnerID))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("digest mismatch = %d, want 400: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "fragment_id") {
		t.Fatalf("rejection should mention fragment_id: %s", w.Body.String())
	}
	// Missing fragment_id is rejected too.
	w = doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", replayFragmentA, leaseHeaders(task, runnerID))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing fragment_id = %d, want 400: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if j.RunID == run.ID && j.ID != task.Job.ID {
			t.Fatalf("rejected fragment inserted child %s", j.Key)
		}
	}
}

// ---------------------------------------------------------------------------
// HIGH-14: memory vs DB-fake insertion-predicate parity
// ---------------------------------------------------------------------------

// fragmentParityCase mutates the stored parent between authorization (the
// snapshot captured right after the lease) and insertion, exactly the window
// the insertion-time predicate closes.
type fragmentParityCase struct {
	name   string
	mutate func(t *testing.T, s *Server, f *dbFakeStore, parent model.Job)
	// want, when non-empty, is a substring BOTH modes' rejection must carry.
	// The stale-generation case pins that the refusal comes from the storage
	// lease predicate (authorization), never from a receipt replay.
	want string
}

func parentLeaseMutation(mut func(j *model.Job)) func(*testing.T, *Server, *dbFakeStore, model.Job) {
	return func(t *testing.T, s *Server, f *dbFakeStore, parent model.Job) {
		apply := func(j model.Job) model.Job {
			mut(&j)
			return j
		}
		if f != nil {
			f.mu.Lock()
			f.jobs[parent.ID] = apply(f.jobs[parent.ID])
			f.mu.Unlock()
			return
		}
		s.mu.Lock()
		s.jobs[parent.ID] = apply(s.jobs[parent.ID])
		s.mu.Unlock()
	}
}

// TestGeneratedFragmentInsertionPredicateParity drives the SAME mutation
// through the memory critical section and the DB-fake transaction and
// requires identical rejection with identical messages: stale generation,
// token mismatch, expired lease, non-running parent and cap exceeded.
func TestGeneratedFragmentInsertionPredicateParity(t *testing.T) {
	cases := []fragmentParityCase{
		{
			// The canonical mutation key is (parent, fragment id): the
			// generation AUTHORIZES but never defines it. A stale generation
			// must be refused by the storage lease predicate even though a
			// generation-free receipt read would match.
			name: "stale generation",
			mutate: parentLeaseMutation(func(j *model.Job) {
				j.LeaseGeneration++
			}),
			want: "generation",
		},
		{
			name: "token mismatch",
			mutate: parentLeaseMutation(func(j *model.Job) {
				j.LeaseTokenHash = []byte("a-different-token-hash")
			}),
		},
		{
			name: "expired lease",
			mutate: parentLeaseMutation(func(j *model.Job) {
				past := j.LeaseExpiresAt.Add(-2 * testLeaseWindow())
				j.LeaseExpiresAt = &past
			}),
		},
		{
			name: "not running",
			mutate: parentLeaseMutation(func(j *model.Job) {
				j.Status = model.StatusSuccess
			}),
		},
		{
			name: "cap exceeded",
			mutate: func(t *testing.T, s *Server, f *dbFakeStore, parent model.Job) {
				fillRunTo(t, s, f, parent.RunID, maxJobsPerRun)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			memMsg := runFragmentParityCase(t, tc, false)
			dbMsg := runFragmentParityCase(t, tc, true)
			if memMsg == "" || dbMsg == "" {
				t.Fatalf("both modes must reject: memory=%q db=%q", memMsg, dbMsg)
			}
			if memMsg != dbMsg {
				t.Fatalf("rejection diverged: memory=%q db=%q", memMsg, dbMsg)
			}
			if tc.want != "" && !strings.Contains(memMsg, tc.want) {
				t.Fatalf("rejection %q does not mention %q", memMsg, tc.want)
			}
		})
	}
}

// runFragmentParityCase authorizes a fragment upload (captures the parent
// snapshot), applies the mutation to the stored parent, then calls
// processGeneratedFragment with the snapshot. It returns the rejection
// message, or "" when the insertion unexpectedly succeeded.
func runFragmentParityCase(t *testing.T, tc fragmentParityCase, db bool) string {
	t.Helper()
	var (
		s        *Server
		f        *dbFakeStore
		runnerID string
		task     Task
	)
	if db {
		f = newDBFakeStore()
		s = trustedGenerateServerDB(t, f)
		runnerID, task = leaseRunJob(t, s)
	} else {
		var run model.Run
		s, run = trustedGenerateServer(t)
		_ = run
		runnerID, task = leaseRunJob(t, s)
	}
	_ = runnerID
	parent, err := s.jobForLease(context.Background(), task.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	tc.mutate(t, s, f, parent)
	frag := parseFragment(t, replayFragmentA)
	if _, err := s.processGeneratedFragment(context.Background(), parent, frag); err != nil {
		return err.Error()
	}
	return ""
}

// testLeaseWindow returns a positive window used to age a lease.
func testLeaseWindow() time.Duration { return time.Minute }

// TestGeneratedFragmentConcurrentCapRaceParity: two concurrent fragments of
// two DIFFERENT parents in the SAME run whose combined size straddles the run
// cap race the insertion in both modes. Distinct parents keep their mutation
// slots independent (same-parent differing digests are refused earlier as
// conflicts), so the per-run cap is the only limiter. Exactly one wins, the
// other is rejected, and the run never exceeds the cap.
func TestGeneratedFragmentConcurrentCapRaceParity(t *testing.T) {
	run := func(t *testing.T, db bool) {
		var (
			s        *Server
			f        *dbFakeStore
			runnerID string
			task     Task
		)
		if db {
			f = newDBFakeStore()
			s = trustedGenerateServerDB(t, f)
			runnerID, task = leaseRunJob(t, s)
		} else {
			s, _ = trustedGenerateServer(t)
			runnerID, task = leaseRunJob(t, s)
		}
		parent, err := s.jobForLease(context.Background(), task.Job.ID)
		if err != nil {
			t.Fatal(err)
		}
		_ = runnerID
		// A second parent job in the SAME run under the same lease identity:
		// its own mutation slot, so both fragments can reach the cap check.
		second, err := newID()
		if err != nil {
			t.Fatal(err)
		}
		parent2 := parent
		parent2.ID = second
		parent2.Key = parent.Key + "-second"
		if f != nil {
			f.mu.Lock()
			f.jobs[parent2.ID] = parent2
			f.mu.Unlock()
		} else {
			s.mu.Lock()
			s.jobs[parent2.ID] = parent2
			s.mu.Unlock()
		}
		// Slack of exactly one fragment: both pre-checks pass, the
		// insertion-time cap check must admit exactly one.
		fragSize := 2
		fillRunTo(t, s, f, task.Job.RunID, maxJobsPerRun-fragSize)
		type outcome struct {
			ok  bool
			err string
		}
		outcomes := make(chan outcome, 2)
		var wg sync.WaitGroup
		parents := []model.Job{parent, parent2}
		for i := 0; i < 2; i++ {
			body := fmt.Sprintf(`{"jobs":{"c%d-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo a"}]},"c%d-b":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo b"}]}},"deps":{}}`, i, i)
			frag := parseFragment(t, body)
			p := parents[i]
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := s.processGeneratedFragment(context.Background(), p, frag)
				outcomes <- outcome{ok: err == nil, err: errString(err)}
			}()
		}
		wg.Wait()
		close(outcomes)
		wins, losses := 0, 0
		for o := range outcomes {
			if o.ok {
				wins++
			} else {
				losses++
				if !strings.Contains(o.err, "limit is") {
					t.Fatalf("unexpected rejection: %s", o.err)
				}
			}
		}
		if wins != 1 || losses != 1 {
			t.Fatalf("concurrent cap race = %d wins/%d losses, want exactly 1/1", wins, losses)
		}
		if got := runJobCount(s, f, task.Job.RunID); got != maxJobsPerRun {
			t.Fatalf("run jobs = %d, want the cap %d", got, maxJobsPerRun)
		}
	}
	t.Run("memory", func(t *testing.T) { run(t, false) })
	t.Run("db", func(t *testing.T) { run(t, true) })
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// fillRunTo pads the run with queued jobs up to want total jobs.
func fillRunTo(t *testing.T, s *Server, f *dbFakeStore, runID string, want int) {
	t.Helper()
	if f != nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		n := 0
		for _, j := range f.jobs {
			if j.RunID == runID {
				n++
			}
		}
		for i := n; i < want; i++ {
			id := fmt.Sprintf("pad%024d", i)
			f.jobs[id] = model.Job{ID: id, RunID: runID, Status: model.StatusQueued}
		}
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, j := range s.jobs {
		if j.RunID == runID {
			n++
		}
	}
	for i := n; i < want; i++ {
		id := fmt.Sprintf("pad%024d", i)
		s.jobs[id] = model.Job{ID: id, RunID: runID, Status: model.StatusQueued}
	}
}

// runJobCount reports how many jobs the run holds in the given mode.
func runJobCount(s *Server, f *dbFakeStore, runID string) int {
	if f != nil {
		f.mu.Lock()
		defer f.mu.Unlock()
		n := 0
		for _, j := range f.jobs {
			if j.RunID == runID {
				n++
			}
		}
		return n
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, j := range s.jobs {
		if j.RunID == runID {
			n++
		}
	}
	return n
}

// parseFragment parses a raw fragment body into the wire type.
func parseFragment(t *testing.T, raw string) generatedFragment {
	t.Helper()
	var frag generatedFragment
	if err := json.Unmarshal([]byte(raw), &frag); err != nil {
		t.Fatalf("parse fragment: %v", err)
	}
	id, err := frag.Digest()
	if err != nil {
		t.Fatalf("fragment digest: %v", err)
	}
	frag.FragmentID = id
	return frag
}

// ---------------------------------------------------------------------------
// P1: infrastructure-retry idempotency under a NEW lease generation
// ---------------------------------------------------------------------------

// retryFragmentABC is a three-child fragment (canonical keys child-a/b/c) used
// to prove an infrastructure retry replays the ORIGINAL child IDs.
const retryFragmentABC = `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo a"}]},"child-b":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo b"}]},"child-c":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo c"}]}},"deps":{}}`

// retryLeaseHeaders presents a lease identity that is not the one contained
// in a Task, so tests can drive a simulated recovery re-lease.
func retryLeaseHeaders(runnerID, token string, generation int64) map[string]string {
	return map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      token,
		"X-Kiwi-Lease-Generation": fmt.Sprint(generation),
	}
}

// rebindParentLeaseForRetry rewrites the stored parent's lease identity to a
// NEW generation with a fresh token, the state an infrastructure retry
// (recovery requeue followed by a new claim) leaves behind. In db mode the
// mutation goes through the fake store map; in memory mode through s.jobs.
func rebindParentLeaseForRetry(t *testing.T, s *Server, f *dbFakeStore, parentID, runnerID, token string, generation int64) {
	t.Helper()
	exp := time.Now().UTC().Add(time.Hour)
	apply := func(j model.Job) model.Job {
		j.Status = model.StatusRunning
		j.LeaseRunnerID = runnerID
		j.LeaseGeneration = generation
		j.LeaseTokenHash = hashLeaseToken(s.leaseKey, token)
		j.LeaseExpiresAt = &exp
		return j
	}
	if f != nil {
		f.mu.Lock()
		j, ok := f.jobs[parentID]
		if !ok {
			f.mu.Unlock()
			t.Fatalf("parent %s missing from the fake store", parentID)
		}
		f.jobs[parentID] = apply(j)
		f.mu.Unlock()
		return
	}
	s.mu.Lock()
	j, ok := s.jobs[parentID]
	if !ok {
		s.mu.Unlock()
		t.Fatalf("parent %s missing from memory", parentID)
	}
	s.jobs[parentID] = apply(j)
	s.mu.Unlock()
}

// generatedFragmentSetup builds the memory and dbFake fixtures for the
// infrastructure-retry tests, returning the server, the fake store (nil in
// memory mode), the runner ID and the leased task.
func generatedFragmentSetup(t *testing.T, db bool) (*Server, *dbFakeStore, string, Task) {
	t.Helper()
	if db {
		f := newDBFakeStore()
		s := trustedGenerateServerDB(t, f)
		runnerID, task := leaseRunJob(t, s)
		return s, f, runnerID, task
	}
	s, _ := trustedGenerateServer(t)
	runnerID, task := leaseRunJob(t, s)
	return s, nil, runnerID, task
}

// TestGeneratedFragmentReplaysAcrossInfrastructureRetry is the P1 regression:
// parent gen1 admits fragment F (children A/B/C); an infrastructure retry
// requeues the same logical parent and claims gen2; re-submitting the
// identical F must replay A/B/C with no new rows and a replayed response,
// and a CHANGED fragment under gen2 is a nondeterministic generator retry:
// 409 with no new children (exactly one child set ever).
func TestGeneratedFragmentReplaysAcrossInfrastructureRetry(t *testing.T) {
	for _, db := range []bool{false, true} {
		name := "memory"
		if db {
			name = "db"
		}
		t.Run(name, func(t *testing.T) {
			s, f, runnerID, task := generatedFragmentSetup(t, db)
			path := "/api/v1/jobs/" + task.Job.ID + "/generated"
			body := fragmentBody(t, retryFragmentABC)
			w := doJSONHeaders(t, s, http.MethodPost, path, "token", body, leaseHeaders(task, runnerID))
			if w.Code != http.StatusCreated {
				t.Fatalf("first upload = %d: %s", w.Code, w.Body.String())
			}
			var first generatedResponse
			if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
				t.Fatal(err)
			}
			if len(first.JobIDs) != 3 || len(first.Keys) != 3 {
				t.Fatalf("first response = %+v, want 3 children", first)
			}
			before := runJobCount(s, f, task.Job.RunID)
			if before != 4 {
				t.Fatalf("run jobs = %d, want parent + 3 children", before)
			}

			// Infrastructure retry: recovery requeued the same logical parent
			// and a new generation was claimed.
			const retryToken = "infra-retry-lease-token"
			retryGen := task.LeaseGeneration + 1
			rebindParentLeaseForRetry(t, s, f, task.Job.ID, runnerID, retryToken, retryGen)
			w = doJSONHeaders(t, s, http.MethodPost, path, "token", body, retryLeaseHeaders(runnerID, retryToken, retryGen))
			if w.Code != http.StatusOK {
				t.Fatalf("retry replay = %d, want 200: %s", w.Code, w.Body.String())
			}
			var replay generatedResponse
			if err := json.Unmarshal(w.Body.Bytes(), &replay); err != nil {
				t.Fatal(err)
			}
			if !replay.Replayed {
				t.Fatalf("retry response not marked replayed: %s", w.Body.String())
			}
			if len(replay.JobIDs) != len(first.JobIDs) {
				t.Fatalf("retry children = %v, want %v", replay.JobIDs, first.JobIDs)
			}
			for i := range first.JobIDs {
				if replay.JobIDs[i] != first.JobIDs[i] || replay.Keys[i] != first.Keys[i] {
					t.Fatalf("retry children differ: %v/%v, want %v/%v", replay.JobIDs, replay.Keys, first.JobIDs, first.Keys)
				}
			}
			if after := runJobCount(s, f, task.Job.RunID); after != before {
				t.Fatalf("retry inserted %d new children (before=%d after=%d)", after-before, before, after)
			}

			// A CHANGED fragment under the new generation is a
			// nondeterministic generator retry for the SAME logical
			// emission: 409 with no new children (much less a second
			// graph). This is the deploy-eu/deploy-us history: gen1 F1
			// commits, gen2 F2 conflicts, exactly one child set remains.
			changedBody := fragmentBody(t, replayFragmentB)
			w = doJSONHeaders(t, s, http.MethodPost, path, "token", changedBody, retryLeaseHeaders(runnerID, retryToken, retryGen))
			if w.Code != http.StatusConflict {
				t.Fatalf("changed fragment = %d, want 409: %s", w.Code, w.Body.String())
			}
			var conflict generatedMutationConflictResponse
			if err := json.Unmarshal(w.Body.Bytes(), &conflict); err != nil {
				t.Fatalf("conflict body is not JSON: %v: %s", err, w.Body.String())
			}
			if conflict.Reason != generatedMutationConflictReason {
				t.Fatalf("conflict reason = %q, want %q", conflict.Reason, generatedMutationConflictReason)
			}
			if after := runJobCount(s, f, task.Job.RunID); after != before {
				t.Fatalf("changed fragment job count = %d, want unchanged %d", after, before)
			}
			// The original receipt still replays after the conflict.
			w = doJSONHeaders(t, s, http.MethodPost, path, "token", body, retryLeaseHeaders(runnerID, retryToken, retryGen))
			if w.Code != http.StatusOK {
				t.Fatalf("replay after conflict = %d, want 200: %s", w.Code, w.Body.String())
			}
		})
	}
}

// TestGeneratedFragmentNondeterministicRetryConflict is the finding-4
// regression in memory mode: a generator retry that emits a DIFFERENT digest
// for the same logical emission (same parent job, same mutation slot, new
// lease generation) is refused with 409 GENERATED_MUTATION_CONFLICT, inserts
// nothing, leaves the first children intact, and keeps the run job count
// unchanged. The PostgreSQL twin lives in
// TestGeneratedFragmentNondeterministicRetryConflict (storage IT).
func TestGeneratedFragmentNondeterministicRetryConflict(t *testing.T) {
	s, _ := trustedGenerateServer(t)
	runnerID, task := leaseRunJob(t, s)
	path := "/api/v1/jobs/" + task.Job.ID + "/generated"
	body := fragmentBody(t, retryFragmentABC)
	w := doJSONHeaders(t, s, http.MethodPost, path, "token", body, leaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated {
		t.Fatalf("first upload = %d: %s", w.Code, w.Body.String())
	}
	var first generatedResponse
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	before := runJobCount(s, nil, task.Job.RunID)

	// Infrastructure retry: the same logical parent is re-leased under a new
	// generation, and the generator re-emits a DIFFERENT fragment.
	const retryToken = "nondeterministic-retry-token"
	retryGen := task.LeaseGeneration + 1
	rebindParentLeaseForRetry(t, s, nil, task.Job.ID, runnerID, retryToken, retryGen)
	w = doJSONHeaders(t, s, http.MethodPost, path, "token", fragmentBody(t, replayFragmentB), retryLeaseHeaders(runnerID, retryToken, retryGen))
	if w.Code != http.StatusConflict {
		t.Fatalf("nondeterministic retry = %d, want 409: %s", w.Code, w.Body.String())
	}
	var conflict generatedMutationConflictResponse
	if err := json.Unmarshal(w.Body.Bytes(), &conflict); err != nil {
		t.Fatalf("conflict body is not JSON: %v: %s", err, w.Body.String())
	}
	if conflict.Reason != generatedMutationConflictReason {
		t.Fatalf("conflict reason = %q, want %q", conflict.Reason, generatedMutationConflictReason)
	}
	for _, id := range first.JobIDs {
		if strings.Contains(w.Body.String(), id) {
			t.Fatalf("conflict response leaked committed child %s: %s", id, w.Body.String())
		}
	}
	if after := runJobCount(s, nil, task.Job.RunID); after != before {
		t.Fatalf("nondeterministic retry changed the job count: %d -> %d", before, after)
	}
	s.mu.Lock()
	for _, id := range first.JobIDs {
		if _, ok := s.jobs[id]; !ok {
			s.mu.Unlock()
			t.Fatalf("first child %s disappeared after the conflict", id)
		}
	}
	s.mu.Unlock()
	// The committed receipt still replays the original children.
	w = doJSONHeaders(t, s, http.MethodPost, path, "token", body, retryLeaseHeaders(runnerID, retryToken, retryGen))
	if w.Code != http.StatusOK {
		t.Fatalf("replay after conflict = %d, want 200: %s", w.Code, w.Body.String())
	}
}

// TestRestoreGeneratedFragmentsSlotConflictKeepsNewest: a pre-0047 fs
// snapshot can carry the nondeterministic-retry history — two receipts for
// one parent under different fragment digests and an empty MutationSlot.
// The restore collapses them deterministically to the newest receipt under
// the default slot, mirroring the database quarantine in migration 0047.
func TestRestoreGeneratedFragmentsSlotConflictKeepsNewest(t *testing.T) {
	s, _ := trustedGenerateServer(t)
	_, task := leaseRunJob(t, s)
	s.mu.Lock()
	parent := s.jobs[task.Job.ID]
	olderChild, err := newID()
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	newerChild, err := newID()
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.jobs[olderChild] = model.Job{ID: olderChild, RunID: parent.RunID, Status: model.StatusQueued}
	s.jobs[newerChild] = model.Job{ID: newerChild, RunID: parent.RunID, Status: model.StatusQueued}
	older := time.Now().UTC().Add(-time.Hour)
	newer := time.Now().UTC()
	s.restoreGeneratedFragmentsLocked(map[string]storage.GeneratedFragmentReceipt{
		// Legacy keys were parent+fragment; the loader recomputes the key.
		parent.ID + ":old": {
			ParentJobID: parent.ID, FragmentID: strings.Repeat("a", 64),
			Children: []storage.GeneratedFragmentChild{{Key: "child", ID: olderChild}}, CreatedAt: older,
		},
		parent.ID + ":new": {
			ParentJobID: parent.ID, FragmentID: strings.Repeat("b", 64),
			Children: []storage.GeneratedFragmentChild{{Key: "child", ID: newerChild}}, CreatedAt: newer,
		},
	})
	rec, ok := s.memoryGeneratedFragment(parent.ID, storage.GeneratedFragmentMutationSlotDefault)
	s.mu.Unlock()
	if !ok {
		t.Fatal("restore dropped the newest receipt")
	}
	if rec.FragmentID != strings.Repeat("b", 64) || len(rec.Children) != 1 || rec.Children[0].ID != newerChild {
		t.Fatalf("restored receipt = %+v, want the newest digest/child", rec)
	}
	if rec.MutationSlot != storage.GeneratedFragmentMutationSlotDefault {
		t.Fatalf("restored receipt slot = %q", rec.MutationSlot)
	}
	if _, ok := s.generatedFragments[generatedFragmentKey(parent.ID, storage.GeneratedFragmentMutationSlotDefault)]; !ok {
		t.Fatal("restored receipt is not keyed by parent+slot")
	}
}

// TestGeneratedFragmentStaleGenerationCannotReplay: after gen2 is leased, a
// request presenting the stale gen1 identity (with its old token) is rejected
// by authorization and NEVER observes the receipt children; the current gen2
// identity then replays the original children.
func TestGeneratedFragmentStaleGenerationCannotReplay(t *testing.T) {
	for _, db := range []bool{false, true} {
		name := "memory"
		if db {
			name = "db"
		}
		t.Run(name, func(t *testing.T) {
			s, f, runnerID, task := generatedFragmentSetup(t, db)
			path := "/api/v1/jobs/" + task.Job.ID + "/generated"
			body := fragmentBody(t, retryFragmentABC)
			w := doJSONHeaders(t, s, http.MethodPost, path, "token", body, leaseHeaders(task, runnerID))
			if w.Code != http.StatusCreated {
				t.Fatalf("first upload = %d: %s", w.Code, w.Body.String())
			}
			var first generatedResponse
			if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
				t.Fatal(err)
			}
			before := runJobCount(s, f, task.Job.RunID)

			const retryToken = "infra-retry-lease-token"
			retryGen := task.LeaseGeneration + 1
			rebindParentLeaseForRetry(t, s, f, task.Job.ID, runnerID, retryToken, retryGen)

			// Stale generation with the OLD token: rejected by the handler's
			// authorizeRunnerLease before processGeneratedFragment runs.
			w = doJSONHeaders(t, s, http.MethodPost, path, "token", body, leaseHeaders(task, runnerID))
			if w.Code != http.StatusConflict {
				t.Fatalf("stale generation upload = %d, want 409: %s", w.Code, w.Body.String())
			}
			for _, id := range first.JobIDs {
				if strings.Contains(w.Body.String(), id) {
					t.Fatalf("stale generation response leaked receipt child %s: %s", id, w.Body.String())
				}
			}
			if after := runJobCount(s, f, task.Job.RunID); after != before {
				t.Fatalf("stale generation inserted %d children", after-before)
			}

			// The current generation replays the original children.
			w = doJSONHeaders(t, s, http.MethodPost, path, "token", body, retryLeaseHeaders(runnerID, retryToken, retryGen))
			if w.Code != http.StatusOK {
				t.Fatalf("current generation replay = %d, want 200: %s", w.Code, w.Body.String())
			}
			var replay generatedResponse
			if err := json.Unmarshal(w.Body.Bytes(), &replay); err != nil {
				t.Fatal(err)
			}
			if !replay.Replayed || len(replay.JobIDs) != len(first.JobIDs) {
				t.Fatalf("current generation replay = %+v, want the original %v", replay, first.JobIDs)
			}
			for i := range first.JobIDs {
				if replay.JobIDs[i] != first.JobIDs[i] {
					t.Fatalf("current generation children = %v, want %v", replay.JobIDs, first.JobIDs)
				}
			}
		})
	}
}

// TestGeneratedFragmentReplaysAcrossFSRestart: the generated-fragment receipt
// is part of the same fs snapshot as its children, so after a restart a
// resubmitted identical fragment under a NEW generation replays the ORIGINAL
// child IDs instead of re-admitting a duplicate graph.
func TestGeneratedFragmentReplaysAcrossFSRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{
		Repositories: map[string]policy.RepoPolicy{
			"o/r": {GenerateChildGraph: boolPtr(true), CrossRepoTrigger: boolPtr(true)},
		},
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: generatePipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	runnerID, task := leaseRunJob(t, s)
	path := "/api/v1/jobs/" + task.Job.ID + "/generated"
	body := fragmentBody(t, retryFragmentABC)
	w := doJSONHeaders(t, s, http.MethodPost, path, "token", body, leaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated {
		t.Fatalf("first upload = %d: %s", w.Code, w.Body.String())
	}
	var first generatedResponse
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}

	// Restart from the same directory WITHOUT re-submitting: the receipt and
	// its children are restored from the one atomic snapshot.
	s2 := fsMatrixReload(t, dir)

	// New generation: rewrite the restored parent's lease and make it durable.
	const retryToken = "restart-retry-lease-token"
	retryGen := task.LeaseGeneration + 1
	rebindParentLeaseForRetry(t, s2, nil, task.Job.ID, runnerID, retryToken, retryGen)
	s2.mu.Lock()
	perr := s2.persistCheckedErrLocked("test.generated_retry")
	s2.mu.Unlock()
	if perr != nil {
		t.Fatalf("persist retry lease: %v", perr)
	}

	w = doJSONHeaders(t, s2, http.MethodPost, path, "token", body, retryLeaseHeaders(runnerID, retryToken, retryGen))
	if w.Code != http.StatusOK {
		t.Fatalf("post-restart resubmit = %d, want 200: %s", w.Code, w.Body.String())
	}
	var replay generatedResponse
	if err := json.Unmarshal(w.Body.Bytes(), &replay); err != nil {
		t.Fatal(err)
	}
	if !replay.Replayed {
		t.Fatalf("post-restart resubmit not marked replayed: %s", w.Body.String())
	}
	if len(replay.JobIDs) != len(first.JobIDs) {
		t.Fatalf("post-restart children = %v, want the original %v", replay.JobIDs, first.JobIDs)
	}
	for i := range first.JobIDs {
		if replay.JobIDs[i] != first.JobIDs[i] || replay.Keys[i] != first.Keys[i] {
			t.Fatalf("post-restart children differ: %v/%v, want %v/%v", replay.JobIDs, replay.Keys, first.JobIDs, first.Keys)
		}
	}
	s2.mu.Lock()
	children := 0
	for _, j := range s2.jobs {
		if j.RunID == task.Job.RunID && j.DynamicDepth == 1 {
			children++
		}
	}
	s2.mu.Unlock()
	if children != 3 {
		t.Fatalf("post-restart dynamic children = %d, want exactly the original 3", children)
	}
}
