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
	if _, err := s.enqueue(SubmitRun{
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

// TestDynamicFragmentDifferentIDInserts: a different fragment under the same
// parent and lease generation is a new insert, not a replay.
func TestDynamicFragmentDifferentIDInserts(t *testing.T) {
	f := newDBFakeStore()
	s := trustedGenerateServerDB(t, f)
	runnerID, task := leaseRunJob(t, s)
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", fragmentBody(t, replayFragmentA), leaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated {
		t.Fatalf("first = %d: %s", w.Code, w.Body.String())
	}
	w = doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", fragmentBody(t, replayFragmentB), leaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated {
		t.Fatalf("different fragment = %d, want 201: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	n := 0
	for _, j := range f.jobs {
		if j.RunID == task.Job.RunID && j.ID != task.Job.ID {
			n++
		}
	}
	f.mu.Unlock()
	if n != 2 {
		t.Fatalf("children = %d, want 2 (one per fragment id)", n)
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
			name: "stale generation",
			mutate: parentLeaseMutation(func(j *model.Job) {
				j.LeaseGeneration++
			}),
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

// TestGeneratedFragmentConcurrentCapRaceParity: two concurrent fragments
// whose combined size straddles the run cap race the insertion in both
// modes. Exactly one wins, the other is rejected, and the run never exceeds
// the cap.
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
		// Slack of exactly one fragment: both pre-checks pass, the
		// insertion-time cap check must admit exactly one.
		fragSize := 2
		fillRunTo(t, s, f, task.Job.RunID, maxJobsPerRun-fragSize)
		parent, err := s.jobForLease(context.Background(), task.Job.ID)
		if err != nil {
			t.Fatal(err)
		}
		_ = runnerID
		type outcome struct {
			ok  bool
			err string
		}
		outcomes := make(chan outcome, 2)
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			body := fmt.Sprintf(`{"jobs":{"c%d-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo a"}]},"c%d-b":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo b"}]}},"deps":{}}`, i, i)
			frag := parseFragment(t, body)
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := s.processGeneratedFragment(context.Background(), parent, frag)
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
