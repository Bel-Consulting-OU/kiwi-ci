package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// Run-scoped logical job identity (finding 7): model.Job.Key is the run's
// logical node identity (matrix/shard suffix included) and must be unique per
// run, while BaseKey intentionally repeats across matrix variants. A generated
// fragment declaring a key that already identifies a job in the run is
// refused whole with 409 GENERATED_JOB_KEY_CONFLICT — in memory mode, in the
// server's fs-backed map, and in DB mode (PostgresStore and the dbFakeStore
// mirror alike). These are the server-side tests; the real-PostgreSQL
// admission and index tests live in internal/storage.

// keyConflictSiblingID and keyConflictCloneID are canonical 32-hex job ids
// for the injected existing job and the cloned second parent.
const (
	keyConflictSiblingID = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"
	keyConflictCloneID   = "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2"
)

// fcPackageFragment declares one child keyed "package", distinct from every
// matrix key in these tests.
const fcPackageFragment = `{"jobs":{"package":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo package"}]}},"deps":{}}`

// keyConflictInjectJob builds the compiled sibling a fragment key may collide
// with: queued, same run, and carrying its Key as BaseKey like a matrix
// variant would.
func keyConflictInjectJob(runID, id, key string) model.Job {
	return model.Job{
		ID: id, RunID: runID, Key: key, BaseKey: key,
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Status: model.StatusQueued, CreatedAt: time.Now().UTC(),
	}
}

// keyConflictFixture is one storage mode of the collision tests: the server,
// the run under test, the leased parent task, an injection hook for existing
// run jobs, and counters for generated children and fragment receipts.
type keyConflictFixture struct {
	server      *Server
	runID       string
	task        Task
	runnerID    string
	inject      func(model.Job)
	countKids   func() int
	countFrags  func() int
	storedParnt func(t *testing.T) model.Job
}

func keyConflictFixtures(t *testing.T) map[string]keyConflictFixture {
	t.Helper()
	memory := func() keyConflictFixture {
		s, run := trustedGenerateServer(t)
		runnerID, task := leaseRunJob(t, s)
		return keyConflictFixture{
			server:   s,
			runID:    run.ID,
			task:     task,
			runnerID: runnerID,
			inject: func(j model.Job) {
				s.mu.Lock()
				s.jobs[j.ID] = j
				s.mu.Unlock()
			},
			countKids: func() int {
				s.mu.Lock()
				defer s.mu.Unlock()
				n := 0
				for _, j := range s.jobs {
					if j.RunID == run.ID && j.DynamicDepth > 0 {
						n++
					}
				}
				return n
			},
			countFrags: func() int {
				s.mu.Lock()
				defer s.mu.Unlock()
				return len(s.generatedFragments)
			},
			storedParnt: func(t *testing.T) model.Job { return fcStoredParent(t, s, task.Job.ID) },
		}
	}
	dbFake := func() keyConflictFixture {
		f := newDBFakeStore()
		s := trustedGenerateServerDB(t, f)
		runnerID, task := leaseRunJob(t, s)
		return keyConflictFixture{
			server:   s,
			runID:    task.Job.RunID,
			task:     task,
			runnerID: runnerID,
			inject: func(j model.Job) {
				f.mu.Lock()
				f.jobs[j.ID] = j
				f.mu.Unlock()
			},
			countKids: func() int {
				f.mu.Lock()
				defer f.mu.Unlock()
				n := 0
				for _, j := range f.jobs {
					if j.RunID == task.Job.RunID && j.DynamicDepth > 0 {
						n++
					}
				}
				return n
			},
			countFrags: func() int {
				f.mu.Lock()
				defer f.mu.Unlock()
				return len(f.fragments)
			},
			storedParnt: func(t *testing.T) model.Job { return fcStoredParentDB(t, f, task.Job.ID) },
		}
	}
	return map[string]keyConflictFixture{"memory": memory(), "dbFake": dbFake()}
}

// TestGeneratedFragmentChildKeyCollidesWithExistingRunJob: a fragment
// declaring a key equal to an existing compiled job key is rejected 409 with
// reason GENERATED_JOB_KEY_CONFLICT and no new rows — the run-scoped logical
// identity is already taken, and the existing job keeps its key.
func TestGeneratedFragmentChildKeyCollidesWithExistingRunJob(t *testing.T) {
	for name, fx := range keyConflictFixtures(t) {
		t.Run(name, func(t *testing.T) {
			fx.inject(keyConflictInjectJob(fx.runID, keyConflictSiblingID, "child-a"))
			w := doJSONHeaders(t, fx.server, http.MethodPost, "/api/v1/jobs/"+fx.task.Job.ID+"/generated", "token",
				fragmentBody(t, fcOneChildFragment), leaseHeaders(fx.task, fx.runnerID))
			if w.Code != http.StatusConflict {
				t.Fatalf("colliding fragment = %d, want 409: %s", w.Code, w.Body.String())
			}
			var body generatedJobKeyConflictResponse
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("conflict body: %v (%s)", err, w.Body.String())
			}
			if body.Reason != generatedJobKeyConflictReason {
				t.Fatalf("conflict reason = %q, want %q", body.Reason, generatedJobKeyConflictReason)
			}
			if kids := fx.countKids(); kids != 0 {
				t.Fatalf("generated children after rejection = %d, want 0 (no partial insert)", kids)
			}
			if frags := fx.countFrags(); frags != 0 {
				t.Fatalf("fragment receipts after rejection = %d, want 0", frags)
			}
			// The existing job still owns the key: a different fragment key
			// is admitted normally on the same run (through a second parent,
			// because the first parent's mutation slot is now untouched).
			clone := fx.storedParnt(t)
			if clone.LeaseTokenHash == nil {
				t.Fatal("stored parent carries no lease token hash")
			}
			clone.ID = keyConflictCloneID
			fx.inject(clone)
			w = doJSONHeaders(t, fx.server, http.MethodPost, "/api/v1/jobs/"+keyConflictCloneID+"/generated", "token",
				fragmentBody(t, fcPackageFragment), leaseHeaders(fx.task, fx.runnerID))
			if w.Code != http.StatusCreated {
				t.Fatalf("non-colliding fragment on the dirty run = %d, want 201: %s", w.Code, w.Body.String())
			}
			if kids := fx.countKids(); kids != 1 {
				t.Fatalf("generated children after admission = %d, want 1", kids)
			}
		})
	}
}

// TestGeneratedFragmentChildKeyCollidesAcrossFragments: two different parents
// of one run emitting the same child key — the second fragment is rejected.
func TestGeneratedFragmentChildKeyCollidesAcrossFragments(t *testing.T) {
	for name, fx := range keyConflictFixtures(t) {
		t.Run(name, func(t *testing.T) {
			w := doJSONHeaders(t, fx.server, http.MethodPost, "/api/v1/jobs/"+fx.task.Job.ID+"/generated", "token",
				fragmentBody(t, fcOneChildFragment), leaseHeaders(fx.task, fx.runnerID))
			if w.Code != http.StatusCreated {
				t.Fatalf("first fragment = %d, want 201: %s", w.Code, w.Body.String())
			}
			var first generatedResponse
			if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil || len(first.JobIDs) != 1 {
				t.Fatalf("first response = %s, err=%v", w.Body.String(), err)
			}
			clone := fx.storedParnt(t)
			clone.ID = keyConflictCloneID
			fx.inject(clone)
			w = doJSONHeaders(t, fx.server, http.MethodPost, "/api/v1/jobs/"+keyConflictCloneID+"/generated", "token",
				fragmentBody(t, fcOneChildFragment), leaseHeaders(fx.task, fx.runnerID))
			if w.Code != http.StatusConflict {
				t.Fatalf("second parent same child key = %d, want 409: %s", w.Code, w.Body.String())
			}
			var body generatedJobKeyConflictResponse
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Reason != generatedJobKeyConflictReason {
				t.Fatalf("conflict body = %s, err=%v", w.Body.String(), err)
			}
			if kids := fx.countKids(); kids != 1 {
				t.Fatalf("generated children after rejection = %d, want the original 1", kids)
			}
			// The originally created child is still the run's owner of the key.
			got, ok, err := fx.server.jobInRun(context.Background(), fx.runID, "child-a")
			if err != nil || !ok || got.ID != first.JobIDs[0] {
				t.Fatalf("jobInRun(child-a) = %+v ok=%v err=%v, want the first child %s", got, ok, err, first.JobIDs[0])
			}
		})
	}
}

// TestGeneratedFragmentMatrixKeysStayDistinct: matrix variants live as
// build[os=linux]/build[os=mac] in one run (same BaseKey "build") and a
// generated child keyed differently is admitted. Key lookups resolve the
// addressed variant. (A fragment key can never carry the bracket suffix —
// fragment keys are declared keys and pipeline.Validate rejects the
// brackets — so the matrix-key collision itself is exercised at the storage
// layer, where the run/jobs come from the compiler.)
func TestGeneratedFragmentMatrixKeysStayDistinct(t *testing.T) {
	for name, fx := range keyConflictFixtures(t) {
		t.Run(name, func(t *testing.T) {
			linux := keyConflictInjectJob(fx.runID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01", "build[os=linux]")
			linux.BaseKey = "build"
			mac := keyConflictInjectJob(fx.runID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02", "build[os=mac]")
			mac.BaseKey = "build"
			fx.inject(linux)
			fx.inject(mac)

			got, ok, err := fx.server.jobInRun(context.Background(), fx.runID, "build[os=mac]")
			if err != nil || !ok || got.ID != mac.ID || got.Key != "build[os=mac]" {
				t.Fatalf("jobInRun(build[os=mac]) = %+v ok=%v err=%v, want job %s", got, ok, err, mac.ID)
			}

			w := doJSONHeaders(t, fx.server, http.MethodPost, "/api/v1/jobs/"+fx.task.Job.ID+"/generated", "token",
				fragmentBody(t, fcPackageFragment), leaseHeaders(fx.task, fx.runnerID))
			if w.Code != http.StatusCreated {
				t.Fatalf("non-matrix child = %d, want 201: %s", w.Code, w.Body.String())
			}
			if kids := fx.countKids(); kids != 1 {
				t.Fatalf("generated children = %d, want 1", kids)
			}
		})
	}
}
