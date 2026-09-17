package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// queueTimeoutPipeline declares a job queue timeout so the enqueue
// materializes a QueueDeadline in BOTH storage modes.
const queueTimeoutPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    queue_timeout: 5m
    steps:
      - run: echo hi
`

// TestMemoryQueueTimeoutNeverLeasesAndCancels pins queue-deadline parity for
// the in-memory path: a job whose deadline passed is not leased, and the next
// poll's recovery pass cancels it terminally with the same audit trail the
// DB scheduler emits.
func TestMemoryQueueTimeoutNeverLeasesAndCancels(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, queueTimeoutPipeline)
	// Age the job's queue deadline into the past (the enqueue set it from
	// the 5m timeout).
	s.mu.Lock()
	j := s.jobs[task.Job.ID]
	past := time.Now().UTC().Add(-time.Minute)
	j.QueueDeadline = &past
	// The job must be queued again for the timeout gate; release the lease.
	j.Status = model.StatusQueued
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	s.jobs[task.Job.ID] = j
	ri := s.runners[runnerID]
	ri.ActiveJobs = nil
	ri.Busy = false
	ri.CurrentJob = ""
	s.runners[runnerID] = ri
	s.mu.Unlock()

	// The next poll runs recovery first: the expired job is cancelled and
	// no lease is handed out.
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", ""); w.Code != http.StatusNoContent {
		t.Fatalf("next with expired queue deadline = %d, want 204: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	j = s.jobs[task.Job.ID]
	s.mu.Unlock()
	if j.Status != model.StatusCancelled || j.Error != "queue timeout" {
		t.Fatalf("job after recovery = %s/%q, want cancelled/queue timeout", j.Status, j.Error)
	}
	if j.FinishedAt == nil {
		t.Fatal("timed-out job has no finished_at")
	}
	found := false
	audits, _ := s.store.ReadAudit(0)
	for _, a := range audits {
		if a.Action == "job.queue_timeout" {
			found = true
		}
	}
	if !found {
		t.Fatal("no job.queue_timeout audit event")
	}
}

// TestMemoryQueueTimeoutFreshDeadlineLeases proves the gate is deadline-
// based, not a blanket refusal: a job with a fresh deadline leases normally.
func TestMemoryQueueTimeoutFreshDeadlineLeases(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, queueTimeoutPipeline)
	s.mu.Lock()
	j := s.jobs[task.Job.ID]
	future := time.Now().UTC().Add(time.Hour)
	j.QueueDeadline = &future
	j.Status = model.StatusQueued
	j.LeaseRunnerID = ""
	j.LeaseTokenHash = nil
	j.LeaseExpiresAt = nil
	s.jobs[task.Job.ID] = j
	ri := s.runners[runnerID]
	ri.ActiveJobs = nil
	ri.Busy = false
	ri.CurrentJob = ""
	s.runners[runnerID] = ri
	s.mu.Unlock()
	if w := doJSON(t, s, http.MethodPost, "/api/v1/runners/"+runnerID+"/next", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("next with fresh queue deadline = %d, want 200: %s", w.Code, w.Body.String())
	}
}

// TestArtifactSameNameDifferentGenerationAccepted: the artifact idempotency
// key is (job, lease generation, name). Re-leasing the job and re-uploading
// the same name under the new generation is a NEW record, not a conflict.
func TestArtifactSameNameDifferentGenerationAccepted(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T) (*Server, *dbFakeStore, string, Task)
	}{
		{
			name: "memory",
			run: func(t *testing.T) (*Server, *dbFakeStore, string, Task) {
				s, err := NewPersistent("token", "token", t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
				return s, nil, runnerID, task
			},
		},
		{
			name: "db",
			run: func(t *testing.T) (*Server, *dbFakeStore, string, Task) {
				f := newDBFakeStore()
				s, err := NewPersistent("token", "token", t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				if err := s.SwitchToDB(f); err != nil {
					t.Fatal(err)
				}
				runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
				return s, f, runnerID, task
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, f, runnerID, task := tc.run(t)
			path := "/api/v1/jobs/" + task.Job.ID + "/artifacts/bin"
			if w := doJSONHeaders(t, s, http.MethodPut, path, "token", "generation-one", leaseHeaders(task, runnerID)); w.Code != http.StatusCreated {
				t.Fatalf("gen-1 upload = %d: %s", w.Code, w.Body.String())
			}
			// Bump the live lease generation (as a lost-runner re-lease
			// would) keeping the same runner and token hash.
			bump := func(j model.Job) model.Job {
				j.LeaseGeneration = 2
				return j
			}
			if f != nil {
				f.mu.Lock()
				f.jobs[task.Job.ID] = bump(f.jobs[task.Job.ID])
				f.mu.Unlock()
			} else {
				s.mu.Lock()
				s.jobs[task.Job.ID] = bump(s.jobs[task.Job.ID])
				s.mu.Unlock()
			}
			hdrs := leaseHeaders(task, runnerID)
			hdrs["X-Kiwi-Lease-Generation"] = "2"
			if w := doJSONHeaders(t, s, http.MethodPut, path, "token", "generation-two", hdrs); w.Code != http.StatusCreated {
				t.Fatalf("gen-2 upload = %d, want 201: %s", w.Code, w.Body.String())
			}
			rows := 0
			if f != nil {
				f.mu.Lock()
				rows = len(f.artifacts)
				f.mu.Unlock()
			} else {
				s.mu.Lock()
				rows = len(s.artifacts)
				s.mu.Unlock()
			}
			if rows != 2 {
				t.Fatalf("artifact rows = %d, want 2 (one per generation)", rows)
			}
		})
	}
}

// TestArtifactUploadAfterTerminalRejected: once the job reached a terminal
// state its lease is void, so an upload (even with the previously valid
// headers) is rejected with 409 and records nothing. The rejection is the
// same in memory and DB modes.
func TestArtifactUploadAfterTerminalRejected(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T) (*Server, *dbFakeStore, string, Task)
	}{
		{
			name: "memory",
			run: func(t *testing.T) (*Server, *dbFakeStore, string, Task) {
				s, err := NewPersistent("token", "token", t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
				return s, nil, runnerID, task
			},
		},
		{
			name: "db",
			run: func(t *testing.T) (*Server, *dbFakeStore, string, Task) {
				f := newDBFakeStore()
				s, err := NewPersistent("token", "token", t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				if err := s.SwitchToDB(f); err != nil {
					t.Fatal(err)
				}
				runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
				return s, f, runnerID, task
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, f, runnerID, task := tc.run(t)
			if w := completeTask(t, s, task, runnerID, "failure"); w.Code != http.StatusNoContent {
				t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
			}
			path := "/api/v1/jobs/" + task.Job.ID + "/artifacts/bin"
			if w := doJSONHeaders(t, s, http.MethodPut, path, "token", "late-bytes", leaseHeaders(task, runnerID)); w.Code != http.StatusConflict {
				t.Fatalf("post-terminal upload = %d, want 409: %s", w.Code, w.Body.String())
			}
			rows := 0
			if f != nil {
				f.mu.Lock()
				rows = len(f.artifacts)
				f.mu.Unlock()
			} else {
				s.mu.Lock()
				rows = len(s.artifacts)
				s.mu.Unlock()
			}
			if rows != 0 {
				t.Fatalf("post-terminal upload recorded %d artifact rows", rows)
			}
		})
	}
}

// TestDBFakeRejectedEnqueueLeavesNoPartialState: the DB-mode test store must
// mirror SQL transactionality for a rejected atomic enqueue: no quota
// increment, no consumed downstream claim, no schedule occurrence.
func TestDBFakeRejectedEnqueueLeavesNoPartialState(t *testing.T) {
	ctx := context.Background()
	t.Run("quota rejection rolls back earlier keys and the launch claim", func(t *testing.T) {
		f := newDBFakeStore()
		f.mu.Lock()
		linkKey := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\x00acme/child\x00refs/heads/main"
		f.downstreamLinks[linkKey] = storage.DownstreamLink{ParentJobID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", TargetRepo: "acme/child", TargetRef: "refs/heads/main", LaunchToken: "tok", CreatedAt: time.Now().UTC()}
		f.mu.Unlock()
		req := storage.InsertCompiledRunRequest{
			Run:  model.Run{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", Repo: "https://github.com/o/r.git", Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
			Jobs: map[string]model.Job{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae": {ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae", RunID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", Key: "build", Status: model.StatusQueued, RepoURL: "https://github.com/o/r.git", CreatedAt: time.Now().UTC()}},
			Quota: &storage.QuotaReservation{
				RepoKey: "https://github.com/o/r.git", TeamKey: "github.com/o",
				JobCount: 1, RepoQueueDepth: 10, TeamConcurrency: 1,
			},
			DownstreamLaunch: &storage.DownstreamLaunchClaim{LinkKey: linkKey, StableChildID: fmt.Sprintf("%064d", 7)},
		}
		// Pre-load the team running counter at its limit: the repo key is
		// evaluated first and passes, the team key rejects.
		if err := f.AdjustQuotaCounter(ctx, "github.com/o", "", 1, 0); err != nil {
			t.Fatal(err)
		}
		err := f.InsertCompiledRun(ctx, req)
		var qe *storage.QuotaExceededError
		if !errors.As(err, &qe) || qe.Reason != "TEAM_QUOTA" {
			t.Fatalf("enqueue = %v, want TEAM_QUOTA", err)
		}
		f.mu.Lock()
		link := f.downstreamLinks[linkKey]
		_, runExists := f.runs[req.Run.ID]
		_, jobExists := f.jobs["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae"]
		repoQueued := f.quotas["https://github.com/o/r.git"][1]
		f.mu.Unlock()
		if link.ChildRunID != "" || link.Reserved {
			t.Fatalf("rejected enqueue consumed the launch claim: %+v", link)
		}
		if runExists || jobExists {
			t.Fatalf("rejected enqueue leaked run=%v job=%v", runExists, jobExists)
		}
		if repoQueued != 0 {
			t.Fatalf("repo queued counter = %d, want 0 (no partial increment)", repoQueued)
		}
	})
	t.Run("schedule claim loss rolls back the quota reservation", func(t *testing.T) {
		f := newDBFakeStore()
		ctx := context.Background()
		sch := storage.Schedule{ID: "11111111111111111111111111111111", Repository: "https://github.com/o/r.git", Spec: "@daily", Enabled: true, CreatedAt: time.Now().UTC()}
		if err := f.UpsertSchedule(ctx, sch); err != nil {
			t.Fatal(err)
		}
		nominal := time.Unix(20000, 0).UTC()
		base := func(runID, jobID string) storage.InsertCompiledRunRequest {
			return storage.InsertCompiledRunRequest{
				Run:  model.Run{ID: runID, Repo: "https://github.com/o/r.git", Status: model.StatusQueued, CreatedAt: time.Now().UTC()},
				Jobs: map[string]model.Job{jobID: {ID: jobID, RunID: runID, Key: "build", Status: model.StatusQueued, RepoURL: "https://github.com/o/r.git", CreatedAt: time.Now().UTC()}},
				Quota: &storage.QuotaReservation{
					RepoKey: "https://github.com/o/r.git", JobCount: 1,
				},
				ScheduleClaim: &storage.ScheduleClaim{ScheduleID: sch.ID, Nominal: nominal},
			}
		}
		if err := f.InsertCompiledRun(ctx, base("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae")); err != nil {
			t.Fatal(err)
		}
		err := f.InsertCompiledRun(ctx, base("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaf", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"))
		if !errors.Is(err, storage.ErrScheduleClaimLost) {
			t.Fatalf("replayed occurrence = %v, want ErrScheduleClaimLost", err)
		}
		f.mu.Lock()
		queued := f.quotas["https://github.com/o/r.git"][1]
		f.mu.Unlock()
		if queued != 1 {
			t.Fatalf("queued after lost schedule claim = %d, want 1", queued)
		}
	})
}

// TestCompletionEffectsPartialFailureConvergesExactlyOnce: a failure landing
// BETWEEN effects (downstream and deployment done, usage not yet) must be
// repaired by the next receipt replay without double-applying the effects
// that already committed. This is the crash window the outbox intents cannot
// cover on their own.
func TestCompletionEffectsPartialFailureConvergesExactlyOnce(t *testing.T) {
	f := newDBFakeStore()
	s, runnerID, task := effectsFixture(t, f)
	crashComplete(t, s, task, runnerID)
	injected := errors.New("injected usage-persist failure")
	f.mu.Lock()
	f.updateJobErr = injected
	f.mu.Unlock()

	// First replay: downstream + deployment effects succeed, usage fails.
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusInternalServerError {
		t.Fatalf("partial-effect replay = %d, want 500: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	j := f.jobs[task.Job.ID]
	_, hasLink := f.downstreamLinks[task.Job.ID+"\x00acme/child\x00refs/heads/main"]
	f.mu.Unlock()
	if !hasLink {
		t.Fatal("downstream link not recorded before the failure")
	}
	if d := deploymentOfJob(t, f, task.Job.ID); d.FinishedAt == nil {
		t.Fatal("deployment not finished before the failure")
	}
	if j.UsageRecorded {
		t.Fatal("usage was recorded despite the injected failure")
	}

	// Clear the fault: the next replay converges, applying the remaining
	// effects exactly once and leaving the earlier ones untouched.
	f.mu.Lock()
	f.updateJobErr = nil
	f.mu.Unlock()
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("recovery replay = %d, want 204: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	j = f.jobs[task.Job.ID]
	f.mu.Unlock()
	if !j.UsageRecorded || j.Cost <= 0 {
		t.Fatalf("usage not recorded after recovery: %+v", j)
	}
	cost := s.Metrics.counters["kiwi_usage_cost_total"][""]
	if downstreamIntentsQueued(f) != 1 {
		t.Fatalf("downstream dispatch intents = %d, want 1", downstreamIntentsQueued(f))
	}
	// Another replay changes nothing.
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("stabilizing replay = %d: %s", w.Code, w.Body.String())
	}
	if got := s.Metrics.counters["kiwi_usage_cost_total"][""]; got != cost {
		t.Fatalf("usage cost doubled on replay: %v -> %v", cost, got)
	}
	if downstreamIntentsQueued(f) != 1 {
		t.Fatalf("downstream intents after replay = %d, want 1", downstreamIntentsQueued(f))
	}
}

// TestOutboxDBConcurrentStaleClaimReclaimedOnce: two flushers race the
// reclaim of a claim older than the TTL; exactly one dispatches the item and
// the durable row is acked exactly once.
func TestOutboxDBConcurrentStaleClaimReclaimedOnce(t *testing.T) {
	f := newDBFakeStore()
	if err := f.OutboxAppend(context.Background(), storage.OutboxItem{ID: "stuck", Kind: forge.OutboxKindGitHubCheck, Payload: []byte("{}"), CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.outboxClaims["stuck"] = fakeOutboxClaim{claimer: "crashed-flusher", at: time.Now().UTC().Add(-2 * storage.OutboxClaimTTL)}
	f.mu.Unlock()
	o1 := NewOutbox(nil)
	o1.AttachDB(f)
	o2 := NewOutbox(nil)
	o2.AttachDB(f)
	d := newOutboxDispatcher()
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, o := range []*Outbox{o1, o2} {
		wg.Add(1)
		go func(o *Outbox) {
			defer wg.Done()
			<-start
			if _, err := o.Flush(context.Background(), d.dispatch); err != nil {
				t.Errorf("concurrent stale reclaim: %v", err)
			}
		}(o)
	}
	close(start)
	wg.Wait()
	if got := d.count("stuck"); got != 1 {
		t.Fatalf("stale intent dispatched %d times, want exactly 1", got)
	}
	f.mu.Lock()
	remaining := len(f.outboxItems)
	f.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("durable rows after reclaim = %d, want 0", remaining)
	}
}
