package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// This file pins the round-2 context threading of the RUN enqueue plumbing
// (enqueue/enqueueID/enqueueDB and the inline fs path) and of the audit-first
// admin mutation path:
//
//   (a) a canceled request context aborts a run enqueue before persistence and
//       leaves no ghost run, in fs and DB mode;
//   (b) audit-first fails an admin mutation closed on a canceled context and
//       records nothing that claims the mutation happened;
//   (c) an outbox-driven re-enqueue (maintenance) whose ORIGIN context is
//       canceled still persists through the bounded detach, and the detached
//       context is proven bounded (deadline present);
//   (d) schedule-fired enqueue keeps working with the maintenance context.

// canceledRequest returns an already-canceled request-scoped context, the
// shape a handler sees when the client hung up before the DB work started.
func canceledRequest(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// TestRunEnqueueCanceledRequestLeavesNoGhostRunFS is (a) in fs mode: the
// canceled request must abort enqueue before the snapshot write, restore the
// in-memory maps, and leave nothing durable for a restart to pick up.
func TestRunEnqueueCanceledRequestLeavesNoGhostRunFS(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.enqueue(canceledRequest(t), SubmitRun{
		RepoURL: "https://github.com/acme/backend.git", RepoFullName: "acme/backend",
		Ref: "refs/heads/main", SHA: "sha", Event: "push", Pipeline: smokePipeline,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled enqueue = %v; want context.Canceled", err)
	}
	s.mu.Lock()
	runs, jobs := len(s.runs), len(s.jobs)
	s.mu.Unlock()
	if runs != 0 || jobs != 0 {
		t.Fatalf("canceled enqueue left %d in-memory run(s) and %d job(s); want 0/0", runs, jobs)
	}
	// Durable check: the snapshot a restart would load must not contain a
	// ghost run either.
	snap, err := s.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Runs) != 0 || len(snap.Jobs) != 0 {
		t.Fatalf("canceled enqueue persisted %d run(s) and %d job(s); want 0/0", len(snap.Runs), len(snap.Jobs))
	}
}

// TestRunEnqueueCanceledRequestLeavesNoGhostRunDB is (a) in DB mode: the
// canceled request must never reach InsertCompiledRun, so neither the fake
// store nor the audit table sees a trace of the attempt.
func TestRunEnqueueCanceledRequestLeavesNoGhostRunDB(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	_, err := s.enqueue(canceledRequest(t), SubmitRun{
		RepoURL: "https://github.com/acme/backend.git", RepoFullName: "acme/backend",
		Ref: "refs/heads/main", SHA: "sha", Event: "push", Pipeline: smokePipeline,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled enqueue = %v; want context.Canceled", err)
	}
	f.mu.Lock()
	inserts := len(f.compiledCalls)
	plainInserts := len(f.insertRunCalls)
	audit := len(f.audit)
	f.mu.Unlock()
	if inserts != 0 || plainInserts != 0 {
		t.Fatalf("canceled enqueue reached the store: compiled=%d plain=%d inserts; want 0", inserts, plainInserts)
	}
	if audit != 0 {
		t.Fatalf("canceled enqueue left %d audit row(s); want 0 (audit-first)", audit)
	}
}

// TestAuditFirstCanceledRequestFailsMutationClosed is (b): the admin
// runner-enable mutation with a canceled request context must fail with 503,
// leave the runner flags untouched, and record no audit row that claims the
// enable happened — audit-first fails closed on evidence.
func TestAuditFirstCanceledRequestFailsMutationClosed(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.runners["runner-1"] = model.Runner{ID: "runner-1", Name: "r1", Disabled: true, Draining: true}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/runners/runner-1/enable", nil)
	req.SetPathValue("id", "runner-1")
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	s.runnerEnable(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("canceled admin mutation = %d %q; want 503", w.Code, w.Body.String())
	}
	ri := s.runners["runner-1"]
	if !ri.Disabled || !ri.Draining {
		t.Fatalf("canceled admin mutation changed the runner: %+v; want it untouched", ri)
	}
	events, err := s.store.ReadAudit(100)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action == "runner.enable" {
			t.Fatalf("refused mutation recorded %q claiming success", e.Action)
		}
	}
}

// TestAuditFirstCanceledContextRefusesStoreAppendDB is (b) for the DB funnel:
// auditFirstLocked itself must refuse a canceled context even when the store
// double ignores contexts, so the mutation that follows never becomes
// reachable without evidence.
func TestAuditFirstCanceledContextRefusesStoreAppendDB(t *testing.T) {
	f := newDBFakeStore()
	s := New("token")
	s.DB = f
	err := s.auditFirstLocked(canceledRequest(t), "runner.enable", "api", "", "", "runner enabled", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("auditFirstLocked canceled = %v; want context.Canceled", err)
	}
	f.mu.Lock()
	audit := len(f.audit)
	f.mu.Unlock()
	if audit != 0 {
		t.Fatalf("canceled auditFirstLocked wrote %d row(s); want 0", audit)
	}
}

// reenqueueDeadlineProbe records how the run-enqueue store call of a
// downstream re-enqueue saw its context: a live (uncanceled) context and a
// deadline prove the flush path passed the bounded detach, not the canceled
// maintain origin.
type reenqueueDeadlineProbe struct {
	*dbFakeStore
	mu           sync.Mutex
	childCtxErr  error
	childBounded bool
	calls        int
}

func (p *reenqueueDeadlineProbe) InsertCompiledRun(ctx context.Context, req storage.InsertCompiledRunRequest) error {
	if req.Run.RepoFullName == "acme/child" {
		_, bounded := ctx.Deadline()
		p.mu.Lock()
		p.childCtxErr = ctx.Err()
		p.childBounded = bounded
		p.calls++
		p.mu.Unlock()
	}
	return p.dbFakeStore.InsertCompiledRun(ctx, req)
}

// TestOutboxReenqueueSurvivesCanceledMaintainContext is (c): the outbox
// dispatch of a downstream intent re-enters the run enqueue while the
// maintenance origin is already canceled. flushOutbox must hand the enqueue
// the BOUNDED detach (live ctx, explicit deadline), so the child run is
// persisted instead of being aborted by the dead tick context.
func TestOutboxReenqueueSurvivesCanceledMaintainContext(t *testing.T) {
	f := newDBFakeStore()
	probe := &reenqueueDeadlineProbe{dbFakeStore: f}
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(probe); err != nil {
		t.Fatal(err)
	}
	s.DownstreamAllowlist = map[string][]string{"acme/child": {"o/r"}}
	s.Policy = &policy.Config{Repositories: map[string]policy.RepoPolicy{"o/r": {CrossRepoTrigger: boolPtr(true)}}}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", SHA: "abc", Event: "push",
		Pipeline: downstreamPipeline, Trusted: true,
	}); err != nil {
		t.Fatalf("parent enqueue: %v", err)
	}
	runnerID, task := leaseRunJob(t, s)
	if w := completeTask(t, s, task, runnerID, "success"); w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}
	s.DownstreamPipelineFetcher = func(context.Context, string, string) (string, error) {
		return childPipeline, nil
	}

	// The maintain tick that drives the flush is canceled BEFORE the flush
	// begins: only the bounded detach can keep the re-enqueue alive.
	mctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.flushOutbox(mctx)

	probe.mu.Lock()
	childCtxErr, childBounded, calls := probe.childCtxErr, probe.childBounded, probe.calls
	probe.mu.Unlock()
	if calls != 1 {
		t.Fatalf("downstream re-enqueues through the store = %d; want 1", calls)
	}
	if childCtxErr != nil {
		t.Fatalf("re-enqueue received the canceled maintain context: %v", childCtxErr)
	}
	if !childBounded {
		t.Fatal("re-enqueue context has no deadline; the detach must be bounded")
	}
	f.mu.Lock()
	children := 0
	for _, r := range f.runs {
		if r.RepoFullName == "acme/child" {
			children++
		}
	}
	f.mu.Unlock()
	if children != 1 {
		t.Fatalf("child runs after canceled-origin flush = %d; want exactly 1", children)
	}
}

// TestScheduleFiredEnqueueKeepsWorking is (d): fireSchedule drives the same
// enqueue plumbing with the maintenance context and must keep enqueueing the
// occurrence (with its schedule metadata) exactly as before.
func TestScheduleFiredEnqueueKeepsWorking(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sc := storage.Schedule{
		ID: "sched-ctx", Repository: "acme/app", RepoID: "github.com/acme/app",
		RepoURL: "https://github.com/acme/app.git", Forge: "github", Enabled: true,
		Spec: "version: 1\non:\n  schedule:\n    cron: \"* * * * *\"\njobs:\n  build:\n    runtime: container\n    image: alpine\n    steps:\n      - run: echo hi\n",
	}
	mctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nominal := time.Now().UTC().Truncate(time.Minute)
	run, fired, err := s.fireSchedule(mctx, sc, nominal)
	if err != nil || !fired {
		t.Fatalf("schedule fire = fired %v, err %v; want fired", fired, err)
	}
	if run.Metadata["schedule_id"] != sc.ID {
		t.Fatalf("fired run metadata = %+v; want schedule_id %q", run.Metadata, sc.ID)
	}
	if _, ok := s.runs[run.ID]; !ok {
		t.Fatalf("fired run %s is not in the state", run.ID)
	}
}
