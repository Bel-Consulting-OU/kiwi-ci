package server

// Direct branch coverage for small package-private helpers and option
// plumbing: option application, the fresh-slice removeString contract, the
// runner protocol registry, the panic recoverer, state capture/rollback
// cloning, the usage window rebuild, the completion-receipt render cache, the
// schema-compatibility read path, runner incarnation compatibility and the
// resource-reconcile no-op gates.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

type floorOverrideStore struct {
	*dbFakeStore
	floor int
	err   error
}

func (f *floorOverrideStore) SchemaCompatibilityFloor(context.Context) (int, error) {
	return f.floor, f.err
}

func TestPersistentOptionsApply(t *testing.T) {
	s := New("secret")
	WithMaxSchedules(7)(s)
	if s.MaxSchedules != 7 {
		t.Fatalf("MaxSchedules = %d, want 7", s.MaxSchedules)
	}
	WithRunRetention(time.Hour, 3)(s)
	if s.RunRetention != time.Hour || s.MaxRetainedRuns != 3 {
		t.Fatalf("retention option = (%v, %d)", s.RunRetention, s.MaxRetainedRuns)
	}
	if o := mustNewOutbox(storage.New(t.TempDir())); o == nil {
		t.Fatal("mustNewOutbox returned nil")
	}
	if o := mustNewOutbox(nil); o == nil {
		t.Fatal("mustNewOutbox(nil) returned nil")
	}
}

func TestRemoveStringAlwaysAllocates(t *testing.T) {
	if got := removeString(nil, "x"); got != nil {
		t.Fatalf("removeString(nil) = %v, want nil", got)
	}
	in := []string{"a", "b", "c"}
	backup := append([]string(nil), in...)
	got := removeString(in, "b")
	if len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Fatalf("removeString = %v", got)
	}
	for i := range backup {
		if in[i] != backup[i] {
			t.Fatalf("removeString mutated its input: %v", in)
		}
	}
	if got := removeString([]string{"a"}, "missing"); len(got) != 1 || got[0] != "a" {
		t.Fatalf("removeString(no match) = %v", got)
	}
}

func TestRunnerProtocolRegistryClampAndCount(t *testing.T) {
	s := New("secret")
	s.setRunnerProtocol("runner-1", maxRunnerProtocol+50)
	info, ok := s.runnerProtocol("runner-1")
	if !ok || info.proto != maxRunnerProtocol || info.registrations != 1 {
		t.Fatalf("protocol info = %+v (ok=%v)", info, ok)
	}
	s.setRunnerProtocol("runner-1", 3)
	if info, _ := s.runnerProtocol("runner-1"); info.registrations != 2 {
		t.Fatalf("registrations = %d, want 2", info.registrations)
	}
}

func TestRecovererWithPanicAndAbort(t *testing.T) {
	t.Run("panic renders 500 and reports", func(t *testing.T) {
		var gotMethod, gotPath string
		var gotPanic any
		h := recovererWith(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }),
			func(id, method, path string, x any, stack string) {
				gotMethod, gotPath, gotPanic = method, path, x
				if stack == "" {
					t.Error("panic handler received an empty stack")
				}
			})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", w.Code)
		}
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["error"] == "" {
			t.Fatalf("panic body = %q (%v)", w.Body.String(), err)
		}
		if gotPanic != "boom" || gotMethod != http.MethodGet || gotPath != "/api/v1/runs" {
			t.Fatalf("reported panic = (%v, %s, %s)", gotPanic, gotMethod, gotPath)
		}
	})

	t.Run("abort handler is re-raised untouched", func(t *testing.T) {
		called := false
		h := recovererWith(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }),
			func(string, string, string, any, string) { called = true })
		func() {
			defer func() {
				if x := recover(); x != http.ErrAbortHandler {
					t.Errorf("recovered %v, want http.ErrAbortHandler", x)
				}
			}()
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/download", nil))
		}()
		if called {
			t.Fatal("abort sentinel was reported as a panic")
		}
	})
}

func TestCaptureStateRollbackClones(t *testing.T) {
	s := New("secret")
	exp := time.Now().UTC().Add(time.Hour)
	s.runs["run-1"] = model.Run{ID: "run-1", Status: model.StatusRunning}
	s.jobs["job-1"] = model.Job{ID: "job-1", RunID: "run-1"}
	s.runners["runner-1"] = model.Runner{ID: "runner-1", ActiveJobs: []string{"job-1"}}
	rb := s.captureStateRollbackLocked()
	// Mutating the live state must not touch the capture.
	s.runs["run-1"] = model.Run{ID: "run-1", Status: model.StatusCancelled}
	delete(s.jobs, "job-1")
	r := s.runners["runner-1"]
	r.ActiveJobs[0] = "mutated"
	s.runners["runner-1"] = r
	if rb.runs["run-1"].Status != model.StatusRunning {
		t.Fatalf("captured run mutated: %+v", rb.runs["run-1"])
	}
	if _, ok := rb.jobs["job-1"]; !ok {
		t.Fatal("captured job lost")
	}
	if rb.runners["runner-1"].ActiveJobs[0] != "job-1" {
		t.Fatalf("captured runner aliases the live slice: %v", rb.runners["runner-1"].ActiveJobs)
	}
	_ = exp
}

func TestRollbackLeaseLockedDeletesAbsentEntries(t *testing.T) {
	s := New("secret")
	s.runs["run-1"] = model.Run{ID: "run-1"}
	s.runners["runner-1"] = model.Runner{ID: "runner-1"}
	s.deployments["job-1"] = model.Deployment{ID: "job-1"}
	s.rollbackLeaseLocked(leaseRollback{
		jobID: "job-1", job: model.Job{ID: "job-1"},
		runID: "run-1", hadRun: false,
		runnerID: "runner-1", hadRunner: false,
		deployment: model.Deployment{ID: "job-1"}, hadDeployment: false,
	})
	if _, ok := s.runs["run-1"]; ok {
		t.Fatal("run not deleted by rollback")
	}
	if _, ok := s.runners["runner-1"]; ok {
		t.Fatal("runner not deleted by rollback")
	}
	if _, ok := s.deployments["job-1"]; ok {
		t.Fatal("deployment not deleted by rollback")
	}
	if j, ok := s.jobs["job-1"]; !ok || j.ID != "job-1" {
		t.Fatal("job not restored by rollback")
	}
	// The had* branches restore the captured values.
	s.runs["run-1"] = model.Run{ID: "run-1"}
	s.rollbackLeaseLocked(leaseRollback{jobID: "job-1", job: model.Job{ID: "job-1"}, runID: "run-1", run: model.Run{ID: "run-1", Status: model.StatusFailure}, hadRun: true})
	if got := s.runs["run-1"]; got.Status != model.StatusFailure {
		t.Fatalf("run not restored: %+v", got)
	}
}

func TestRebuildUsageWindowFiltersAndOrders(t *testing.T) {
	s := New("secret")
	recent := time.Now().UTC().Add(-time.Hour)
	older := time.Now().UTC().Add(-25 * time.Hour)
	jobs := map[string]model.Job{
		"b":          {ID: "b", UsageRecorded: true, FinishedAt: &recent, Cost: 2},
		"a":          {ID: "a", UsageRecorded: true, FinishedAt: &recent, Cost: 1},
		"old":        {ID: "old", UsageRecorded: true, FinishedAt: &older},
		"unrecorded": {ID: "unrecorded", FinishedAt: &recent},
		"nil-finish": {ID: "nil-finish", UsageRecorded: true},
	}
	s.rebuildUsageWindow(jobs)
	s.usageMu.Lock()
	got := append([]usageEntry(nil), s.usage...)
	s.usageMu.Unlock()
	if len(got) != 2 {
		t.Fatalf("usage window = %+v, want exactly the two recent recorded jobs", got)
	}
	if got[0].Cost != 1 || got[1].Cost != 2 {
		t.Fatalf("usage order = %+v, want tie broken by job id", got)
	}
	// An empty source replaces the window with an empty one.
	s.rebuildUsageWindow(map[string]model.Job{})
	s.usageMu.Lock()
	n := len(s.usage)
	s.usageMu.Unlock()
	if n != 0 {
		t.Fatalf("pruned window = %d entries, want 0", n)
	}
}

func TestCompletionReceiptRecordsCacheLifecycle(t *testing.T) {
	s := New("secret")
	s.mu.Lock()
	if got := s.completionReceiptRecordsLocked(); got != nil {
		t.Fatalf("empty receipt table = %v, want nil", got)
	}
	rec := model.CompletionReceipt{JobID: "job-1", Generation: 1, RunnerID: "runner-1"}
	s.completions["k1"] = rec
	s.completionReceiptAt["k1"] = time.Now().UTC()
	s.mu.Unlock()

	s.mu.Lock()
	first := s.completionReceiptRecordsLocked()
	if len(first) != 1 || first[0].Receipt.JobID != "job-1" || first[0].CreatedAt.IsZero() {
		t.Fatalf("rendered records = %+v", first)
	}
	// A second read with an unchanged version takes the cache path.
	second := s.completionReceiptRecordsLocked()
	if len(second) != 1 || second[0].Receipt.JobID != "job-1" {
		t.Fatalf("cached records = %+v", second)
	}
	// Expire the cache by pushing its expiry into the past: the render must
	// recompute instead of serving stale entries.
	s.completionReceiptsCacheExpiry = time.Now().UTC().Add(-time.Minute)
	third := s.completionReceiptRecordsLocked()
	if len(third) != 1 {
		t.Fatalf("recomputed records = %+v", third)
	}
	// An entry with no timestamp falls back to the finished job, and an
	// already-aged entry is pruned from the table.
	s.completions["k2"] = model.CompletionReceipt{JobID: "job-2", Generation: 2, RunnerID: "runner-1"}
	stale := time.Now().UTC().Add(-storage.CompletionReceiptTTL - time.Hour)
	s.completionReceiptAt["k2"] = stale
	timestamped := model.CompletionReceipt{JobID: "job-3", Generation: 3, RunnerID: "runner-1"}
	s.completions["k3"] = timestamped
	s.completionReceiptAt["k3"] = time.Now().UTC()
	s.jobs["job-2"] = model.Job{ID: "job-2", FinishedAt: &stale}
	s.markCompletionReceiptsChangedLocked()
	fourth := s.completionReceiptRecordsLocked()
	for _, r := range fourth {
		if r.Receipt.JobID == "job-2" {
			t.Fatalf("expired receipt survived the render: %+v", fourth)
		}
	}
	if _, ok := s.completions["k2"]; ok {
		t.Fatal("expired receipt not pruned from the table")
	}
	s.mu.Unlock()
}

func TestCheckSchemaCompatibilityReadPath(t *testing.T) {
	ctx := context.Background()
	s := New("secret")
	if err := s.checkSchemaCompatibility(ctx); err != nil {
		t.Fatalf("memory server = %v, want nil", err)
	}

	// A cached bad verdict refuses without a new store read.
	f := &floorOverrideStore{dbFakeStore: newDBFakeStore(), floor: 9999}
	s.DB = f
	s.mu.Lock()
	s.schemaFloorBad = true
	s.schemaFloorCheck = time.Now()
	s.schemaFloor = 9999
	s.mu.Unlock()
	if err := s.checkSchemaCompatibility(ctx); err == nil {
		t.Fatal("cached incompatible floor admitted")
	}

	// A stale cache re-reads the store: a compatible floor clears the flag.
	s.mu.Lock()
	s.schemaFloorCheck = time.Now().Add(-2 * time.Minute)
	s.mu.Unlock()
	f.floor = 0
	if err := s.checkSchemaCompatibility(ctx); err != nil {
		t.Fatalf("compatible floor = %v, want nil", err)
	}
	s.mu.Lock()
	bad := s.schemaFloorBad
	s.mu.Unlock()
	if bad {
		t.Fatal("compatible read kept the incompatible flag")
	}

	// An incompatible floor still fails after a fresh read.
	f.floor = 9999
	s.mu.Lock()
	s.schemaFloorCheck = time.Now().Add(-2 * time.Minute)
	s.mu.Unlock()
	if err := s.checkSchemaCompatibility(ctx); err == nil {
		t.Fatal("incompatible floor admitted")
	}
}

func TestRunnerIncarnationCompatibility(t *testing.T) {
	ctx := context.Background()
	s := New("secret")

	// Headerless legacy sessions keep the rolling-upgrade tolerance.
	if !s.runnerIncarnationCurrent(ctx, "unknown", "") {
		t.Fatal("unknown runner with no incarnation must be tolerated in dev mode")
	}
	s.setRunnerProtocol("legacy", 2)
	if !s.runnerIncarnationCurrent(ctx, "legacy", "") {
		t.Fatal("protocol-2 session must be tolerated")
	}
	s.setRunnerProtocol("modern", 3)
	if !s.runnerIncarnationCurrent(ctx, "modern", "") {
		t.Fatal("first modern registration must be tolerated")
	}
	s.setRunnerProtocol("modern", 3)
	if s.runnerIncarnationCurrent(ctx, "modern", "") {
		t.Fatal("superseded modern session admitted headerless")
	}
	s.RequireRunnerIncarnation = true
	if s.runnerIncarnationCurrent(ctx, "unknown", "") {
		t.Fatal("production mode admitted a headerless request")
	}
	s.RequireRunnerIncarnation = false

	// Non-empty incarnation against memory state.
	if s.runnerIncarnationCurrent(ctx, "missing-runner", "inc") {
		t.Fatal("unknown memory runner admitted with an incarnation")
	}
	s.mu.Lock()
	s.runners["r1"] = model.Runner{ID: "r1"}
	s.mu.Unlock()
	if !s.runnerIncarnationCurrent(ctx, "r1", "any") {
		t.Fatal("pre-incarnation runner row must stay compatible")
	}
	s.mu.Lock()
	s.runners["r1"] = model.Runner{ID: "r1", Incarnation: "inc-1"}
	s.mu.Unlock()
	if !s.runnerIncarnationCurrent(ctx, "r1", "inc-1") {
		t.Fatal("matching incarnation refused")
	}
	if s.runnerIncarnationCurrent(ctx, "r1", "inc-2") {
		t.Fatal("mismatched incarnation admitted")
	}

	// DB mode reads the durable row.
	f := newDBFakeStore()
	s.DB = f
	if s.runnerIncarnationCurrent(ctx, "missing", "inc") {
		t.Fatal("unknown durable runner admitted with an incarnation")
	}
	f.mu.Lock()
	f.runners["r2"] = model.Runner{ID: "r2", Incarnation: ""}
	f.mu.Unlock()
	if !s.runnerIncarnationCurrent(ctx, "r2", "inc") {
		t.Fatal("pre-incarnation durable row must stay compatible")
	}
	f.mu.Lock()
	f.runners["r2"] = model.Runner{ID: "r2", Incarnation: "inc-db"}
	f.mu.Unlock()
	if s.runnerIncarnationCurrent(ctx, "r2", "other") {
		t.Fatal("mismatched durable incarnation admitted")
	}
}

func TestResourceReconcileNoOpGates(t *testing.T) {
	ctx := context.Background()
	s := New("secret")
	if err := s.ensureResourceReconciled(ctx); err != nil {
		t.Fatalf("memory ensure = %v, want nil", err)
	}
	if res, err := s.ReconcileResourceReservations(ctx); err != nil || res != (storage.ResourceReconcileResult{}) {
		t.Fatalf("memory reconcile = (%+v, %v), want zero/nil", res, err)
	}
	// A store without the reconcile contract opens the gate without a read.
	s.DB = newDBFakeStore()
	if err := s.ensureResourceReconciled(ctx); err != nil {
		t.Fatalf("contract-less ensure = %v, want nil", err)
	}
	if res, err := s.ReconcileResourceReservations(ctx); err != nil || res != (storage.ResourceReconcileResult{}) {
		t.Fatalf("contract-less reconcile = (%+v, %v)", res, err)
	}
}

func TestPruneLogBatchesForRunsGates(t *testing.T) {
	// Memory mode has no store: a no-op.
	s := New("secret")
	s.pruneLogBatchesForRuns([]string{"run-1"})

	// fs mode runs the pruner for the named run.
	fs, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fs.pruneLogBatchesForRuns([]string{"run-unknown"})

	// DB mode owns its logs: the fs pruner is skipped.
	fs.DB = newDBFakeStore()
	fs.pruneLogBatchesForRuns([]string{"run-unknown"})
}
