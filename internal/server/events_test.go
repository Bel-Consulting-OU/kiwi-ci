package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// eventsFakeStore adds the ExecutionEventStore contract to dbFakeStore so the
// DB-mode event handlers can be exercised without PostgreSQL.
type eventsFakeStore struct {
	*dbFakeStore
	eventsMu sync.Mutex
	events   []model.ExecutionEvent
}

func (f *eventsFakeStore) AppendExecutionEvent(_ context.Context, e model.ExecutionEvent) error {
	f.eventsMu.Lock()
	defer f.eventsMu.Unlock()
	if e.SchemaVersion == 0 {
		e.SchemaVersion = 1
	}
	e.Seq = int64(len(f.events)) + 1
	f.events = append(f.events, e)
	return nil
}

func (f *eventsFakeStore) ListExecutionEvents(_ context.Context, after int64, limit int, runID string) ([]model.ExecutionEvent, int64, error) {
	f.eventsMu.Lock()
	defer f.eventsMu.Unlock()
	limit = storage.ClampExecutionEventLimit(limit)
	out := []model.ExecutionEvent{}
	cursor := after
	for _, e := range f.events {
		if e.Seq <= after || (runID != "" && e.RunID != runID) {
			continue
		}
		out = append(out, e)
		cursor = e.Seq
		if len(out) >= limit {
			break
		}
	}
	return out, cursor, nil
}

func decodeEventsResponse(t *testing.T, body []byte) executionEventsResponse {
	t.Helper()
	var resp executionEventsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode events response: %v: %s", err, body)
	}
	return resp
}

// TestEventsEndpointAdminOnlyAndPagination pins the list endpoint's
// authorization (admin tier, same as audit), its pagination shape
// ({events, next_cursor}) and the run filter.
func TestEventsEndpointAdminOnlyAndPagination(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		run := "run-a"
		if i == 3 {
			run = "run-b"
		}
		if err := s.store.AppendExecutionEvent(ctx, model.ExecutionEvent{
			RunID: run, JobID: fmt.Sprintf("job-%d", i), Type: "job.queued", ToStatus: "queued",
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Unauthenticated and non-admin bearers are refused before any read.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/events", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated events = %d, want 401: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/events", "runner-tok", ""); w.Code != http.StatusForbidden && w.Code != http.StatusUnauthorized {
		t.Fatalf("runner-token events = %d, want 401/403: %s", w.Code, w.Body.String())
	}

	w := doJSON(t, s, http.MethodGet, "/api/v1/events", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("list events = %d: %s", w.Code, w.Body.String())
	}
	resp := decodeEventsResponse(t, w.Body.Bytes())
	if len(resp.Events) != 3 || resp.NextCursor != "3" {
		t.Fatalf("events = %d next_cursor %q, want 3/3", len(resp.Events), resp.NextCursor)
	}
	for i, e := range resp.Events {
		if e.Seq != int64(i+1) || e.SchemaVersion != 1 {
			t.Fatalf("event %d = %+v, want ascending seq + schema 1", i, e)
		}
	}

	// Page 1 ends at the cursor; page 2 resumes with no gap.
	w = doJSON(t, s, http.MethodGet, "/api/v1/events?limit=2", "admin-tok", "")
	resp = decodeEventsResponse(t, w.Body.Bytes())
	if len(resp.Events) != 2 || resp.NextCursor != "2" {
		t.Fatalf("page 1 = %d next %q", len(resp.Events), resp.NextCursor)
	}
	w = doJSON(t, s, http.MethodGet, "/api/v1/events?after=2&limit=2", "admin-tok", "")
	resp = decodeEventsResponse(t, w.Body.Bytes())
	if len(resp.Events) != 1 || resp.Events[0].Seq != 3 || resp.NextCursor != "3" {
		t.Fatalf("page 2 = %+v next %q", resp.Events, resp.NextCursor)
	}

	// run_id filter.
	w = doJSON(t, s, http.MethodGet, "/api/v1/events?run_id=run-b", "admin-tok", "")
	resp = decodeEventsResponse(t, w.Body.Bytes())
	if len(resp.Events) != 1 || resp.Events[0].RunID != "run-b" {
		t.Fatalf("run filter = %+v", resp.Events)
	}

	// Malformed cursors fail closed with 400 instead of restarting the stream.
	for _, after := range []string{"abc", "-1"} {
		if w := doJSON(t, s, http.MethodGet, "/api/v1/events?after="+after, "admin-tok", ""); w.Code != http.StatusBadRequest {
			t.Fatalf("after=%s = %d, want 400", after, w.Code)
		}
	}
}

// TestEventsEndpointDBMode proves the DB branch uses the store's
// ExecutionEventStore implementation and fails closed (503) for a store
// without the contract.
func TestEventsEndpointDBMode(t *testing.T) {
	s := New("admin-tok")
	if err := s.SwitchToDB(newDBFakeStore()); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/events", "admin-tok", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("store without the contract = %d, want 503: %s", w.Code, w.Body.String())
	}

	f := &eventsFakeStore{dbFakeStore: newDBFakeStore()}
	s2 := New("admin-tok")
	if err := s2.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if err := f.AppendExecutionEvent(context.Background(), model.ExecutionEvent{RunID: "r1", Type: "run.running", ToStatus: "running"}); err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s2, http.MethodGet, "/api/v1/events", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("db events = %d: %s", w.Code, w.Body.String())
	}
	resp := decodeEventsResponse(t, w.Body.Bytes())
	if len(resp.Events) != 1 || resp.Events[0].Type != "run.running" || resp.NextCursor != "1" {
		t.Fatalf("db events = %+v next %q", resp.Events, resp.NextCursor)
	}
}

// TestEventsFSLifecycleParity proves the fs/memory transition funnels append
// the same lifecycle vocabulary the PostgreSQL triggers do: enqueue, lease,
// complete, cancel and requeue, with from/to and attempt, durable across a
// restart.
func TestEventsFSLifecycleParity(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "token")

	runID, jobID, runnerID, leaseToken, generation := leaseJob(t, c)
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", Complete{
		RunnerID: runnerID, LeaseToken: leaseToken, LeaseGeneration: generation, Status: model.StatusSuccess,
	}, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("complete = %d: %s", w.Code, w.Body.String())
	}

	// A second run cancelled through the admin path contributes the cancel
	// events.
	w = c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: testPipeline}, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("second submit = %d: %s", w.Code, w.Body.String())
	}
	var second struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if w := c.do(http.MethodPost, "/api/v1/runs/"+second.ID+"/cancel", nil, nil); w.Code != http.StatusOK {
		t.Fatalf("cancel = %d: %s", w.Code, w.Body.String())
	}

	readEvents := func(srv *Server) []model.ExecutionEvent {
		t.Helper()
		w := doJSON(t, srv, http.MethodGet, "/api/v1/events?limit=1000", "token", "")
		if w.Code != http.StatusOK {
			t.Fatalf("list events = %d: %s", w.Code, w.Body.String())
		}
		return decodeEventsResponse(t, w.Body.Bytes()).Events
	}
	events := readEvents(s)
	byType := map[string]model.ExecutionEvent{}
	for _, e := range events {
		byType[e.Type+"/"+e.RunID] = e
		if e.Seq <= 0 {
			t.Fatalf("event without seq: %+v", e)
		}
	}
	wantTypes := []string{
		"run.queued/" + runID,
		"job.queued/" + runID,
		"run.running/" + runID,
		"job.running/" + runID,
		"job.succeeded/" + runID,
		"run.succeeded/" + runID,
		"run.queued/" + second.ID,
		"job.queued/" + second.ID,
		"job.cancelled/" + second.ID,
		"run.cancelled/" + second.ID,
	}
	for _, key := range wantTypes {
		if _, ok := byType[key]; !ok {
			t.Fatalf("missing event %q in %+v", key, events)
		}
	}
	running := byType["job.running/"+runID]
	if running.FromStatus != "queued" || running.ToStatus != "running" || running.Attempt != 1 || running.Payload["runner"] != runnerID {
		t.Fatalf("job.running event = %+v", running)
	}
	done := byType["job.succeeded/"+runID]
	if done.FromStatus != "running" || done.ToStatus != "success" || done.Attempt != 1 || done.Payload["finished_at"] == "" {
		t.Fatalf("job.succeeded event = %+v", done)
	}
	cancelled := byType["job.cancelled/"+second.ID]
	if cancelled.FromStatus != "queued" || cancelled.ToStatus != "cancelled" || cancelled.Actor == "" {
		t.Fatalf("job.cancelled event = %+v", cancelled)
	}

	// Restart: the journal is durable and the stream continues after the
	// highest seq, never reusing a cursor.
	s2, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	restored := readEvents(s2)
	if len(restored) != len(events) {
		t.Fatalf("after restart = %d events, want %d", len(restored), len(events))
	}
	c2 := newTestClient(t, s2.Handler(), "token")
	if w := c2.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/kiwi/repo.git", Ref: "main", Pipeline: testPipeline}, nil); w.Code != http.StatusAccepted {
		t.Fatalf("post-restart submit = %d: %s", w.Code, w.Body.String())
	}
	after := readEvents(s2)
	if len(after) <= len(restored) {
		t.Fatalf("post-restart enqueue appended no events: %d -> %d", len(restored), len(after))
	}
	if after[len(after)-1].Seq <= restored[len(restored)-1].Seq {
		t.Fatalf("seq not monotonic across restart: %d then %d", restored[len(restored)-1].Seq, after[len(after)-1].Seq)
	}
}

// TestEventsAppendFailureSemantics pins the fs failure contract at both kinds
// of site: a best-effort transition (lease, next to auditLocked) still
// completes and only loses its event, while the evidence-first approval
// (auditFirstLocked) refuses the mutation with 503.
func TestEventsAppendFailureSemantics(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	// Block the journal: a directory at the journal path makes every append
	// fail while list/read also fail closed.
	if err := os.Mkdir(filepath.Join(dir, "execution-events.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "token")

	// Best-effort lease: the durable snapshot/audit path is unaffected, so
	// the lease still succeeds.
	_, jobID, runnerID, leaseToken, generation := leaseJob(t, c)
	if jobID == "" || runnerID == "" {
		t.Fatal("lease under a failed event append did not return a task")
	}
	if w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/complete", Complete{
		RunnerID: runnerID, LeaseToken: leaseToken, LeaseGeneration: generation, Status: model.StatusSuccess,
	}, nil); w.Code != http.StatusNoContent {
		t.Fatalf("complete under a failed event append = %d: %s", w.Code, w.Body.String())
	}

	// Evidence-first approval: the same failure refuses the mutation before
	// any state change.
	s2, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://example.com/o/r.git", RepoFullName: "o/r",
		Ref: "refs/heads/main", Event: "push", Pipeline: approvalPipeline,
	}); err != nil {
		t.Fatal(err)
	}
	var waiting string
	s2.mu.Lock()
	for id, j := range s2.jobs {
		if j.ApprovalRequired {
			waiting = id
		}
	}
	s2.mu.Unlock()
	if waiting == "" {
		t.Fatal("approval fixture job not found")
	}
	if err := os.RemoveAll(filepath.Join(s2.dataDir, "execution-events.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(s2.dataDir, "execution-events.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s2, http.MethodPost, "/api/v1/jobs/"+waiting+"/approve", "token", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("approval with a failed event append = %d, want 503: %s", w.Code, w.Body.String())
	}
	s2.mu.Lock()
	j := s2.jobs[waiting]
	s2.mu.Unlock()
	if j.Status != model.StatusWaitingApproval || j.ApprovedBy != "" {
		t.Fatalf("refused approval changed the job: %+v", j)
	}
}

// TestEventsStreamDeliversAndResumes proves the SSE endpoint carries
// `event: execution` frames with `id: <seq>` and honors ?after for reconnect
// resumption.
func TestEventsStreamDeliversAndResumes(t *testing.T) {
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		if err := s.store.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "r1", Type: "job.queued", ToStatus: "queued"}); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	streamCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	frames := startStream(t, streamCtx, srv.URL+"/api/v1/events/stream?after=1", "admin-tok")
	expectEventFrame(t, frames, 2)
	expectEventFrame(t, frames, 3)

	// A live append arrives without a reconnect.
	if err := s.store.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "r1", Type: "run.succeeded", ToStatus: "success"}); err != nil {
		t.Fatal(err)
	}
	expectEventFrame(t, frames, 4)
	cancel()
}

func expectEventFrame(t *testing.T, frames <-chan sseFrame, seq int64) {
	t.Helper()
	select {
	case f, ok := <-frames:
		if !ok {
			t.Fatalf("stream closed before event %d", seq)
		}
		if f.event != "execution" || f.id != fmt.Sprint(seq) {
			t.Fatalf("frame = %+v, want execution id %d", f, seq)
		}
		var e model.ExecutionEvent
		if err := json.Unmarshal([]byte(f.data), &e); err != nil {
			t.Fatalf("frame data is not an ExecutionEvent: %v: %q", err, f.data)
		}
		if e.Seq != seq {
			t.Fatalf("event seq = %d, want %d", e.Seq, seq)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for event %d", seq)
	}
}

// TestEventsStreamGuards pins the SSE endpoint's refusals: no persistent
// store is 503 and an unauthenticated request is 401 before streaming.
func TestEventsStreamGuards(t *testing.T) {
	if w := doJSON(t, New("token"), http.MethodGet, "/api/v1/events/stream", "token", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("memory stream = %d, want 503", w.Code)
	}
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/events/stream", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated stream = %d, want 401", w.Code)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/events/stream?after=oops", "admin-tok", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed cursor stream = %d, want 400", w.Code)
	}
}
