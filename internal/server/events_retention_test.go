package server

// Execution event retention (finding 15) and fs honesty (finding 13) tests.
// The DB-mode 410 path is exercised over the eventsFakeStore contract (no
// PostgreSQL needed in the unit lane); the real-store prune is covered by the
// storage integration tests. The fs tests pin the documented non-canonical,
// best-effort stance and the fs-mode semantic emission sites.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// eventsRetentionFakeStore adds the RetentionExecutionEventStore contract to
// eventsFakeStore: a monotonic cursor watermark (a prefix prune must never
// let a later append reuse a seq) plus the prefix-delete rule.
type eventsRetentionFakeStore struct {
	*eventsFakeStore
	seq          int64
	retainedFrom int64
}

func (f *eventsRetentionFakeStore) AppendExecutionEvent(_ context.Context, e model.ExecutionEvent) error {
	f.eventsMu.Lock()
	defer f.eventsMu.Unlock()
	if e.SchemaVersion == 0 {
		e.SchemaVersion = 1
	}
	f.seq++
	e.Seq = f.seq
	f.events = append(f.events, e)
	return nil
}

func (f *eventsRetentionFakeStore) LatestExecutionEventSeq(_ context.Context) (int64, error) {
	f.eventsMu.Lock()
	defer f.eventsMu.Unlock()
	return f.seq, nil
}

func (f *eventsRetentionFakeStore) PruneExecutionEvents(_ context.Context, olderThan time.Time, limit int) (int64, int64, error) {
	if limit <= 0 {
		limit = 1000
	}
	f.eventsMu.Lock()
	defer f.eventsMu.Unlock()
	keepIdx := -1
	for i, e := range f.events {
		if !e.CreatedAt.Before(olderThan) {
			keepIdx = i
			break
		}
	}
	victims := 0
	highest := f.retainedFrom
	for victims < len(f.events) && victims < limit {
		e := f.events[victims]
		if (keepIdx >= 0 && e.Seq >= f.events[keepIdx].Seq) || e.Seq <= f.retainedFrom {
			break
		}
		victims++
		if e.Seq > highest {
			highest = e.Seq
		}
	}
	if victims == 0 {
		return 0, f.retainedFrom, nil
	}
	f.events = append([]model.ExecutionEvent(nil), f.events[victims:]...)
	f.retainedFrom = highest
	return int64(victims), highest, nil
}

func (f *eventsRetentionFakeStore) ExecutionEventRetainedFrom(_ context.Context) (int64, error) {
	f.eventsMu.Lock()
	defer f.eventsMu.Unlock()
	return f.retainedFrom, nil
}

// newRetentionServer builds a DB-mode server over the retention fake.
func newRetentionServer(t *testing.T) (*Server, *eventsRetentionFakeStore) {
	t.Helper()
	f := &eventsRetentionFakeStore{eventsFakeStore: &eventsFakeStore{dbFakeStore: newDBFakeStore()}}
	s := New("admin-tok")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	return s, f
}

// TestEventsCursorExpiredList pins the 410 contract: a nonzero after cursor
// below retained_from-1 is refused with cursor_expired and the watermark,
// while retained_from-1 and retained_from remain valid and latest_cursor is
// still the bootstrap reference.
func TestEventsCursorExpiredList(t *testing.T) {
	s, f := newRetentionServer(t)
	now := time.Now().UTC()
	for i := 1; i <= 5; i++ {
		at := now
		if i <= 3 {
			at = now.Add(-48 * time.Hour)
		}
		if err := f.AppendExecutionEvent(context.Background(), model.ExecutionEvent{RunID: "r1", Type: "job.queued", ToStatus: "queued", CreatedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	pruned, retained, err := f.PruneExecutionEvents(context.Background(), now.Add(-24*time.Hour), 3)
	if err != nil || pruned != 3 || retained != 3 {
		t.Fatalf("prune = %d/%d err %v, want 3/3", pruned, retained, err)
	}

	// Expired: after=0 and after=retainedFrom-2 (retention deleted through 3).
	for _, after := range []string{"0", "1"} {
		w := doJSON(t, s, http.MethodGet, "/api/v1/events?after="+after, "admin-tok", "")
		if w.Code != http.StatusGone {
			t.Fatalf("after=%s = %d, want 410: %s", after, w.Code, w.Body.String())
		}
		var body cursorExpiredResponse
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode 410 body: %v: %s", err, w.Body.String())
		}
		if body.Error != "cursor_expired" || body.RetainedFrom != "3" || body.LatestCursor != "5" {
			t.Fatalf("after=%s 410 = %+v, want cursor_expired/3/5", after, body)
		}
	}

	// Valid boundary: after=retainedFrom-1 and after=retainedFrom both page
	// the survivors, and the response carries the watermark.
	for _, after := range []string{"2", "3"} {
		w := doJSON(t, s, http.MethodGet, "/api/v1/events?after="+after, "admin-tok", "")
		if w.Code != http.StatusOK {
			t.Fatalf("after=%s = %d, want 200: %s", after, w.Code, w.Body.String())
		}
		resp := decodeEventsResponse(t, w.Body.Bytes())
		if len(resp.Events) != 2 || resp.Events[0].Seq != 4 || resp.RetainedFrom != "3" {
			t.Fatalf("after=%s page = %+v, want seqs 4,5 retained_from 3", after, resp)
		}
	}

	// Bootstrap: after=latest_cursor returns nothing until a new event, then
	// exactly the new event.
	w := doJSON(t, s, http.MethodGet, "/api/v1/events?after=5", "admin-tok", "")
	if resp := decodeEventsResponse(t, w.Body.Bytes()); len(resp.Events) != 0 || resp.LatestCursor != "5" {
		t.Fatalf("bootstrap empty page = %+v", resp)
	}
	if err := f.AppendExecutionEvent(context.Background(), model.ExecutionEvent{RunID: "r1", Type: "run.succeeded", ToStatus: "success", CreatedAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, s, http.MethodGet, "/api/v1/events?after=5", "admin-tok", "")
	if resp := decodeEventsResponse(t, w.Body.Bytes()); len(resp.Events) != 1 || resp.Events[0].Seq != 6 || resp.LatestCursor != "6" {
		t.Fatalf("bootstrap page = %+v, want seq 6", resp)
	}
}

// TestEventsCursorExpiredStream pins the SSE reconnect contract: an expired
// after cursor gets HTTP 410 with the JSON error BEFORE any stream starts,
// authorization still runs first, and a valid cursor streams from the
// survivor.
func TestEventsCursorExpiredStream(t *testing.T) {
	s, f := newRetentionServer(t)
	now := time.Now().UTC()
	for i := 1; i <= 4; i++ {
		at := now
		if i <= 2 {
			at = now.Add(-48 * time.Hour)
		}
		if err := f.AppendExecutionEvent(context.Background(), model.ExecutionEvent{RunID: "r1", Type: "job.queued", CreatedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	if _, retained, err := f.PruneExecutionEvents(context.Background(), now.Add(-24*time.Hour), 10); err != nil || retained != 2 {
		t.Fatalf("prune = retained %d err %v, want 2", retained, err)
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	get := func(t *testing.T, url, bearer string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// Unauthenticated must stay 401: auth runs before the retention check.
	resp := get(t, srv.URL+"/api/v1/events/stream?after=0", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated expired stream = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	resp = get(t, srv.URL+"/api/v1/events/stream?after=0", "admin-tok")
	if resp.StatusCode != http.StatusGone {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("expired stream = %d, want 410: %s", resp.StatusCode, body)
	}
	var body cursorExpiredResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode 410 stream body: %v", err)
	}
	resp.Body.Close()
	if body.Error != "cursor_expired" || body.RetainedFrom != "2" || body.LatestCursor != "4" {
		t.Fatalf("expired stream 410 = %+v, want cursor_expired/2/4", body)
	}

	// A valid cursor (retainedFrom-1) streams the survivors.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	frames := startStream(t, ctx, srv.URL+"/api/v1/events/stream?after=1", "admin-tok")
	expectEventFrame(t, frames, 3)
	expectEventFrame(t, frames, 4)
	cancel()
}

// TestEventsFSBestEffortCanonicalFalse pins finding 13: fs mode reports
// canonical=false and its stream is best-effort. A lease whose event append
// fails still commits durably (state and stream diverge: the mutation wins),
// and the stream read itself fails closed while the journal is unwritable.
func TestEventsFSBestEffortCanonicalFalse(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s.Handler(), "token")
	_, _, _, _, _ = leaseJob(t, c)

	w := doJSON(t, s, http.MethodGet, "/api/v1/events?limit=1000", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", w.Code, w.Body.String())
	}
	resp := decodeEventsResponse(t, w.Body.Bytes())
	if resp.Canonical {
		t.Fatalf("fs response claims canonical: %s", w.Body.String())
	}
	if resp.RetainedFrom != "0" {
		t.Fatalf("fs retained_from = %q, want 0", resp.RetainedFrom)
	}
	if len(resp.Events) == 0 {
		t.Fatal("fs lease appended no events")
	}

	// Block the journal: the next lease must still succeed (best-effort
	// stream), while the event read fails closed instead of pretending the
	// stream is empty.
	journal := filepath.Join(dir, "execution-events.jsonl")
	if err := os.Remove(journal); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatal(err)
	}
	_, jobID, _, _, _ := leaseJob(t, c)
	if jobID == "" {
		t.Fatal("lease under a failed event append did not return a task")
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/events", "token", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("list with a blocked journal = %d, want 500 (fail closed): %s", w.Code, w.Body.String())
	}
	// The lease is durable state: with the journal restored, the stream shows
	// the event log WITHOUT the lost lease event (the divergence direction fs
	// mode documents: the mutation wins, the event may be lost).
	if err := os.Remove(journal); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, s, http.MethodGet, "/api/v1/events?limit=1000", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("list after unblock = %d: %s", w.Code, w.Body.String())
	}
	for _, e := range decodeEventsResponse(t, w.Body.Bytes()).Events {
		if e.Type == model.EventAttemptCreated && e.JobID == jobID {
			t.Fatalf("lost best-effort event reappeared: %+v", e)
		}
	}
}

// TestEventsMaintenancePrunesAndExpires proves the maintenance hook: with a
// positive EventsRetention the GC tick prunes the old fs prefix and advances
// the durable watermark (so the API then answers 410), while the disabled
// sentinel never prunes.
func TestEventsMaintenancePrunesAndExpires(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistent("token", "token", dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 4; i++ {
		if err := s.store.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "r", Type: "job.queued", CreatedAt: now.Add(-48 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	s.EventsRetention = -1 // explicitly disabled
	s.GC(ctx, now)
	if rf, err := s.store.ExecutionEventRetainedFrom(ctx); err != nil || rf != 0 {
		t.Fatalf("disabled retention pruned: watermark %d err %v, want 0", rf, err)
	}

	s.EventsRetention = time.Hour
	s.GC(ctx, now)
	rf, err := s.store.ExecutionEventRetainedFrom(ctx)
	if err != nil || rf != 4 {
		t.Fatalf("maintenance watermark = %d err %v, want 4", rf, err)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/events?after=0", "token", ""); w.Code != http.StatusGone {
		t.Fatalf("after maintenance prune = %d, want 410: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/events?after=3", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("after=retainedFrom-1 = %d, want 200: %s", w.Code, w.Body.String())
	}
}

// TestEventsFSSemanticEmission proves the fs/memory mutation sites emit the
// semantic events with their payloads: attempt.created on lease,
// artifact.published on upload and approval.granted on approval.
func TestEventsFSSemanticEmission(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/bin", "token", "artifact-bytes", leaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated {
		t.Fatalf("artifact upload = %d: %s", w.Code, w.Body.String())
	}

	// Approval site on a second server (approval pipeline).
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
	if w := doJSON(t, s2, http.MethodPost, "/api/v1/jobs/"+waiting+"/approve", "token", ""); w.Code != http.StatusOK {
		t.Fatalf("approve = %d: %s", w.Code, w.Body.String())
	}

	byType := func(srv *Server) map[string]model.ExecutionEvent {
		t.Helper()
		w := doJSON(t, srv, http.MethodGet, "/api/v1/events?limit=1000", "token", "")
		if w.Code != http.StatusOK {
			t.Fatalf("list events = %d: %s", w.Code, w.Body.String())
		}
		out := map[string]model.ExecutionEvent{}
		for _, e := range decodeEventsResponse(t, w.Body.Bytes()).Events {
			out[e.Type] = e
		}
		return out
	}

	events := byType(s)
	attempt, ok := events[model.EventAttemptCreated]
	if !ok || attempt.Attempt != task.LeaseGeneration || attempt.JobID != task.Job.ID || attempt.Actor != runnerID {
		t.Fatalf("attempt.created = %+v (present %v)", attempt, ok)
	}
	if attempt.Payload["runner"] != runnerID {
		t.Fatalf("attempt.created payload = %+v", attempt.Payload)
	}
	art, ok := events[model.EventArtifactPublished]
	if !ok || art.JobID != task.Job.ID || art.Payload["name"] != "bin" || art.Payload["sha256"] == "" || art.Payload["generation"] != fmt.Sprint(task.LeaseGeneration) {
		t.Fatalf("artifact.published = %+v (present %v)", art, ok)
	}

	approval := byType(s2)[model.EventApprovalGranted]
	if approval.Type != model.EventApprovalGranted || approval.JobID != waiting || approval.Actor == "" {
		t.Fatalf("approval.granted = %+v", approval)
	}
	if approval.Payload["status"] != "queued" {
		t.Fatalf("approval.granted payload = %+v", approval.Payload)
	}
}
