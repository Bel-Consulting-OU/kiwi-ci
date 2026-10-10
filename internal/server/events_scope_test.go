package server

// Scope-correct execution event contract tests (closure gate): repository
// scoping and its typed cursors, the scoped resume decision (resume_ok when
// only other scopes were pruned, 410 snapshot-required when the scope itself
// lost events), cursor scope binding, auth-loss denial and retention racing
// scoped pagination. The fake store gives deterministic control over the
// pruned rows; the real store semantics are covered by the storage unit and
// PostgreSQL integration tests.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

const (
	scopeRepoA = "github.com/acme/repo-a"
	scopeRepoB = "github.com/acme/repo-b"
)

// ExecutionSnapshot is the fake's atomic bootstrap read: the cursor is the
// monotonic event watermark (read first, mirroring the store contract) and
// the active-run/state summary is built from the fake's runs/jobs, filtered
// by repository when repoID is non-empty.
func (f *eventsRetentionFakeStore) ExecutionSnapshot(_ context.Context, runLimit int, repoID string) (storage.ExecutionSnapshot, error) {
	if runLimit <= 0 || runLimit > storage.MaxExecutionSnapshotRuns {
		runLimit = storage.DefaultExecutionSnapshotRuns
	}
	f.eventsMu.Lock()
	cursor := f.seq
	f.eventsMu.Unlock()
	snap := storage.ExecutionSnapshot{Cursor: cursor, GeneratedAt: time.Now().UTC(), Runs: []storage.ExecutionSnapshotRun{}}
	f.mu.Lock()
	defer f.mu.Unlock()
	matching := make(map[string]bool, len(f.runs))
	for _, run := range f.runs {
		if repoID != "" && run.RepoID != repoID {
			continue
		}
		matching[run.ID] = true
		if run.Status.Terminal() {
			continue
		}
		snap.Runs = append(snap.Runs, storage.ExecutionSnapshotRun{
			ID: run.ID, RepoID: run.RepoID, Ref: run.Ref, Status: run.Status, CreatedAt: run.CreatedAt,
		})
	}
	sort.Slice(snap.Runs, func(i, j int) bool {
		if !snap.Runs[i].CreatedAt.Equal(snap.Runs[j].CreatedAt) {
			return snap.Runs[i].CreatedAt.After(snap.Runs[j].CreatedAt)
		}
		return snap.Runs[i].ID < snap.Runs[j].ID
	})
	if len(snap.Runs) > runLimit {
		snap.Runs = snap.Runs[:runLimit]
	}
	for _, j := range f.jobs {
		if repoID != "" && !matching[j.RunID] {
			continue
		}
		switch j.Status {
		case model.StatusQueued:
			snap.Queued++
		case model.StatusRunning:
			snap.Running++
		}
	}
	return snap, nil
}

// forcePruneEvents removes exactly the events matching pred from the fake
// store, recording their per-run frontier and advancing the global watermark
// to the highest removed seq. It models the state a global prefix prune
// leaves when it removed only those (older) events.
func forcePruneEvents(t *testing.T, f *eventsRetentionFakeStore, pred func(model.ExecutionEvent) bool) []int64 {
	t.Helper()
	f.eventsMu.Lock()
	defer f.eventsMu.Unlock()
	if f.pruned == nil {
		f.pruned = map[string]eventsPrunedRecord{}
	}
	kept := make([]model.ExecutionEvent, 0, len(f.events))
	var removed []int64
	for _, e := range f.events {
		if !pred(e) {
			kept = append(kept, e)
			continue
		}
		removed = append(removed, e.Seq)
		if e.RunID != "" {
			rec := f.pruned[e.RunID]
			if e.Seq > rec.max {
				rec.max = e.Seq
			}
			if e.RepoID != "" {
				rec.repo = e.RepoID
			}
			f.pruned[e.RunID] = rec
		}
		if e.Seq > f.retainedFrom {
			f.retainedFrom = e.Seq
		}
	}
	f.events = kept
	return removed
}

// scopedEventsServer builds a DB-mode server over the retention fake with
// controller principals (events-a for repo A, events-a-rot for the same
// repo, events-b for repo B, global-events) and two queued runs with three
// queued jobs each.
func scopedEventsServer(t *testing.T) (*Server, *eventsRetentionFakeStore, model.Run, model.Run) {
	t.Helper()
	f := &eventsRetentionFakeStore{eventsFakeStore: &eventsFakeStore{dbFakeStore: newDBFakeStore()}}
	now := time.Now().UTC()
	runA := model.Run{ID: "run-a", RepoID: scopeRepoA, Ref: "refs/heads/main", Status: model.StatusQueued, CreatedAt: now}
	runB := model.Run{ID: "run-b", RepoID: scopeRepoB, Ref: "refs/heads/main", Status: model.StatusQueued, CreatedAt: now.Add(time.Second)}
	f.mu.Lock()
	f.runs[runA.ID] = runA
	f.runs[runB.ID] = runB
	for i := 1; i <= 3; i++ {
		f.jobs[fmt.Sprintf("job-a%d", i)] = model.Job{ID: fmt.Sprintf("job-a%d", i), RunID: runA.ID, RepoID: scopeRepoA, Key: fmt.Sprintf("a%d", i), Status: model.StatusQueued}
		f.jobs[fmt.Sprintf("job-b%d", i)] = model.Job{ID: fmt.Sprintf("job-b%d", i), RunID: runB.ID, RepoID: scopeRepoB, Key: fmt.Sprintf("b%d", i), Status: model.StatusQueued}
	}
	f.mu.Unlock()

	s := New("admin-tok")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	principals := map[string]auth.Principal{
		"events-a": {Subject: "faktor-a", RepositoryCapabilities: map[string][]auth.Capability{
			capabilityRepoKey(t, scopeRepoA): {auth.CapExecutionEventsRead},
		}},
		"events-a-rot": {Subject: "faktor-a-rot", RepositoryCapabilities: map[string][]auth.Capability{
			capabilityRepoKey(t, scopeRepoA): {auth.CapExecutionEventsRead},
		}},
		"events-b": {Subject: "faktor-b", RepositoryCapabilities: map[string][]auth.Capability{
			capabilityRepoKey(t, scopeRepoB): {auth.CapExecutionEventsRead},
		}},
		"events-a-lost": {Subject: "faktor-a-lost", RepositoryCapabilities: map[string][]auth.Capability{
			capabilityRepoKey(t, scopeRepoB): {auth.CapExecutionEventsRead},
		}},
		"global-events": {Subject: "feed", Capabilities: []auth.Capability{auth.CapExecutionEventsRead}},
	}
	for raw, p := range principals {
		if err := s.AuthStore.AddToken(raw, p); err != nil {
			t.Fatalf("AddToken(%s): %v", raw, err)
		}
	}
	return s, f, runA, runB
}

// seedInterleavedEvents appends three repo A and three repo B events,
// interleaved, each carrying the run/job/repo metadata the isolation
// assertions look for.
func seedInterleavedEvents(t *testing.T, f *eventsRetentionFakeStore) {
	t.Helper()
	now := time.Now().UTC()
	events := []model.ExecutionEvent{
		{RunID: "run-b", JobID: "job-b1", RepoID: scopeRepoB, Type: "job.queued", ToStatus: "queued", CreatedAt: now, Payload: map[string]string{"job": "b1", "repo": "B"}},
		{RunID: "run-a", JobID: "job-a1", RepoID: scopeRepoA, Type: "job.queued", ToStatus: "queued", CreatedAt: now, Payload: map[string]string{"job": "a1", "repo": "A"}},
		{RunID: "run-b", JobID: "job-b2", RepoID: scopeRepoB, Type: "job.running", ToStatus: "running", CreatedAt: now, Payload: map[string]string{"job": "b2", "repo": "B"}},
		{RunID: "run-a", JobID: "job-a2", RepoID: scopeRepoA, Type: "job.running", ToStatus: "running", CreatedAt: now, Payload: map[string]string{"job": "a2", "repo": "A"}},
		{RunID: "run-b", JobID: "job-b3", RepoID: scopeRepoB, Type: "job.succeeded", ToStatus: "success", CreatedAt: now, Payload: map[string]string{"job": "b3", "repo": "B"}},
		{RunID: "run-a", JobID: "job-a3", RepoID: scopeRepoA, Type: "job.succeeded", ToStatus: "success", CreatedAt: now, Payload: map[string]string{"job": "a3", "repo": "A"}},
	}
	for _, e := range events {
		if err := f.AppendExecutionEvent(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
}

// TestEventsRepoScopeIsolationAndScopedResumeMatrix is the closure matrix:
// a repo A consumer never observes repo B ids/metadata in events, snapshot
// runs/counts or cursor fields; a global prune that removed ONLY repo B
// events past its cursor still reports resume_ok and continues gap-free;
// deleting one of its own events turns the resume into 410
// cursor_expired_snapshot_required with the scoped frontier; and the
// repo-scoped snapshot recovers it with through_sequence so the stream
// resumes above the snapshot with zero gaps or duplicates.
func TestEventsRepoScopeIsolationAndScopedResumeMatrix(t *testing.T) {
	s, f, runA, _ := scopedEventsServer(t)
	seedInterleavedEvents(t, f)
	ctx := context.Background()

	// Page 1: one repo A event, typed A cursor at seq 2.
	w := doJSON(t, s, http.MethodGet, "/api/v1/events?repo_id="+scopeRepoA+"&limit=1", "events-a", "")
	if w.Code != http.StatusOK {
		t.Fatalf("repo A page 1 = %d: %s", w.Code, w.Body.String())
	}
	page1 := decodeEventsResponse(t, w.Body.Bytes())
	if len(page1.Events) != 1 || page1.Events[0].JobID != "job-a1" || page1.Events[0].RepoID != scopeRepoA {
		t.Fatalf("repo A page 1 = %+v", page1.Events)
	}
	if page1.ResumeStatus != "resume_ok" || page1.ScopeFingerprint == "" || page1.RetainedFrom != "0" {
		t.Fatalf("repo A page 1 metadata = %+v", page1)
	}
	cursorA := page1.NextCursor
	if eventCursorSeq(t, cursorA) != 2 {
		t.Fatalf("repo A cursor = %q, want seq 2", cursorA)
	}
	// Resume from the held cursor before any prune: A2 and A3, nothing else.
	w = doJSON(t, s, http.MethodGet, "/api/v1/events?repo_id="+scopeRepoA+"&limit=100&after="+cursorA, "events-a", "")
	if w.Code != http.StatusOK {
		t.Fatalf("repo A page 2 = %d: %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, leak := range []string{"run-b", "job-b", scopeRepoB, `"repo":"B"`} {
		if strings.Contains(body, leak) {
			t.Fatalf("repo A page leaked %q: %s", leak, body)
		}
	}
	page2 := decodeEventsResponse(t, w.Body.Bytes())
	if len(page2.Events) != 2 || page2.Events[0].Seq != 4 || page2.Events[1].Seq != 6 {
		t.Fatalf("repo A page 2 = %+v, want seqs 4,6", page2.Events)
	}

	// The repo A snapshot exposes only run A and its jobs, and carries the
	// global high-water as through_sequence plus a typed resume cursor.
	w = doJSON(t, s, http.MethodGet, "/api/v1/execution-snapshot?repo_id="+scopeRepoA, "events-a", "")
	if w.Code != http.StatusOK {
		t.Fatalf("repo A snapshot = %d: %s", w.Code, w.Body.String())
	}
	body = w.Body.String()
	for _, leak := range []string{"run-b", "job-b", scopeRepoB} {
		if strings.Contains(body, leak) {
			t.Fatalf("repo A snapshot leaked %q: %s", leak, body)
		}
	}
	var snap executionSnapshotResponse
	if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.Runs) != 1 || snap.Runs[0].ID != runA.ID || snap.Runs[0].RepoID != scopeRepoA {
		t.Fatalf("repo A snapshot runs = %+v", snap.Runs)
	}
	if snap.Counts.Queued != 3 || snap.Counts.Running != 0 {
		t.Fatalf("repo A snapshot counts = %+v, want its three queued jobs only", snap.Counts)
	}
	if snap.ThroughSequence != 6 || eventCursorSeq(t, snap.ResumeCursor) != 6 || snap.ScopeFingerprint == "" {
		t.Fatalf("repo A snapshot cursors = %+v", snap)
	}

	// A global prune that removed ONLY repo B's events: the global watermark
	// (5) passes the consumer's cursor (2) yet repo A lost nothing visible.
	removed := forcePruneEvents(t, f, func(e model.ExecutionEvent) bool { return e.RunID == "run-b" })
	if len(removed) != 3 {
		t.Fatalf("removed = %v, want the three repo B events", removed)
	}
	if f.retainedFrom != 5 {
		t.Fatalf("global watermark = %d, want 5", f.retainedFrom)
	}
	w = doJSON(t, s, http.MethodGet, "/api/v1/events?repo_id="+scopeRepoA+"&limit=100&after="+cursorA, "events-a", "")
	if w.Code != http.StatusOK {
		t.Fatalf("repo A resume after other-scope prune = %d: %s", w.Code, w.Body.String())
	}
	resume := decodeEventsResponse(t, w.Body.Bytes())
	if resume.ResumeStatus != "resume_ok" || resume.RetainedFrom != "0" {
		t.Fatalf("repo A resume metadata = resume %q retained %q, want resume_ok/0", resume.ResumeStatus, resume.RetainedFrom)
	}
	if len(resume.Events) != 2 || resume.Events[0].Seq != 4 || resume.Events[1].Seq != 6 {
		t.Fatalf("repo A resume events = %+v, want seqs 4,6 with no duplicates", resume.Events)
	}

	// Now delete ONE repo A event (A2 at seq 4) and advance its frontier.
	removed = forcePruneEvents(t, f, func(e model.ExecutionEvent) bool { return e.Seq == 4 })
	if len(removed) != 1 {
		t.Fatalf("removed = %v, want seq 4", removed)
	}
	w = doJSON(t, s, http.MethodGet, "/api/v1/events?repo_id="+scopeRepoA+"&limit=100&after="+cursorA, "events-a", "")
	if w.Code != http.StatusGone {
		t.Fatalf("repo A resume after own-scope prune = %d, want 410: %s", w.Code, w.Body.String())
	}
	var expired cursorExpiredResponse
	if err := json.Unmarshal(w.Body.Bytes(), &expired); err != nil {
		t.Fatal(err)
	}
	if expired.Error != "cursor_expired" || expired.Reason != "cursor_expired_snapshot_required" {
		t.Fatalf("410 body = %+v", expired)
	}
	if expired.RetainedFrom != "4" || eventCursorSeq(t, expired.LatestCursor) != 6 || expired.ScopeFingerprint != page1.ScopeFingerprint {
		t.Fatalf("410 scoped fields = %+v, want frontier 4, latest 6, fingerprint %q", expired, page1.ScopeFingerprint)
	}

	// Recovery through the repo A snapshot: stream strictly above
	// through_sequence and see exactly the new repo A transition.
	w = doJSON(t, s, http.MethodGet, "/api/v1/execution-snapshot?repo_id="+scopeRepoA, "events-a", "")
	if w.Code != http.StatusOK {
		t.Fatalf("recovery snapshot = %d: %s", w.Code, w.Body.String())
	}
	var recovery executionSnapshotResponse
	if err := json.Unmarshal(w.Body.Bytes(), &recovery); err != nil {
		t.Fatal(err)
	}
	if recovery.ThroughSequence != 6 || eventCursorSeq(t, recovery.ResumeCursor) != 6 {
		t.Fatalf("recovery snapshot cursors = %+v", recovery)
	}
	if err := f.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "run-a", JobID: "job-a4", RepoID: scopeRepoA, Type: "job.queued", ToStatus: "queued", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := f.AppendExecutionEvent(ctx, model.ExecutionEvent{RunID: "run-b", JobID: "job-b4", RepoID: scopeRepoB, Type: "job.queued", ToStatus: "queued", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, s, http.MethodGet, "/api/v1/events?repo_id="+scopeRepoA+"&limit=100&after="+recovery.ResumeCursor, "events-a", "")
	if w.Code != http.StatusOK {
		t.Fatalf("post-recovery stream = %d: %s", w.Code, w.Body.String())
	}
	caught := decodeEventsResponse(t, w.Body.Bytes())
	if len(caught.Events) != 1 || caught.Events[0].Seq != 7 || caught.Events[0].JobID != "job-a4" {
		t.Fatalf("post-recovery events = %+v, want exactly the repo A seq 7", caught.Events)
	}
}

// TestEventsStreamRepoScopeNeverEmitsOtherRepos pins the SSE wrapper: a
// repository-scoped stream starts at the first event of ITS repository
// (never another repo's lower seq), carries only that repository's events,
// and reconnects cleanly with the typed id it emitted (a numeric id could
// not be replayed under a repository scope).
func TestEventsStreamRepoScopeNeverEmitsOtherRepos(t *testing.T) {
	s, f, _, _ := scopedEventsServer(t)
	seedInterleavedEvents(t, f)
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	frames := startStream(t, ctx, srv.URL+"/api/v1/events/stream?repo_id="+scopeRepoA, "events-a")
	// Repo B's seq 1 precedes every repo A event: a leaking stream would
	// deliver it first.
	var lastID string
	for _, seq := range []int64{2, 4, 6} {
		select {
		case frame, ok := <-frames:
			if !ok {
				t.Fatalf("stream closed before seq %d", seq)
			}
			if eventCursorSeq(t, frame.id) != seq {
				t.Fatalf("frame id = %q, want %d (another repo's event leaked)", frame.id, seq)
			}
			if strings.Contains(frame.data, "run-b") || strings.Contains(frame.data, "job-b") {
				t.Fatalf("frame %d leaked repo B metadata: %s", seq, frame.data)
			}
			lastID = frame.id
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for repo A seq %d", seq)
		}
	}
	cancel()
	// Reconnect with the typed frame id one event back: the resume must
	// establish (200) and deliver exactly the final repo A event once.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	reconnectID := buildExecutionEventCursor(4, storage.ExecutionEventScope{Kind: storage.ExecutionEventScopeRepo, RepoID: scopeRepoA})
	if reconnectID == lastID {
		t.Fatal("test setup: reconnect cursor equals the last delivered id")
	}
	reconnected := startStream(t, ctx2, srv.URL+"/api/v1/events/stream?repo_id="+scopeRepoA+"&after="+reconnectID, "events-a")
	select {
	case frame, ok := <-reconnected:
		if !ok {
			t.Fatal("reconnected stream closed before seq 6")
		}
		if eventCursorSeq(t, frame.id) != 6 {
			t.Fatalf("reconnected frame id = %q, want 6", frame.id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the reconnected repo A seq 6")
	}
}

// TestEventsCursorScopeBinding pins the typed cursor rules: a cursor issued
// for repo A is refused (409 cursor_scope_mismatch) under repo B, a run and
// the global scope, a legacy bare integer works only on the global scope,
// and a same-scope token rotation keeps the cursor valid because the
// fingerprint binds the scope, never the principal.
func TestEventsCursorScopeBinding(t *testing.T) {
	s, f, runA, _ := scopedEventsServer(t)
	seedInterleavedEvents(t, f)

	w := doJSON(t, s, http.MethodGet, "/api/v1/events?repo_id="+scopeRepoA+"&limit=1", "events-a", "")
	if w.Code != http.StatusOK {
		t.Fatalf("repo A page = %d: %s", w.Code, w.Body.String())
	}
	cursorA := decodeEventsResponse(t, w.Body.Bytes()).NextCursor

	for _, tc := range []struct {
		name, path, token string
		want              int
	}{
		{"A cursor under repo B", "/api/v1/events?repo_id=" + scopeRepoB + "&after=" + cursorA, "events-b", http.StatusConflict},
		{"A cursor under run A", "/api/v1/events?run_id=" + runA.ID + "&after=" + cursorA, "events-a", http.StatusConflict},
		{"A cursor under global", "/api/v1/events?after=" + cursorA, "global-events", http.StatusConflict},
		{"A cursor under global admin", "/api/v1/events?after=" + cursorA, "admin-tok", http.StatusConflict},
		{"legacy integer under repo A", "/api/v1/events?repo_id=" + scopeRepoA + "&after=1", "events-a", http.StatusConflict},
		{"legacy integer under global", "/api/v1/events?after=1", "global-events", http.StatusOK},
		{"malformed typed cursor", "/api/v1/events?repo_id=" + scopeRepoA + "&after=xe1:oops", "events-a", http.StatusBadRequest},
		{"wrong fingerprint under global", "/api/v1/events?after=xe1:1:deadbeefdeadbeef", "global-events", http.StatusConflict},
		{"A cursor under its own scope", "/api/v1/events?repo_id=" + scopeRepoA + "&after=" + cursorA, "events-a", http.StatusOK},
	} {
		if w := doJSON(t, s, http.MethodGet, tc.path, tc.token, ""); w.Code != tc.want {
			t.Errorf("%s: GET %s with %s = %d, want %d: %s", tc.name, tc.path, tc.token, w.Code, tc.want, w.Body.String())
		}
	}
	var mismatch cursorScopeMismatchResponse
	w = doJSON(t, s, http.MethodGet, "/api/v1/events?repo_id="+scopeRepoB+"&after="+cursorA, "events-b", "")
	if err := json.Unmarshal(w.Body.Bytes(), &mismatch); err != nil {
		t.Fatal(err)
	}
	if mismatch.Error != "cursor_scope_mismatch" || mismatch.ScopeFingerprint == "" {
		t.Fatalf("409 body = %+v", mismatch)
	}
	// A second token for the same scope keeps the cursor valid: the
	// fingerprint is scope-bound, not token-bound.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/events?repo_id="+scopeRepoA+"&after="+cursorA, "events-a-rot", ""); w.Code != http.StatusOK {
		t.Fatalf("rotated-token cursor = %d, want 200: %s", w.Code, w.Body.String())
	}
	// The two same-scope tokens see the same fingerprint.
	base := doJSON(t, s, http.MethodGet, "/api/v1/events?repo_id="+scopeRepoA, "events-a", "")
	rot := doJSON(t, s, http.MethodGet, "/api/v1/events?repo_id="+scopeRepoA, "events-a-rot", "")
	if decodeEventsResponse(t, base.Body.Bytes()).ScopeFingerprint != decodeEventsResponse(t, rot.Body.Bytes()).ScopeFingerprint {
		t.Fatal("same-scope tokens produced different scope fingerprints")
	}
}

// TestEventsRetentionRacingScopedPagination pins the scoped pagination
// contract under a prune between page N and page N+1: the prefix both pages
// already consumed is removed, page N+1 resumes at the cursor with the
// survivors, no gap and no duplicate, and reports resume_ok because the
// consumer lost nothing visible.
func TestEventsRetentionRacingScopedPagination(t *testing.T) {
	s, f, _, _ := scopedEventsServer(t)
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	for i := 1; i <= 5; i++ {
		at := now
		if i <= 2 {
			at = old
		}
		if err := f.AppendExecutionEvent(ctx, model.ExecutionEvent{
			RunID: "run-a", JobID: fmt.Sprintf("job-a%d", i), RepoID: scopeRepoA,
			Type: "job.queued", ToStatus: "queued", CreatedAt: at,
		}); err != nil {
			t.Fatal(err)
		}
	}

	w := doJSON(t, s, http.MethodGet, "/api/v1/events?repo_id="+scopeRepoA+"&limit=2", "events-a", "")
	if w.Code != http.StatusOK {
		t.Fatalf("page 1 = %d: %s", w.Code, w.Body.String())
	}
	page1 := decodeEventsResponse(t, w.Body.Bytes())
	if len(page1.Events) != 2 || page1.Events[0].Seq != 1 || page1.Events[1].Seq != 2 || page1.ResumeStatus != "resume_ok" {
		t.Fatalf("page 1 = %+v", page1)
	}

	// The prune lands between the pages and removes exactly the consumed
	// prefix: the scoped frontier (2) equals the page 1 cursor.
	pruned, retained, err := f.PruneExecutionEvents(ctx, now.Add(-24*time.Hour), 100)
	if err != nil || pruned != 2 || retained != 2 {
		t.Fatalf("racing prune = %d/%d err %v, want 2/2", pruned, retained, err)
	}

	w = doJSON(t, s, http.MethodGet, "/api/v1/events?repo_id="+scopeRepoA+"&limit=2&after="+page1.NextCursor, "events-a", "")
	if w.Code != http.StatusOK {
		t.Fatalf("page 2 = %d: %s", w.Code, w.Body.String())
	}
	page2 := decodeEventsResponse(t, w.Body.Bytes())
	if page2.ResumeStatus != "resume_ok" || page2.RetainedFrom != "2" {
		t.Fatalf("page 2 metadata = %+v", page2)
	}
	if len(page2.Events) != 2 || page2.Events[0].Seq != 3 || page2.Events[1].Seq != 4 {
		t.Fatalf("page 2 = %+v, want seqs 3,4 (no gap, no duplicate)", page2.Events)
	}
	// Page 3 completes the stream without a gap.
	w = doJSON(t, s, http.MethodGet, "/api/v1/events?repo_id="+scopeRepoA+"&limit=2&after="+page2.NextCursor, "events-a", "")
	if w.Code != http.StatusOK {
		t.Fatalf("page 3 = %d: %s", w.Code, w.Body.String())
	}
	page3 := decodeEventsResponse(t, w.Body.Bytes())
	if len(page3.Events) != 1 || page3.Events[0].Seq != 5 {
		t.Fatalf("page 3 = %+v, want seq 5", page3.Events)
	}
}

// TestEventsRepoAccessLossForbidden pins the auth-change contract: a token
// that loses its repo A capability is answered 403 (never 410 or a 200 with
// another scope) on the list, the stream and the snapshot, both repo-scoped
// and unscoped.
func TestEventsRepoAccessLossForbidden(t *testing.T) {
	s, f, _, _ := scopedEventsServer(t)
	seedInterleavedEvents(t, f)
	if w := doJSON(t, s, http.MethodGet, "/api/v1/events?repo_id="+scopeRepoA, "events-a", ""); w.Code != http.StatusOK {
		t.Fatalf("pre-loss list = %d: %s", w.Code, w.Body.String())
	}
	// Rotate the token to a principal that holds only repo B: the repo A
	// routes (and the unscoped snapshot) must now be forbidden.
	if err := s.AuthStore.AddToken("events-a", auth.Principal{Subject: "faktor-a", RepositoryCapabilities: map[string][]auth.Capability{
		capabilityRepoKey(t, scopeRepoB): {auth.CapExecutionEventsRead},
	}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path string
		want       int
	}{
		{"list loses repo A", "/api/v1/events?repo_id=" + scopeRepoA, http.StatusForbidden},
		{"stream loses repo A", "/api/v1/events/stream?repo_id=" + scopeRepoA, http.StatusForbidden},
		{"snapshot loses repo A", "/api/v1/execution-snapshot?repo_id=" + scopeRepoA, http.StatusForbidden},
		{"unscoped snapshot still needs global", "/api/v1/execution-snapshot", http.StatusForbidden},
		{"run-scoped list loses repo A", "/api/v1/events?run_id=run-a", http.StatusForbidden},
	} {
		if w := doJSON(t, s, http.MethodGet, tc.path, "events-a", ""); w.Code != tc.want {
			t.Errorf("%s: GET %s = %d, want %d: %s", tc.name, tc.path, w.Code, tc.want, w.Body.String())
		}
	}
}

// TestExecutionSnapshotFSRepoScope proves the fs/memory snapshot builder
// filters its runs and job counts by repository exactly like the SQL
// payload->>'repo_id' filter, while through_sequence stays the global
// cursor.
func TestExecutionSnapshotFSRepoScope(t *testing.T) {
	s, runA, runB := capabilityServer(t)
	w := doJSON(t, s, http.MethodGet, "/api/v1/execution-snapshot?repo_id="+scopeRepoA, "events-a", "")
	if w.Code != http.StatusOK {
		t.Fatalf("fs repo A snapshot = %d: %s", w.Code, w.Body.String())
	}
	var snap executionSnapshotResponse
	if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.Runs) != 1 || snap.Runs[0].ID != runA.ID || snap.Runs[0].RepoID != scopeRepoA {
		t.Fatalf("fs repo A snapshot runs = %+v", snap.Runs)
	}
	if snap.Counts.Queued != 1 || snap.Counts.Running != 0 {
		t.Fatalf("fs repo A snapshot counts = %+v, want its one queued job", snap.Counts)
	}
	if snap.ThroughSequence == 0 || eventCursorSeq(t, snap.ResumeCursor) != snap.ThroughSequence || snap.ScopeFingerprint == "" {
		t.Fatalf("fs repo A snapshot cursors = %+v", snap)
	}
	if strings.Contains(w.Body.String(), runB.ID) || strings.Contains(w.Body.String(), scopeRepoB) {
		t.Fatalf("fs repo A snapshot leaked repo B: %s", w.Body.String())
	}
	// The global form keeps the whole summary.
	w = doJSON(t, s, http.MethodGet, "/api/v1/execution-snapshot", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("fs global snapshot = %d: %s", w.Code, w.Body.String())
	}
	var global executionSnapshotResponse
	if err := json.Unmarshal(w.Body.Bytes(), &global); err != nil {
		t.Fatal(err)
	}
	if len(global.Runs) != 2 || global.Counts.Queued != 2 {
		t.Fatalf("fs global snapshot = runs %+v counts %+v, want both runs and jobs", global.Runs, global.Counts)
	}
}
