package server

// Atomic retention-read and execution-bootstrap tests. The store-level
// consistency proofs live in internal/storage (PostgreSQL two-connection
// tests); these exercise the HTTP contract over the deterministic fakes and
// the fs repository.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// failingRetentionReadStore fails the atomic retention read with a configured
// error, proving every list/stream read surfaces the failure instead of
// defaulting the watermark or cursor to 0.
type failingRetentionReadStore struct {
	*eventsRetentionFakeStore
	readErr error
}

func (f *failingRetentionReadStore) ReadExecutionEventsRetention(ctx context.Context, afterSeq int64, limit int, scope storage.ExecutionEventScope) ([]model.ExecutionEvent, int64, int64, int64, error) {
	if f.readErr != nil {
		return nil, afterSeq, 0, 0, f.readErr
	}
	return f.eventsRetentionFakeStore.ReadExecutionEventsRetention(ctx, afterSeq, limit, scope)
}

// TestEventsRetentionReadFailureFailsClosed proves a watermark/cursor read
// failure surfaces 500 on the list and refuses the stream before the 200,
// instead of treating the retention state as 0 (which would silently replay
// or skip history).
func TestEventsRetentionReadFailureFailsClosed(t *testing.T) {
	f := &failingRetentionReadStore{
		eventsRetentionFakeStore: &eventsRetentionFakeStore{eventsFakeStore: &eventsFakeStore{dbFakeStore: newDBFakeStore()}},
		readErr:                  errors.New("watermark read failed"),
	}
	s := New("admin-tok")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/events?after=0", "admin-tok", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("list with a failing watermark read = %d, want 500: %s", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/events/stream?after=0", "admin-tok", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("stream with a failing watermark read = %d, want 500: %s", w.Code, w.Body.String())
	}
	// The failure must be surfaced, never mistaken for an empty stream.
	f.readErr = nil
	w := doJSON(t, s, http.MethodGet, "/api/v1/events?after=0", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("list after recovery = %d: %s", w.Code, w.Body.String())
	}
	// A DB store without the atomic snapshot contract fails closed instead of
	// serving a non-atomic summary.
	sNoSnap := New("admin-tok")
	if err := sNoSnap.SwitchToDB(&eventsFakeStore{dbFakeStore: newDBFakeStore()}); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, sNoSnap, http.MethodGet, "/api/v1/execution-snapshot", "admin-tok", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("snapshot on a store without the contract = %d, want 503: %s", w.Code, w.Body.String())
	}
}

// TestEventsLatestCursorNeverRegressesUnderPrune proves latest_cursor comes
// from the store's monotonic cursor, not from the surviving rows: pruning
// EVERY event still reports the pre-prune high-water and the cursor at the
// watermark stays valid.
func TestEventsLatestCursorNeverRegressesUnderPrune(t *testing.T) {
	s, f := newRetentionServer(t)
	now := time.Now().UTC()
	for i := 1; i <= 3; i++ {
		if err := f.AppendExecutionEvent(context.Background(), model.ExecutionEvent{RunID: "r1", Type: "job.queued", CreatedAt: now.Add(-time.Duration(i) * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	highWater, err := f.LatestExecutionEventSeq(context.Background())
	if err != nil || highWater != 3 {
		t.Fatalf("pre-prune latest = %d err %v, want 3", highWater, err)
	}
	// Prune the whole stream (cutoff in the future for every row).
	pruned, retained, err := f.PruneExecutionEvents(context.Background(), now.Add(time.Hour), 100)
	if err != nil || pruned != 3 || retained != 3 {
		t.Fatalf("prune all = %d/%d err %v, want 3/3", pruned, retained, err)
	}
	// The page is empty, but the cursor and latest do not regress.
	w := doJSON(t, s, http.MethodGet, "/api/v1/events?after=3", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("after=watermark with everything pruned = %d, want 200: %s", w.Code, w.Body.String())
	}
	resp := decodeEventsResponse(t, w.Body.Bytes())
	if len(resp.Events) != 0 || eventCursorSeq(t, resp.LatestCursor) != 3 || resp.RetainedFrom != "3" || resp.ResumeStatus != "resume_ok" {
		t.Fatalf("all-pruned page = %+v, want empty latest 3 retained 3", resp)
	}
	if latest, err := f.LatestExecutionEventSeq(context.Background()); err != nil || latest != highWater {
		t.Fatalf("latest after prune = %d err %v, want the pre-prune high-water %d", latest, err, highWater)
	}
	// One below the watermark is expired; the watermark itself is valid.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/events?after=2", "admin-tok", ""); w.Code != http.StatusGone {
		t.Fatalf("after=watermark-1 = %d, want 410: %s", w.Code, w.Body.String())
	}
	// A later append continues from the monotonic cursor, not from 1.
	if err := f.AppendExecutionEvent(context.Background(), model.ExecutionEvent{RunID: "r1", Type: "run.succeeded", CreatedAt: now.Add(2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, s, http.MethodGet, "/api/v1/events?after=3", "admin-tok", "")
	if resp := decodeEventsResponse(t, w.Body.Bytes()); len(resp.Events) != 1 || resp.Events[0].Seq != 4 || eventCursorSeq(t, resp.LatestCursor) != 4 {
		t.Fatalf("post-prune append page = %+v, want seq 4 latest 4", resp)
	}
}

// TestExecutionSnapshotFSBootstrapNoGap proves the fs-mode bootstrap contract:
// a transition applied AFTER the snapshot is read appears in the event stream
// strictly above snapshot.cursor, so a consumer that starts from the snapshot
// can catch up without a gap. It also pins the response shape and the bounded
// active-run/state summary.
func TestExecutionSnapshotFSBootstrapNoGap(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueue(context.Background(), SubmitRun{
		RepoURL: "https://github.com/acme/repo-a.git", RepoFullName: "acme/repo-a",
		Ref: "refs/heads/main", Event: "push", Pipeline: testPipeline,
	}); err != nil {
		t.Fatal(err)
	}

	w := doJSON(t, s, http.MethodGet, "/api/v1/execution-snapshot", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("snapshot = %d: %s", w.Code, w.Body.String())
	}
	var snap executionSnapshotResponse
	if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil {
		t.Fatalf("decode snapshot: %v: %s", err, w.Body.String())
	}
	if snap.Cursor == "" || snap.GeneratedAt.IsZero() {
		t.Fatalf("snapshot cursor/generated_at missing: %+v", snap)
	}
	if len(snap.Runs) != 1 || snap.Runs[0].Status != model.StatusQueued || snap.Runs[0].RepoID != "github.com/acme/repo-a" {
		t.Fatalf("snapshot runs = %+v", snap.Runs)
	}
	if snap.Counts.Queued != 1 || snap.Counts.Running != 0 {
		t.Fatalf("snapshot counts = %+v, want queued 1 running 0", snap.Counts)
	}

	// Inject a transition after the snapshot: lease the queued job.
	c := newTestClientForServer(t, s, "token")
	_, jobID, _, _, _ := leaseJob(t, c)
	if jobID == "" {
		t.Fatal("lease returned no job")
	}

	// A consumer that starts from the snapshot cursor sees every committed
	// transition since, with seq strictly above the snapshot cursor.
	w = doJSON(t, s, http.MethodGet, "/api/v1/events?after="+snap.Cursor, "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("events after snapshot = %d: %s", w.Code, w.Body.String())
	}
	page := decodeEventsResponse(t, w.Body.Bytes())
	sawRunning := false
	for _, e := range page.Events {
		if e.Type == "job.running" && e.JobID == jobID {
			sawRunning = true
		}
	}
	if !sawRunning {
		t.Fatalf("job.running transition missing from after-snapshot page: %+v", page.Events)
	}
	// The later snapshot includes the running state and a higher cursor.
	w = doJSON(t, s, http.MethodGet, "/api/v1/execution-snapshot", "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("second snapshot = %d: %s", w.Code, w.Body.String())
	}
	var snap2 executionSnapshotResponse
	if err := json.Unmarshal(w.Body.Bytes(), &snap2); err != nil {
		t.Fatal(err)
	}
	sawRunningRun := false
	for _, r := range snap2.Runs {
		if r.RepoID == "github.com/acme/repo-a" && r.Status == model.StatusRunning {
			sawRunningRun = true
		}
	}
	if !sawRunningRun || snap2.Counts.Running != 1 {
		t.Fatalf("post-transition snapshot = %+v, want the acme run running and one running job", snap2)
	}
}

// TestExecutionSnapshotCapabilityScope pins the bootstrap route's
// authorization to the event stream's visibility: without repo_id the
// snapshot spans every repository, so only a GLOBAL grant (or admin) passes;
// with repo_id it is authorized exactly like a repository-scoped event read
// (capability for the repository or plain read access to it). A
// repository-scoped grant, a plain reader and the runner bearer are refused
// for the unscoped form; a different repository is refused for the scoped
// form.
func TestExecutionSnapshotCapabilityScope(t *testing.T) {
	s, _, _ := capabilityServer(t)
	for _, tc := range []struct {
		name, token, query string
		want               int
	}{
		{"global capability reads the snapshot", "global-events", "", http.StatusOK},
		{"repo-scoped capability denied (global scope required)", "events-a", "", http.StatusForbidden},
		{"repo reader denied (global scope required)", "reader-a", "", http.StatusForbidden},
		{"read role denied without capability", "read-role", "", http.StatusForbidden},
		{"unrelated capability denied", "graph-only", "", http.StatusForbidden},
		{"admin token unchanged", "admin-tok", "", http.StatusOK},
		{"runner bearer refused", "runner-tok", "", http.StatusUnauthorized},
		{"unauthenticated refused", "", "", http.StatusUnauthorized},
		{"repo-scoped capability reads its repo", "events-a", "?repo_id=github.com/acme/repo-a", http.StatusOK},
		{"repo-scoped capability denied another repo", "events-a", "?repo_id=github.com/acme/repo-b", http.StatusForbidden},
		{"repo reader reads its repo", "reader-a", "?repo_id=github.com/acme/repo-a", http.StatusOK},
		{"repo reader denied another repo", "reader-a", "?repo_id=github.com/acme/repo-b", http.StatusForbidden},
		{"global capability reads any repo", "global-events", "?repo_id=github.com/acme/repo-b", http.StatusOK},
		{"admin token unchanged for a repo", "admin-tok", "?repo_id=github.com/acme/repo-a", http.StatusOK},
	} {
		if w := doJSON(t, s, http.MethodGet, "/api/v1/execution-snapshot"+tc.query, tc.token, ""); w.Code != tc.want {
			t.Errorf("%s: snapshot%s with %q = %d, want %d: %s", tc.name, tc.query, tc.token, w.Code, tc.want, w.Body.String())
		}
	}
	// The repo-scoped snapshot exposes only the addressed repository.
	w := doJSON(t, s, http.MethodGet, "/api/v1/execution-snapshot?repo_id=github.com/acme/repo-a", "events-a", "")
	if w.Code != http.StatusOK {
		t.Fatalf("repo A snapshot = %d: %s", w.Code, w.Body.String())
	}
	var snap executionSnapshotResponse
	if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	for _, run := range snap.Runs {
		if run.RepoID != "github.com/acme/repo-a" {
			t.Fatalf("repo A snapshot leaked run %+v", run)
		}
	}
	if strings.Contains(w.Body.String(), "repo-b") {
		t.Fatalf("repo A snapshot body leaked repo B: %s", w.Body.String())
	}
}
