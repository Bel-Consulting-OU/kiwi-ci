package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// gatedSnapshotStore stalls the two SnapshotStore reads the DB branch of
// listSnapshots performs on channels. A test can therefore park the handler
// inside a store call — deterministically, without timing sleeps — and probe
// the server's lock state while the read is in flight.
type gatedSnapshotStore struct {
	*dbFakeStore
	getRunEntered chan struct{}
	listEntered   chan struct{}
	releaseGetRun chan struct{}
	releaseList   chan struct{}
	getRunOnce    sync.Once
	listOnce      sync.Once
}

func newGatedSnapshotStore(f *dbFakeStore) *gatedSnapshotStore {
	return &gatedSnapshotStore{
		dbFakeStore:   f,
		getRunEntered: make(chan struct{}),
		listEntered:   make(chan struct{}),
		releaseGetRun: make(chan struct{}),
		releaseList:   make(chan struct{}),
	}
}

func (g *gatedSnapshotStore) GetRun(ctx context.Context, id string) (model.Run, error) {
	g.getRunOnce.Do(func() { close(g.getRunEntered) })
	<-g.releaseGetRun
	return g.dbFakeStore.GetRun(ctx, id)
}

func (g *gatedSnapshotStore) ListSnapshotsPage(ctx context.Context, runID string, afterCreatedAt time.Time, afterID string, limit int) (storage.SnapshotPage, error) {
	g.listOnce.Do(func() { close(g.listEntered) })
	<-g.releaseList
	return g.dbFakeStore.ListSnapshotsPage(ctx, runID, afterCreatedAt, afterID, limit)
}

// probeServerLock proves s.mu is free by acquiring it without blocking
// (TryLock never waits) and performing an unrelated control-plane state
// read/write under it. A held lock (the defect) makes TryLock fail instead of
// hanging the test.
func probeServerLock(t *testing.T, s *Server, stage string) {
	t.Helper()
	if !s.mu.TryLock() {
		t.Fatalf("listSnapshots holds s.mu while stalled in the %s", stage)
	}
	_ = s.runs["run-c"]
	s.runs["lock-probe"] = model.Run{ID: "lock-probe"}
	delete(s.runs, "lock-probe")
	s.mu.Unlock()
}

// TestSnapshotListDBLookupReleasesServerLock proves the P2 control-plane
// contract: while the DB branch of listSnapshots is stalled inside GetRun and
// then inside the paged snapshot record read, an unrelated goroutine can
// acquire s.mu and
// read/write server state. Channels gate the fake store and Mutex.TryLock
// probes acquisition, so the test uses no timing sleeps and cannot deadlock.
func TestSnapshotListDBLookupReleasesServerLock(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	g := newGatedSnapshotStore(f)
	s.DB = g
	now := time.Now().UTC()
	f.mu.Lock()
	f.snapshots = append(f.snapshots,
		model.SnapshotRecord{ID: "s-new", RunID: "run-c", CreatedAt: now},
		model.SnapshotRecord{ID: "s-old", RunID: "run-c", CreatedAt: now.Add(-time.Hour)})
	f.mu.Unlock()

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/runs/run-c/snapshots", nil)
		r.Header.Set("Authorization", "Bearer admin-tok")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		done <- w
	}()

	<-g.getRunEntered // the handler is inside the DB run read
	probeServerLock(t, s, "run read")

	close(g.releaseGetRun)
	<-g.listEntered // now inside the DB snapshot record read
	probeServerLock(t, s, "snapshot list read")

	close(g.releaseList)
	w := <-done
	if w.Code != http.StatusOK {
		t.Fatalf("db snapshot list = %d, want 200: %s", w.Code, w.Body.String())
	}
	var listed []struct {
		ID   string `json:"id"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 {
		t.Fatalf("listed snapshots = %d, want 2", len(listed))
	}
	if listed[0].ID != "s-old" || listed[1].ID != "s-new" {
		t.Fatalf("list order = [%s %s], want [s-old s-new]", listed[0].ID, listed[1].ID)
	}
	if listed[0].Path != "" || listed[1].Path != "" {
		t.Fatalf("server-local path leaked in list response: %+v", listed)
	}
}

// TestSnapshotListDBBranchNeverTakesServerLock pins the structural contract:
// the DB branch of listSnapshots never reaches the memory-mode lock site, on
// the success and the missing-run 404 paths alike. The snapshotListMemoryLock
// seam counts entries; the same server flipped to memory mode re-lists the
// run to prove the probe is actually wired.
func TestSnapshotListDBBranchNeverTakesServerLock(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	f.mu.Lock()
	f.snapshots = append(f.snapshots, model.SnapshotRecord{ID: "s-db", RunID: "run-c", CreatedAt: time.Now().UTC()})
	f.mu.Unlock()

	var lockCalls atomic.Int32
	prev := snapshotListMemoryLock
	snapshotListMemoryLock = func() { lockCalls.Add(1) }
	t.Cleanup(func() { snapshotListMemoryLock = prev })

	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("db snapshot list = %d: %s", w.Code, w.Body.String())
	}
	if !bytesContainID(w.Body.Bytes(), "s-db") {
		t.Fatalf("db snapshot list missing record: %s", w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/missing/snapshots", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("db missing run list = %d, want 404", w.Code)
	}
	if got := lockCalls.Load(); got != 0 {
		t.Fatalf("db branch reached the s.mu lock site %d times, want 0", got)
	}

	// Sanity: memory mode does reach the lock site, so the probe is wired.
	s.DB = nil
	s.mu.Lock()
	s.runs["run-c"] = model.Run{ID: "run-c", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Status: model.StatusRunning}
	s.snapshots["s-mem"] = model.SnapshotRecord{ID: "s-mem", RunID: "run-c", CreatedAt: time.Now().UTC()}
	s.mu.Unlock()
	w = doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("memory snapshot list = %d: %s", w.Code, w.Body.String())
	}
	if !bytesContainID(w.Body.Bytes(), "s-mem") {
		t.Fatalf("memory snapshot list missing record: %s", w.Body.String())
	}
	if got := lockCalls.Load(); got != 1 {
		t.Fatalf("memory branch lock-site entries = %d, want 1", got)
	}
}

// bytesContainID reports whether a JSON array body contains the given id,
// without depending on field order or record ordering.
func bytesContainID(body []byte, id string) bool {
	var recs []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &recs); err != nil {
		return false
	}
	for _, rec := range recs {
		if rec.ID == id {
			return true
		}
	}
	return false
}
