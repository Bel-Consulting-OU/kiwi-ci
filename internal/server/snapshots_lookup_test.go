package server

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// countingSnapshotStore wraps the fake store and counts the two snapshot
// reads, so a test can prove which one the download used. listErr makes the
// unbounded collection read fail: a download that still succeeds cannot have
// depended on it.
type countingSnapshotStore struct {
	*dbFakeStore
	getCalls  atomic.Int32
	listCalls atomic.Int32
	listErr   error
	lastRun   string
	lastID    string
}

func (c *countingSnapshotStore) GetSnapshot(ctx context.Context, runID, snapshotID string) (model.SnapshotRecord, bool, error) {
	c.getCalls.Add(1)
	c.lastRun, c.lastID = runID, snapshotID
	return c.dbFakeStore.GetSnapshot(ctx, runID, snapshotID)
}

func (c *countingSnapshotStore) ListSnapshotsByRun(ctx context.Context, runID string) ([]model.SnapshotRecord, error) {
	c.listCalls.Add(1)
	if c.listErr != nil {
		return nil, c.listErr
	}
	return c.dbFakeStore.ListSnapshotsByRun(ctx, runID)
}

// TestSnapshotDownloadUsesSingleRecordLookup pins the L4-B retrieval
// contract: the DB-mode download resolves the record through ONE
// GetSnapshot(run_id, id) point read and never through the run's whole
// record collection — even when the collection read is failing, the download
// still works.
func TestSnapshotDownloadUsesSingleRecordLookup(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	if w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t)); w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	rec := f.snapshots[len(f.snapshots)-1]
	// A second record of the same run must not be touched either.
	f.snapshots = append(f.snapshots, model.SnapshotRecord{ID: "other", RunID: "run-c", CreatedAt: time.Now().UTC()})
	f.mu.Unlock()

	counter := &countingSnapshotStore{dbFakeStore: f, listErr: context.DeadlineExceeded}
	s.DB = counter
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/"+rec.ID, "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("download = %d, want 200: %s", w.Code, w.Body.String())
	}
	if got := counter.getCalls.Load(); got != 1 {
		t.Fatalf("GetSnapshot calls = %d, want exactly 1", got)
	}
	if got := counter.listCalls.Load(); got != 0 {
		t.Fatalf("ListSnapshotsByRun calls = %d, want 0 (download must not list the run)", got)
	}
	if counter.lastRun != "run-c" || counter.lastID != rec.ID {
		t.Fatalf("GetSnapshot(%q, %q), want (run-c, %s)", counter.lastRun, counter.lastID, rec.ID)
	}

	// An unknown id is one point read too, answered 404.
	counter.getCalls.Store(0)
	counter.listCalls.Store(0)
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/missing", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown snapshot = %d, want 404", w.Code)
	}
	if got := counter.getCalls.Load(); got != 1 {
		t.Fatalf("unknown-id GetSnapshot calls = %d, want 1", got)
	}
	if got := counter.listCalls.Load(); got != 0 {
		t.Fatalf("unknown-id ListSnapshotsByRun calls = %d, want 0", got)
	}

	// A cross-run id is a point read scoped by run_id: the store reports
	// not-found and no other run's record can be served.
	cross := &countingSnapshotStore{dbFakeStore: f}
	s.DB = cross
	f.mu.Lock()
	f.snapshots = append(f.snapshots, model.SnapshotRecord{ID: "cross-run", RunID: "run-other", CreatedAt: time.Now().UTC()})
	f.mu.Unlock()
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/cross-run", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("cross-run snapshot = %d, want 404", w.Code)
	}
	if got := cross.getCalls.Load(); got != 1 {
		t.Fatalf("cross-run GetSnapshot calls = %d, want 1", got)
	}
}
