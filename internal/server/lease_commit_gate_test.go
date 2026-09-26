package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
)

// readCounter counts how many bytes a handler pulled from a request body.
type readCounter struct {
	r io.Reader
	n int64
}

func (c *readCounter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// serveCountingBody drives one handler request with a body whose reads are
// observable, so a test can prove the handler refused before touching it.
func serveCountingBody(s *Server, method, path, bearer string, body []byte, hdrs map[string]string) (*httptest.ResponseRecorder, *readCounter) {
	cr := &readCounter{r: bytes.NewReader(body)}
	req := httptest.NewRequest(method, path, cr)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w, cr
}

// assertLeaseCommitRefusal pins the X1-C contract for one refused upload: 503
// with the typed message, before a single body byte is read and before any
// staging reservation is taken.
func assertLeaseCommitRefusal(t *testing.T, w *httptest.ResponseRecorder, cr *readCounter, budget *staging.Budget) {
	t.Helper()
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("upload = %d, want 503: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "transactional lease commits") {
		t.Fatalf("refusal body = %q, want the typed unsupported-store message", w.Body.String())
	}
	if cr.n != 0 {
		t.Fatalf("handler read %d body bytes before refusing the store", cr.n)
	}
	if used := budget.Used(); used != 0 {
		t.Fatalf("refusal took a staging reservation: Used() = %d, want 0", used)
	}
}

// countCASFiles counts the files under a CAS root (0 when it does not exist).
func countCASFiles(t *testing.T, root string) int {
	t.Helper()
	n := 0
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}

// TestUploadsWithoutLeaseCommitSupportRefusedBeforeBodyOrStaging is the X1-C
// regression: for cache, artifact and snapshot uploads, a DB store lacking
// storage.LeaseCommitStore is refused IMMEDIATELY after request/lease
// authorization — before the body is read, before any staging reservation,
// before any CAS/record work — instead of after the whole body was staged,
// hashed and published.
func TestUploadsWithoutLeaseCommitSupportRefusedBeforeBodyOrStaging(t *testing.T) {
	t.Run("cache", func(t *testing.T) {
		s, f, mb, hdrs := cacheFixture(t)
		budget := s.StagingBudget()
		if budget == nil {
			t.Fatal("cache fixture carries no staging budget")
		}
		s.DB = baseOnlyStore{f}
		w, cr := serveCountingBody(s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+strings.Repeat("a", 64), "runner-tok", []byte("cache-payload"), hdrs)
		assertLeaseCommitRefusal(t, w, cr, budget)
		f.mu.Lock()
		manifests := len(f.cacheMans)
		f.mu.Unlock()
		if manifests != 0 {
			t.Fatalf("cache manifests = %d, want 0", manifests)
		}
		mb.mu.Lock()
		objects := len(mb.objects)
		mb.mu.Unlock()
		if objects != 0 {
			t.Fatalf("CAS objects = %d, want 0", objects)
		}
	})

	t.Run("artifact", func(t *testing.T) {
		s, f, mb, hdrs := artifactIdentityFixture(t)
		budget := s.StagingBudget()
		if budget == nil {
			t.Fatal("artifact fixture carries no staging budget")
		}
		s.DB = baseOnlyStore{f}
		w, cr := serveCountingBody(s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", "runner-tok", []byte("payload"), hdrs)
		assertLeaseCommitRefusal(t, w, cr, budget)
		f.mu.Lock()
		rows := len(f.artifacts)
		f.mu.Unlock()
		if rows != 0 {
			t.Fatalf("artifact rows = %d, want 0", rows)
		}
		mb.mu.Lock()
		objects := len(mb.objects)
		mb.mu.Unlock()
		if objects != 0 {
			t.Fatalf("CAS objects = %d, want 0", objects)
		}
	})

	t.Run("snapshot", func(t *testing.T) {
		f := newDBFakeStore()
		casDir := t.TempDir()
		s, runnerID, jobID, task, _ := snapshotCASServer(t, f, casDir)
		budget := s.StagingBudget()
		if budget == nil {
			t.Fatal("snapshot fixture carries no staging budget")
		}
		s.DB = baseOnlyStore{f}
		hdrs := map[string]string{
			"X-Kiwi-Runner-ID":        runnerID,
			"X-Kiwi-Lease-Token":      task.LeaseToken,
			"X-Kiwi-Lease-Generation": fmt.Sprint(task.LeaseGeneration),
		}
		w, cr := serveCountingBody(s, http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", "token", []byte("snapshot-archive-bytes"), hdrs)
		assertLeaseCommitRefusal(t, w, cr, budget)
		f.mu.Lock()
		records := len(f.snapshots)
		f.mu.Unlock()
		if records != 0 {
			t.Fatalf("snapshot records = %d, want 0", records)
		}
		if n := countCASFiles(t, casDir); n != 0 {
			t.Fatalf("refused snapshot upload wrote %d CAS file(s)", n)
		}
	})
}

// snapshotCountStoreWrapper adds the optional SnapshotCountStore capability to
// a dbFakeStore while counting both the count calls and any list calls, so a
// test can prove the preflight used the count and never scanned the run.
type snapshotCountStoreWrapper struct {
	*dbFakeStore

	mu         sync.Mutex
	count      int
	countErr   error
	countCalls int
	listCalls  int
}

func (w *snapshotCountStoreWrapper) CountSnapshotsForJob(ctx context.Context, runID, jobID string) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.countCalls++
	return w.count, w.countErr
}

func (w *snapshotCountStoreWrapper) ListSnapshotsByRun(ctx context.Context, runID string) ([]model.SnapshotRecord, error) {
	w.mu.Lock()
	w.listCalls++
	w.mu.Unlock()
	return w.dbFakeStore.ListSnapshotsByRun(ctx, runID)
}

func (w *snapshotCountStoreWrapper) calls() (count, list int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.countCalls, w.listCalls
}

// TestSnapshotPreflightUsesStoreCountNeverList pins the X1-D fix: the cap
// preflight uses the optional store-level count when the store provides one
// and never falls back to listing and decoding every record of the run.
func TestSnapshotPreflightUsesStoreCountNeverList(t *testing.T) {
	f := newDBFakeStore()
	s, _, _, _, _ := snapshotCASServer(t, f, t.TempDir())
	wrapped := &snapshotCountStoreWrapper{dbFakeStore: f, count: 7}
	s.DB = wrapped
	n, err := s.snapshotCountForJob(context.Background(), "run-x", "job-y")
	if err != nil || n != 7 {
		t.Fatalf("snapshotCountForJob = (%d, %v), want (7, nil)", n, err)
	}
	countCalls, listCalls := wrapped.calls()
	if countCalls != 1 || listCalls != 0 {
		t.Fatalf("preflight calls = count:%d list:%d, want count-only", countCalls, listCalls)
	}

	// A store without the optional count reports "unsupported" so the caller
	// skips the preflight entirely (the commit-time cap is authoritative)
	// instead of scanning the run.
	s.DB = baseOnlyStore{f}
	if _, err := s.snapshotCountForJob(context.Background(), "run-x", "job-y"); !errors.Is(err, errSnapshotCountUnsupported) {
		t.Fatalf("store without count = %v, want errSnapshotCountUnsupported", err)
	}
}

// TestSnapshotPreflightCountRejectsBeforeBody proves the bandwidth saving is
// real: an over-cap upload is answered 409 from the store count before a
// single body byte is read and before any staging reservation.
func TestSnapshotPreflightCountRejectsBeforeBody(t *testing.T) {
	f := newDBFakeStore()
	s, runnerID, jobID, task, _ := snapshotCASServer(t, f, t.TempDir(), WithSnapshotMaxPerJob(1))
	wrapped := &snapshotCountStoreWrapper{dbFakeStore: f, count: 1}
	s.DB = wrapped
	budget := s.StagingBudget()
	hdrs := map[string]string{
		"X-Kiwi-Runner-ID":        runnerID,
		"X-Kiwi-Lease-Token":      task.LeaseToken,
		"X-Kiwi-Lease-Generation": fmt.Sprint(task.LeaseGeneration),
	}
	w, cr := serveCountingBody(s, http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", "token", []byte("snapshot-archive-bytes"), hdrs)
	if w.Code != http.StatusConflict {
		t.Fatalf("over-cap upload = %d, want 409: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "snapshot count limit reached") {
		t.Fatalf("refusal body = %q, want the count-limit message", w.Body.String())
	}
	if cr.n != 0 {
		t.Fatalf("preflight read %d body bytes; the count must reject before the body", cr.n)
	}
	if used := budget.Used(); used != 0 {
		t.Fatalf("preflight took a staging reservation: Used() = %d, want 0", used)
	}
	countCalls, listCalls := wrapped.calls()
	if countCalls != 1 || listCalls != 0 {
		t.Fatalf("preflight calls = count:%d list:%d, want count-only", countCalls, listCalls)
	}
}

// TestSnapshotCommitTimeCapMaps409WithoutCountStore pins the X1-D decision for
// stores without the optional count (the PostgreSQL store today): the early
// preflight is skipped and the transaction-time cap is authoritative. An
// over-cap upload is therefore answered 409 from the commit predicate, and
// exactly the cap's worth of records exist.
func TestSnapshotCommitTimeCapMaps409WithoutCountStore(t *testing.T) {
	f := newDBFakeStore()
	_, runnerID, jobID, task, c := snapshotCASServer(t, f, t.TempDir(), WithSnapshotMaxPerJob(1))
	body, _ := snapshotArchive(t)
	if w := uploadSnapshotCAS(t, c, jobID, runnerID, task, body); w.Code != http.StatusCreated {
		t.Fatalf("first upload = %d: %s", w.Code, w.Body.String())
	}
	w := uploadSnapshotCAS(t, c, jobID, runnerID, task, body)
	if w.Code != http.StatusConflict {
		t.Fatalf("over-cap upload = %d, want 409 from the commit-time cap: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "snapshot count limit reached") {
		t.Fatalf("refusal body = %q, want the count-limit message", w.Body.String())
	}
	f.mu.Lock()
	records := len(f.snapshots)
	f.mu.Unlock()
	if records != 1 {
		t.Fatalf("snapshot records = %d, want exactly the cap (1)", records)
	}
}
