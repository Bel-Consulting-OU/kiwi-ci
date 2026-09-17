package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

func TestFlowGCSweepTempFiles(t *testing.T) {
	if got := sweepTempFiles("", time.Now()); got != 0 {
		t.Fatalf("empty root sweep = %d", got)
	}
	root := t.TempDir()
	old := time.Now().Add(-48 * time.Hour)
	for _, sub := range []string{"artifacts", "cache"} {
		dir := filepath.Join(root, sub)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		stale := filepath.Join(dir, "stale.tmp")
		fresh := filepath.Join(dir, "fresh.tmp")
		keep := filepath.Join(dir, "keep.txt")
		for _, p := range []string{stale, fresh, keep} {
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chtimes(stale, old, old); err != nil {
			t.Fatal(err)
		}
		// A directory named *.tmp is skipped.
		if err := os.MkdirAll(filepath.Join(dir, "dir.tmp"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Recursive upload scratch files: a fresh one survives, a stale one is
	// removed, and depth beyond the bound is left alone.
	deep := filepath.Join(root, "artifacts", "run", "job")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	staleDeep := filepath.Join(deep, ".a.tmp")
	freshDeep := filepath.Join(deep, ".b.tmp")
	for _, p := range []string{staleDeep, freshDeep} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(staleDeep, old, old); err != nil {
		t.Fatal(err)
	}
	tooDeep := filepath.Join(deep, "l1", "l2", "l3")
	if err := os.MkdirAll(tooDeep, 0o700); err != nil {
		t.Fatal(err)
	}
	tooDeepFile := filepath.Join(tooDeep, "deep.tmp")
	if err := os.WriteFile(tooDeepFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tooDeepFile, old, old); err != nil {
		t.Fatal(err)
	}

	removed := sweepTempFiles(root, time.Now())
	if removed != 3 {
		t.Fatalf("swept %d temp files, want 3", removed)
	}
	for _, gone := range []string{filepath.Join(root, "artifacts", "stale.tmp"), filepath.Join(root, "cache", "stale.tmp"), staleDeep} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Fatalf("%s not removed: %v", gone, err)
		}
	}
	for _, kept := range []string{filepath.Join(root, "artifacts", "fresh.tmp"), freshDeep, tooDeepFile} {
		if _, err := os.Stat(kept); err != nil {
			t.Fatalf("%s unexpectedly removed: %v", kept, err)
		}
	}
	// A missing directory is skipped, not fatal.
	if got := sweepTempFilesRecursive(filepath.Join(root, "ghost"), 0, time.Now()); got != 0 {
		t.Fatalf("missing dir recursive sweep = %d", got)
	}
	if got := sweepTempFilesRecursive(root, 3, time.Now()); got != 0 {
		t.Fatalf("depth-bounded sweep = %d", got)
	}
}

func TestFlowGCPrunesJobLocksAndDeliveries(t *testing.T) {
	s := New("tok")
	s.jobLock("ghost")
	s.mu.Lock()
	s.deliveries["d1"] = "missing-run"
	s.runs["old-run"] = model.Run{ID: "old-run", CreatedAt: time.Now().UTC().Add(-48 * time.Hour)}
	s.deliveries["d2"] = "old-run"
	s.runs["live-run"] = model.Run{ID: "live-run", CreatedAt: time.Now().UTC()}
	s.deliveries["d3"] = "live-run"
	s.mu.Unlock()
	s.GC(context.Background(), time.Now().UTC())
	s.mu.Lock()
	_, ghostLock := s.jobLocks["ghost"]
	_, d1 := s.deliveries["d1"]
	_, d2 := s.deliveries["d2"]
	_, d3 := s.deliveries["d3"]
	s.mu.Unlock()
	if ghostLock {
		t.Fatal("stale job lock survived GC")
	}
	if d1 || d2 {
		t.Fatal("stale deliveries survived GC")
	}
	if !d3 {
		t.Fatal("live delivery was pruned")
	}
}

func TestFlowGCPendingSidecarPruning(t *testing.T) {
	// Memory mirror: stale entries are dropped, fresh kept.
	s := New("tok")
	old := encodePendingSidecar("old", time.Now().UTC().Add(-8*24*time.Hour))
	fresh := encodePendingSidecar("fresh", time.Now().UTC())
	s.pendingSidecars["a"] = old
	s.pendingSidecars["b"] = fresh
	s.pendingSidecars["legacy"] = "digest-only"
	s.GC(context.Background(), time.Now().UTC())
	if _, ok := s.pendingSidecars["a"]; ok {
		t.Fatal("stale pending sidecar survived")
	}
	if _, ok := s.pendingSidecars["b"]; !ok {
		t.Fatal("fresh pending sidecar pruned")
	}
	if _, ok := s.pendingSidecars["legacy"]; ok {
		t.Fatal("legacy bare-digest entry must be pruned")
	}

	// DB store failure is logged only.
	s2, f, _, _ := cacheFixture(t)
	f.mu.Lock()
	f.pendingErr = errors.New("prune down")
	f.mu.Unlock()
	s2.GC(context.Background(), time.Now().UTC())
	f.mu.Lock()
	f.pendingErr = nil
	f.pendingSidecars["job-a\x00bin\x00sbom"] = fakePendingSidecar{digest: "d", createdAt: time.Now().UTC().Add(-8 * 24 * time.Hour)}
	f.mu.Unlock()
	s2.GC(context.Background(), time.Now().UTC())
	f.mu.Lock()
	_, survived := f.pendingSidecars["job-a\x00bin\x00sbom"]
	f.mu.Unlock()
	if survived {
		t.Fatal("db stale pending sidecar survived GC")
	}
}

func TestFlowGCStatsAndStoreSweep(t *testing.T) {
	s, _ := fcMemoryBlobServer(t)
	stale := filepath.Join(s.store.Root, "cache")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	oldFile := filepath.Join(stale, "x.tmp")
	if err := os.WriteFile(oldFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(oldFile, past, past); err != nil {
		t.Fatal(err)
	}
	stats := s.GC(context.Background(), time.Now().UTC())
	if stats.TempFilesRemoved != 1 {
		t.Fatalf("GC stats = %+v", stats)
	}
}

// fcScopedLogServer installs a principal that may read repo-b only.
func fcScopedLogServer(t *testing.T, s *Server) {
	t.Helper()
	if err := s.AuthStore.AddToken("outsider", fcOutsiderPrincipal()); err != nil {
		t.Fatal(err)
	}
}

func TestFlowStreamLogsErrorBranches(t *testing.T) {
	// Missing run: 404.
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/missing/logs/stream", "secret", ""); w.Code != http.StatusNotFound {
		t.Fatalf("missing run stream = %d, want 404", w.Code)
	}
	// DB run read failure: 500.
	sdb, f, _, _ := cacheFixture(t)
	sdb.DB = &fcStore{dbFakeStore: f, getRunErr: errors.New("run read down")}
	if w := doJSON(t, sdb, http.MethodGet, "/api/v1/runs/run-c/logs/stream", "admin-tok", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("run read failure stream = %d, want 500", w.Code)
	}
	// Scoped denial: 403.
	sdb2, _, _, _ := cacheFixture(t)
	fcScopedLogServer(t, sdb2)
	if w := doJSON(t, sdb2, http.MethodGet, "/api/v1/runs/run-c/logs/stream", "outsider", ""); w.Code != http.StatusForbidden {
		t.Fatalf("scoped stream = %d, want 403", w.Code)
	}
}

func TestFlowStreamLogsReadErrors(t *testing.T) {
	// A generic read failure emits an SSE error event and closes.
	s, f, _, _ := cacheFixture(t)
	s.LogStreamIdleTimeout = time.Hour
	s.DB = &fcStore{dbFakeStore: f, readLogsErr: errors.New("log store down")}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/runs/run-c/logs/stream", nil)
	r.SetPathValue("id", "run-c")
	r.Header.Set("Authorization", "Bearer admin-tok")
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.streamLogs(w, r)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not close on read failure")
	}
	if body := w.Body.String(); !strings.Contains(body, "event: error") || !strings.Contains(body, "log store down") {
		t.Fatalf("error stream body = %q", body)
	}

	// ErrNotFound read failure ends the stream cleanly: the 200 response is
	// already committed, so the stream signals done instead of a 404 body.
	s2, f2, _, _ := cacheFixture(t)
	s2.DB = &fcStore{dbFakeStore: f2, readLogsErr: storage.ErrNotFound}
	r2 := httptest.NewRequest(http.MethodGet, "/api/v1/runs/run-c/logs/stream", nil)
	r2.SetPathValue("id", "run-c")
	r2.Header.Set("Authorization", "Bearer admin-tok")
	w2 := httptest.NewRecorder()
	s2.streamLogs(w2, r2)
	if body := w2.Body.String(); !strings.Contains(body, "event: done") || strings.Contains(body, "event: error") {
		t.Fatalf("not-found stream body = %q", body)
	}
}

func TestFlowStreamLogsCanceledContext(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	s.DB = &fcStore{dbFakeStore: f, readLogsErr: errors.New("log store down")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/runs/run-c/logs/stream", nil).WithContext(ctx)
	r.SetPathValue("id", "run-c")
	r.Header.Set("Authorization", "Bearer admin-tok")
	w := httptest.NewRecorder()
	s.streamLogs(w, r)
	if strings.Contains(w.Body.String(), "event: error") {
		t.Fatalf("canceled context must close silently, got %q", w.Body.String())
	}
}

type fcNoFlushWriter struct {
	hdr  http.Header
	code int
}

func (w *fcNoFlushWriter) Header() http.Header {
	if w.hdr == nil {
		w.hdr = http.Header{}
	}
	return w.hdr
}
func (w *fcNoFlushWriter) WriteHeader(code int) { w.code = code }
func (w *fcNoFlushWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func TestFlowStreamLogsNonFlusher(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.runs["run1"] = model.Run{ID: "run1", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Status: model.StatusRunning}
	s.mu.Unlock()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/runs/run1/logs/stream", nil)
	r.SetPathValue("id", "run1")
	w := &fcNoFlushWriter{}
	s.streamLogs(w, r)
	if w.code != http.StatusInternalServerError {
		t.Fatalf("non-flusher stream = %d, want 500", w.code)
	}
}

func TestFlowJSONQuote(t *testing.T) {
	if got := jsonQuote("a\"b\n"); got != `"a\"b\n"` {
		t.Fatalf("jsonQuote = %q", got)
	}
}
