package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// TestCacheUploadTargetsJobScopedRoute exercises the executor-facing store:
// a save must reach PUT /api/v1/jobs/{id}/cache/{key} with the lease
// contract headers and without the retired repository/trust-domain headers.
func TestCacheUploadTargetsJobScopedRoute(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	task := basicTask("version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n")
	r := testRunnerFor(t, ts, Config{})
	store := mustJobCache(t, r, task)

	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Save("k123", ws, []string{"f.txt"}); err != nil {
		t.Fatalf("save: %v", err)
	}

	var putPath string
	fsrv.mu.Lock()
	for _, req := range fsrv.requests {
		if req.Method == http.MethodPut && strings.Contains(req.Path, "/cache/") {
			putPath = req.Path
		}
	}
	fsrv.mu.Unlock()
	if putPath != "/api/v1/jobs/job-1/cache/k123" {
		t.Fatalf("cache PUT path = %q, want /api/v1/jobs/job-1/cache/k123", putPath)
	}
	h := fsrv.headerOf(http.MethodPut, "/api/v1/jobs/job-1/cache/")
	if h == nil {
		t.Fatal("no cache PUT recorded")
	}
	for name, want := range map[string]string{
		cache.HeaderRunnerID:        "runner-1",
		cache.HeaderLeaseToken:      "lease-token",
		cache.HeaderLeaseGeneration: "3",
	} {
		if got := h.Get(name); got != want {
			t.Errorf("cache PUT %s = %q, want %q", name, got, want)
		}
	}
	for _, retired := range []string{"X-Kiwi-Repository", "X-Kiwi-Trust-Domain"} {
		if got := h.Get(retired); got != "" {
			t.Errorf("cache PUT must not send %s, got %q", retired, got)
		}
	}
}

// TestJobCacheInheritsUnifiedArchiveBound pins W5-A at the runner layer: the
// executor's job-scoped cache client and Store leave both compressed-size
// knobs at 0 (use the layer default), which resolves to the cache package's
// ONE authoritative MaxArchiveBytes — the same bound the Store and the
// control-plane endpoint enforce, and above the retired 4 GiB client cap.
func TestJobCacheInheritsUnifiedArchiveBound(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()
	task := basicTask("version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n")
	r := testRunnerFor(t, ts, Config{})
	store := mustJobCache(t, r, task)
	if store.MaxCacheBytes != 0 {
		t.Fatalf("job cache Store.MaxCacheBytes = %d, want 0 (shared default)", store.MaxCacheBytes)
	}
	tr, ok := store.Client.Transport.(*cacheTransport)
	if !ok {
		t.Fatalf("store transport = %T, want *cacheTransport", store.Client.Transport)
	}
	if tr.client.MaxCompressedBytes != 0 {
		t.Fatalf("job cache client MaxCompressedBytes = %d, want 0 (shared default)", tr.client.MaxCompressedBytes)
	}
	if cache.MaxArchiveBytes != 8<<30 {
		t.Fatalf("cache.MaxArchiveBytes = %d, want 8 GiB", cache.MaxArchiveBytes)
	}
	if cache.MaxArchiveBytes <= 4<<30 {
		t.Fatalf("cache.MaxArchiveBytes = %d, not above the retired 4 GiB client cap", cache.MaxArchiveBytes)
	}
}

// TestCacheRestoreFallsBackToJobScopedRoute verifies the restore path: a
// miss on the job-scoped route leaves the store empty, and a subsequent hit
// downloads and extracts the archive the server signed with a digest.
func TestCacheRestoreFallsBackToJobScopedRoute(t *testing.T) {
	task := basicTask("version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n")
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "cached.txt"), []byte("cached"), 0o644); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "k.tar.gz")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	wsRoot, err := safefs.OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer wsRoot.Close()
	if err := safefs.WriteTarGzFromRoot(f, wsRoot, []string{"cached.txt"}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)

	var mu sync.Mutex
	var gets int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/api/v1/jobs/job-1/cache/") {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		gets++
		mu.Unlock()
		w.Header().Set(cache.HeaderCacheSHA256, hex.EncodeToString(sum[:]))
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	r := testRunnerFor(t, srv, Config{})
	store := mustJobCache(t, r, task)
	dest := t.TempDir()
	hit, err := store.Restore("k", dest, []string{"cached.txt"})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !hit {
		t.Fatal("restore reported miss, want hit from the job-scoped route")
	}
	got, err := os.ReadFile(filepath.Join(dest, "cached.txt"))
	if err != nil || string(got) != "cached" {
		t.Fatalf("extracted content = %q, %v", got, err)
	}
	mu.Lock()
	n := gets
	mu.Unlock()
	if n != 1 {
		t.Fatalf("cache GET count = %d, want 1", n)
	}
}

// TestCacheClientRestoreDigestAndBounds checks the raw client contract:
// lease headers are attached, the stream is bounded by MaxCompressedBytes,
// a present digest is verified at EOF, and an absent digest skips
// verification with a debug log.
func TestCacheClientRestoreDigestAndBounds(t *testing.T) {
	content := []byte("hello-cache")
	sum := sha256.Sum256(content)
	lease := map[string]string{
		cache.HeaderRunnerID:        "runner-7",
		cache.HeaderLeaseToken:      "tok",
		cache.HeaderLeaseGeneration: "2",
	}
	var mu sync.Mutex
	var lastHeader http.Header
	body := content
	digest := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastHeader = r.Header.Clone()
		mu.Unlock()
		if digest != "" {
			w.Header().Set(cache.HeaderCacheSHA256, digest)
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	t.Run("digest verified", func(t *testing.T) {
		c := &cache.Client{Server: srv.URL}
		rc, err := c.Restore(context.Background(), "job-9", lease, "k")
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		got, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(got) != string(content) {
			t.Fatalf("content = %q", got)
		}
		mu.Lock()
		h := lastHeader
		mu.Unlock()
		if h.Get(cache.HeaderRunnerID) != "runner-7" || h.Get(cache.HeaderLeaseToken) != "tok" || h.Get(cache.HeaderLeaseGeneration) != "2" {
			t.Fatalf("lease headers not attached: %v", h)
		}
		if h.Get("X-Kiwi-Repository") != "" || h.Get("X-Kiwi-Trust-Domain") != "" {
			t.Fatalf("retired headers must not be sent: %v", h)
		}
	})

	t.Run("digest mismatch rejected", func(t *testing.T) {
		mu.Lock()
		digest = strings.Repeat("0", 64)
		mu.Unlock()
		defer func() {
			mu.Lock()
			digest = hex.EncodeToString(sum[:])
			mu.Unlock()
		}()
		c := &cache.Client{Server: srv.URL}
		rc, err := c.Restore(context.Background(), "job-9", lease, "k")
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		if _, err := io.ReadAll(rc); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
			t.Fatalf("read error = %v, want digest mismatch", err)
		}
	})

	t.Run("bounded stream", func(t *testing.T) {
		c := &cache.Client{Server: srv.URL, MaxCompressedBytes: 4}
		rc, err := c.Restore(context.Background(), "job-9", lease, "k")
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		if _, err := io.ReadAll(rc); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("read error = %v, want compressed-bytes bound", err)
		}
	})

	t.Run("absent digest skips with debug log", func(t *testing.T) {
		mu.Lock()
		digest = ""
		mu.Unlock()
		defer func() {
			mu.Lock()
			digest = hex.EncodeToString(sum[:])
			mu.Unlock()
		}()
		// An absent digest header is only accepted through the explicit
		// legacy opt-in; the modern job-scoped route always sends it.
		var logged bool
		c := &cache.Client{Server: srv.URL, AllowUnverifiedLegacyRestore: true, Logf: func(string, ...any) { logged = true }}
		rc, err := c.Restore(context.Background(), "job-9", lease, "k")
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		if _, err := io.ReadAll(rc); err != nil {
			t.Fatalf("read: %v", err)
		}
		if !logged {
			t.Fatal("missing digest header must be logged as a debug diagnostic")
		}
	})
}

// TestCacheRestoreCloseDrainStaysStallBounded pins the runner adaptation's
// close ordering: the cache client verifies the digest on Close by draining
// the unread stream, and the runner's stall guard must stay armed through
// that drain, so a peer that delivered a prefix and stopped sending
// terminates Close on the idle bound instead of hanging it. Disarming the
// guard (or canceling the request) before the inner Close is the regression
// this guards.
func TestCacheRestoreCloseDrainStaysStallBounded(t *testing.T) {
	full := bytes.Repeat([]byte("z"), 64)
	sum := sha256.Sum256(full)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(cache.HeaderCacheSHA256, hex.EncodeToString(sum[:]))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(full[:8])
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()

	c := &cache.Client{Server: srv.URL, HTTP: srv.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := newStallGuard(cancel, 200*time.Millisecond)
	rc, err := c.Restore(ctx, "job-1", nil, "key")
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	body := &stallGuardedBody{ReadCloser: rc, guard: guard, cancel: cancel}
	if _, err := io.ReadFull(body, make([]byte, 4)); err != nil {
		t.Fatalf("prefix read: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- body.Close() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stalled verifying drain reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung: the stall guard was disarmed before the verifying drain")
	}
}

// mustJobCache builds a job cache through the runner's ownership-checked
// manager, failing the test when the namespace cannot be acquired.
func mustJobCache(t *testing.T, r *Runner, task server.Task) *cache.Store {
	t.Helper()
	return mustJobCacheWithMetrics(t, r, task, r.Metrics)
}

// mustJobCacheWithMetrics is mustJobCache for tests that pass an explicit
// metrics registry.
func mustJobCacheWithMetrics(t *testing.T, r *Runner, task server.Task, metrics *Metrics) *cache.Store {
	t.Helper()
	store, err := r.newJobCache(task, metrics)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
