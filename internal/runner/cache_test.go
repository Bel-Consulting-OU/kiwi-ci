package runner

import (
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

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
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
	store := r.newJobCache(task, r.Metrics)

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
	if err := safefs.WriteTarGz(f, ws, []string{"cached.txt"}, false); err != nil {
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
	store := r.newJobCache(task, r.Metrics)
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
		var logged bool
		c := &cache.Client{Server: srv.URL, Logf: func(string, ...any) { logged = true }}
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
