package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// TestRunnerCachePreflightUsesResolvedBound is the P2 regression: the
// download preflight must use the RESOLVED per-archive bound (8 GiB default),
// not the raw zero MaxCacheBytes field that disabled it entirely for the
// normal unconfigured runner.
func TestRunnerCachePreflightUsesResolvedBound(t *testing.T) {
	r := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{})
	store := r.newJobCache(basicTask(payloadPipeline), r.Metrics)
	if store.MaxCacheBytes != 0 {
		t.Fatalf("sanity: MaxCacheBytes = %d, want the unconfigured zero", store.MaxCacheBytes)
	}
	tr, ok := store.Client.Transport.(*cacheTransport)
	if !ok {
		t.Fatalf("transport = %T, want *cacheTransport", store.Client.Transport)
	}
	if tr.maxDisk != cache.MaxArchiveBytes {
		t.Fatalf("preflight maxDisk = %d, want the resolved default %d", tr.maxDisk, cache.MaxArchiveBytes)
	}

	r2 := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{CacheArchiveMaxBytes: 1 << 20})
	store2 := r2.newJobCache(basicTask(payloadPipeline), r2.Metrics)
	tr2 := store2.Client.Transport.(*cacheTransport)
	if tr2.maxDisk != 1<<20 || store2.MaxStoredBytes() != 1<<20 {
		t.Fatalf("configured bound not used consistently: maxDisk=%d MaxStoredBytes=%d", tr2.maxDisk, store2.MaxStoredBytes())
	}
}

// TestRunnerCacheRetentionEvictsToBounds pins the runner-local aggregate
// bound: even when every save uses a fresh logical key, the cache tree never
// exceeds the configured byte/entry caps, and the maintenance entry point
// reports the (now empty) remainder.
func TestRunnerCacheRetentionEvictsToBounds(t *testing.T) {
	r := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{
		CacheRoot: t.TempDir(), CacheMaxBytes: 2500, CacheMaxEntries: 3, CacheMaxAge: time.Hour,
	})
	store := &cache.Store{Root: r.cacheRootDir(), Retention: r.cacheRetentionPolicy()}
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 6; i++ {
		ws := t.TempDir()
		writeCaptureBytes(t, filepath.Join(ws, "f.bin"), 800)
		key := fmt.Sprintf("key%02d", i)
		if err := store.SaveContext(context.Background(), key, ws, []string{"f.bin"}); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(r.cacheRootDir(), key+".tar.gz")
		when := base.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(r.cacheRootDir())
	if err != nil {
		t.Fatal(err)
	}
	var count int
	var total int64
	for _, de := range entries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".tar.gz") {
			continue
		}
		fi, ierr := de.Info()
		if ierr != nil {
			continue
		}
		count++
		total += fi.Size()
	}
	if count > 3 {
		t.Fatalf("cache entries = %d, want <= 3", count)
	}
	if total > 2500 {
		t.Fatalf("cache bytes = %d, want <= 2500", total)
	}
	if _, err := os.Stat(filepath.Join(r.cacheRootDir(), "key05.tar.gz")); err != nil {
		t.Fatalf("newest entry missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.cacheRootDir(), "key00.tar.gz")); !os.IsNotExist(err) {
		t.Fatalf("oldest entry survived the caps (err=%v)", err)
	}
	// The maintenance pass is idempotent once the policy holds.
	r.pruneJobCache(context.Background())
}

// TestRunnerJobTimeoutStopsCacheRestoreBeforeSteps is the P1/P2 lifecycle
// regression: cache restore runs under the declared job lifetime. The remote
// cache endpoint never answers; with a 150ms job timeout the restore must be
// torn down and the job completed as cancelled well before the streaming
// stall guard's 90-second bound.
func TestRunnerJobTimeoutStopsCacheRestoreBeforeSteps(t *testing.T) {
	release := make(chan struct{})
	var completeMu atomic.Value
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/cache/"):
			select {
			case <-r.Context().Done():
			case <-release:
			}
		case strings.HasSuffix(r.URL.Path, "/complete"):
			var c server.Complete
			_ = json.NewDecoder(r.Body).Decode(&c)
			completeMu.Store(c.Status)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()
	defer close(release)

	r := testRunnerFor(t, ts, Config{CacheArchiveMaxBytes: 1 << 20})
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }
	pipelineText := "version: 1\njobs:\n  build:\n    steps:\n      - run: " + nativeScript("true", "exit 0") + "\n    cache:\n      - name: c\n        key: k\n        paths: [out]\n"
	task := basicTask(pipelineText)
	task.Job.JobTimeout = 150 * time.Millisecond

	start := time.Now()
	r.execute(context.Background(), task)
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("execute took %v; the cache restore ignored the job deadline", elapsed)
	}
	got, ok := completeMu.Load().(model.Status)
	if !ok || got != model.StatusCancelled {
		t.Fatalf("completion status = %v, want cancelled", completeMu.Load())
	}
}

// TestRunnerArtifactCaptureFinalizeKeepsBytesOnRemovalFailure pins the
// artifact staging fail-closed rule: when the archive cannot be removed, the
// finalize callback must NOT release the staging charge; the bytes stay
// charged as cleanup debt until a maintenance retry reclaims them.
func TestRunnerArtifactCaptureFinalizeKeepsBytesOnRemovalFailure(t *testing.T) {
	const reserve = 4096
	r := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{StagingMaxBytes: reserve})
	budget, err := r.dependencyStaging()
	if err != nil {
		t.Fatal(err)
	}
	fin, err := r.artifactCaptureReserve()(context.Background(), reserve)
	if err != nil {
		t.Fatal(err)
	}
	// A non-empty directory where the archive is expected: os.Remove fails,
	// so both the artifact cleanup and CleanupSpool cannot reclaim it.
	dir := filepath.Join(t.TempDir(), "capture")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(dir, "x")
	if err := os.WriteFile(inner, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fin(dir); err == nil {
		t.Fatal("finalize reported success while the archive was still present")
	}
	if used := budget.Used(); used != reserve {
		t.Fatalf("staging ledger = %d after a failed cleanup, want the full %d still charged", used, reserve)
	}
	if pending := budget.PendingCleanup(); pending != 1 {
		t.Fatalf("pending cleanup = %d, want 1", pending)
	}
	// Make the path removable; the maintenance retry reclaims the debt.
	if err := os.Remove(inner); err != nil {
		t.Fatal(err)
	}
	r.maintainStaging(context.Background())
	if used := budget.Used(); used != 0 {
		t.Fatalf("staging ledger = %d after the retry, want 0", used)
	}
	if pending := budget.PendingCleanup(); pending != 0 {
		t.Fatalf("pending cleanup = %d after the retry, want 0", pending)
	}
}

// runnerArchiveBytes returns a real cache archive (tar.gz of "f") for tests
// that need a remote endpoint serving a valid, extractable entry.
func runnerArchiveBytes(t *testing.T) []byte {
	t.Helper()
	src := &cache.Store{Root: t.TempDir()}
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "f"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := src.SaveContext(context.Background(), "seed", ws, []string{"f"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(src.Root, "seed.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// runnerPublishedCacheBytes sums the published archives under the runner's
// cache root.
func runnerPublishedCacheBytes(t *testing.T, root string) int64 {
	t.Helper()
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, de := range entries {
		if de.IsDir() || strings.HasPrefix(de.Name(), ".") || !strings.HasSuffix(de.Name(), ".tar.gz") {
			continue
		}
		fi, ierr := de.Info()
		if ierr != nil {
			continue
		}
		total += fi.Size()
	}
	return total
}

// TestRunnerCacheAggregateBoundAcrossJobs is the P1 core regression: every
// job builds its own Store, but all of them share the runner's Manager, so
// concurrent jobs can never publish more than the aggregate cache budget.
func TestRunnerCacheAggregateBoundAcrossJobs(t *testing.T) {
	root := t.TempDir()
	r := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{
		CacheRoot: root, CacheMaxBytes: 2500, CacheMaxEntries: 100, CacheArchiveMaxBytes: 1200,
	})
	taskA := basicTask(payloadPipeline)
	taskB := basicTask(payloadPipeline)
	taskB.Job.ID = "job-2"
	stores := []*cache.Store{r.newJobCache(taskA, r.Metrics), r.newJobCache(taskB, r.Metrics)}

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		ws := t.TempDir()
		writeCaptureBytes(t, filepath.Join(ws, "f.bin"), 800)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = stores[i%len(stores)].SaveContext(context.Background(), fmt.Sprintf("key%02d", i), ws, []string{"f.bin"})
		}(i)
	}
	wg.Wait()
	if got := runnerPublishedCacheBytes(t, filepath.Join(root, "cache")); got > 2500 {
		t.Fatalf("published cache bytes across jobs = %d, want <= 2500", got)
	}
}

// TestRunnerCacheAggregateBoundIncludesConcurrentRestores pins that remote
// restores take the same aggregate reservation as saves: two jobs restoring
// concurrently cannot exceed the runner budget, and both still succeed.
func TestRunnerCacheAggregateBoundIncludesConcurrentRestores(t *testing.T) {
	archive := runnerArchiveBytes(t)
	sum := sha256.Sum256(archive)
	var served atomic.Int64
	var nonCache atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/cache/") {
			nonCache.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		served.Add(1)
		w.Header().Set(cache.HeaderCacheSHA256, hex.EncodeToString(sum[:]))
		w.Header().Set("Content-Length", fmt.Sprint(len(archive)))
		_, _ = w.Write(archive)
	}))
	defer ts.Close()

	root := t.TempDir()
	r := testRunnerFor(t, ts, Config{
		CacheRoot: root, CacheMaxBytes: 2500, CacheMaxEntries: 100, CacheArchiveMaxBytes: 1200,
	})
	// A cold retained entry that the reservations must account for.
	cold := filepath.Join(root, "cache")
	if err := os.MkdirAll(cold, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCaptureBytes(t, filepath.Join(cold, "cold.tar.gz"), 1200)
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(cold, "cold.tar.gz"), old, old); err != nil {
		t.Fatal(err)
	}

	taskA := basicTask(payloadPipeline)
	taskB := basicTask(payloadPipeline)
	taskB.Job.ID = "job-2"
	stores := []*cache.Store{r.newJobCache(taskA, r.Metrics), r.newJobCache(taskB, r.Metrics)}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	hits := make([]bool, 2)
	for i := range stores {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hits[i], errs[i] = stores[i].RestoreContext(context.Background(), fmt.Sprintf("remote-key-%d", i), t.TempDir(), []string{"."})
		}(i)
	}
	wg.Wait()
	for i := range stores {
		if errs[i] != nil || !hits[i] {
			entries, _ := os.ReadDir(filepath.Join(root, "cache"))
			var names []string
			for _, e := range entries {
				fi, _ := e.Info()
				names = append(names, fmt.Sprintf("%s:%d", e.Name(), fi.Size()))
			}
			t.Fatalf("restore %d = hit=%t err=%v (remote=%q served=%d non-cache=%d files=%v)",
				i, hits[i], errs[i], stores[i].RemoteURL, served.Load(), nonCache.Load(), names)
		}
	}
	if got := runnerPublishedCacheBytes(t, filepath.Join(root, "cache")); got > 2500 {
		t.Fatalf("published cache bytes after concurrent restores = %d, want <= 2500", got)
	}
}

// TestRunnerPruneJobCacheReportsEvictionsAndErrors covers the maintenance
// entry point's report branches.
func TestRunnerPruneJobCacheReportsEvictionsAndErrors(t *testing.T) {
	root := t.TempDir()
	r := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{
		CacheRoot: root, CacheMaxBytes: 1000, CacheMaxEntries: 1, CacheMaxAge: time.Hour,
	})
	cacheDir := r.cacheRootDir()
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Hour)
	for i, key := range []string{"old", "new"} {
		p := filepath.Join(cacheDir, key+".tar.gz")
		writeCaptureBytes(t, p, 100)
		when := base.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatal(err)
		}
	}
	r.pruneJobCache(context.Background())
	if got := metricCounter(r.Metrics, "kiwi_runner_cache_evicted_entries_total"); got != 1 {
		t.Fatalf("evicted-entries counter = %v, want 1", got)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "new.tar.gz")); err != nil {
		t.Fatalf("newest entry was evicted: %v", err)
	}
	// A canceled context aborts the pass through the error branch.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.pruneJobCache(ctx)
}
