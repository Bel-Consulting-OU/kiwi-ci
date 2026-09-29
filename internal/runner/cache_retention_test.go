package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
)

// TestRunnerCachePreflightUsesResolvedBound is the P2 regression: the
// download preflight must use the RESOLVED per-archive bound (8 GiB default),
// not the raw zero MaxCacheBytes field that disabled it entirely for the
// normal unconfigured runner.
func TestRunnerCachePreflightUsesResolvedBound(t *testing.T) {
	r := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{})
	store := mustJobCache(t, r, basicTask(payloadPipeline))
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
	store2 := mustJobCache(t, r2, basicTask(payloadPipeline))
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
	stores := []*cache.Store{mustJobCache(t, r, taskA), mustJobCache(t, r, taskB)}

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
	if got := runnerPublishedCacheBytes(t, r.cacheRootDir()); got > 2500 {
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
	cold := r.cacheRootDir()
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
	stores := []*cache.Store{mustJobCache(t, r, taskA), mustJobCache(t, r, taskB)}

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
			entries, _ := os.ReadDir(r.cacheRootDir())
			var names []string
			for _, e := range entries {
				fi, _ := e.Info()
				names = append(names, fmt.Sprintf("%s:%d", e.Name(), fi.Size()))
			}
			t.Fatalf("restore %d = hit=%t err=%v (remote=%q served=%d non-cache=%d files=%v)",
				i, hits[i], errs[i], stores[i].RemoteURL, served.Load(), nonCache.Load(), names)
		}
	}
	if got := runnerPublishedCacheBytes(t, r.cacheRootDir()); got > 2500 {
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

// TestRunnerCacheNamespacesAreProcessPrivate pins the P1 multi-process fix:
// the manager's budget and locks are process-local, so each runner process
// gets its own <cache root>/<runner instance id> directory. Two runners
// sharing a CacheRoot can therefore never double-spend one physical budget
// through unrelated ledgers, and each namespace stays within the policy.
func TestRunnerCacheNamespacesAreProcessPrivate(t *testing.T) {
	root := t.TempDir()
	cfg := Config{CacheRoot: root, CacheMaxBytes: 2500, CacheMaxEntries: 100, CacheArchiveMaxBytes: 1200}
	r1 := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), cfg)
	r2 := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), cfg)
	r2.ID = "runner-2"
	dir1, dir2 := r1.cacheRootDir(), r2.cacheRootDir()
	if dir1 == dir2 {
		t.Fatalf("two runner identities share the cache directory %q", dir1)
	}
	if !strings.HasPrefix(dir1, filepath.Join(root, "cache")) || !strings.HasPrefix(dir2, filepath.Join(root, "cache")) {
		t.Fatalf("namespaces not rooted under the configured cache root: %q %q", dir1, dir2)
	}
	for _, r := range []*Runner{r1, r2} {
		store := mustJobCache(t, r, basicTask(payloadPipeline))
		store.RemoteURL = "" // local-only saves
		for i := 0; i < 4; i++ {
			ws := t.TempDir()
			writeCaptureBytes(t, filepath.Join(ws, "f.bin"), 800)
			_ = store.SaveContext(context.Background(), fmt.Sprintf("ns%02d", i), ws, []string{"f.bin"})
		}
		if got := runnerPublishedCacheBytes(t, r.cacheRootDir()); got > 2500 {
			t.Fatalf("runner %s namespace = %d bytes, policy 2500", r.ID, got)
		}
	}
	// Each namespace holds its own newest entries (older ones were evicted
	// under the policy).
	for _, key := range []string{"ns03"} {
		if _, err := os.Stat(filepath.Join(dir1, key+".tar.gz")); err != nil {
			t.Fatalf("runner-1 namespace missing %s: %v", key, err)
		}
		if _, err := os.Stat(filepath.Join(dir2, key+".tar.gz")); err != nil {
			t.Fatalf("runner-2 namespace missing %s: %v", key, err)
		}
	}
}

// TestRunnerCacheManagerFollowsConfigAcrossRestarts pins the lifecycle fix:
// a Run started with a changed cache root or policy replaces the manager
// instead of accounting new files against the previous ledger. Direct
// callers keep the lazy construction.
func TestRunnerCacheManagerFollowsConfigAcrossRestarts(t *testing.T) {
	r := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{CacheRoot: t.TempDir(), CacheMaxBytes: 2000})
	m1, err := r.cacheManager()
	if err != nil {
		t.Fatal(err)
	}
	r.configureCacheManager()
	m1b, err := r.cacheManager()
	if err != nil {
		t.Fatal(err)
	}
	if m1b != m1 {
		t.Fatal("same-config reconfigure replaced the manager")
	}
	r.Cfg.CacheMaxBytes = 1234
	r.configureCacheManager()
	m2, err := r.cacheManager()
	if err != nil {
		t.Fatal(err)
	}
	if m2 == m1 {
		t.Fatal("changed policy kept the stale manager")
	}
	if m2.Policy().MaxBytes != 1234 {
		t.Fatalf("new manager policy = %+v, want 1234 bytes", m2.Policy())
	}
	r.Cfg.CacheRoot = t.TempDir()
	r.configureCacheManager()
	m3, err := r.cacheManager()
	if err != nil {
		t.Fatal(err)
	}
	if m3.Root() != r.cacheRootDir() {
		t.Fatalf("manager root = %q, want %q", m3.Root(), r.cacheRootDir())
	}
	if m3 == m2 {
		t.Fatal("changed root kept the stale manager")
	}
}

// TestRunnerCacheRootDefaultsToHomeCache covers the unconfigured-root branch:
// the default root still gains the per-runner instance namespace.
func TestRunnerCacheRootDefaultsToHomeCache(t *testing.T) {
	r := &Runner{ID: "default-root"}
	dir := r.cacheRootDir()
	if filepath.Base(dir) != runnerStagingInstanceID("default-root") {
		t.Fatalf("default cache dir = %q, want it suffixed with the instance id", dir)
	}
	if !strings.HasSuffix(filepath.Dir(dir), "cache") {
		t.Fatalf("default cache dir = %q, want it under a cache root", dir)
	}
}

// TestRunnerStartupPreservesLegacySharedCacheDuringRollingUpgrade pins the
// mixed-version safety rule: a new per-runner namespace lock proves nothing
// about the pre-namespace shared layout, so startup must NOT delete legacy
// archives that a still-running old-version runner may own. Reclamation is an
// explicit operator migration command.
func TestRunnerStartupPreservesLegacySharedCacheDuringRollingUpgrade(t *testing.T) {
	root := t.TempDir()
	legacyDir := filepath.Join(root, "cache")
	if err := os.MkdirAll(legacyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("d", 64)
	legacy := filepath.Join(legacyDir, key+".tar.gz")
	if err := os.WriteFile(legacy, []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy+".sha256", []byte("digest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{CacheRoot: root})
	if _, err := r.cacheManager(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("legacy archive deleted during startup: %v", err)
	}
	if _, err := os.Stat(legacy + ".sha256"); err != nil {
		t.Fatalf("legacy sidecar deleted during startup: %v", err)
	}
	// A file inside the runner's private namespace is untouched as well.
	nsDir := r.cacheRootDir()
	if err := os.MkdirAll(nsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	nsFile := filepath.Join(nsDir, strings.Repeat("e", 64)+".tar.gz")
	if err := os.WriteFile(nsFile, []byte("namespaced"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.pruneJobCache(context.Background())
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("legacy archive deleted by maintenance: %v", err)
	}
	if _, err := os.Stat(nsFile); err != nil {
		t.Fatalf("namespace file deleted by maintenance: %v", err)
	}
}

// TestRunnerMaintenanceDoesNotDeleteLegacySharedCache pins the periodic path:
// repeated maintenance passes never touch the pre-namespace layout.
func TestRunnerMaintenanceDoesNotDeleteLegacySharedCache(t *testing.T) {
	root := t.TempDir()
	r := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{CacheRoot: root, CacheMaxBytes: 2000})
	legacyDir := filepath.Join(root, "cache")
	if err := os.MkdirAll(legacyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("9", 64)
	legacy := filepath.Join(legacyDir, key+".tar.gz")
	if err := os.WriteFile(legacy, []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		r.pruneJobCache(context.Background())
		if _, err := os.Stat(legacy); err != nil {
			t.Fatalf("maintenance pass %d removed the legacy archive: %v", i, err)
		}
	}
}

// TestRunnerCacheManagerReplacementRefusedWithDebt pins the fail-closed
// lifecycle: while the old manager still holds cleanup debt, a changed
// policy cannot silently drop the ledger; the change is refused until the
// debt is cleared.
func TestRunnerCacheManagerReplacementRefusedWithDebt(t *testing.T) {
	r := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{CacheRoot: t.TempDir(), CacheMaxBytes: 2000})
	mgr, err := r.cacheManager()
	if err != nil {
		t.Fatal(err)
	}
	res, err := mgr.Reserve(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	// A non-empty directory at the temp path cannot be removed by a single
	// os.Remove, so the retained charge survives.
	debt := filepath.Join(mgr.Root(), ".debt.tar.gz-1.tmp")
	if err := os.MkdirAll(debt, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(debt, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !mgr.RetainTempCleanup(res, debt) {
		t.Fatal("retain did not accept the open reservation")
	}
	r.Cfg.CacheMaxBytes = 1000
	err = r.configureCacheManager()
	if err == nil || !strings.Contains(err.Error(), "replacement refused") {
		t.Fatalf("configureCacheManager = %v, want a refusal naming the retained debt", err)
	}
	mgrb, err := r.cacheManager()
	if err != nil {
		t.Fatal(err)
	}
	if mgrb != mgr {
		t.Fatal("refused replacement swapped the manager anyway")
	}
	// Clear the debt; the next attempt succeeds.
	if err := os.Remove(filepath.Join(debt, "x")); err != nil {
		t.Fatal(err)
	}
	if err := r.configureCacheManager(); err != nil {
		t.Fatalf("configureCacheManager after clearing debt = %v", err)
	}
	mgrAfter, err := r.cacheManager()
	if err != nil {
		t.Fatal(err)
	}
	if got := mgrAfter.Policy().MaxBytes; got != 1000 {
		t.Fatalf("new manager policy = %d, want 1000", got)
	}
	if mgr.PendingTempCleanup() != 0 {
		t.Fatalf("old manager still has %d pending temps", mgr.PendingTempCleanup())
	}
}

// TestCacheManagerStartupFailureDoesNotRetainStagingOwnership pins the
// startup ordering: a cache-manager refusal must return before the staging
// directory lock/process-registry ownership is acquired, so a Run that never
// started cannot block a later same-identity Run with ErrStagingDirOwned.
func TestCacheManagerStartupFailureDoesNotRetainStagingOwnership(t *testing.T) {
	served := make(chan struct{}, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/register"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
		default:
			select {
			case served <- struct{}{}:
			default:
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer ts.Close()

	stagingRoot := t.TempDir()
	r := &Runner{ID: "runner-1", Cfg: Config{
		Server: ts.URL, Poll: time.Millisecond, Concurrency: 1,
		IdentityDir: t.TempDir(), WorkDir: t.TempDir(),
		StagingDir: stagingRoot, StagingMaxBytes: 1 << 20,
		CacheRoot: t.TempDir(), CacheMaxBytes: 2000,
	}, Client: ts.Client(), Metrics: NewMetrics()}
	// Force retained cache cleanup debt, then change the policy so
	// configureCacheManager must refuse the replacement.
	mgr, err := r.cacheManager()
	if err != nil {
		t.Fatal(err)
	}
	res, err := mgr.Reserve(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	debt := filepath.Join(mgr.Root(), ".debt.tar.gz-1.tmp")
	if err := os.MkdirAll(debt, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(debt, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !mgr.RetainTempCleanup(res, debt) {
		t.Fatal("retain did not accept the reservation")
	}
	r.Cfg.CacheMaxBytes = 1000

	err = r.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "replacement refused") {
		t.Fatalf("Run = %v, want the cache replacement refusal", err)
	}
	if r.currentStaging() != nil {
		t.Fatal("staging was configured before the cache refusal")
	}
	// The staging directory lock is available for the same runner identity:
	// a Run that failed at cache startup must not hold it.
	probe, perr := staging.NewReplicaBudget(stagingRoot, runnerStagingInstanceID("runner-1"), 1<<20)
	if perr != nil {
		t.Fatalf("staging ownership leaked by the failed startup: %v", perr)
	}
	if cerr := probe.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	// The runner must not have leased a job either.
	select {
	case <-served:
		t.Fatal("failed startup leased a job")
	default:
	}
}

// TestCacheNamespaceOwnershipReleasedOnStartupFailure pins transactional
// startup: Run acquires the cache namespace, then staging configuration
// fails; the cache ownership must be rolled back so the namespace is
// available for a later Run/process.
func TestCacheNamespaceOwnershipReleasedOnStartupFailure(t *testing.T) {
	served := make(chan struct{}, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/register"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
		default:
			select {
			case served <- struct{}{}:
			default:
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer ts.Close()

	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cacheRoot := t.TempDir()
	r := &Runner{ID: "runner-1", Cfg: Config{
		Server: ts.URL, Poll: time.Millisecond, Concurrency: 1,
		IdentityDir: t.TempDir(), WorkDir: t.TempDir(),
		StagingDir: filepath.Join(blocked, "staging"),
		CacheRoot:  cacheRoot, CacheMaxBytes: 2000,
	}, Client: ts.Client(), Metrics: NewMetrics()}

	err := r.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "staging") {
		t.Fatalf("Run = %v, want the staging startup failure", err)
	}
	if r.cacheMgr != nil {
		t.Fatal("failed startup retained the cache manager")
	}
	// The cache namespace lock must be released again.
	probe, perr := cache.NewManager(r.cacheRootDir(), r.cacheRetentionPolicy())
	if perr != nil {
		t.Fatalf("cache namespace ownership leaked by the failed startup: %v", perr)
	}
	if cerr := probe.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	select {
	case <-served:
		t.Fatal("failed startup leased a job")
	default:
	}
}

// TestCacheNamespaceOwnershipReleasedOnCleanShutdown pins the normal
// lifecycle: after Run returns (cancellation/drain), the fully joined stop
// releases the cache namespace so a successor process can own it.
func TestCacheNamespaceOwnershipReleasedOnCleanShutdown(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/register"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer ts.Close()

	cacheRoot := t.TempDir()
	r := &Runner{ID: "runner-1", Cfg: Config{
		Server: ts.URL, Poll: 5 * time.Millisecond, Concurrency: 1,
		IdentityDir: t.TempDir(), WorkDir: t.TempDir(),
		CacheRoot: cacheRoot, CacheMaxBytes: 2000,
	}, Client: ts.Client(), Metrics: NewMetrics()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	// Let Run reach the lease loop, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	if r.cacheMgr != nil {
		t.Fatal("shutdown retained the cache manager pointer")
	}
	probe, err := cache.NewManager(r.cacheRootDir(), r.cacheRetentionPolicy())
	if err != nil {
		t.Fatalf("cache namespace ownership leaked by shutdown: %v", err)
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestExecuteCacheNamespaceUnavailableFailsJob pins the executor-path
// failure: when another live owner holds the cache namespace, a job that
// needs a cache fails closed before running instead of writing unbudgeted.
func TestExecuteCacheNamespaceUnavailableFailsJob(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	r := testRunnerFor(t, ts, Config{CacheRoot: t.TempDir(), CacheMaxBytes: 2000})
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }
	foreign, ferr := cache.NewManager(r.cacheRootDir(), r.cacheRetentionPolicy())
	if ferr != nil {
		t.Fatal(ferr)
	}
	defer func() { _ = foreign.Close() }()
	pipelineText := "version: 1\njobs:\n  build:\n    steps:\n      - run: " + nativeScript("true", "exit 0") + "\n    cache:\n      - name: c\n        key: k\n        paths: [out]\n"
	r.execute(context.Background(), basicTask(pipelineText))
	c, ok := fsrv.lastComplete()
	if !ok || c.Status != model.StatusFailure || !strings.Contains(c.Error, "owned by another live process") {
		t.Fatalf("complete = %+v ok=%v, want the ownership refusal", c, ok)
	}
}

// TestRunnerPruneJobCacheReportsNamespaceUnavailable covers the maintenance
// entry point when the namespace belongs to another live owner.
func TestRunnerPruneJobCacheReportsNamespaceUnavailable(t *testing.T) {
	r := testRunnerFor(t, httptest.NewServer(http.NotFoundHandler()), Config{CacheRoot: t.TempDir(), CacheMaxBytes: 2000})
	foreign, err := cache.NewManager(r.cacheRootDir(), r.cacheRetentionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = foreign.Close() }()
	r.pruneJobCache(context.Background()) // must not panic or touch the foreign namespace
}

// TestRunRetriesClosedCacheManagerReleaseBeforeRestart is the P2 lifecycle
// regression: a shutdown whose namespace release fails retains a CLOSED
// manager so the release can be retried. The next Run with identical
// configuration must retry that release and install a fresh OPEN manager
// instead of returning early and leaving every cache operation failing with
// ErrManagerClosed.
func TestRunRetriesClosedCacheManagerReleaseBeforeRestart(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/register") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	cacheRoot := t.TempDir()
	r := &Runner{ID: "runner-1", Cfg: Config{
		Server: ts.URL, Poll: 5 * time.Millisecond, Concurrency: 1,
		IdentityDir: t.TempDir(), WorkDir: t.TempDir(),
		CacheRoot: cacheRoot, CacheMaxBytes: 2000, CacheArchiveMaxBytes: 1000,
	}, Client: ts.Client(), Metrics: NewMetrics()}

	// Run #1: the namespace release fails at shutdown, so the closed manager
	// must be retained for a retry.
	cache.SetNamespaceReleaseHookForTest(func() error { return errors.New("test: transient release failure") })
	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan error, 1)
	go func() { done1 <- r.Run(ctx1) }()
	time.Sleep(80 * time.Millisecond)
	cancel1()
	select {
	case <-done1:
	case <-time.After(15 * time.Second):
		t.Fatal("first Run did not return")
	}
	old := r.cacheMgr
	if old == nil {
		t.Fatal("failed shutdown discarded the manager instead of retaining it")
	}
	if !old.Closed() {
		t.Fatal("retained manager is not closed")
	}
	// Restore the release primitive and drive the EXACT Run #2 startup step:
	// it must retry the retained release and install a fresh open manager.
	cache.SetNamespaceReleaseHookForTest(nil)
	if err := r.configureCacheManager(); err != nil {
		t.Fatalf("configureCacheManager after failed release = %v", err)
	}
	if r.cacheMgr == old {
		t.Fatal("startup reused the closed manager as healthy")
	}
	if r.cacheMgr == nil || r.cacheMgr.Closed() {
		t.Fatal("startup did not install an open manager")
	}

	// A full Run #2 with identical configuration now starts and stops
	// cleanly, and a cache-using job succeeds afterwards.
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() { done2 <- r.Run(ctx2) }()
	time.Sleep(80 * time.Millisecond)
	cancel2()
	select {
	case <-done2:
	case <-time.After(15 * time.Second):
		t.Fatal("second Run did not return")
	}
	store, err := r.newJobCache(basicTask(payloadPipeline), r.Metrics)
	if err != nil {
		t.Fatalf("newJobCache after recovery = %v", err)
	}
	store.RemoteURL = ""
	ws := t.TempDir()
	writeCaptureBytes(t, filepath.Join(ws, "f.bin"), 200)
	if err := store.SaveContext(context.Background(), "recovered", ws, []string{"f.bin"}); err != nil {
		t.Fatalf("cache save after recovery = %v", err)
	}
}
