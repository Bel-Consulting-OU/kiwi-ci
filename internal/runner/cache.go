package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// cacheRoutePrefix is the legacy route shape the local cache.Store builds
// from its RemoteURL. The runner's transport rewrites those requests onto
// the job-scoped control-plane routes and attaches the lease contract.
const cacheRoutePrefix = "/api/v1/cache/"

// cacheTransport adapts the local cache.Store's remote requests to the
// job-scoped cache API: /api/v1/cache/{key} GET/PUT becomes
// /api/v1/jobs/{jobID}/cache/{key} with the runner lease headers. The
// control plane derives the repository and trust domain from the job, so
// the former X-Kiwi-Repository/X-Kiwi-Trust-Domain headers are gone
// entirely. Downloads are bounded and digest-verified inside cache.Client
// and disk availability is checked before a download starts.
type cacheTransport struct {
	client  *cache.Client
	jobID   string
	lease   map[string]string
	root    string
	maxDisk int64
	metrics *Metrics
}

func (t *cacheTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(req.URL.Path, cacheRoutePrefix) {
		return t.passthrough(req)
	}
	key := strings.TrimPrefix(req.URL.Path, cacheRoutePrefix)
	ctx := req.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	switch req.Method {
	case http.MethodGet:
		if err := safefs.FitsAvailable(t.root, t.maxDisk); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("cache download preflight: %w", err)
		}
		// The restore stream carries no total timeout; the sliding guard
		// cancels the transfer when the peer stops sending bytes.
		guardCtx, cancel := context.WithCancel(ctx)
		guard := newStallGuard(cancel, streamIdleTimeout.get())
		rc, err := t.client.Restore(guardCtx, t.jobID, t.lease, key)
		if errors.Is(err, cache.ErrRemoteNotFound) {
			guard.stop()
			cancel()
			if t.metrics != nil {
				t.metrics.Counter("kiwi_runner_cache_misses", 1)
			}
			return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Body: http.NoBody, Header: http.Header{}, Request: req}, nil
		}
		if err != nil {
			guard.stop()
			cancel()
			return nil, err
		}
		if t.metrics != nil {
			t.metrics.Counter("kiwi_runner_cache_hits", 1)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: &stallGuardedBody{ReadCloser: rc, guard: guard, cancel: cancel}, Header: http.Header{}, Request: req}, nil
	case http.MethodPut:
		guardCtx, cancel := context.WithCancel(ctx)
		guard := newStallGuard(cancel, streamIdleTimeout.get())
		var body io.Reader = req.Body
		if body != nil {
			body = &stallGuardReader{r: body, guard: guard}
		}
		if err := t.client.Upload(guardCtx, t.jobID, t.lease, key, body); err != nil {
			guard.stop()
			cancel()
			return nil, err
		}
		guard.stop()
		cancel()
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: http.NoBody, Header: http.Header{}, Request: req}, nil
	default:
		return t.passthrough(req)
	}
}

// passthrough forwards non-cache requests on the runner's transport. It
// exists only for safety: the store's client only issues cache requests.
func (t *cacheTransport) passthrough(req *http.Request) (*http.Response, error) {
	if t.client != nil && t.client.HTTP != nil && t.client.HTTP.Transport != nil {
		return t.client.HTTP.Transport.RoundTrip(req)
	}
	return http.DefaultTransport.RoundTrip(req)
}

// cacheRootRoot resolves the shared-ish root above the runner-specific cache
// namespace: <CacheRoot>/cache when configured, else the user cache root.
func (r *Runner) cacheRootRoot() string {
	if r.Cfg.CacheRoot != "" {
		return filepath.Join(r.Cfg.CacheRoot, "cache")
	}
	return cache.Default().Root
}

// cacheRootDir resolves the runner's PRIVATE cache directory:
// <root>/<runner instance id>. The manager's budget, reservations and locks
// are process-local, so two runner processes sharing one directory would
// each believe they own the whole policy — double the physical bound, with
// unrelated eviction/publication locks. A per-runner namespace makes the
// configured budget physically real and keeps restart reclaim deterministic
// (a restarted runner reuses its own id-derived directory). Cross-runner
// local cache sharing is deliberately sacrificed: the cache is a performance
// optimization, and correctness of the disk bound wins.
func (r *Runner) cacheRootDir() string {
	return filepath.Join(r.cacheRootRoot(), runnerStagingInstanceID(r.ID))
}

// cacheRetentionPolicy resolves the aggregate local-cache bound: every
// dimension falls back to the built-in default so a distributed runner never
// runs without one.
func (r *Runner) cacheRetentionPolicy() cache.RetentionPolicy {
	p := cache.RetentionPolicy{MaxBytes: r.Cfg.CacheMaxBytes, MaxEntries: r.Cfg.CacheMaxEntries, MaxAge: r.Cfg.CacheMaxAge}
	if p.MaxBytes <= 0 {
		p.MaxBytes = defaultCacheMaxBytes
	}
	if p.MaxEntries <= 0 {
		p.MaxEntries = defaultCacheMaxEntries
	}
	if p.MaxAge <= 0 {
		p.MaxAge = defaultCacheMaxAge
	}
	return p
}

// configureCacheManager installs the manager for THIS Run. Run calls it
// before any job can be leased; all work from a previous Run has joined by
// then, so a changed root or policy replaces the manager instead of
// accounting new files against the old ledger (which would be worse with a
// changed root: reservations and writes would refer to different
// directories). Direct execute callers keep the lazy construction.
//
// Replacement is fail-closed against outstanding cleanup debt: the old
// manager first retries its retained temp files, and if any charge remains
// the change is refused — the bytes are still on disk and only that manager
// accounts for them, so dropping the ledger would strand them invisibly.
func (r *Runner) configureCacheManager() error {
	root := r.cacheRootDir()
	policy := r.cacheRetentionPolicy()
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if r.cacheMgr != nil && r.cacheMgr.Root() == root && r.cacheMgr.Policy() == policy && !r.cacheMgr.Closed() {
		return nil
	}
	if old := r.cacheMgr; old != nil {
		if old.Closed() {
			// A previous shutdown's release failed and retained the closed
			// manager so it could be retried. NEVER reuse it as healthy: it
			// refuses every cache operation. Retry the release, then build a
			// fresh open manager.
			if err := old.Close(); err != nil {
				return fmt.Errorf("cache: retry previous namespace release: %w", err)
			}
			r.cacheMgr = nil
		} else {
			_, _ = old.RetryTempCleanup(context.Background())
			if pending := old.PendingTempCleanup(); pending > 0 || old.InflightBytes() > 0 {
				return fmt.Errorf("cache manager replacement refused: %d temp cleanup item(s) and %d charged bytes remain under %s; remove them or restart the process", pending, old.InflightBytes(), old.Root())
			}
			// The old namespace ownership must be released before the new
			// manager can acquire it (same root) and must not outlive the
			// replacement (changed root).
			if err := old.Close(); err != nil {
				return fmt.Errorf("cache: release previous namespace: %w", err)
			}
			r.cacheMgr = nil
		}
	}
	mgr, err := cache.NewManager(root, policy)
	if err != nil {
		return err
	}
	r.cacheMgr = mgr
	return nil
}

// closeCacheManager releases the cache namespace ownership after all cache
// work has stopped (the same fully-joined condition as closeStaging) or to
// roll back a startup that acquired cache ownership and then failed.
func (r *Runner) closeCacheManager() {
	r.cacheMu.Lock()
	mgr := r.cacheMgr
	r.cacheMu.Unlock()
	if mgr == nil {
		return
	}
	if err := mgr.Close(); err != nil {
		// Retain the manager pointer: Close is retryable and the lock handle
		// must survive a transient release failure.
		reportf("kiwi runner %s: cache namespace close: %v\n", r.ID, err)
		return
	}
	r.cacheMu.Lock()
	if r.cacheMgr == mgr {
		r.cacheMgr = nil
	}
	r.cacheMu.Unlock()
}

// cacheManager returns the runner-wide aggregate cache budget owner, shared
// by every job's Store. The manager is what makes the aggregate bound real:
// it serializes reservations, evictions and publications across jobs that
// each hold their own Store.
func (r *Runner) cacheManager() (*cache.Manager, error) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if r.cacheMgr != nil && !r.cacheMgr.Closed() {
		return r.cacheMgr, nil
	}
	if old := r.cacheMgr; old != nil {
		// Retry the failed release from a previous lifecycle instead of
		// handing out a closed manager, then reopen the namespace.
		if err := old.Close(); err != nil {
			return nil, fmt.Errorf("cache: retry previous namespace release: %w", err)
		}
		r.cacheMgr = nil
	}
	mgr, err := cache.NewManager(r.cacheRootDir(), r.cacheRetentionPolicy())
	if err != nil {
		return nil, err
	}
	r.cacheMgr = mgr
	return mgr, nil
}

// pruneJobCache runs one retention pass over the runner-local cache tree and
// reports what it reclaimed. Removal failures stay in the tree (and in the
// next pass's accounting) instead of silently freeing capacity; entries
// refreshed after ranking are skipped by the freshness fence.
func (r *Runner) pruneJobCache(ctx context.Context) {
	mgr, merr := r.cacheManager()
	if merr != nil {
		reportf("kiwi runner %s: cache namespace unavailable: %v\n", r.ID, merr)
		return
	}
	// Temp files whose removal failed on an aborted operation still occupy
	// disk and still hold their charge; retry them before the retention
	// pass so the budget reflects reality as soon as possible.
	if removed, err := mgr.RetryTempCleanup(ctx); err != nil {
		reportf("kiwi runner %s: cache temp cleanup retry failed (%d removed): %v\n", r.ID, removed, err)
	} else if removed > 0 {
		reportf("kiwi runner %s: cache temp cleanup reclaimed %d file(s)\n", r.ID, removed)
	}
	res, err := mgr.Prune(ctx)
	if err != nil {
		reportf("kiwi runner %s: cache retention: %v\n", r.ID, err)
		return
	}
	if res.Entries > 0 || res.Bytes > 0 {
		r.Metrics.Counter("kiwi_runner_cache_evicted_entries_total", float64(res.Entries))
		r.Metrics.Counter("kiwi_runner_cache_evicted_bytes_total", float64(res.Bytes))
		reportf("kiwi runner %s: cache retention evicted %d entries (%d bytes)\n", r.ID, res.Entries, res.Bytes)
	}
	if res.Failed > 0 {
		reportf("kiwi runner %s: cache retention could not remove %d entries; they stay accounted and are retried next pass\n", r.ID, res.Failed)
	}
}

// newJobCache builds the executor's cache store for one job: local
// content-addressed storage whose remote fallback targets the job-scoped
// control-plane cache routes with the runner's lease contract headers. The
// store carries the aggregate retention policy, so every save prunes the
// tree as soon as a cap is exceeded instead of waiting for maintenance.
func (r *Runner) newJobCache(t server.Task, metrics *Metrics) (*cache.Store, error) {
	mgr, err := r.cacheManager()
	if err != nil {
		return nil, err
	}
	store := cache.Default()
	store.Root = r.cacheRootDir()
	store.Retention = r.cacheRetentionPolicy()
	store.Manager = mgr
	store.MaxCacheBytes = r.Cfg.CacheArchiveMaxBytes
	store.RemoteURL = r.Cfg.Server
	store.Token = r.Cfg.Token
	// Cache traffic is bulk streaming traffic: it runs on the streaming
	// client's transport with NO total timeout (an 8 GiB cache archive at any
	// sustainable rate must complete). The per-request stall guard added in
	// RoundTrip bounds inactivity instead. A runner built without an explicit
	// StreamClient (tests) falls back to the control client and inherits its
	// total timeout, preserving the historical bounded behavior.
	stream := r.streamClient()
	transport := http.RoundTripper(http.DefaultTransport)
	var timeout time.Duration
	if stream != nil {
		if stream.Transport != nil {
			transport = stream.Transport
		}
		timeout = stream.Timeout
	}
	client := &cache.Client{
		Server: r.Cfg.Server,
		Token:  r.Cfg.Token,
		HTTP: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Logf: func(format string, args ...any) {
			fmt.Printf("kiwi runner %s: cache: "+format+"\n", append([]any{r.ID}, args...)...)
		},
	}
	store.Client = &http.Client{
		Timeout: timeout,
		Transport: &cacheTransport{
			client: client,
			jobID:  t.Job.ID,
			lease: map[string]string{
				cache.HeaderRunnerID:        r.ID,
				cache.HeaderLeaseToken:      t.LeaseToken,
				cache.HeaderLeaseGeneration: fmt.Sprint(t.LeaseGeneration),
			},
			root: store.Root,
			// The preflight must use the RESOLVED bound (configured
			// MaxCacheBytes, else the shared 8 GiB default): branching on the
			// raw field disabled the free-space preflight entirely for the
			// normal unconfigured runner while its transfers stayed capped at
			// 8 GiB.
			maxDisk: store.MaxStoredBytes(),
			metrics: metrics,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return store, nil
}
