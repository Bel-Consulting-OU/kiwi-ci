package server

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

const testHistoryFile = "test-history.json"

// testHistoryIdentityUnavailable is the fixed opaque body for a failed or
// missing authoritative run lookup on the test-intelligence paths (shard
// assignment and report upload); the store detail stays in the server log.
const testHistoryIdentityUnavailable = "test history identity unavailable"

// historyWholeCacheKey is the cache key of the whole-history snapshot used in
// memory/fs mode and by legacy TestHistoryStore-backed servers: ONE
// testintel.History holds every repository (it is the persisted history
// file). Canonical repository IDs are non-empty forge paths, so this sentinel
// can never collide with a per-repository entry.
const historyWholeCacheKey = "*"

// repoHistoryCacheMaxRepos bounds the number of decoded per-repository
// history snapshots kept resident. A multi-repository control plane must not
// grow the cache with every repository it ever served, so the least recently
// used repository is evicted once the bound is exceeded and simply reloaded
// from its durable aggregates on the next request (the per-repository version
// makes that reload detectable and always safe). The bound is deliberately
// small: one entry is a repository's whole decoded test suite.
const repoHistoryCacheMaxRepos = 64

// historyStaleVersion marks a cached snapshot that a local write (the
// aggregate upload mirror) has superseded: durable versions start at 1, so a
// stale entry never validates and the next read reloads the repository. It is
// the keyed equivalent of the old single-slot historyDBRepo reset that forced
// the next sync to reload.
const historyStaleVersion = -1

// repoHistoryCacheEntry is one repository's cached history snapshot: the
// decoded history plus the durable per-repository version it was decoded
// from (or historyStaleVersion after a local mirror write). Snapshots are
// replaced whole, never swapped between repositories, so a request that took
// a snapshot can answer Shard, Manifest and Flaky from that one generation
// for its entire response.
type repoHistoryCacheEntry struct {
	version int64
	history *testintel.History
}

// historyOrNew returns the entry's snapshot, allocating an empty one when the
// entry has none.
func (e repoHistoryCacheEntry) historyOrNew() *testintel.History {
	if e.history == nil {
		return testintel.NewHistory()
	}
	return e.history
}

// repoHistoryCache is the keyed, versioned test-history cache: entries maps a
// repository key to its snapshot entry, and recency (a parallel map of
// monotonically increasing stamps, assigned under mu) keeps entries bounded
// with least-recently-used eviction. LOCKING: mu guards entries, recency and
// tick, and it is the ONLY lock that guards them — s.mu never does. mu is a
// leaf lock: no other server lock may be acquired while it is held (the
// testintel.History mutex taken inside Record/Shard/Manifest/Flaky/Save is
// the only nested acquisition), while acquiring mu with s.mu held
// (memory-mode history writes) is fine. Eviction scans the bounded map for
// the smallest recency stamp, so it costs O(cap) and only runs when the cap
// is exceeded.
type repoHistoryCache struct {
	mu      sync.Mutex
	max     int
	tick    uint64
	entries map[string]repoHistoryCacheEntry
	recency map[string]uint64
}

// newRepoHistoryCache builds a cache bounded to max entries (at least one).
func newRepoHistoryCache(max int) *repoHistoryCache {
	if max < 1 {
		max = 1
	}
	return &repoHistoryCache{max: max, entries: map[string]repoHistoryCacheEntry{}, recency: map[string]uint64{}}
}

// newEmptyHistoryCache is the constructor-time cache: a bounded cache already
// holding the empty whole-history snapshot, so a server that never loaded a
// data dir still answers test-intelligence reads (memory/fs mode).
func newEmptyHistoryCache() *repoHistoryCache {
	c := newRepoHistoryCache(repoHistoryCacheMaxRepos)
	c.store(historyWholeCacheKey, repoHistoryCacheEntry{history: testintel.NewHistory()})
	return c
}

// lookup returns the snapshot entry for key and marks it most recently used.
// A nil cache (bare test servers) misses.
func (c *repoHistoryCache) lookup(key string) (repoHistoryCacheEntry, bool) {
	if c == nil {
		return repoHistoryCacheEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return repoHistoryCacheEntry{}, false
	}
	c.tick++
	c.recency[key] = c.tick
	return entry, true
}

// store replaces (or inserts) key's snapshot, marks it most recently used and
// evicts the least recently used entries beyond the cap. A nil cache is a
// no-op.
func (c *repoHistoryCache) store(key string, entry repoHistoryCacheEntry) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.storeLocked(key, entry)
}

// storeLocked is store for callers already holding mu.
func (c *repoHistoryCache) storeLocked(key string, entry repoHistoryCacheEntry) {
	c.entries[key] = entry
	c.tick++
	c.recency[key] = c.tick
	for len(c.entries) > c.max {
		var oldestKey string
		var oldestUsed uint64
		first := true
		for k := range c.entries {
			if used := c.recency[k]; first || used < oldestUsed {
				oldestKey, oldestUsed, first = k, used, false
			}
		}
		delete(c.entries, oldestKey)
		delete(c.recency, oldestKey)
	}
}

// update runs fn under the cache mutex against key's entry (created with an
// empty history when absent), then stores the result and marks it most
// recently used. fn must not call back into the cache and must not acquire
// s.mu (the cache mutex is a leaf); the memory-mode persistence helpers it
// calls are safe. A nil cache runs fn against a throwaway entry so callers
// (and bare test servers) never crash.
func (c *repoHistoryCache) update(key string, fn func(*repoHistoryCacheEntry)) {
	if c == nil {
		entry := repoHistoryCacheEntry{history: testintel.NewHistory()}
		fn(&entry)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[key]
	entry.history = entry.historyOrNew()
	fn(&entry)
	c.storeLocked(key, entry)
}

// invalidateAll drops every cached snapshot (explicit repair/rebuild made the
// durable generations younger than what is cached). The next read of any
// repository reloads it.
func (c *repoHistoryCache) invalidateAll() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]repoHistoryCacheEntry{}
	c.recency = map[string]uint64{}
}

// len reports how many snapshots are cached. Test/observability helper.
func (c *repoHistoryCache) len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// has reports whether key has a cached snapshot without changing recency.
func (c *repoHistoryCache) has(key string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.entries[key]
	return ok
}

// loadTestintelHistory installs the whole-history snapshot. In memory/fs mode
// it restores the persisted history from dataDir/test-history.json; a missing
// file starts empty. The file is always persisted (both memory and DB modes):
// it is the complete durable history store for servers without SQL.
func (s *Server) loadTestintelHistory(dataDir string) error {
	path := ""
	if dataDir != "" {
		path = filepath.Join(dataDir, testHistoryFile)
		if h, err := testintel.LoadHistory(path); err == nil {
			s.historyFile = path
			s.historyCache.store(historyWholeCacheKey, repoHistoryCacheEntry{history: h})
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	s.historyFile = path
	s.historyCache.store(historyWholeCacheKey, repoHistoryCacheEntry{history: testintel.NewHistory()})
	return nil
}

// saveTestintelHistory stages the whole-history snapshot at path+".tmp";
// commitTestintelHistory renames it into place. Whole-history writes are
// serialized through repoHistoryCache.update, so a concurrent upload can
// never interleave the staged file with another upload's rename. Servers
// without a data dir keep the history in memory only.
func (s *Server) saveTestintelHistory(h *testintel.History) error {
	if h == nil || s.historyFile == "" {
		return nil
	}
	return h.Save(s.historyFile + ".tmp")
}

// commitTestintelHistory commits the staged whole-history snapshot
// atomically (see saveTestintelHistory).
func (s *Server) commitTestintelHistory() error {
	if s.historyFile == "" {
		return nil
	}
	return os.Rename(s.historyFile+".tmp", s.historyFile)
}

// mirrorTestReportHistoryDB marks THIS repository's cached snapshot stale
// after an upload whose report and history aggregates ALREADY committed in
// one durable transaction (see
// storage.TestHistoryAggregateStore.InsertTestReportWithHistory). The cached
// snapshot is IMMUTABLE for readers, so the mirror never folds into it: a
// request that took the pointer keeps answering Shard, Manifest and Flaky
// from its own generation for the whole response, even while a same-or
// other-repository upload commits. The stale marker makes the next
// historyForRepo reload the repository's durable aggregates and atomically
// swap in a freshly decoded pointer; if the store is temporarily down the old
// immutable snapshot keeps serving. An empty repository key is never mirrored:
// it would mask unrelated repositories' history.
func (s *Server) mirrorTestReportHistoryDB(repo string) {
	if repo == "" {
		return
	}
	s.historyCache.update(repo, func(e *repoHistoryCacheEntry) {
		e.version = historyStaleVersion
	})
}

// foldReportCases records every case of rep under repo into h. h must be
// privately owned by the caller (a clone): the fold is the mutation that must
// never reach a published snapshot.
func foldReportCases(h *testintel.History, repo string, rep model.TestReport) {
	for _, c := range rep.Cases {
		h.Record(repo, rep.JobKey, c.Class, c.Name, c.Duration, c.Passed, rep.CreatedAt)
	}
}

// recordTestReportHistory is the LEGACY-store and memory-mode history write.
// Both branches publish a NEW snapshot (copy-on-write): the report's cases
// are folded into a deep clone of the current snapshot, never into the
// snapshot itself, so a concurrent test-intelligence reader that already took
// the previous pointer can neither observe the fold nor have its generation
// change under it.
//
// In memory mode the history file under dataDir is the durable store: the
// clone's staged-then-renamed file commit runs in one critical section (s.mu,
// as before, so concurrent test-intelligence readers holding s.mu cannot
// observe a report without its history), with the cache mutex taken inside
// s.mu, and the clone is published ONLY after the commit SUCCEEDED. On a
// failed save or commit the old snapshot keeps serving and the failure is
// logged: mutation is never visible without durability.
//
// A DB store without the incremental aggregate contract falls back to the
// explicit full rebuild (the documented maintenance path); the production
// PostgresStore implements the aggregate contract, so an upload never
// rebuilds the whole history. ctx is the request context: a canceled request
// performs no durable write (the legacy rebuild logs and aborts).
func (s *Server) recordTestReportHistory(ctx context.Context, repo string, rep model.TestReport) {
	if s.DB != nil {
		// Legacy store: the report is already durable, so folding a clone
		// locally makes this instance serve the new data immediately, then
		// the shared cache is repaired from the committed reports.
		s.historyCache.update(historyWholeCacheKey, func(e *repoHistoryCacheEntry) {
			next := e.history.Clone()
			foldReportCases(next, repo, rep)
			e.history = next
		})
		s.rebuildTestHistoryDB(ctx)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := repoHistoryCacheEntry{}
	if cached, hit := s.historyCache.lookup(historyWholeCacheKey); hit {
		entry = cached
	}
	next := entry.historyOrNew().Clone()
	foldReportCases(next, repo, rep)
	if err := s.saveTestintelHistory(next); err != nil {
		s.logError("test history: save failed", "error", err.Error())
		return
	}
	if err := s.commitTestintelHistory(); err != nil {
		s.logError("test history: commit failed", "error", err.Error())
		return
	}
	entry.history = next
	s.historyCache.store(historyWholeCacheKey, entry)
}

// rebuildTestHistoryDB is the EXPLICIT maintenance/repair operation (never
// called per upload). With an incremental aggregate store it enumerates and
// rebuilds EVERY repository through the bounded per-repository repair: the
// store's keyset pagination returns every repository across as many bounded
// pages as it takes (the page size is a bound on one query, never a cap on
// the enumeration). With a legacy TestHistoryStore it recomputes the
// serialized cache from all durable reports exactly as the pre-0026 code
// did. A failure only logs: the durable reports are untouched and the cached
// snapshots keep serving.
func (s *Server) rebuildTestHistoryDB(ctx context.Context) {
	if agg, ok := s.DB.(storage.TestHistoryAggregateStore); ok {
		repos, err := agg.ListTestHistoryRepoIDs(ctx, storage.TestHistoryRepoPageSize)
		if err != nil {
			s.logError("test history: list repositories failed", "error", err.Error())
			return
		}
		for _, repoID := range repos {
			if err := ctx.Err(); err != nil {
				s.logError("test history: repair aborted", "error", err.Error())
				return
			}
			if _, err := agg.RebuildRepoTestHistory(ctx, repoID); err != nil {
				s.logError("test history: repository repair failed", "repo", repoID, "error", err.Error())
			}
		}
		// The repair bumped every repository's version: drop the cached
		// generations so the next read reloads the repaired aggregates.
		s.historyCache.invalidateAll()
		return
	}
	ts, ok := s.DB.(storage.TestHistoryStore)
	if !ok {
		return
	}
	reports, err := s.DB.ListTestReportsAll(ctx)
	if err != nil {
		s.logError("test history: list reports failed", "error", err.Error())
		return
	}
	h := testintel.NewHistory()
	repoForRun := map[string]string{}
	for _, r := range reports {
		repo, cached := repoForRun[r.RunID]
		if !cached {
			if run, gerr := s.DB.GetRun(ctx, r.RunID); gerr == nil {
				repo = repoIDForRun(run)
			}
			repoForRun[r.RunID] = repo
		}
		for _, c := range r.Cases {
			h.Record(repo, r.JobKey, c.Class, c.Name, c.Duration, c.Passed, r.CreatedAt)
		}
	}
	stats, err := historyStats(h)
	if err != nil {
		s.logError("test history: serialize failed", "error", err.Error())
		return
	}
	version, err := ts.SaveTestHistory(ctx, stats)
	if err != nil {
		s.logError("test history: cache save failed", "error", err.Error())
		return
	}
	s.historyCache.store(historyWholeCacheKey, repoHistoryCacheEntry{version: version, history: h})
}

// loadRepoHistoryWithRepair loads one repository's durable aggregates. A
// repository with no version row predates migration 0026 (or its aggregates
// were truncated): it is rebuilt ONCE from its durable reports through the
// explicit bounded repair operation, then re-read. This is the upgrade
// bridge — uploads never trigger a rebuild.
func (s *Server) loadRepoHistoryWithRepair(ctx context.Context, agg storage.TestHistoryAggregateStore, repoID string) (int64, []byte, error) {
	version, stats, err := agg.LoadRepoTestHistory(ctx, repoID)
	if err != nil {
		return 0, nil, err
	}
	if version == 0 && len(stats) == 0 {
		if _, rerr := agg.RebuildRepoTestHistory(ctx, repoID); rerr != nil {
			return 0, nil, rerr
		}
		return agg.LoadRepoTestHistory(ctx, repoID)
	}
	return version, stats, nil
}

// historyForRepo returns the ONE history snapshot that must answer every
// test-intelligence decision of one request for repoID. The cache is keyed by
// repository and versioned: the snapshot is validated against the durable
// per-repository aggregates (including the lazy repair bridge) exactly as the
// pre-keyed sync did, and the returned pointer can never be replaced by
// another repository's generation while the response is being built. In
// memory/fs mode and for legacy TestHistoryStore-backed servers the single
// whole-history snapshot (which already contains every repository) is
// returned.
//
// A load failure or a corrupt snapshot returns the degraded generation — the
// last cached snapshot, or an empty history on a cold cache — together with
// the error, because an unreachable history store must not fail a shard
// request (the pre-keyed sync logged and kept serving too). Callers log the
// error and MUST NOT consult a nil snapshot: the returned history is never
// nil.
func (s *Server) historyForRepo(ctx context.Context, repoID string) (*testintel.History, error) {
	agg, ok := s.DB.(storage.TestHistoryAggregateStore)
	if !ok {
		if s.DB != nil {
			s.syncTestHistoryDBLegacy(ctx)
		}
		return s.cachedHistoryOrEmpty(repoID), nil
	}
	if repoID == "" {
		// No canonical repository identity: no cached snapshot may answer, so
		// a request can never be served another repository's tests under the
		// empty key.
		return testintel.NewHistory(), nil
	}
	version, stats, err := s.loadRepoHistoryWithRepair(ctx, agg, repoID)
	if err != nil {
		return s.cachedHistoryOrEmpty(repoID), err
	}
	if entry, hit := s.historyCache.lookup(repoID); hit && entry.history != nil && entry.version == version {
		return entry.history, nil
	}
	if len(stats) == 0 {
		// An empty repository is a valid state: record the observation so the
		// empty snapshot is not reloaded on every request.
		empty := testintel.NewHistory()
		s.historyCache.store(repoID, repoHistoryCacheEntry{version: version, history: empty})
		return empty, nil
	}
	h, err := historyFromStats(stats)
	if err != nil {
		return s.cachedHistoryOrEmpty(repoID), err
	}
	s.historyCache.store(repoID, repoHistoryCacheEntry{version: version, history: h})
	return h, nil
}

// cachedHistoryOrEmpty is the degraded-mode floor of historyForRepo: the last
// cached snapshot when one exists, otherwise a fresh empty history. Never
// nil.
func (s *Server) cachedHistoryOrEmpty(repoID string) *testintel.History {
	if h := s.cachedHistory(repoID); h != nil {
		return h
	}
	return testintel.NewHistory()
}

// cachedHistory returns the last cached snapshot for repoID WITHOUT any store
// I/O: the repository's entry in DB aggregate mode, the whole-history entry
// in memory/fs and legacy-store mode. Nil means "nothing cached" and callers
// must treat it as no history rather than falling back to another key.
func (s *Server) cachedHistory(repoID string) *testintel.History {
	key := historyWholeCacheKey
	if _, ok := s.DB.(storage.TestHistoryAggregateStore); ok {
		if repoID == "" {
			return nil
		}
		key = repoID
	}
	if entry, hit := s.historyCache.lookup(key); hit {
		return entry.history
	}
	return nil
}

// syncTestHistoryDBLegacy is the pre-0026 whole-cache convergence for stores
// that only implement TestHistoryStore: version 0/absent is the empty start,
// and a version that did not advance is left alone.
func (s *Server) syncTestHistoryDBLegacy(ctx context.Context) {
	ts, ok := s.DB.(storage.TestHistoryStore)
	if !ok {
		return
	}
	version, stats, err := ts.LoadTestHistory(ctx)
	if err != nil {
		s.logError("test history: cache load failed", "error", err.Error())
		return
	}
	entry, hit := s.historyCache.lookup(historyWholeCacheKey)
	if hit && entry.history != nil && version <= entry.version {
		return
	}
	if len(stats) == 0 {
		s.historyCache.store(historyWholeCacheKey, repoHistoryCacheEntry{version: version, history: entry.historyOrNew()})
		return
	}
	h, err := historyFromStats(stats)
	if err != nil {
		s.logError("test history: decode cached stats failed", "error", err.Error())
		return
	}
	s.historyCache.store(historyWholeCacheKey, repoHistoryCacheEntry{version: version, history: h})
}

// historyStats serializes the current in-memory history in the same JSON
// shape the history file uses (testintel.History.Save).
func historyStats(h *testintel.History) ([]byte, error) {
	f, err := os.CreateTemp("", "kiwi-history-*")
	if err != nil {
		return nil, err
	}
	path := f.Name()
	defer os.Remove(path)
	if err := h.Save(path); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// historyFromStats restores a testintel.History from serialized stats bytes.
func historyFromStats(stats []byte) (*testintel.History, error) {
	f, err := os.CreateTemp("", "kiwi-history-*")
	if err != nil {
		return nil, err
	}
	path := f.Name()
	defer os.Remove(path)
	if _, err := f.Write(stats); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return testintel.LoadHistory(path)
}

// flakyFromHistory returns the flaky set of the last cached snapshot for repo.
// The read is synchronized through the cache mutex (the pre-fix helper read
// the mutable global history without the writer's lock); request paths that
// need the full Shard/Manifest/Flaky trio take ONE snapshot through
// historyForRepo instead.
func (s *Server) flakyFromHistory(repo string) []string {
	h := s.cachedHistory(repo)
	if h == nil {
		return nil
	}
	return h.Flaky(repo)
}

// requireRunIdentity loads the run that keys every test-intelligence
// decision (shard assignment, report history). The lookup is NEVER
// best-effort: an unavailable or missing run answers an opaque 5xx and
// reports false BEFORE any shard assignment or history write, so a
// zero-valued run can never produce the empty repository key that would
// merge unrelated repositories' test history. In DB mode the durable row is
// authoritative; in memory mode the run map entry is required.
func (s *Server) requireRunIdentity(w http.ResponseWriter, r *http.Request, runID string) (model.Run, bool) {
	if s.DB != nil {
		run, err := s.DB.GetRun(r.Context(), runID)
		if err != nil {
			s.serverError(w, r, http.StatusServiceUnavailable, err, testHistoryIdentityUnavailable)
			return model.Run{}, false
		}
		return run, true
	}
	s.mu.Lock()
	run, ok := s.runs[runID]
	s.mu.Unlock()
	if !ok {
		s.serverError(w, r, http.StatusServiceUnavailable, storage.ErrNotFound, testHistoryIdentityUnavailable)
		return model.Run{}, false
	}
	return run, true
}

// testShards implements GET /api/v1/jobs/{id}/test-shards: under the job's
// active lease it returns the deterministic shard assignment derived from
// the persisted test history plus the environment contract the runner must
// honor (KIWI_TEST_SHARD_TOTAL / KIWI_TEST_SHARD_INDEX). The shard count
// comes from ?shards= or the job's declared tests.shards, and ?shard=i
// narrows the response to one shard.
func (s *Server) testShards(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	runnerID := r.Header.Get("X-Kiwi-Runner-ID")
	token := r.Header.Get("X-Kiwi-Lease-Token")
	gen, _ := strconv.ParseInt(r.Header.Get("X-Kiwi-Lease-Generation"), 10, 64)
	j, authErr := s.authorizeRunnerLease(r, runnerID, token, gen)
	if authErr != nil {
		s.writeLeaseAuthError(w, r, authErr)
		return
	}
	// The shard/history key is the run's canonical repository identity, so
	// two forges presenting the same bare name never share test history. A
	// failed or missing authoritative run lookup fails the request closed
	// instead of sharding under an empty key.
	run, ok := s.requireRunIdentity(w, r, j.RunID)
	if !ok {
		return
	}
	repo := repoIDForRun(run)
	// DB mode: converge THIS repository's cached snapshot with its durable
	// aggregates before any decision so replicas shard identically. The read
	// is scoped by the run's canonical repository identity and never touches
	// another repository's history. The ONE returned snapshot answers every
	// decision below, so a concurrent request for another repository can
	// never swap the history between Shard, Manifest and Flaky.
	h, err := s.historyForRepo(r.Context(), repo)
	if err != nil {
		s.logError("test history: serving cached snapshot after load failure", "repo", repo, "error", err.Error())
	}
	suite := j.Key
	shards := 1
	if v, err := strconv.Atoi(r.URL.Query().Get("shards")); err == nil && v > 0 && v <= 256 {
		shards = v
	} else if cj, ok := compileJobFromPipeline(j); ok && cj.Job.Tests.Shards > 0 {
		shards = cj.Job.Tests.Shards
	}
	if shards < 1 {
		shards = 1
	}
	assignment := h.Shard(repo, suite, shards)
	manifest := h.Manifest(repo, suite)
	flaky := h.Flaky(repo)
	sort.Strings(flaky)
	body := map[string]any{
		"job_id":      jobID,
		"repo":        repo,
		"suite":       suite,
		"shards":      shards,
		"assignment":  assignment,
		"manifest":    manifest,
		"flaky_tests": flaky,
		"env_contract": map[string]any{
			"KIWI_TEST_SHARD_TOTAL": strconv.Itoa(shards),
			"KIWI_TEST_SHARD_INDEX": "${{ matrix.test_shard }}",
		},
	}
	if v := r.URL.Query().Get("shard"); v != "" {
		if idx, err := strconv.Atoi(v); err == nil && idx >= 0 && idx < shards {
			body["shard"] = idx
			body["tests"] = assignment[idx]
			body["env_contract"] = map[string]any{
				"KIWI_TEST_SHARD_TOTAL": strconv.Itoa(shards),
				"KIWI_TEST_SHARD_INDEX": strconv.Itoa(idx),
			}
		} else {
			http.Error(w, "shard index out of range", http.StatusBadRequest)
			return
		}
	}
	writeJSON(w, http.StatusOK, body)
}
