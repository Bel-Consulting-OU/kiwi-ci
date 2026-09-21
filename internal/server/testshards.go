package server

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

const testHistoryFile = "test-history.json"

// testHistoryIdentityUnavailable is the fixed opaque body for a failed or
// missing authoritative run lookup on the test-intelligence paths (shard
// assignment and report upload); the store detail stays in the server log.
const testHistoryIdentityUnavailable = "test history identity unavailable"

// testintelHistory wraps the package-level testintel.History with its
// persistence path so the server owns save/load atomically.
type testintelHistory struct {
	h    *testintel.History
	path string
}

func newTestintelHistory(path string) *testintelHistory {
	return &testintelHistory{h: testintel.NewHistory(), path: path}
}

// loadTestintelHistory restores the persisted history from
// dataDir/test-history.json; a missing file starts empty. The file is
// always persisted (both memory and DB modes): it is the complete durable
// history store.
func (s *Server) loadTestintelHistory(dataDir string) error {
	path := ""
	if dataDir != "" {
		path = filepath.Join(dataDir, testHistoryFile)
		if h, err := testintel.LoadHistory(path); err == nil {
			s.history = &testintelHistory{h: h, path: path}
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	s.history = newTestintelHistory(path)
	return nil
}

// saveTestintelHistoryLocked atomically persists the history. Callers hold
// s.mu. Servers without a data dir keep the history in memory only.
func (s *Server) saveTestintelHistoryLocked() error {
	if s.history == nil || s.history.path == "" {
		return nil
	}
	return s.history.h.Save(s.history.path + ".tmp")
}

// renameTestintelHistoryLocked commits the staged history file atomically.
func (s *Server) commitTestintelHistoryLocked() error {
	if s.history == nil || s.history.path == "" {
		return nil
	}
	return os.Rename(s.history.path+".tmp", s.history.path)
}

// mirrorTestReportHistoryDB folds one ALREADY DURABLY COMMITTED report into
// this replica's in-memory history. In the aggregate-store path the durable
// aggregate was updated in the same transaction as the report (see
// storage.TestHistoryAggregateStore.InsertTestReportWithHistory), so this is
// a local mirror only: it makes the new data visible immediately without any
// database work, and it deliberately marks the in-memory history as a local
// mix so the next sync reloads the repository's durable aggregates.
func (s *Server) mirrorTestReportHistoryDB(repo string, rep model.TestReport) {
	if s.history == nil {
		return
	}
	s.mu.Lock()
	for _, c := range rep.Cases {
		s.history.h.Record(repo, rep.JobKey, c.Class, c.Name, c.Duration, c.Passed, rep.CreatedAt)
	}
	s.historyDBRepo = ""
	s.mu.Unlock()
}

// recordTestReportHistory is the LEGACY-store and memory-mode history write.
// In memory mode the history file under dataDir is the durable store. A DB
// store without the incremental aggregate contract falls back to the
// explicit full rebuild (the documented maintenance path); the production
// PostgresStore implements the aggregate contract, so an upload never
// rebuilds the whole history. ctx is the request context: a canceled request
// performs no durable write (the legacy rebuild logs and aborts).
func (s *Server) recordTestReportHistory(ctx context.Context, repo string, rep model.TestReport) {
	if s.history == nil {
		return
	}
	if s.DB != nil {
		// Legacy store: fold locally so this instance serves the new data,
		// then repair the shared cache from the committed reports.
		s.mu.Lock()
		for _, c := range rep.Cases {
			s.history.h.Record(repo, rep.JobKey, c.Class, c.Name, c.Duration, c.Passed, rep.CreatedAt)
		}
		s.mu.Unlock()
		s.rebuildTestHistoryDB(ctx)
		return
	}
	s.mu.Lock()
	for _, c := range rep.Cases {
		s.history.h.Record(repo, rep.JobKey, c.Class, c.Name, c.Duration, c.Passed, rep.CreatedAt)
	}
	if err := s.saveTestintelHistoryLocked(); err != nil {
		s.logError("test history: save failed", "error", err.Error())
	} else if err := s.commitTestintelHistoryLocked(); err != nil {
		s.logError("test history: commit failed", "error", err.Error())
	}
	s.mu.Unlock()
}

// maintenanceRepoLimit bounds the explicit repair/rebuild enumeration.
const maintenanceRepoLimit = 1000

// rebuildTestHistoryDB is the EXPLICIT maintenance/repair operation (never
// called per upload). With an incremental aggregate store it rebuilds every
// repository's aggregates through the bounded per-repository repair; with a
// legacy TestHistoryStore it recomputes the serialized cache from all
// durable reports exactly as the pre-0026 code did. A failure only logs: the
// durable reports are untouched and the in-memory history keeps serving.
func (s *Server) rebuildTestHistoryDB(ctx context.Context) {
	if agg, ok := s.DB.(storage.TestHistoryAggregateStore); ok {
		repos, err := agg.ListTestHistoryRepoIDs(ctx, maintenanceRepoLimit)
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
		// Force the next sync to reload the repaired aggregates.
		s.mu.Lock()
		s.historyDBVersion = 0
		s.historyDBRepo = ""
		s.mu.Unlock()
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
	s.mu.Lock()
	s.history.h = h
	s.historyDBVersion = version
	s.historyDBRepo = ""
	s.mu.Unlock()
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

// syncTestHistoryDB converges the in-memory history with the durable
// per-repository aggregates when their version advanced (another replica
// uploaded reports). Only the requested repository's aggregates are read; a
// load failure keeps the current in-memory history. Stores without the
// incremental contract fall back to the legacy whole-cache sync.
func (s *Server) syncTestHistoryDB(ctx context.Context, repoID string) {
	agg, ok := s.DB.(storage.TestHistoryAggregateStore)
	if !ok {
		s.syncTestHistoryDBLegacy(ctx)
		return
	}
	if repoID == "" {
		return
	}
	version, stats, err := s.loadRepoHistoryWithRepair(ctx, agg, repoID)
	if err != nil {
		s.logError("test history: repository load failed", "repo", repoID, "error", err.Error())
		return
	}
	s.mu.Lock()
	local, localRepo := s.historyDBVersion, s.historyDBRepo
	s.mu.Unlock()
	if version == local && repoID == localRepo {
		return
	}
	if len(stats) == 0 {
		// An empty repository is a valid state: record which repository the
		// process observed so it does not reload it on every call.
		s.mu.Lock()
		s.historyDBVersion = version
		s.historyDBRepo = repoID
		s.mu.Unlock()
		return
	}
	h, err := historyFromStats(stats)
	if err != nil {
		s.logError("test history: decode cached stats failed", "error", err.Error())
		return
	}
	s.mu.Lock()
	s.history.h = h
	s.historyDBVersion = version
	s.historyDBRepo = repoID
	s.mu.Unlock()
}

// syncTestHistoryDBLegacy is the pre-0026 whole-cache convergence for stores
// that only implement TestHistoryStore.
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
	s.mu.Lock()
	local := s.historyDBVersion
	s.mu.Unlock()
	if version <= local {
		return
	}
	if len(stats) == 0 {
		s.mu.Lock()
		s.historyDBVersion = version
		s.mu.Unlock()
		return
	}
	h, err := historyFromStats(stats)
	if err != nil {
		s.logError("test history: decode cached stats failed", "error", err.Error())
		return
	}
	s.mu.Lock()
	s.history.h = h
	s.historyDBVersion = version
	s.historyDBRepo = ""
	s.mu.Unlock()
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

// flakyFromHistory returns the persisted-history flaky set for a repo.
func (s *Server) flakyFromHistory(repo string) []string {
	if s.history == nil {
		return nil
	}
	return s.history.h.Flaky(repo)
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
	// DB mode: converge the in-memory history with THIS repository's durable
	// aggregates before any decision so replicas shard identically. The read
	// is scoped by the run's canonical repository identity and never touches
	// another repository's history.
	if s.DB != nil {
		s.syncTestHistoryDB(r.Context(), repo)
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
	assignment := s.history.h.Shard(repo, suite, shards)
	manifest := s.history.h.Manifest(repo, suite)
	flaky := s.flakyFromHistory(repo)
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
