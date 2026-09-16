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

// recordTestReportHistory folds one uploaded test report into the
// persistent history. In memory mode the history file under dataDir is the
// durable store; in DB mode the durable reports are the source of truth and
// the history is rebuilt from them and cached with a version bump (see
// rebuildTestHistoryDB).
func (s *Server) recordTestReportHistory(repo string, rep model.TestReport) {
	if s.history == nil {
		return
	}
	if s.DB != nil {
		// Fold into the in-memory history first so this instance serves the
		// new data immediately, then rebuild the durable cache from the
		// committed reports (the upload already persisted the report).
		s.mu.Lock()
		for _, c := range rep.Cases {
			s.history.h.Record(repo, rep.JobKey, c.Class, c.Name, c.Duration, c.Passed, rep.CreatedAt)
		}
		s.mu.Unlock()
		s.rebuildTestHistoryDB(context.Background())
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

// rebuildTestHistoryDB recomputes the full test history from the durable
// reports and caches the serialized aggregates with a version bump. Every
// replica that rebuilds from the same committed reports derives the same
// history, so shard assignments converge. A failure only logs: the durable
// reports are untouched and the in-memory history (already folded with the
// new report) keeps serving locally.
func (s *Server) rebuildTestHistoryDB(ctx context.Context) {
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
				repo = run.RepoFullName
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
	s.mu.Unlock()
}

// syncTestHistoryDB converges the in-memory history with the durable cache
// when its version advanced (another replica uploaded reports). A load
// failure keeps the current in-memory history.
func (s *Server) syncTestHistoryDB(ctx context.Context) {
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
	// DB mode: converge the in-memory test history with the durable cache
	// before any decision so replicas shard identically.
	if s.DB != nil {
		s.syncTestHistoryDB(r.Context())
	}
	run := model.Run{}
	if s.DB != nil {
		run, _ = s.DB.GetRun(r.Context(), j.RunID)
	} else {
		s.mu.Lock()
		run = s.runs[j.RunID]
		s.mu.Unlock()
	}
	repo := run.RepoFullName
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
