package server

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

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
// persistent history under s.mu.
func (s *Server) recordTestReportHistory(repo string, rep model.TestReport) {
	if s.history == nil {
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
	now := time.Now().UTC()
	j, err := s.jobForLease(r.Context(), jobID)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if !s.verifyRunnerIdentity(r, runnerID) {
		http.Error(w, "runner identity mismatch", http.StatusForbidden)
		return
	}
	if !s.validActiveLease(j, runnerID, token, gen, now) {
		http.Error(w, "stale or invalid lease", http.StatusConflict)
		return
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
