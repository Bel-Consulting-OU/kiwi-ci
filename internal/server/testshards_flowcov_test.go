package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

const fcShardsPipeline = `version: 1
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    tests:
      shards: 2
    steps:
      - run: echo hi
`

func TestFlowTestShardsBranches(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	// The seeded job has no pipeline: the shard count defaults to 1.
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/test-shards", "runner-tok", "", hdrs)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"shards":1`) {
		t.Fatalf("default shards = %d %s", w.Code, w.Body.String())
	}
	// Invalid lease.
	bad := map[string]string{"X-Kiwi-Runner-ID": "runner-a", "X-Kiwi-Lease-Token": "wrong", "X-Kiwi-Lease-Generation": "5"}
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/test-shards", "runner-tok", "", bad); w.Code != http.StatusConflict {
		t.Fatalf("bad lease shards = %d, want 409", w.Code)
	}
	// Query shard count valid, invalid, and out of the 256 bound.
	// Seed the whole-history snapshot a memory-mode server serves. ADAPTED:
	// the single-slot s.history field became the keyed cache, so the seed
	// goes through the cache's whole-history entry.
	s.historyCache.update(historyWholeCacheKey, func(e *repoHistoryCacheEntry) {
		e.history.Record("github.com/o/repo-a", "build", "C", "flaky", 1, false, time.Now().UTC())
		e.history.Record("github.com/o/repo-a", "build", "C", "flaky", 1, true, time.Now().UTC())
	})
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/test-shards?shards=3", "runner-tok", "", hdrs); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"shards":3`) {
		t.Fatalf("query shards = %d %s", w.Code, w.Body.String())
	}
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/test-shards?shards=0", "runner-tok", "", hdrs); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"shards":1`) {
		t.Fatalf("zero shards = %d %s", w.Code, w.Body.String())
	}
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/test-shards?shards=999", "runner-tok", "", hdrs); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"shards":1`) {
		t.Fatalf("oversize shards = %d %s", w.Code, w.Body.String())
	}
	// Pipeline-declared shards drive the default.
	s.mu.Lock()
	j := s.jobs["job-a"]
	j.Pipeline = fcShardsPipeline
	j.BaseKey = "build"
	j.Key = "build[test_shard=0]"
	s.jobs["job-a"] = j
	s.mu.Unlock()
	w = doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/test-shards", "runner-tok", "", hdrs)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"shards":2`) {
		t.Fatalf("pipeline shards = %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "flaky") {
		t.Fatalf("flaky list missing: %s", w.Body.String())
	}
	// Valid single-shard narrowing and out-of-range rejection.
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/test-shards?shard=0", "runner-tok", "", hdrs); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"shard":0`) {
		t.Fatalf("shard narrowing = %d %s", w.Code, w.Body.String())
	}
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/test-shards?shard=5", "runner-tok", "", hdrs); w.Code != http.StatusBadRequest {
		t.Fatalf("shard out of range = %d, want 400", w.Code)
	}
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/test-shards?shard=x", "runner-tok", "", hdrs); w.Code != http.StatusBadRequest {
		t.Fatalf("non-numeric shard = %d, want 400", w.Code)
	}
}

func TestFlowTestShardsDBMode(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	// The DB run has no repo identity: the canonical id resolves empty.
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/test-shards", "runner-tok", "", hdrs)
	if w.Code != http.StatusOK {
		t.Fatalf("db shards = %d: %s", w.Code, w.Body.String())
	}
	// A converged replica history is served from the durable cache.
	stats, err := historyStats(fcHistoryWithFlaky(t))
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.testHistoryVersion = 7
	f.testHistoryStats = stats
	f.mu.Unlock()
	w = doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/test-shards", "runner-tok", "", hdrs)
	if w.Code != http.StatusOK {
		t.Fatalf("db shards after sync = %d: %s", w.Code, w.Body.String())
	}
}

func fcHistoryWithFlaky(t *testing.T) *testintel.History {
	t.Helper()
	h := testintel.NewHistory()
	h.Record("github.com/o/repo-a", "build", "C", "flaky", 1, false, time.Now().UTC())
	h.Record("github.com/o/repo-a", "build", "C", "flaky", 1, true, time.Now().UTC())
	return h
}

// TestFlowTestShardsRunLookupFailsClosed proves a failed or missing
// authoritative run lookup never yields a shard assignment derived from an
// empty repository key: the DB store error, the missing DB row and the
// missing memory run entry all answer an opaque 5xx BEFORE any assignment.
func TestFlowTestShardsRunLookupFailsClosed(t *testing.T) {
	fault := errors.New("run read down")
	t.Run("db store error", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		s.DB = &fcStore{dbFakeStore: f, getRunErr: fault}
		w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/test-shards", "runner-tok", "", hdrs)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("run read failure shards = %d, want 503: %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), fault.Error()) {
			t.Fatalf("response leaked the raw store error: %q", w.Body.String())
		}
		if strings.Contains(w.Body.String(), `"assignment"`) || strings.Contains(w.Body.String(), `"repo"`) {
			t.Fatalf("failed lookup returned a shard assignment: %s", w.Body.String())
		}
	})
	t.Run("db run missing", func(t *testing.T) {
		s, f, _, hdrs := cacheFixture(t)
		f.mu.Lock()
		delete(f.runs, "run-c")
		f.mu.Unlock()
		w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/test-shards", "runner-tok", "", hdrs)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("missing db run shards = %d, want 503: %s", w.Code, w.Body.String())
		}
	})
	t.Run("memory run missing", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t)
		s.mu.Lock()
		delete(s.runs, "run-c")
		s.mu.Unlock()
		w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/test-shards", "runner-tok", "", hdrs)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("missing memory run shards = %d, want 503: %s", w.Code, w.Body.String())
		}
	})
}

func TestFlowTestShardsHistoryNil(t *testing.T) {
	s := New("tok")
	// ADAPTED: the nil single-slot history guard became the empty keyed
	// cache, which has no snapshot for any repository.
	s.historyCache.invalidateAll()
	// ADAPTED for the derived-history contract: the memory/fs read derives an
	// empty snapshot from the (empty) durable report set instead of returning
	// a nil cache miss.
	if got := s.flakyFromHistory("github.com/o/repo-a"); len(got) != 0 {
		t.Fatalf("uncached flaky = %v", got)
	}
	// testShards with an empty cache is not reachable through the handler
	// (New always installs one whole-history snapshot); the helper guard is
	// covered above.
	_ = context.Background()
	_ = model.Job{}
}
