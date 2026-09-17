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
	s.mu.Lock()
	s.history.h.Record("github.com/o/repo-a", "build", "C", "flaky", 1, false, time.Now().UTC())
	s.history.h.Record("github.com/o/repo-a", "build", "C", "flaky", 1, true, time.Now().UTC())
	s.mu.Unlock()
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

func TestFlowTestShardsRunLookup(t *testing.T) {
	// DB run read failure leaves a zero run; the shard key resolves empty.
	s, f, _, hdrs := cacheFixture(t)
	s.DB = &fcStore{dbFakeStore: f, getRunErr: errors.New("run read down")}
	w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/test-shards", "runner-tok", "", hdrs)
	if w.Code != http.StatusOK {
		t.Fatalf("run read failure shards = %d", w.Code)
	}
}

func TestFlowTestShardsHistoryNil(t *testing.T) {
	s := New("tok")
	s.history = nil
	if got := s.flakyFromHistory("github.com/o/repo-a"); got != nil {
		t.Fatalf("nil-history flaky = %v", got)
	}
	// testShards with a nil history is not reachable through the handler
	// (New always installs one); the helper guard is covered above.
	_ = context.Background()
	_ = model.Job{}
}
