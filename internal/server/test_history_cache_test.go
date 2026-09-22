package server

// Keyed, versioned test-history cache tests (testshards.go): the deterministic
// pre-fix regression, the concurrent no-mixed-generations stress proof, the
// LRU bound, and the version/mirror semantics.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testintel"
)

// seedTestHistoryRepo inserts one durable report per test name for repoID so
// the repository has distinct aggregate history. The named test is recorded
// pass+fail (flaky).
func seedTestHistoryRepo(t *testing.T, ctx context.Context, st storage.TestHistoryAggregateStore, repoID, runID, suite string, names []string, flaky string) {
	t.Helper()
	now := time.Now().UTC()
	for i, name := range names {
		cases := []model.TestResult{{Class: "C", Name: name, Passed: true, Duration: float64(i + 1)}}
		if name == flaky {
			cases = []model.TestResult{
				{Class: "C", Name: name, Passed: false, Duration: float64(i + 1)},
				{Class: "C", Name: name, Passed: true, Duration: float64(i + 1)},
			}
		}
		if _, err := st.InsertTestReportWithHistory(ctx, model.TestReport{
			ID: "rep-" + repoID + "-" + name, RunID: runID, JobKey: suite, Tests: len(cases), Cases: cases, CreatedAt: now,
		}, repoID); err != nil {
			t.Fatal(err)
		}
	}
}

// TestTestHistorySnapshotKeyedPerRepository is the deterministic,
// single-threaded regression for the pre-fix single global slot: the snapshot
// a request takes for repo A must keep answering Shard/Manifest/Flaky from A
// after repo B has been loaded. The pre-fix read path (re-reading the global
// slot at every call) returned B's emptiness for A's repository/suite — the
// scratch reproduction against HEAD showed "assignment covers 2 tests,
// manifest [], flaky []".
func TestTestHistorySnapshotKeyedPerRepository(t *testing.T) {
	ctx := context.Background()
	f := newDBFakeStore()
	s := New("tok")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	seedTestHistoryRepo(t, ctx, f, "github.com/o/a", "run-a", "build", []string{"a-slow", "a-quick"}, "a-slow")
	seedTestHistoryRepo(t, ctx, f, "github.com/o/b", "run-b", "build", []string{"b-only"}, "")

	// Request A converges A and takes ONE snapshot...
	hA, err := s.historyForRepo(ctx, "github.com/o/a")
	if err != nil {
		t.Fatal(err)
	}
	// ...then request B converges its own repository.
	hB, err := s.historyForRepo(ctx, "github.com/o/b")
	if err != nil {
		t.Fatal(err)
	}

	assignment := hA.Shard("github.com/o/a", "build", 2)
	manifest := hA.Manifest("github.com/o/a", "build")
	flaky := hA.Flaky("github.com/o/a")
	total := 0
	for _, shard := range assignment {
		total += len(shard)
	}
	if total != 2 || !reflect.DeepEqual(manifest, []string{"C.a-quick", "C.a-slow"}) || !reflect.DeepEqual(flaky, []string{"C.a-slow"}) {
		t.Fatalf("A's snapshot after B's load: assignment covers %d tests, manifest %v, flaky %v; want 2/2/[C.a-slow]", total, manifest, flaky)
	}
	// B's snapshot answers from B and never from A.
	if got := hB.Manifest("github.com/o/b", "build"); !reflect.DeepEqual(got, []string{"C.b-only"}) {
		t.Fatalf("B's manifest = %v, want [C.b-only]", got)
	}
	if got := hB.Manifest("github.com/o/a", "build"); len(got) != 0 {
		t.Fatalf("B's snapshot leaked A's tests: %v", got)
	}
	if got := hB.Flaky("github.com/o/a"); len(got) != 0 {
		t.Fatalf("B's snapshot leaked A's flaky set: %v", got)
	}
	// The keyed entries are intact: A's entry was not replaced by B.
	entryA, ok := s.historyCache.lookup("github.com/o/a")
	if !ok || entryA.history != hA {
		t.Fatalf("A's cache entry was replaced by another repository: ok=%v", ok)
	}
	// An unchanged durable version is served from the SAME snapshot (the
	// version check avoids re-decoding) — generation stability for the whole
	// response follows from that single pointer.
	hA2, err := s.historyForRepo(ctx, "github.com/o/a")
	if err != nil || hA2 != hA {
		t.Fatalf("unchanged version returned a new snapshot: same=%v err=%v", hA2 == hA, err)
	}
}

// TestTestHistorySnapshotEmptyRepoIdentityNeverBorrows proves a request whose
// run has no canonical repository identity can never be answered from a
// cached repository's history (the empty key used to merge repositories).
func TestTestHistorySnapshotEmptyRepoIdentityNeverBorrows(t *testing.T) {
	ctx := context.Background()
	f := newDBFakeStore()
	s := New("tok")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	seedTestHistoryRepo(t, ctx, f, "github.com/o/a", "run-a", "build", []string{"a-1"}, "a-1")
	if _, err := s.historyForRepo(ctx, "github.com/o/a"); err != nil {
		t.Fatal(err)
	}
	h, err := s.historyForRepo(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if manifest := h.Manifest("github.com/o/a", "build"); len(manifest) != 0 {
		t.Fatalf("empty repository identity borrowed A's manifest: %v", manifest)
	}
	if flaky := h.Flaky("github.com/o/a"); len(flaky) != 0 {
		t.Fatalf("empty repository identity borrowed A's flaky set: %v", flaky)
	}
}

// slowHistoryStore widens the durable load window so concurrent requests for
// different repositories interleave as much as possible, and counts the
// per-repository loads.
type slowHistoryStore struct {
	*dbFakeStore
	delay time.Duration
	mu    sync.Mutex
	loads map[string]int
}

func newSlowHistoryStore(delay time.Duration) *slowHistoryStore {
	return &slowHistoryStore{dbFakeStore: newDBFakeStore(), delay: delay, loads: map[string]int{}}
}

func (s *slowHistoryStore) LoadRepoTestHistory(ctx context.Context, repoID string) (int64, []byte, error) {
	s.mu.Lock()
	s.loads[repoID]++
	s.mu.Unlock()
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		}
	}
	return s.dbFakeStore.LoadRepoTestHistory(ctx, repoID)
}

// countingLoadStore counts per-repository durable history loads.
type countingLoadStore struct {
	*dbFakeStore
	mu    sync.Mutex
	loads map[string]int
}

func (c *countingLoadStore) LoadRepoTestHistory(ctx context.Context, repoID string) (int64, []byte, error) {
	c.mu.Lock()
	c.loads[repoID]++
	c.mu.Unlock()
	return c.dbFakeStore.LoadRepoTestHistory(ctx, repoID)
}

func (c *countingLoadStore) loadCount(repoID string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loads[repoID]
}

// historyStressRepo is one seeded repository of the concurrency stress test.
type historyStressRepo struct {
	repoID string
	jobID  string
	names  []string
	flaky  string
	hdrs   map[string]string
}

// manifest is the exact sorted test list the repository's history answers.
func (r historyStressRepo) manifest() []string {
	out := make([]string, 0, len(r.names))
	for _, name := range r.names {
		out = append(out, "C."+name)
	}
	return out
}

func (r historyStressRepo) flakyNames() []string {
	return []string{"C." + r.flaky}
}

// historyStressServer wires a DB-mode server over a deliberately slow
// aggregate store with two repositories whose test names and durations are
// disjoint, plus a leased job and run per repository.
func historyStressServer(t *testing.T) (*Server, *slowHistoryStore, historyStressRepo, historyStressRepo) {
	t.Helper()
	st := newSlowHistoryStore(250 * time.Microsecond)
	s := New("token")
	if err := s.SwitchToDB(st); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	mk := func(tag string) historyStressRepo {
		repoID := "github.com/o/" + tag
		runID := "run-" + tag
		jobID := "job-" + tag
		runnerID := "runner-" + tag
		names := make([]string, 0, 24)
		for i := 0; i < 24; i++ {
			names = append(names, fmt.Sprintf("%s-%02d", tag, i))
		}
		now := time.Now().UTC()
		exp := now.Add(time.Hour)
		job := model.Job{ID: jobID, RunID: runID, Key: "build", RepoID: repoID, RepoURL: "https://" + repoID + ".git", RepoFullName: "o/" + tag,
			Status: model.StatusRunning, Trusted: true, LeaseRunnerID: runnerID, LeaseTokenHash: hashLeaseToken(s.leaseKey, "cache-lease-token"),
			LeaseGeneration: 5, LeaseExpiresAt: &exp}
		run := model.Run{ID: runID, RepoID: repoID, RepoFullName: "o/" + tag, Repo: "https://" + repoID + ".git", Status: model.StatusRunning}
		st.mu.Lock()
		st.runs[runID] = run
		st.jobs[jobID] = job
		st.runners[runnerID] = model.Runner{ID: runnerID, Name: runnerID, Capacity: 1}
		st.mu.Unlock()
		s.mu.Lock()
		s.runs[runID] = run
		s.jobs[jobID] = job
		s.runners[runnerID] = model.Runner{ID: runnerID, Name: runnerID, Capacity: 1}
		s.mu.Unlock()
		seedTestHistoryRepo(t, ctx, st, repoID, runID, "build", names, tag+"-00")
		return historyStressRepo{
			repoID: repoID, jobID: jobID, names: names, flaky: tag + "-00",
			hdrs: map[string]string{"X-Kiwi-Runner-ID": runnerID, "X-Kiwi-Lease-Token": "cache-lease-token", "X-Kiwi-Lease-Generation": "5"},
		}
	}
	return s, st, mk("a"), mk("b")
}

// checkAssignmentSet verifies the shard union covers exactly the repository's
// known tests, once each.
func checkAssignmentSet(rp historyStressRepo, assignment [][]string, report func(string, ...any)) {
	seen := map[string]int{}
	for _, shard := range assignment {
		for _, name := range shard {
			seen[name]++
		}
	}
	for _, name := range rp.manifest() {
		if seen[name] != 1 {
			report("repo %s: test %s appears %d times across shards", rp.repoID, name, seen[name])
		}
	}
	if len(seen) != len(rp.names) {
		report("repo %s: assignment covers %d distinct tests, want %d", rp.repoID, len(seen), len(rp.names))
	}
}

// checkShardResponse serves one test-shards request for rp and proves the
// response contains exactly rp's own history: its manifest, its flaky set and
// a shard union over its tests (exact equality, so no name of another
// repository can appear and no generation can be mixed in).
func checkShardResponse(s *Server, rp historyStressRepo, report func(string, ...any)) {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+rp.jobID+"/test-shards?shards=3", nil)
	r.Header.Set("Authorization", "Bearer token")
	for k, v := range rp.hdrs {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		report("repo %s: test-shards = %d: %s", rp.repoID, w.Code, w.Body.String())
		return
	}
	var out struct {
		Repo       string     `json:"repo"`
		Manifest   []string   `json:"manifest"`
		Assignment [][]string `json:"assignment"`
		Flaky      []string   `json:"flaky_tests"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		report("repo %s: decode response: %v", rp.repoID, err)
		return
	}
	if out.Repo != rp.repoID {
		report("repo %s: response repo label = %q", rp.repoID, out.Repo)
		return
	}
	if !reflect.DeepEqual(out.Manifest, rp.manifest()) {
		report("repo %s: manifest = %v, want %v", rp.repoID, out.Manifest, rp.manifest())
	}
	if !reflect.DeepEqual(out.Flaky, rp.flakyNames()) {
		report("repo %s: flaky = %v, want %v", rp.repoID, out.Flaky, rp.flakyNames())
	}
	checkAssignmentSet(rp, out.Assignment, report)
}

// checkSnapshotTrio proves ONE snapshot pointer answers Shard, Manifest and
// Flaky consistently and only from its own repository.
func checkSnapshotTrio(rp historyStressRepo, h *testintel.History, report func(string, ...any)) {
	if h == nil {
		report("repo %s: nil snapshot", rp.repoID)
		return
	}
	first := h.Manifest(rp.repoID, "build")
	assignment := h.Shard(rp.repoID, "build", 3)
	second := h.Manifest(rp.repoID, "build")
	flaky := h.Flaky(rp.repoID)
	if !reflect.DeepEqual(first, second) {
		report("repo %s: snapshot changed between reads: %v vs %v", rp.repoID, first, second)
	}
	if !reflect.DeepEqual(first, rp.manifest()) {
		report("repo %s: snapshot manifest = %v, want %v", rp.repoID, first, rp.manifest())
	}
	if !reflect.DeepEqual(flaky, rp.flakyNames()) {
		report("repo %s: snapshot flaky = %v, want %v", rp.repoID, flaky, rp.flakyNames())
	}
	checkAssignmentSet(rp, assignment, report)
}

// TestTestHistoryConcurrentReposNeverMixGenerations hammers the shard
// endpoint from many goroutines for two repositories with disjoint test
// histories while the slow store forces the loads to interleave. Every
// response and every snapshot must see exactly its own repository's
// generation; run with -race. Pre-fix, the shared global slot made responses
// answer from the other repository's history.
func TestTestHistoryConcurrentReposNeverMixGenerations(t *testing.T) {
	s, st, a, b := historyStressServer(t)
	const workers, rounds = 8, 10
	var mu sync.Mutex
	var problems []string
	report := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if len(problems) < 25 {
			problems = append(problems, fmt.Sprintf(format, args...))
		}
	}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			order := []historyStressRepo{a, b}
			if seed%2 == 1 {
				order = []historyStressRepo{b, a}
			}
			for i := 0; i < rounds; i++ {
				for _, rp := range order {
					checkShardResponse(s, rp, report)
					h, err := s.historyForRepo(context.Background(), rp.repoID)
					if err != nil {
						report("repo %s: snapshot error %v", rp.repoID, err)
						continue
					}
					checkSnapshotTrio(rp, h, report)
				}
			}
		}(w)
	}
	wg.Wait()
	if len(problems) > 0 {
		t.Fatalf("mixed generations / cross-repository leakage observed:\n%s", strings.Join(problems, "\n"))
	}
	// Both repositories' durable histories were actually loaded, so the storm
	// exercised the interleaving the test is about.
	st.mu.Lock()
	loadsA, loadsB := st.loads[a.repoID], st.loads[b.repoID]
	st.mu.Unlock()
	if loadsA == 0 || loadsB == 0 {
		t.Fatalf("slow store loads = A:%d B:%d, want both repositories exercised", loadsA, loadsB)
	}
}

// TestRepoHistoryCacheEvictionBound pins the bounded LRU: the least recently
// used repository is evicted past the cap, recency is honored, overwriting an
// existing key cannot grow the cache, invalidateAll drops everything and a
// nil cache is inert.
func TestRepoHistoryCacheEvictionBound(t *testing.T) {
	entry := func(v int64) repoHistoryCacheEntry {
		return repoHistoryCacheEntry{version: v, history: testintel.NewHistory()}
	}
	c := newRepoHistoryCache(2)
	c.store("a", entry(1))
	c.store("b", entry(2))
	c.lookup("a") // a is now the most recently used; b is the LRU
	c.store("c", entry(3))
	if c.has("b") {
		t.Fatal("least recently used repository survived the eviction bound")
	}
	if !c.has("a") || !c.has("c") {
		t.Fatal("recently used repositories were evicted")
	}
	if c.len() != 2 {
		t.Fatalf("cache len = %d, want the 2-entry bound", c.len())
	}
	c.store("a", entry(4))
	if c.len() != 2 {
		t.Fatalf("overwriting a key grew the cache to %d, want 2", c.len())
	}
	if e, _ := c.lookup("a"); e.version != 4 {
		t.Fatalf("overwritten entry version = %d, want 4", e.version)
	}
	// update creates missing keys and preserves existing versions unless fn
	// changes them.
	c.update("new", func(e *repoHistoryCacheEntry) {
		if e.history == nil {
			t.Fatal("update must provide a snapshot")
		}
		e.version = 9
	})
	if e, ok := c.lookup("new"); !ok || e.version != 9 {
		t.Fatalf("updated entry = %+v ok=%v", e, ok)
	}
	c.invalidateAll()
	if c.len() != 0 || c.has("a") || c.has("c") {
		t.Fatalf("invalidateAll left %d entries", c.len())
	}
	// max < 1 clamps to a single entry.
	one := newRepoHistoryCache(0)
	one.store("a", entry(1))
	one.store("b", entry(2))
	if one.len() != 1 || !one.has("b") {
		t.Fatalf("clamped cache len = %d, want 1 holding the newest key", one.len())
	}
	// A nil cache (bare test servers) is inert, never panics.
	var nilCache *repoHistoryCache
	if _, ok := nilCache.lookup("a"); ok {
		t.Fatal("nil cache reported a hit")
	}
	nilCache.store("a", entry(1))
	nilCache.update("a", func(e *repoHistoryCacheEntry) { e.version = 7 })
	nilCache.invalidateAll()
	if nilCache.len() != 0 || nilCache.has("a") {
		t.Fatal("nil cache is not inert")
	}
}

// TestTestHistoryCacheVersionAndEviction pins the server-level cache
// semantics: an unchanged durable version serves the same snapshot, the
// eviction bound forces a reload, a version advance replaces the generation
// (leaving already-taken snapshots untouched), and the local upload mirror
// marks the entry stale so the next read reloads the durable generation.
func TestTestHistoryCacheVersionAndEviction(t *testing.T) {
	ctx := context.Background()
	f := newDBFakeStore()
	cs := &countingLoadStore{dbFakeStore: f, loads: map[string]int{}}
	s := New("tok")
	if err := s.SwitchToDB(cs); err != nil {
		t.Fatal(err)
	}
	s.historyCache = newRepoHistoryCache(2) // small bound: eviction observable
	for _, tag := range []string{"a", "b", "c"} {
		seedTestHistoryRepo(t, ctx, cs, "github.com/o/"+tag, "run-"+tag, "build", []string{tag + "-1"}, "")
	}
	a := "github.com/o/a"

	hA, err := s.historyForRepo(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if got := hA.Manifest(a, "build"); !reflect.DeepEqual(got, []string{"C.a-1"}) {
		t.Fatalf("A manifest = %v, want [C.a-1]", got)
	}
	loads := cs.loadCount(a)
	// Unchanged version: version validation still reads the store, but the
	// snapshot is served as-is.
	hSame, err := s.historyForRepo(ctx, a)
	if err != nil || hSame != hA {
		t.Fatalf("unchanged version: same=%v err=%v", hSame == hA, err)
	}
	if got := cs.loadCount(a); got != loads+1 {
		t.Fatalf("version validations = %d, want %d", got, loads+1)
	}

	// Fill the 2-entry cache and push A out (A is the least recently used).
	if _, err := s.historyForRepo(ctx, "github.com/o/b"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.historyForRepo(ctx, "github.com/o/c"); err != nil {
		t.Fatal(err)
	}
	if s.historyCache.has(a) {
		t.Fatal("least recently used repository survived the cache bound")
	}
	if !s.historyCache.has("github.com/o/b") || !s.historyCache.has("github.com/o/c") {
		t.Fatal("recently used repositories were evicted")
	}
	loads = cs.loadCount(a)
	hReloaded, err := s.historyForRepo(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if hReloaded == hA {
		t.Fatal("an evicted repository must be reloaded from its durable aggregates")
	}
	if got := cs.loadCount(a); got != loads+1 {
		t.Fatalf("reloads after eviction = %d, want %d", got, loads+1)
	}
	if got := hReloaded.Manifest(a, "build"); !reflect.DeepEqual(got, []string{"C.a-1"}) {
		t.Fatalf("reloaded manifest = %v, want [C.a-1]", got)
	}

	// A version advance replaces the repository's generation; a snapshot
	// already taken for the response keeps answering its own generation.
	if _, err := cs.InsertTestReportWithHistory(ctx, model.TestReport{
		ID: "rep-a-new", RunID: "run-a", JobKey: "build", CreatedAt: time.Now().UTC(),
		Cases: []model.TestResult{{Class: "C", Name: "a-new", Passed: true, Duration: 1}},
	}, a); err != nil {
		t.Fatal(err)
	}
	hNew, err := s.historyForRepo(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if got := hNew.Manifest(a, "build"); !reflect.DeepEqual(got, []string{"C.a-1", "C.a-new"}) {
		t.Fatalf("manifest after version advance = %v, want [C.a-1 C.a-new]", got)
	}
	if got := hReloaded.Manifest(a, "build"); !reflect.DeepEqual(got, []string{"C.a-1"}) {
		t.Fatalf("taken snapshot changed under a newer generation: %v", got)
	}

	// A same-repository upload mirror marks the entry stale but NEVER mutates
	// the cached snapshot: the stale entry still holds hNew, the exact
	// immutable generation already taken above. The next read atomically
	// swaps in a freshly decoded pointer.
	s.mirrorTestReportHistoryDB(a)
	e, ok := s.historyCache.lookup(a)
	if !ok || e.version != historyStaleVersion {
		t.Fatalf("mirrored entry version = %d ok=%v, want stale (%d)", e.version, ok, historyStaleVersion)
	}
	if e.history != hNew {
		t.Fatal("the mirror replaced or mutated the cached snapshot instead of only marking it stale")
	}
	if got := hNew.Manifest(a, "build"); !reflect.DeepEqual(got, []string{"C.a-1", "C.a-new"}) {
		t.Fatalf("held snapshot changed under the mirror: %v", got)
	}
	hDurable, err := s.historyForRepo(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if hDurable == hNew {
		t.Fatal("the stale entry must be reloaded into a fresh pointer")
	}
	if got := hDurable.Manifest(a, "build"); !reflect.DeepEqual(got, []string{"C.a-1", "C.a-new"}) {
		t.Fatalf("mirror was not superseded by the durable generation: %v", got)
	}
}

// TestTestHistorySnapshotStableAcrossSameRepoUpload is the reviewer's
// deterministic immutability regression: ONE snapshot taken for a response
// must keep answering Shard, Manifest and Flaky from its own generation while
// a same-repository upload commits and mirrors. Pre-fix the mirror called
// Record on the cached snapshot in place, so the held pointer observed the
// later generation (counters, manifest, flaky) mid-response.
func TestTestHistorySnapshotStableAcrossSameRepoUpload(t *testing.T) {
	ctx := context.Background()
	f := newDBFakeStore()
	s := New("tok")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	repo := "github.com/o/a"
	seedTestHistoryRepo(t, ctx, f, repo, "run-a", "build", []string{"a-slow", "a-quick"}, "a-slow")
	h, err := s.historyForRepo(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	beforeManifest := h.Manifest(repo, "build")
	beforeFlaky := h.Flaky(repo)
	beforeAssignment := h.Shard(repo, "build", 2)

	// The same repository's next upload commits its durable aggregate (a new
	// test plus fresh outcomes) and mirrors the cache entry stale.
	if _, err := f.InsertTestReportWithHistory(ctx, model.TestReport{
		ID: "rep-late", RunID: "run-a", JobKey: "build", CreatedAt: time.Now().UTC(),
		Cases: []model.TestResult{{Class: "C", Name: "a-late", Passed: true}, {Class: "C", Name: "a-slow", Passed: false}},
	}, repo); err != nil {
		t.Fatal(err)
	}
	s.mirrorTestReportHistoryDB(repo)

	// The held pointer answers its own generation consistently: the exact
	// Manifest/Shard/Flaky trio of the response cannot change mid-flight.
	if got := h.Manifest(repo, "build"); !reflect.DeepEqual(got, beforeManifest) {
		t.Fatalf("held manifest changed under a same-repo upload: %v -> %v", beforeManifest, got)
	}
	if got := h.Shard(repo, "build", 2); !reflect.DeepEqual(got, beforeAssignment) {
		t.Fatalf("held assignment changed under a same-repo upload: %v -> %v", beforeAssignment, got)
	}
	if got := h.Flaky(repo); !reflect.DeepEqual(got, beforeFlaky) {
		t.Fatalf("held flaky set changed under a same-repo upload: %v -> %v", beforeFlaky, got)
	}
	if strings.Contains(strings.Join(h.Manifest(repo, "build"), ","), "a-late") {
		t.Fatal("held snapshot observed a later generation")
	}

	// The next read swaps in the durable generation as a NEW pointer; the
	// held one stays frozen.
	next, err := s.historyForRepo(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if next == h {
		t.Fatal("the same-repo mirror did not force a fresh decode")
	}
	if got := next.Manifest(repo, "build"); !reflect.DeepEqual(got, []string{"C.a-late", "C.a-quick", "C.a-slow"}) {
		t.Fatalf("fresh generation manifest = %v", got)
	}
	if got := h.Manifest(repo, "build"); !reflect.DeepEqual(got, beforeManifest) {
		t.Fatalf("held snapshot changed after the reload: %v", got)
	}
}

// TestTestHistoryMemorySnapshotStableAcrossUpdate is the memory/fs half of
// the same-repo immutability regression: recordTestReportHistory publishes a
// deep clone, so the whole-history snapshot a reader holds is never mutated.
func TestTestHistoryMemorySnapshotStableAcrossUpdate(t *testing.T) {
	ctx := context.Background()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repo := "github.com/o/a"
	s.recordTestReportHistory(ctx, repo, model.TestReport{JobKey: "build", CreatedAt: time.Now().UTC(),
		Cases: []model.TestResult{{Class: "C", Name: "a-slow", Passed: false}, {Class: "C", Name: "a-slow", Passed: true}}})
	held := s.cachedHistory(repo)
	if held == nil {
		t.Fatal("memory snapshot missing")
	}
	beforeManifest := held.Manifest(repo, "build")
	beforeFlaky := held.Flaky(repo)

	s.recordTestReportHistory(ctx, repo, model.TestReport{JobKey: "build", CreatedAt: time.Now().UTC(),
		Cases: []model.TestResult{{Class: "C", Name: "a-late", Passed: true}, {Class: "C", Name: "a-slow", Passed: false}}})

	if got := held.Manifest(repo, "build"); !reflect.DeepEqual(got, beforeManifest) {
		t.Fatalf("memory snapshot mutated in place: %v -> %v", beforeManifest, got)
	}
	if got := held.Flaky(repo); !reflect.DeepEqual(got, beforeFlaky) {
		t.Fatalf("memory snapshot flaky set mutated in place: %v -> %v", beforeFlaky, got)
	}
	next := s.cachedHistory(repo)
	if next == held {
		t.Fatal("memory update must publish a NEW snapshot (copy-on-write)")
	}
	if got := next.Manifest(repo, "build"); !reflect.DeepEqual(got, []string{"C.a-late", "C.a-slow"}) {
		t.Fatalf("new memory generation manifest = %v", got)
	}
}

// TestTestHistoryMemoryWriteFailureKeepsFoldVisible pins the durability rule
// of the memory/fs copy-on-write AFTER the durable-report fix: the report is
// the durable artifact (the caller committed it to state.json before calling
// this), so a failed history-CACHE write must not withhold the fold — the
// derived snapshot is published as a NEW generation while every snapshot a
// reader already holds stays frozen (never mutated in place). The cache file
// is repaired by the next successful write or by the startup rebuild.
func TestTestHistoryMemoryWriteFailureKeepsFoldVisible(t *testing.T) {
	ctx := context.Background()
	repo := "github.com/o/a"
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.recordTestReportHistory(ctx, repo, model.TestReport{ID: "rep-1", JobKey: "build", CreatedAt: time.Now().UTC(),
		Cases: []model.TestResult{{Class: "C", Name: "a-slow", Passed: false}, {Class: "C", Name: "a-slow", Passed: true}}})
	held := s.cachedHistory(repo)
	before := held.Manifest(repo, "build")

	// Save failure: the history path's parent is a regular file.
	block := filepath.Join(t.TempDir(), "block")
	if err := os.WriteFile(block, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.historyFile = block + "/sub/history.json"
	s.recordTestReportHistory(ctx, repo, model.TestReport{ID: "rep-2", JobKey: "build", CreatedAt: time.Now().UTC(),
		Cases: []model.TestResult{{Class: "C", Name: "a-late", Passed: true}}})
	afterSave := s.cachedHistory(repo)
	if afterSave == held {
		t.Fatal("the durable report's fold did not publish a new snapshot")
	}
	if got := held.Manifest(repo, "build"); !reflect.DeepEqual(got, before) {
		t.Fatalf("a failed save mutated a held snapshot: %v", got)
	}
	if got := afterSave.Manifest(repo, "build"); !reflect.DeepEqual(got, []string{"C.a-late", "C.a-slow"}) {
		t.Fatalf("the fold was withheld after a failed cache save: %v", got)
	}

	// Commit failure: the staged file writes next to a DIRECTORY, so the
	// rename onto the history path fails after a successful stage.
	s.historyFile = t.TempDir()
	s.recordTestReportHistory(ctx, repo, model.TestReport{ID: "rep-3", JobKey: "build", CreatedAt: time.Now().UTC(),
		Cases: []model.TestResult{{Class: "C", Name: "a-later", Passed: true}}})
	afterCommit := s.cachedHistory(repo)
	if afterCommit == afterSave {
		t.Fatal("the durable report's fold did not publish a new snapshot after a failed commit")
	}
	if got := strings.Join(afterSave.Manifest(repo, "build"), ","); got != "C.a-late,C.a-slow" {
		t.Fatalf("held snapshot changed after a failed commit: %v", got)
	}
	if got := afterCommit.Manifest(repo, "build"); !reflect.DeepEqual(got, []string{"C.a-late", "C.a-later", "C.a-slow"}) {
		t.Fatalf("fold after a failed commit = %v", got)
	}
}

// TestTestHistoryFlakyDropsOutAfterCleanWindow pins the window-derived flaky
// predicate across the aggregate mirror and the server snapshot: a test with
// a lifetime failure that then passes its last 16 observations is no longer
// flaky, and a fresh failure restores it.
func TestTestHistoryFlakyDropsOutAfterCleanWindow(t *testing.T) {
	ctx := context.Background()
	f := newDBFakeStore()
	s := New("tok")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	repo := "github.com/o/a"
	now := time.Now().UTC()
	if _, err := f.InsertTestReportWithHistory(ctx, model.TestReport{
		ID: "rep-fail", RunID: "run-a", JobKey: "build", CreatedAt: now,
		Cases: []model.TestResult{{Class: "C", Name: "t", Passed: false}},
	}, repo); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < testintel.OutcomeWindow; i++ {
		if _, err := f.InsertTestReportWithHistory(ctx, model.TestReport{
			ID: fmt.Sprintf("rep-pass-%02d", i), RunID: "run-a", JobKey: "build", CreatedAt: now.Add(time.Duration(i+1) * time.Second),
			Cases: []model.TestResult{{Class: "C", Name: "t", Passed: true}},
		}, repo); err != nil {
			t.Fatal(err)
		}
	}
	if flaky, err := f.FlakyTestNames(ctx, []string{repo}, 100); err != nil || len(flaky) != 0 {
		t.Fatalf("aggregate flaky after clean window = %v, %v; want none", flaky, err)
	}
	h, err := s.historyForRepo(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if got := h.Flaky(repo); len(got) != 0 {
		t.Fatalf("snapshot flaky after clean window = %v, want none", got)
	}
	// A fresh failure inside the window puts the test back on both paths.
	if _, err := f.InsertTestReportWithHistory(ctx, model.TestReport{
		ID: "rep-fail-again", RunID: "run-a", JobKey: "build", CreatedAt: now.Add(time.Minute),
		Cases: []model.TestResult{{Class: "C", Name: "t", Passed: false}},
	}, repo); err != nil {
		t.Fatal(err)
	}
	if flaky, err := f.FlakyTestNames(ctx, []string{repo}, 100); err != nil || !reflect.DeepEqual(flaky, []string{"C.t"}) {
		t.Fatalf("aggregate flaky after fresh failure = %v, %v; want [C.t]", flaky, err)
	}
	h2, err := s.historyForRepo(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}
	if got := h2.Flaky(repo); !reflect.DeepEqual(got, []string{"C.t"}) {
		t.Fatalf("snapshot flaky after fresh failure = %v, want [C.t]", got)
	}
}

// TestSummarizeTestIntelligenceWindowAligned proves the report-derived
// summary uses the same bounded window as the persisted history and the SQL
// aggregates: a test that failed long ago and passed its whole window is not
// reported flaky, and the fold order is deterministic (created_at, then id).
func TestSummarizeTestIntelligenceWindowAligned(t *testing.T) {
	base := time.Now().UTC()
	reports := []model.TestReport{{ID: "old", CreatedAt: base,
		Cases: []model.TestResult{{Class: "C", Name: "t", Passed: false}}}}
	for i := 0; i < testintel.OutcomeWindow; i++ {
		reports = append(reports, model.TestReport{ID: fmt.Sprintf("p%02d", i), CreatedAt: base.Add(time.Duration(i+1) * time.Second),
			Cases: []model.TestResult{{Class: "C", Name: "t", Passed: true}}})
	}
	out := summarizeTestIntelligence(reports)
	if got, _ := out["flaky_tests"].([]string); len(got) != 0 {
		t.Fatalf("report-derived flaky after a clean window = %v, want none", got)
	}
	// The same reports in any input order yield the same answer (the fold
	// order is created_at/id, not slice order).
	shuffled := append([]model.TestReport(nil), reports...)
	for i, j := 0, len(shuffled)-1; i < j; i, j = i+1, j-1 {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	out2 := summarizeTestIntelligence(shuffled)
	if fmt.Sprint(out2["flaky_tests"]) != fmt.Sprint(out["flaky_tests"]) {
		t.Fatalf("summary is order-dependent: %v vs %v", out2["flaky_tests"], out["flaky_tests"])
	}
	// A fresh failure inside the window restores flakiness.
	fresh := append([]model.TestReport(nil), reports...)
	fresh = append(fresh, model.TestReport{ID: "new", CreatedAt: base.Add(time.Minute),
		Cases: []model.TestResult{{Class: "C", Name: "t", Passed: false}}})
	out3 := summarizeTestIntelligence(fresh)
	if got, _ := out3["flaky_tests"].([]string); len(got) != 1 || got[0] != "C.t" {
		t.Fatalf("report-derived flaky after a fresh failure = %v, want [C.t]", got)
	}
}
