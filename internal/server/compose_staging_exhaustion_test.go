package server

// Cross-feature composition: staging-budget exhaustion shared by the snapshot
// and cache upload paths.
//
// The snapshot archive and the cache entry are the two large bodies that
// consume the ONE shared staging budget (staging.Budget). These tests fill it
// with a real in-flight snapshot upload and prove the cache upload waits, and
// vice versa that typical interleavings of success, copy error, client
// disconnect and request cancellation all return the budget exactly to
// baseline while leaving no spool file behind. A TMPDIR watcher pins the
// "never a bare system temp directory" property for the whole composition, and
// the configured-bound refusal is composed with real upload attempts against
// a server that has no usable bound installed.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/config"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
)

// composeTmpWatcher points TMPDIR at a fresh watched directory so a test can
// assert that no staging path ever fell back to the bare system temp
// directory.
func composeTmpWatcher(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	return dir
}

// composeTempEntries lists the entries under a watched temp dir.
func composeTempEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read watched temp dir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// composeStagingWorld builds the GC/staging world with a fresh shared budget
// of maxBytes in its own directory, returning the budget.
func composeStagingWorld(t *testing.T, maxBytes int64) (*Server, *dbFakeStore, *staging.Budget) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "staging")
	b, err := staging.NewBudget(dir, maxBytes)
	if err != nil {
		t.Fatalf("staging budget: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	s, f, _ := composeGCWorld(t, WithStagingBudget(b))
	return s, f, b
}

// composeSnapshotRequest builds a snapshot upload request for the compose
// server whose runner token is "token" (snapshotUploadRequest hardcodes the
// legacy "runner-tok" fixture token).
func composeSnapshotRequest(jobID string, body io.Reader, contentLength int64, hdrs map[string]string) *http.Request {
	r := snapshotUploadRequest(http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", body, contentLength, hdrs)
	r.Header.Set("Authorization", "Bearer token")
	return r
}

// composeCacheBody is a request body that closes touched on its first Read, so
// a test can prove the handler never touched the body (it was blocked on the
// shared budget) without sleeping for a fixed drain time.
type composeCacheBody struct {
	b       []byte
	touched chan struct{}
	once    sync.Once
}

func newComposeCacheBody(b []byte) *composeCacheBody {
	return &composeCacheBody{b: b, touched: make(chan struct{})}
}

func (r *composeCacheBody) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.touched) })
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

// TestComposeStagingBudgetSharedBySnapshotAndCache fills the shared budget
// with an in-flight snapshot upload (held by a gated body) and proves a
// concurrent cache upload waits for the release instead of overcommitting the
// staging directory: while the snapshot owns the budget the cache body is not
// touched, and once the snapshot finishes the cache proceeds and both leave
// the ledger at zero with no spool files.
func TestComposeStagingBudgetSharedBySnapshotAndCache(t *testing.T) {
	watched := composeTmpWatcher(t)
	archive, _ := snapshotArchive(t)
	const budgetBytes = 64 << 10
	const snapshotDeclared = 60 << 10
	const cacheBytes = 8 << 10
	s, f, budget := composeStagingWorld(t, budgetBytes)
	hdrs := composeSeedLeasedJob(t, s, f, "job-share", "runner-share")
	cachePayload := bytes.Repeat([]byte{'c'}, cacheBytes)

	// The snapshot declares (and therefore reserves) most of the shared
	// budget while it stages its archive.
	snapReader := newGatedBodyReader(archive)
	snapReq := composeSnapshotRequest("job-share", snapReader, snapshotDeclared, hdrs)
	snapDone := uploadSnapshotAsync(s, snapReq)
	<-snapReader.started
	if got, want := budget.Used(), int64(snapshotDeclared); got != want {
		t.Fatalf("staging used while snapshot in flight = %d, want %d", got, want)
	}
	// Exactly one spool file, inside the budget directory, carrying the
	// package prefix.
	inFlight := stageFiles(t, budget.Dir())
	if len(inFlight) != 1 || !strings.HasPrefix(inFlight[0], staging.FilePrefix) {
		t.Fatalf("in-flight staging files = %v, want one %s* file in %s", inFlight, staging.FilePrefix, budget.Dir())
	}

	// The cache upload cannot fit (8 KiB > the 4 KiB left): it must wait
	// before touching its body.
	cacheBody := newComposeCacheBody(cachePayload)
	cacheReq := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-share/cache/"+fmt.Sprintf("%064x", 3), cacheBody)
	cacheReq.ContentLength = cacheBytes
	cacheReq.Header.Set("Authorization", "Bearer token")
	for k, v := range hdrs {
		cacheReq.Header.Set(k, v)
	}
	cacheDone := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, cacheReq)
		cacheDone <- w.Code
	}()
	select {
	case <-cacheBody.touched:
		t.Fatal("cache body was read while the shared staging budget had no room")
	case <-time.After(150 * time.Millisecond):
	}
	if got := budget.Used(); got != int64(snapshotDeclared) {
		t.Fatalf("staging used changed while the cache waited = %d, want %d", got, snapshotDeclared)
	}

	// Release the snapshot: it commits, the cache proceeds.
	snapReader.releaseBody()
	if w := <-snapDone; w.Code != http.StatusCreated {
		t.Fatalf("snapshot upload = %d, want 201: %s", w.Code, w.Body.String())
	}
	if code := <-cacheDone; code != http.StatusCreated {
		t.Fatalf("cache upload after snapshot released the budget = %d, want 201", code)
	}
	if got := budget.Used(); got != 0 {
		t.Fatalf("staging used after both uploads = %d, want 0", got)
	}
	if leftovers := stageFiles(t, budget.Dir()); len(leftovers) != 0 {
		t.Fatalf("staging files left after both uploads: %v", leftovers)
	}
	if entries := composeTempEntries(t, watched); len(entries) != 0 {
		t.Fatalf("uploads staged into the bare system temp directory: %v", entries)
	}
	// Both artifacts are durable and resolvable.
	f.mu.Lock()
	manifests := len(f.cacheMans)
	snapshots := len(f.snapshots)
	f.mu.Unlock()
	if manifests != 1 || snapshots != 1 {
		t.Fatalf("committed manifests=%d snapshots=%d, want 1/1", manifests, snapshots)
	}
}

// TestComposeStagingExhaustionTypedErrors proves the documented typed
// refusals when the shared budget can never satisfy a request, and that a
// blocked waiter's cancellation changes nothing and the next request
// succeeds.
func TestComposeStagingExhaustionTypedErrors(t *testing.T) {
	watched := composeTmpWatcher(t)
	archive, _ := snapshotArchive(t)
	s, f, budget := composeStagingWorld(t, int64(len(archive)))
	hdrs := composeSeedLeasedJob(t, s, f, "job-types", "runner-types")

	// A snapshot reservation larger than the whole budget fails immediately
	// with the documented reason and never touches its body.
	counting := &countingBodyReader{}
	big := composeSnapshotRequest("job-types", counting, int64(len(archive))+1, hdrs)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, big)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "staging budget") {
		t.Fatalf("over-budget snapshot = %d %q, want 503 staging-budget refusal", w.Code, w.Body.String())
	}
	if counting.reads != 0 {
		t.Fatalf("over-budget snapshot read its body %d time(s)", counting.reads)
	}

	// A cache entry whose declared length exceeds the budget is refused
	// before staging with the cache 413 contract.
	cacheBody := bytes.NewReader(bytes.Repeat([]byte{'x'}, int(len(archive))+1))
	cacheReq := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-types/cache/"+fmt.Sprintf("%064x", 4), cacheBody)
	cacheReq.ContentLength = int64(len(archive)) + 1
	cacheReq.Header.Set("Authorization", "Bearer token")
	for k, v := range hdrs {
		cacheReq.Header.Set(k, v)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, cacheReq)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-budget cache = %d, want 413: %s", w.Code, w.Body.String())
	}
	if got := budget.Used(); got != 0 {
		t.Fatalf("refused uploads changed the staging ledger to %d", got)
	}

	// Fill the budget, then cancel the blocked cache waiter: the reservation
	// it never got changes nothing, no spool file appears, and the next
	// upload succeeds once the holder finishes.
	snapReader := newGatedBodyReader(archive)
	snapReq := composeSnapshotRequest("job-types", snapReader, int64(len(archive)), hdrs)
	snapDone := uploadSnapshotAsync(s, snapReq)
	<-snapReader.started

	waitCtx, cancelWait := context.WithCancel(context.Background())
	waitBody := newComposeCacheBody([]byte("compose-waiter"))
	waitReq := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-types/cache/"+fmt.Sprintf("%064x", 5), waitBody).WithContext(waitCtx)
	waitReq.ContentLength = 64
	waitReq.Header.Set("Authorization", "Bearer token")
	for k, v := range hdrs {
		waitReq.Header.Set(k, v)
	}
	waitDone := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, waitReq)
		waitDone <- w.Code
	}()
	select {
	case <-waitBody.touched:
		t.Fatal("blocked cache waiter read its body before the budget was free")
	case <-time.After(150 * time.Millisecond):
	}
	cancelWait()
	if code := <-waitDone; code == http.StatusCreated {
		t.Fatalf("cancelled waiter was acknowledged with %d", code)
	}
	if got := budget.Used(); got != int64(len(archive)) {
		t.Fatalf("cancelled waiter changed the ledger to %d, want %d", got, len(archive))
	}

	snapReader.releaseBody()
	if w := <-snapDone; w.Code != http.StatusCreated {
		t.Fatalf("snapshot upload = %d, want 201: %s", w.Code, w.Body.String())
	}
	// The next request succeeds cleanly.
	next := bytes.NewReader([]byte("compose-next"))
	nextReq := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-types/cache/"+fmt.Sprintf("%064x", 6), next)
	nextReq.ContentLength = 13
	nextReq.Header.Set("Authorization", "Bearer token")
	for k, v := range hdrs {
		nextReq.Header.Set(k, v)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, nextReq)
	if w.Code != http.StatusCreated {
		t.Fatalf("next upload after cancellation = %d, want 201: %s", w.Code, w.Body.String())
	}
	if got := budget.Used(); got != 0 {
		t.Fatalf("staging used at end = %d, want 0", got)
	}
	if leftovers := stageFiles(t, budget.Dir()); len(leftovers) != 0 {
		t.Fatalf("staging files left: %v", leftovers)
	}
	if entries := composeTempEntries(t, watched); len(entries) != 0 {
		t.Fatalf("bare system temp staging observed: %v", entries)
	}
}

// TestComposeStagingReleasesOnEveryExitPath drives error and disconnect exits
// for both consumers back-to-back and measures the ledger at baseline after
// each; the final upload proves the shared budget is still fully usable.
func TestComposeStagingReleasesOnEveryExitPath(t *testing.T) {
	watched := composeTmpWatcher(t)
	archive, _ := snapshotArchive(t)
	s, f, budget := composeStagingWorld(t, int64(len(archive))*4)
	hdrs := composeSeedLeasedJob(t, s, f, "job-exit", "runner-exit")

	// 1. Snapshot copy error.
	r := composeSnapshotRequest("job-exit", &fcErrReader{}, 1024, hdrs)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code < 400 {
		t.Fatalf("snapshot copy error = %d, want an error status", w.Code)
	}
	if got := budget.Used(); got != 0 {
		t.Fatalf("snapshot copy error left %d staged bytes", got)
	}

	// 2. Snapshot client disconnect (request context cancelled mid-copy).
	ctx, cancel := context.WithCancel(context.Background())
	reader := newGatedBodyReader(archive)
	req := composeSnapshotRequest("job-exit", reader, int64(len(archive)), hdrs).WithContext(ctx)
	done := uploadSnapshotAsync(s, req)
	<-reader.started
	cancel()
	reader.releaseBody()
	<-done
	if got := budget.Used(); got != 0 {
		t.Fatalf("snapshot disconnect left %d staged bytes", got)
	}

	// 3. Cache copy error.
	broken := &brokenBody{prefix: []byte("partial"), err: fmt.Errorf("client went away")}
	cacheReq := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-exit/cache/"+fmt.Sprintf("%064x", 7), broken)
	cacheReq.ContentLength = 4096
	cacheReq.Header.Set("Authorization", "Bearer token")
	for k, v := range hdrs {
		cacheReq.Header.Set(k, v)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, cacheReq)
	if w.Code < 400 {
		t.Fatalf("cache copy error = %d, want an error status", w.Code)
	}
	if got := budget.Used(); got != 0 {
		t.Fatalf("cache copy error left %d staged bytes", got)
	}

	if leftovers := stageFiles(t, budget.Dir()); len(leftovers) != 0 {
		t.Fatalf("staging files left after error/disconnect exits: %v", leftovers)
	}
	if entries := composeTempEntries(t, watched); len(entries) != 0 {
		t.Fatalf("bare system temp staging observed: %v", entries)
	}

	// Baseline is intact: a full-budget-sized upload still succeeds.
	payload := bytes.Repeat([]byte{'z'}, int(budget.MaxBytes()))
	okReq := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-exit/cache/"+fmt.Sprintf("%064x", 8), bytes.NewReader(payload))
	okReq.ContentLength = budget.MaxBytes()
	okReq.Header.Set("Authorization", "Bearer token")
	for k, v := range hdrs {
		okReq.Header.Set(k, v)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, okReq)
	if w.Code != http.StatusCreated {
		t.Fatalf("full-budget upload after released exits = %d, want 201: %s", w.Code, w.Body.String())
	}
	if got := budget.Used(); got != 0 {
		t.Fatalf("staging used after the final upload = %d, want 0", got)
	}
}

// TestComposeNoUsableStagingBoundRefusesStartupAndFailsUploadsClosed composes
// the production configuration refusal with the runtime guard: the real
// config validation rejects an unusable bound, staging.NewBudget rejects the
// same shapes, and a server left without a usable bound fails BOTH large
// upload routes closed without spooling a single byte anywhere.
func TestComposeNoUsableStagingBoundRefusesStartupAndFailsUploadsClosed(t *testing.T) {
	watched := composeTmpWatcher(t)

	// The real configuration validator: max_bytes without a dir, and a dir
	// without a positive budget, are both startup errors.
	cfg := config.Default()
	cfg.Staging = config.StagingConfig{Dir: "", MaxBytes: 1 << 30}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "staging.dir") {
		t.Fatalf("config validation of max_bytes without dir = %v, want staging.dir error", err)
	}
	cfg.Staging = config.StagingConfig{Dir: filepath.Join(t.TempDir(), "s"), MaxBytes: 0}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "staging.max_bytes") {
		t.Fatalf("config validation of dir without budget = %v, want staging.max_bytes error", err)
	}

	// The constructor behind the app wiring: an unusable bound cannot be
	// turned into a budget.
	if _, err := staging.NewBudget("", 0); err == nil {
		t.Fatal("staging.NewBudget accepted an empty bound")
	}
	badParent := filepath.Join(t.TempDir(), "regular-file")
	if err := os.WriteFile(badParent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := staging.NewBudget(filepath.Join(badParent, "staging"), 1024); err == nil {
		t.Fatal("staging.NewBudget accepted a path under a regular file")
	}

	// The runtime guard: a server with no usable bound still serves, but
	// every large upload fails closed BEFORE touching the body. An explicit
	// construction-time nil budget (WithStagingBudget(nil)) supplies "no
	// bound" and suppresses the constructor's data-dir default.
	s, f, _ := composeGCWorld(t, WithStagingBudget(nil))
	hdrs := composeSeedLeasedJob(t, s, f, "job-nobound", "runner-nobound")
	archive, _ := snapshotArchive(t)

	counting := &countingBodyReader{}
	snapReq := composeSnapshotRequest("job-nobound", counting, int64(len(archive)), hdrs)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, snapReq)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "staging budget") {
		t.Fatalf("snapshot without a bound = %d %q, want 503 staging-budget refusal", w.Code, w.Body.String())
	}
	if counting.reads != 0 {
		t.Fatalf("snapshot without a bound read its body %d time(s)", counting.reads)
	}

	cacheCounting := &countingBodyReader{}
	cacheReq := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-nobound/cache/"+fmt.Sprintf("%064x", 9), cacheCounting)
	cacheReq.ContentLength = 16
	cacheReq.Header.Set("Authorization", "Bearer token")
	for k, v := range hdrs {
		cacheReq.Header.Set(k, v)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, cacheReq)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "staging budget") {
		t.Fatalf("cache without a bound = %d %q, want 503 staging-budget refusal", w.Code, w.Body.String())
	}
	if cacheCounting.reads != 0 {
		t.Fatalf("cache without a bound read its body %d time(s)", cacheCounting.reads)
	}

	// Nothing was staged anywhere.
	if entries := composeTempEntries(t, watched); len(entries) != 0 {
		t.Fatalf("no-bound uploads wrote to the bare system temp directory: %v", entries)
	}
	f.mu.Lock()
	if len(f.cacheMans) != 0 || len(f.snapshots) != 0 {
		t.Fatalf("no-bound uploads committed state: manifests=%d snapshots=%d", len(f.cacheMans), len(f.snapshots))
	}
	f.mu.Unlock()
	if s.StagingBudget() != nil {
		t.Fatal("server still carries a staging budget")
	}
}
