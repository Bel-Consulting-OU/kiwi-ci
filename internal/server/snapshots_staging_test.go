package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
)

// gatedBodyReader signals when the handler has started reading the body and
// blocks every read until release() is called, so a test can hold a staged
// upload inside its copy loop while asserting the staging reservation.
type gatedBodyReader struct {
	data    []byte
	off     int
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func newGatedBodyReader(data []byte) *gatedBodyReader {
	return &gatedBodyReader{
		data:    data,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (r *gatedBodyReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

func (r *gatedBodyReader) releaseBody() { close(r.release) }

// countingBodyReader counts reads and never yields data; it proves a request
// was refused before its body was touched.
type countingBodyReader struct {
	reads int
}

func (r *countingBodyReader) Read(p []byte) (int, error) {
	r.reads++
	return 0, io.EOF
}

// snapshotUploadRequest builds a POST /jobs/job-a/snapshots request with an
// explicit body and Content-Length, carrying the runner bearer and the seeded
// lease headers.
func snapshotUploadRequest(method, target string, body io.Reader, contentLength int64, hdrs map[string]string) *http.Request {
	r := httptest.NewRequest(method, target, body)
	r.ContentLength = contentLength
	r.Header.Set("Authorization", "Bearer runner-tok")
	for k, v := range hdrs {
		r.Header.Set(k, v)
	}
	return r
}

// newUploadBudget installs a budget of maxBytes over a fresh directory and
// returns it.
func newUploadBudget(t *testing.T, s *Server, maxBytes int64) *staging.Budget {
	t.Helper()
	b, err := staging.NewBudget(t.TempDir(), maxBytes)
	if err != nil {
		t.Fatalf("staging budget: %v", err)
	}
	s.SetStagingBudget(b)
	return b
}

// uploadSnapshotAsync runs the upload handler in a goroutine and returns the
// response channel.
func uploadSnapshotAsync(s *Server, r *http.Request) chan *httptest.ResponseRecorder {
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		done <- w
	}()
	return done
}

// TestSnapshotUploadStagingReservationEnforced proves the L4-C bound: with a
// budget smaller than the sum of two upload reservations, the second upload
// cannot proceed while the first stages its body — it waits on the budget
// instead of overcommitting the staging directory — and both complete once
// the first releases.
func TestSnapshotUploadStagingReservationEnforced(t *testing.T) {
	s, _, _, hdrs := cacheFixture(t)
	body := fcSnapshotArchive(t)
	size := int64(len(body))
	budget := newUploadBudget(t, s, 2*size-1)

	first := newGatedBodyReader(body)
	aDone := uploadSnapshotAsync(s, snapshotUploadRequest(http.MethodPost, "/api/v1/jobs/job-a/snapshots", first, size, hdrs))
	select {
	case <-first.started:
		// The first upload holds its reservation inside the copy.
	case w := <-aDone:
		t.Fatalf("upload returned before reading its body: %d %s", w.Code, w.Body.String())
	case <-time.After(5 * time.Second):
		t.Fatal("upload never started reading its body")
	}
	if got := budget.Used(); got != size {
		t.Fatalf("staging used = %d, want the first upload's reservation %d", got, size)
	}

	second := snapshotUploadRequest(http.MethodPost, "/api/v1/jobs/job-a/snapshots", bytes.NewReader(body), size, hdrs)
	bDone := uploadSnapshotAsync(s, second)
	// Give the second upload time to reach Acquire; it must be blocked, so
	// it cannot have completed and only the first reservation is charged.
	time.Sleep(50 * time.Millisecond)
	if got := budget.Used(); got != size {
		t.Fatalf("staging used = %d while the first upload holds %d; the second reservation was granted (overcommit)", got, size)
	}
	select {
	case w := <-bDone:
		t.Fatalf("second upload completed while the budget was exhausted: %d %s", w.Code, w.Body.String())
	default:
	}

	first.releaseBody()
	aw := <-aDone
	if aw.Code != http.StatusCreated {
		t.Fatalf("first upload = %d: %s", aw.Code, aw.Body.String())
	}
	bw := <-bDone
	if bw.Code != http.StatusCreated {
		t.Fatalf("second upload = %d: %s", bw.Code, bw.Body.String())
	}
	if got := budget.Used(); got != 0 {
		t.Fatalf("staging used = %d after both uploads, want 0", got)
	}
}

// TestSnapshotUploadStagingReservationReleasedOnCopyError proves the
// reservation is returned when the staged copy fails: the failed upload
// leaves the budget intact (a full-budget reservation succeeds immediately
// afterwards) and no staging file survives.
func TestSnapshotUploadStagingReservationReleasedOnCopyError(t *testing.T) {
	s, _, _, hdrs := cacheFixture(t)
	budget := newUploadBudget(t, s, 4096)

	r := snapshotUploadRequest(http.MethodPost, "/api/v1/jobs/job-a/snapshots", &fcErrReader{}, 1024, hdrs)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("staging copy error = %d, want 500: %s", w.Code, w.Body.String())
	}
	if got := budget.Used(); got != 0 {
		t.Fatalf("staging used = %d after a copy error, want 0", got)
	}
	// The whole budget is immediately available again.
	res, err := budget.Acquire(context.Background(), 4096)
	if err != nil {
		t.Fatalf("budget not released after copy error: %v", err)
	}
	res.Release()
	if leftovers := stageFiles(t, budget.Dir()); len(leftovers) != 0 {
		t.Fatalf("staging files left after copy error: %v", leftovers)
	}
}

// TestSnapshotUploadStagingReservationReleasedOnDisconnect proves a client
// disconnect (request context cancelled mid-copy) neither leaks the
// reservation nor a partial staging file.
func TestSnapshotUploadStagingReservationReleasedOnDisconnect(t *testing.T) {
	s, _, _, hdrs := cacheFixture(t)
	body := fcSnapshotArchive(t)
	size := int64(len(body))
	budget := newUploadBudget(t, s, size)

	ctx, cancel := context.WithCancel(context.Background())
	reader := newGatedBodyReader(body)
	r := snapshotUploadRequest(http.MethodPost, "/api/v1/jobs/job-a/snapshots", reader, size, hdrs).WithContext(ctx)
	done := uploadSnapshotAsync(s, r)
	<-reader.started
	if got := budget.Used(); got != size {
		t.Fatalf("staging used = %d, want %d", got, size)
	}

	cancel() // the client disconnects
	reader.releaseBody()
	<-done // whatever the dead connection produced, the handler must exit cleanly

	if got := budget.Used(); got != 0 {
		t.Fatalf("staging used = %d after disconnect, want 0", got)
	}
	res, err := budget.Acquire(context.Background(), size)
	if err != nil {
		t.Fatalf("budget not released after disconnect: %v", err)
	}
	res.Release()
	if leftovers := stageFiles(t, budget.Dir()); len(leftovers) != 0 {
		t.Fatalf("staging files left after disconnect: %v", leftovers)
	}
}

// TestSnapshotUploadStagingUnknownLengthReservesMaximum proves the
// reservation policy for an unknown Content-Length: the endpoint maximum is
// reserved BEFORE the body is read, so a request that could still stream the
// whole endpoint cap is refused when that cap exceeds the budget — and the
// body is never touched.
func TestSnapshotUploadStagingUnknownLengthReservesMaximum(t *testing.T) {
	s, _, _, hdrs := cacheFixture(t)
	body := fcSnapshotArchive(t)
	oldMax := snapshotUploadMaxBytes
	t.Cleanup(func() { snapshotUploadMaxBytes = oldMax })
	snapshotUploadMaxBytes = int64(len(body))
	newUploadBudget(t, s, int64(len(body))-1)

	reader := &countingBodyReader{}
	r := snapshotUploadRequest(http.MethodPost, "/api/v1/jobs/job-a/snapshots", reader, -1, hdrs)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unknown-length upload over the budget = %d, want 503: %s", w.Code, w.Body.String())
	}
	if reader.reads != 0 {
		t.Fatalf("body read %d times before the staging reservation was granted", reader.reads)
	}

	// With the endpoint maximum inside the budget the same unknown-length
	// upload succeeds, charging exactly the maximum.
	budget2 := newUploadBudget(t, s, int64(len(body)))
	r2 := snapshotUploadRequest(http.MethodPost, "/api/v1/jobs/job-a/snapshots", bytes.NewReader(body), -1, hdrs)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r2)
	if w.Code != http.StatusCreated {
		t.Fatalf("unknown-length upload within the budget = %d, want 201: %s", w.Code, w.Body.String())
	}
	if got := budget2.Used(); got != 0 {
		t.Fatalf("staging used = %d after the upload, want 0", got)
	}
}

// TestSnapshotUploadStagingDeclaredLengthOverCap proves a declared
// Content-Length above the endpoint cap is refused before any reservation or
// body read.
func TestSnapshotUploadStagingDeclaredLengthOverCap(t *testing.T) {
	s, _, _, hdrs := cacheFixture(t)
	reader := &countingBodyReader{}
	r := snapshotUploadRequest(http.MethodPost, "/api/v1/jobs/job-a/snapshots", reader, snapshotUploadMaxBytes+1, hdrs)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-cap upload = %d, want 413: %s", w.Code, w.Body.String())
	}
	if reader.reads != 0 {
		t.Fatalf("over-cap body read %d times", reader.reads)
	}
}

// TestSnapshotUploadStagingStartupPrune proves the persistent constructor
// reclaims every spool file (staging.FilePrefix) left inside its OWN
// replica-private directory, while legacy top-level files in the configured
// staging root are NOT reclaimed at startup (R4-A: a pre-contract replica
// staged them with no ownership lock, so a live old replica may still be
// writing one during a rolling upgrade). They are reclaimed only by the
// explicit migration. Foreign files are never touched. Runtime Prune is
// age-based: it removes a stale spool file but keeps a fresh one.
func TestSnapshotUploadStagingStartupPrune(t *testing.T) {
	dir := t.TempDir()
	stagingRoot := filepath.Join(dir, "kiwi-staging")
	if err := os.MkdirAll(stagingRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	staleTime := time.Now().Add(-2 * staging.DefaultPruneMinAge)
	writeSpool := func(name string, stale bool) string {
		p := filepath.Join(stagingRoot, name)
		if err := os.WriteFile(p, []byte("spool"), 0o600); err != nil {
			t.Fatal(err)
		}
		if stale {
			if err := os.Chtimes(p, staleTime, staleTime); err != nil {
				t.Fatal(err)
			}
		}
		return p
	}
	abandoned := writeSpool(staging.FilePrefix+"snapshot-abandoned", true)
	fresh := writeSpool(staging.FilePrefix+"snapshot-live", false)
	foreign := filepath.Join(stagingRoot, "unrelated-file")
	if err := os.WriteFile(foreign, []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	foreignOld := filepath.Join(stagingRoot, "unrelated-old-file")
	if err := os.WriteFile(foreignOld, []byte("not ours either"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(foreignOld, staleTime, staleTime); err != nil {
		t.Fatal(err)
	}

	s, err := NewPersistent("runner-tok", "admin-tok", dir)
	if err != nil {
		t.Fatal(err)
	}
	budget := s.StagingBudget()
	if budget == nil {
		t.Fatal("persistent server has no staging budget")
	}
	if budget.Dir() == stagingRoot || !strings.HasPrefix(budget.Dir(), stagingRoot+string(os.PathSeparator)) {
		t.Fatalf("budget dir %q is not the replica-private subdirectory of %q", budget.Dir(), stagingRoot)
	}
	// Startup does NOT reclaim legacy top-level files: they may belong to a
	// still-live old-layout replica. Foreign files are never touched either.
	for _, keep := range []string{abandoned, fresh, foreign, foreignOld} {
		if _, err := os.Stat(keep); err != nil {
			t.Fatalf("startup removed %s (legacy top-level files must survive): %v", filepath.Base(keep), err)
		}
	}
	// The explicit migration (run once the old replicas have drained) is the
	// only path that reclaims them, and it reclaims only top-level FilePrefix
	// entries.
	res, err := staging.MigrateLegacyStagingLayout(context.Background(), stagingRoot)
	if err != nil {
		t.Fatalf("staging layout migration: %v", err)
	}
	if len(res.Reclaimed) != 2 {
		t.Fatalf("migration reclaimed %v, want the 2 legacy spool files", res.Reclaimed)
	}
	for _, gone := range []string{abandoned, fresh} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Fatalf("spool file %s survived the explicit migration: %v", filepath.Base(gone), err)
		}
	}
	for _, keep := range []string{foreign, foreignOld} {
		if _, err := os.Stat(keep); err != nil {
			t.Fatalf("foreign file %s was removed: %v", filepath.Base(keep), err)
		}
	}
	// Runtime Prune is age-based, inside the replica-private directory.
	stale := filepath.Join(budget.Dir(), staging.FilePrefix+"runtime-stale")
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(stale, staleTime, staleTime); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(budget.Dir(), staging.FilePrefix+"runtime-live")
	if err := os.WriteFile(live, []byte("live"), 0o600); err != nil {
		t.Fatal(err)
	}
	foreignInReplica := filepath.Join(budget.Dir(), "foreign.dat")
	if err := os.WriteFile(foreignInReplica, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := budget.Prune(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale spool file survived Prune: %v", err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("fresh spool file was pruned: %v", err)
	}
	if _, err := os.Stat(foreignInReplica); err != nil {
		t.Fatalf("Prune touched a foreign file: %v", err)
	}
}

// TestSnapshotUploadStagingUsesConfiguredPrefix proves a staged snapshot
// upload is created under staging.FilePrefix inside the configured directory
// (so the package's prune owns it) and removed on every exit path.
func TestSnapshotUploadStagingUsesConfiguredPrefix(t *testing.T) {
	s, _, _, hdrs := cacheFixture(t)
	budget := newUploadBudget(t, s, snapshotUploadMaxBytes)
	body := fcSnapshotArchive(t)
	r := snapshotUploadRequest(http.MethodPost, "/api/v1/jobs/job-a/snapshots", bytes.NewReader(body), int64(len(body)), hdrs)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	if leftovers := stageFiles(t, budget.Dir()); len(leftovers) != 0 {
		t.Fatalf("staging leftovers after a successful upload: %v", leftovers)
	}
}

// TestSnapshotUploadStagingNeverUsesSystemTempDir is the L4-C regression pin:
// while an upload is staged, nothing appears in the system temporary
// directory (the defect staged there via os.CreateTemp("", ...)), because the
// bytes go through the configured staging budget instead.
func TestSnapshotUploadStagingNeverUsesSystemTempDir(t *testing.T) {
	systemTmp := t.TempDir()
	t.Setenv("TMPDIR", systemTmp)
	s, _, _, hdrs := cacheFixture(t)
	body := fcSnapshotArchive(t)
	size := int64(len(body))
	newUploadBudget(t, s, snapshotUploadMaxBytes)

	reader := newGatedBodyReader(body)
	done := uploadSnapshotAsync(s, snapshotUploadRequest(http.MethodPost, "/api/v1/jobs/job-a/snapshots", reader, size, hdrs))
	select {
	case <-reader.started:
	case w := <-done:
		t.Fatalf("upload returned before reading its body: %d %s", w.Code, w.Body.String())
	case <-time.After(5 * time.Second):
		t.Fatal("upload never started reading its body")
	}
	entries, err := os.ReadDir(systemTmp)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, e := range entries {
		names = append(names, e.Name())
	}
	reader.releaseBody()
	if w := <-done; w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	if len(names) != 0 {
		t.Fatalf("upload staged inside the bare system temp directory: %v", names)
	}
}

// stageFiles lists the staging directory entries.
func stageFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	out := []string{}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), staging.FilePrefix) {
			out = append(out, e.Name())
		}
	}
	return out
}
