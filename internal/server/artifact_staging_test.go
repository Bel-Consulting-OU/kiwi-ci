package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// fcMemoryBlobServerWithStaging builds the artifact fixture server with a
// CONSTRUCTION-TIME staging budget of max over a fresh directory and returns
// it (staging is immutable after construction).
func fcMemoryBlobServerWithStaging(t *testing.T, max int64) (*Server, map[string]string, *staging.Budget) {
	t.Helper()
	b, err := staging.NewBudget(filepath.Join(t.TempDir(), "staging"), max)
	if err != nil {
		t.Fatalf("staging budget: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	s, hdrs := fcMemoryBlobServer(t, WithStagingBudget(b))
	return s, hdrs, b
}

// TestArtifactUploadStagesInsideBudgetAndReleases proves the artifact body
// spools through the configured bounded staging budget (never the artifact
// data dir, never a bare system temp directory), charges exactly the request's
// Content-Length while it is staged, and releases the reservation and removes
// the spool file on the success path — the same contract the cache endpoint
// carries.
func TestArtifactUploadStagesInsideBudgetAndReleases(t *testing.T) {
	s, f, b, hdrs, _ := cacheFixtureWithStaging(t, 1<<20)
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": fcBinContract()}
	f.mu.Unlock()

	var (
		mu         sync.Mutex
		stagedPath string
		reserved   int64
	)
	oldHook := artifactStageHook
	artifactStageHook = func(path string, reservedBytes int64) {
		mu.Lock()
		stagedPath, reserved = path, reservedBytes
		mu.Unlock()
	}
	defer func() { artifactStageHook = oldHook }()

	payload := "artifact-staging-payload"
	w := fcUploadBlobArtifact(t, s, hdrs, payload)
	if w.Code != http.StatusCreated {
		t.Fatalf("artifact upload = %d: %s", w.Code, w.Body.String())
	}
	mu.Lock()
	path, gotReserved := stagedPath, reserved
	mu.Unlock()
	if path == "" {
		t.Fatal("artifact staging hook never ran: the body was not staged through SpoolFile")
	}
	if filepath.Dir(path) != b.Dir() {
		t.Fatalf("staged file %q is not inside the budget directory %q", path, b.Dir())
	}
	if !strings.HasPrefix(filepath.Base(path), staging.FilePrefix) {
		t.Fatalf("staged file %q lacks the staging prefix", path)
	}
	if gotReserved != int64(len(payload)) {
		t.Fatalf("reserved %d bytes, want the Content-Length %d", gotReserved, len(payload))
	}
	if got := b.Used(); got != 0 {
		t.Fatalf("budget used after upload = %d, want 0 (reservation released)", got)
	}
	if leftovers := stageFiles(t, b.Dir()); len(leftovers) != 0 {
		t.Fatalf("staging leftovers after a successful upload: %v", leftovers)
	}
}

// TestArtifactUploadCrossFilesystemFinalize proves the filesystem-mode
// publication does not assume the staging directory and the artifact data dir
// share a filesystem: when the fast-path rename reports cross-device, the
// handler falls back to a destination-local streamed copy (fsync, checked
// close, rename, parent fsync) and the artifact is still committed with the
// exact staged bytes.
func TestArtifactUploadCrossFilesystemFinalize(t *testing.T) {
	s, hdrs, b := fcMemoryBlobServerWithStaging(t, 1<<20)
	fcSeedContract(s, "job-a", fcBinContract())

	orig := stagedRename
	stagedRename = func(oldpath, newpath string) error {
		return errors.New("invalid cross-device link")
	}
	defer func() { stagedRename = orig }()

	payload := "cross-filesystem-artifact-bytes"
	w := fcUploadBlobArtifact(t, s, hdrs, payload)
	if w.Code != http.StatusCreated {
		t.Fatalf("cross-filesystem artifact upload = %d: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	var rec model.ArtifactRecord
	for _, r := range s.artifacts {
		if r.Name == "bin" {
			rec = r
		}
	}
	s.mu.Unlock()
	if rec.Path == "" {
		t.Fatal("cross-filesystem upload committed no artifact record")
	}
	got, err := os.ReadFile(rec.Path)
	if err != nil {
		t.Fatalf("read finalized artifact: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("finalized artifact = %q, want %q", got, payload)
	}
	if used := b.Used(); used != 0 {
		t.Fatalf("budget used after finalization = %d, want 0", used)
	}
	if leftovers := stageFiles(t, b.Dir()); len(leftovers) != 0 {
		t.Fatalf("staging leftovers after finalization: %v", leftovers)
	}
}

// TestArtifactUploadNeverUsesSystemTempDir pins that while an artifact body is
// being staged, nothing appears in the system temporary directory: the bytes
// go through the configured staging budget, not os.CreateTemp("", ...).
func TestArtifactUploadNeverUsesSystemTempDir(t *testing.T) {
	b, err := staging.NewBudget(filepath.Join(t.TempDir(), "staging"), 1<<20)
	if err != nil {
		t.Fatalf("staging budget: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	s, hdrs := fcMemoryBlobServer(t, WithStagingBudget(b))
	fcSeedContract(s, "job-a", fcBinContract())
	systemTmp := t.TempDir()
	t.Setenv("TMPDIR", systemTmp)

	body := []byte("artifact-tmpdir-watch")
	reader := newGatedBodyReader(body)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", reader)
		r.ContentLength = int64(len(body))
		r.Header.Set("Authorization", "Bearer runner-tok")
		for k, v := range hdrs {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		done <- w
	}()
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
		t.Fatalf("artifact staging touched the bare system temp directory: %v", names)
	}
}

// TestMaxSizePublicationsIgnoreUnusableSystemTempDir is the O1 regression: with
// TMPDIR pointed at an unwritable directory while the configured staging
// budget is healthy, a MAX-SIZED cache entry, artifact payload (contract limit
// == body length) and snapshot archive must all publish successfully and must
// not create anything under TMPDIR. The publication paths stage only through
// the budget directory, so making TMPDIR unusable cannot change their outcome.
func TestMaxSizePublicationsIgnoreUnusableSystemTempDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permission bits")
	}
	// Build every fixture before TMPDIR becomes unusable (t.TempDir resolves
	// TMPDIR, so a later t.TempDir would fail or land inside the watcher).
	s, f, _, hdrs, _ := cacheFixtureWithStaging(t, 1<<20)

	cachePayload := "max-sized-cache-entry"
	oldCacheMax := cacheUploadMaxBytes
	t.Cleanup(func() { cacheUploadMaxBytes = oldCacheMax })
	cacheUploadMaxBytes = int64(len(cachePayload))

	artifactPayload := "max-sized-artifact-payload"
	artC := fcBinContract()
	artC.MaxSize = int64(len(artifactPayload))
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": artC}
	f.mu.Unlock()

	snapBody := fcSnapshotArchive(t)
	oldSnapMax := snapshotUploadMaxBytes
	t.Cleanup(func() { snapshotUploadMaxBytes = oldSnapMax })
	snapshotUploadMaxBytes = int64(len(snapBody))

	systemTmp := t.TempDir()
	if err := os.Chmod(systemTmp, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(systemTmp, 0o700) })
	t.Setenv("TMPDIR", systemTmp)

	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+strings.Repeat("a", 64), "runner-tok", cachePayload, hdrs); w.Code != http.StatusCreated {
		t.Fatalf("max-sized cache upload = %d: %s", w.Code, w.Body.String())
	}
	if w := fcUploadBlobArtifact(t, s, hdrs, artifactPayload); w.Code != http.StatusCreated {
		t.Fatalf("max-sized artifact upload = %d: %s", w.Code, w.Body.String())
	}
	if w := fcUploadSnapshot(t, s, hdrs, snapBody); w.Code != http.StatusCreated {
		t.Fatalf("max-sized snapshot upload = %d: %s", w.Code, w.Body.String())
	}
	entries, err := os.ReadDir(systemTmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("publication touched the unusable system temp dir: %v", entries)
	}
}
