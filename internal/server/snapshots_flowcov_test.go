package server

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
)

func fcSnapshotArchive(t *testing.T) []byte {
	t.Helper()
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "out.txt"), []byte("snapshot data"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := snapshot.Create(ws, &buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func fcPOSTBytes(t *testing.T, s *Server, path, bearer string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func fcUploadSnapshot(t *testing.T, s *Server, hdrs map[string]string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	return fcPOSTBytes(t, s, "/api/v1/jobs/job-a/snapshots", "runner-tok", body, hdrs)
}

func TestFlowSnapshotDBRequiresCAS(t *testing.T) {
	s, _, _, hdrs := cacheFixture(t)
	s.CAS = nil
	w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("db snapshot without CAS = %d, want 503: %s", w.Code, w.Body.String())
	}
}

func TestFlowSnapshotMemoryRequiresStore(t *testing.T) {
	s := New("runner-tok")
	s.AdminToken = "admin-tok"
	exp := time.Now().UTC().Add(time.Hour)
	s.mu.Lock()
	s.runs["run-c"] = model.Run{ID: "run-c", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Status: model.StatusRunning}
	s.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-c", Key: "build", Status: model.StatusRunning,
		LeaseRunnerID: "runner-a", LeaseTokenHash: hashLeaseToken(s.leaseKey, "cache-lease-token"), LeaseGeneration: 5, LeaseExpiresAt: &exp}
	s.mu.Unlock()
	hdrs := map[string]string{"X-Kiwi-Runner-ID": "runner-a", "X-Kiwi-Lease-Token": "cache-lease-token", "X-Kiwi-Lease-Generation": "5"}
	w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("memory snapshot without store = %d, want 503: %s", w.Code, w.Body.String())
	}
}

func TestFlowSnapshotMemoryMkdirFailure(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	if err := os.WriteFile(filepath.Join(s.store.Root, "snapshots"), []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("snapshot mkdir failure = %d, want 500: %s", w.Code, w.Body.String())
	}
}

// TestFlowSnapshotMemoryStagingOpenFailure covers the staging open failing
// after the snapshot directory has been created: the fixed entropy pins the
// staging filename and a directory placed there refuses the O_CREATE|O_EXCL
// open with EEXIST for any euid (path existence, not permission bits), so
// the assertion stays active as root.
func TestFlowSnapshotMemoryStagingOpenFailure(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	restore := seamRand(t, seamFixedReader{})
	defer restore()
	id, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(s.store.Root, "snapshots", "run-c", "job-a")
	if err := os.MkdirAll(filepath.Join(dir, "."+id+".tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("snapshot staging failure = %d, want 500: %s", w.Code, w.Body.String())
	}
}

func TestFlowSnapshotMemoryBodyCopyFailure(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-a/snapshots", &fcErrReader{})
	r.Header.Set("Authorization", "Bearer runner-tok")
	for k, v := range hdrs {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("snapshot body copy failure = %d, want 500: %s", w.Code, w.Body.String())
	}
}

func TestFlowSnapshotMemoryRenameFailure(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	dir := filepath.Join(s.store.Root, "snapshots", "run-c", "job-a")
	reader := &fcHookReader{data: fcSnapshotArchive(t), hook: func() {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
		_ = os.Remove(dir)
		_ = os.WriteFile(dir, []byte("not a dir"), 0o600)
	}}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-a/snapshots", reader)
	r.Header.Set("Authorization", "Bearer runner-tok")
	for k, v := range hdrs {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("snapshot rename failure = %d, want 500: %s", w.Code, w.Body.String())
	}
}

func TestFlowSnapshotMemorySuccessAndDownload(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t))
	if w.Code != http.StatusCreated {
		t.Fatalf("snapshot upload = %d: %s", w.Code, w.Body.String())
	}
	var rec model.SnapshotRecord
	if err := jsonUnmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.ID == "" || rec.RunID != "run-c" {
		t.Fatalf("snapshot record = %+v", rec)
	}
	// Stored with a manifest sidecar.
	s.mu.Lock()
	stored := s.snapshots[rec.ID]
	s.mu.Unlock()
	if _, err := os.Stat(stored.Path + ".manifest.json"); err != nil {
		t.Fatalf("manifest sidecar missing: %v", err)
	}

	// List: two records exercise the CreatedAt ordering.
	s.mu.Lock()
	s.snapshots["older"] = model.SnapshotRecord{ID: "older", RunID: "run-c", CreatedAt: time.Now().UTC().Add(-time.Hour)}
	s.mu.Unlock()
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("snapshot list = %d", w.Code)
	} else if !strings.Contains(w.Body.String(), rec.ID) {
		t.Fatalf("snapshot list missing record: %s", w.Body.String())
	}

	// Download streams the archive.
	dw := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/"+rec.ID, "admin-tok", "")
	if dw.Code != http.StatusOK {
		t.Fatalf("snapshot download = %d: %s", dw.Code, dw.Body.String())
	}
	if dw.Header().Get("X-Kiwi-Snapshot-SHA256") != rec.SHA256 {
		t.Fatal("snapshot digest header mismatch")
	}
	if int64(dw.Body.Len()) != rec.Size {
		t.Fatalf("snapshot bytes = %d, want %d", dw.Body.Len(), rec.Size)
	}
}

func TestFlowSnapshotMemoryDownloadErrors(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	if w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t)); w.Code != http.StatusCreated {
		t.Fatalf("upload = %d", w.Code)
	}
	// Unknown snapshot id.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/missing", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("missing snapshot = %d, want 404", w.Code)
	}
	s.mu.Lock()
	s.snapshots["other-run"] = model.SnapshotRecord{ID: "other-run", RunID: "run-x", CreatedAt: time.Now().UTC()}
	s.snapshots["no-run"] = model.SnapshotRecord{ID: "no-run", RunID: "ghost", CreatedAt: time.Now().UTC()}
	s.snapshots["bad-path"] = model.SnapshotRecord{ID: "bad-path", RunID: "run-c", Path: filepath.Join(t.TempDir(), "gone"), CreatedAt: time.Now().UTC()}
	s.mu.Unlock()
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/other-run", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("cross-run snapshot = %d, want 404", w.Code)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/ghost/snapshots/no-run", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("missing run snapshot = %d, want 404", w.Code)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/bad-path", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("missing archive = %d, want 404", w.Code)
	}
}

func TestFlowSnapshotMemoryDownloadCopyFailure(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	if w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t)); w.Code != http.StatusCreated {
		t.Fatalf("upload = %d", w.Code)
	}
	var rec model.SnapshotRecord
	s.mu.Lock()
	for _, r := range s.snapshots {
		if r.RunID == "run-c" && r.Path != "" {
			rec = r
		}
	}
	s.mu.Unlock()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/runs/run-c/snapshots/"+rec.ID, nil)
	r.SetPathValue("id", "run-c")
	r.SetPathValue("sid", rec.ID)
	r.Header.Set("Authorization", "Bearer admin-tok")
	fw := &fcFailWriter{limit: 0}
	s.downloadSnapshot(fw, r)
	if got := fw.Header().Get("X-Kiwi-Snapshot-SHA256"); got != rec.SHA256 {
		t.Fatalf("copy-failure download did not reach the copy stage: %q", got)
	}
}

// TestFlowSnapshotMemoryDownloadScopedDenial: a repository-scoped reader of
// another repository is denied the archive download. The download is admin
// tier, so no repository read grant opens it (see
// TestSnapshotDownloadIsAdminTierMemory), and the denial stays 403.
func TestFlowSnapshotMemoryDownloadScopedDenial(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	if w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t)); w.Code != http.StatusCreated {
		t.Fatalf("upload = %d", w.Code)
	}
	var sid string
	s.mu.Lock()
	for id, r := range s.snapshots {
		sid = id
		_ = r
	}
	s.mu.Unlock()
	if err := s.AuthStore.AddToken("outsider", auth.Principal{
		Subject: "outsider",
		Repositories: map[string]auth.RepositoryPermission{
			"github.com/o/repo-b": {Read: true},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/"+sid, "outsider", ""); w.Code != http.StatusForbidden {
		t.Fatalf("scoped snapshot download = %d, want 403", w.Code)
	}
}

func TestFlowSnapshotDBUploadBranches(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	// Invalid archive under a valid lease.
	if w := fcUploadSnapshot(t, s, hdrs, []byte("not a tar.gz")); w.Code != http.StatusBadRequest {
		t.Fatalf("db invalid archive = %d, want 400: %s", w.Code, w.Body.String())
	}
	// Body copy failure.
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-a/snapshots", &fcErrReader{})
	r.Header.Set("Authorization", "Bearer runner-tok")
	for k, v := range hdrs {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("db snapshot body copy failure = %d, want 500: %s", w.Code, w.Body.String())
	}
	// CAS put failure.
	s.SetBlobStore(&fcErrBlob{memBlob: newMemBlob(), putErr: errors.New("cas down")})
	if w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t)); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("db cas failure = %d, want 503: %s", w.Code, w.Body.String())
	}
	_ = f
	// Store without the snapshot extension.
	s.SetBlobStore(newMemBlob())
	s.DB = fcPlainStore{f}
	if w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t)); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("db snapshot store unavailable = %d, want 503: %s", w.Code, w.Body.String())
	}
	// Record insert failure.
	s.DB = f
	f.mu.Lock()
	f.snapshotErr = errors.New("snapshot insert down")
	f.mu.Unlock()
	if w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t)); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("db snapshot insert failure = %d, want 503: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	f.snapshotErr = nil
	f.mu.Unlock()
	// Success.
	if w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t)); w.Code != http.StatusCreated {
		t.Fatalf("db snapshot upload = %d: %s", w.Code, w.Body.String())
	}
}

// TestFlowSnapshotDBStagingBudgetMissing covers the fail-closed staging
// contract: a DB-mode upload without an installed staging budget refuses with
// 503 instead of falling back to the bare system temporary directory.
func TestFlowSnapshotDBStagingBudgetMissing(t *testing.T) {
	s, _, _, hdrs := cacheFixture(t, WithStagingBudget(nil))
	w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("snapshot upload without a staging budget = %d, want 503: %s", w.Code, w.Body.String())
	}
}

// TestFlowSnapshotDBStagingDirFailure covers an unusable configured staging
// directory: the wiring's budget construction refuses the bound (so startup
// fails instead of the first upload), and a server left without a budget
// fails the upload closed rather than staging elsewhere.
func TestFlowSnapshotDBStagingDirFailure(t *testing.T) {
	s, _, _, hdrs := cacheFixture(t, WithStagingBudget(nil))
	// A FILE at the configured staging path makes NewBudget's directory
	// probe fail for any euid (path shape, not permission bits).
	blocked := filepath.Join(t.TempDir(), "staging-blocked")
	if err := os.WriteFile(blocked, []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := staging.NewBudget(blocked, 1<<20); err == nil {
		t.Fatal("staging budget over a file path must not install")
	}
	w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("snapshot upload with unusable staging = %d, want 503: %s", w.Code, w.Body.String())
	}
}

func TestFlowSnapshotDBListBranches(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/missing/snapshots", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("db missing run list = %d, want 404", w.Code)
	}
	s.DB = &fcStore{dbFakeStore: f, getRunErr: errors.New("run table down")}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", "admin-tok", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("db list run error = %d, want 500", w.Code)
	}
	s.DB = &fcStore{dbFakeStore: f, listSnapshotsErr: errors.New("snapshot table down")}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", "admin-tok", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("db list snapshots error = %d, want 500", w.Code)
	}
	// A store without the paged capability fails closed: an unbounded list
	// window cannot honor a cursor.
	s.DB = fcPlainStore{f}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", "admin-tok", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("db list without paged capability = %d, want 500: %s", w.Code, w.Body.String())
	}
	s.DB = f
	// Two records exercise the ordering comparator.
	f.mu.Lock()
	f.snapshots = append(f.snapshots,
		model.SnapshotRecord{ID: "s-old", RunID: "run-c", CreatedAt: time.Now().UTC().Add(-time.Hour)},
		model.SnapshotRecord{ID: "s-new", RunID: "run-c", CreatedAt: time.Now().UTC()})
	f.mu.Unlock()
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("db snapshot list = %d: %s", w.Code, w.Body.String())
	}
	_ = hdrs
}

func TestFlowSnapshotDBListScopedDenial(t *testing.T) {
	s, _, _, _ := cacheFixture(t)
	if err := s.AuthStore.AddToken("outsider", auth.Principal{
		Subject: "outsider",
		Repositories: map[string]auth.RepositoryPermission{
			"github.com/o/repo-b": {Read: true},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots", "outsider", ""); w.Code != http.StatusForbidden {
		t.Fatalf("scoped db snapshot list = %d, want 403", w.Code)
	}
}

func TestFlowSnapshotDBDownloadBranches(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	if w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t)); w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	rec := f.snapshots[len(f.snapshots)-1]
	f.mu.Unlock()

	// Missing run and store errors.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/missing/snapshots/"+rec.ID, "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("db download missing run = %d, want 404", w.Code)
	}
	s.DB = &fcStore{dbFakeStore: f, getRunErr: errors.New("run table down")}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/"+rec.ID, "admin-tok", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("db download run error = %d, want 500", w.Code)
	}
	s.DB = &fcStore{dbFakeStore: f, snapshotGetErr: errors.New("snapshot table down")}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/"+rec.ID, "admin-tok", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("db download get error = %d, want 500", w.Code)
	}
	// Store without the snapshot extension.
	s.DB = fcPlainStore{f}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/"+rec.ID, "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("db download without store = %d, want 404", w.Code)
	}
	s.DB = f
	// Unknown snapshot id.
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/unknown", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("db download unknown id = %d, want 404", w.Code)
	}
	// CAS blob missing.
	s.SetBlobStore(&fcErrBlob{memBlob: newMemBlob()})
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/"+rec.ID, "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("db download missing blob = %d, want 404", w.Code)
	}
	// Legacy local file records cover the non-cas branches.
	dir := t.TempDir()
	archive := filepath.Join(dir, "legacy.tar.gz")
	if err := os.WriteFile(archive, []byte("legacy-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.snapshots = append(f.snapshots,
		model.SnapshotRecord{ID: "legacy-ok", RunID: "run-c", Path: archive, Size: 12, SHA256: "abc"},
		model.SnapshotRecord{ID: "legacy-gone", RunID: "run-c", Path: filepath.Join(dir, "gone"), Size: 1},
		model.SnapshotRecord{ID: "legacy-empty", RunID: "run-c"})
	f.mu.Unlock()
	s.SetBlobStore(newMemBlob())
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/legacy-gone", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("legacy missing file = %d, want 404", w.Code)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/legacy-ok", "admin-tok", ""); w.Code != http.StatusOK || w.Body.String() != "legacy-bytes" {
		t.Fatalf("legacy download = %d %q", w.Code, w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/legacy-empty", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("pathless record = %d, want 404", w.Code)
	}
}

func TestFlowSnapshotDBCopyFailures(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	if w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t)); w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	rec := f.snapshots[len(f.snapshots)-1]
	f.mu.Unlock()
	// CAS stream write failure.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/runs/run-c/snapshots/"+rec.ID, nil)
	r.SetPathValue("id", "run-c")
	r.SetPathValue("sid", rec.ID)
	r.Header.Set("Authorization", "Bearer admin-tok")
	fw := &fcFailWriter{limit: 0}
	s.downloadSnapshotDB(fw, r)
	if got := fw.Header().Get("X-Kiwi-Snapshot-SHA256"); got != rec.SHA256 {
		t.Fatalf("db copy failure did not reach the copy stage: %q", got)
	}
	// Legacy local file write failure.
	dir := t.TempDir()
	archive := filepath.Join(dir, "legacy.tar.gz")
	if err := os.WriteFile(archive, []byte("legacy-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.snapshots = append(f.snapshots, model.SnapshotRecord{ID: "legacy-copy", RunID: "run-c", Path: archive, Size: 12, SHA256: "abc"})
	f.mu.Unlock()
	r = httptest.NewRequest(http.MethodGet, "/api/v1/runs/run-c/snapshots/legacy-copy", nil)
	r.SetPathValue("id", "run-c")
	r.SetPathValue("sid", "legacy-copy")
	r.Header.Set("Authorization", "Bearer admin-tok")
	fw = &fcFailWriter{limit: 0}
	s.downloadSnapshotDB(fw, r)
	if got := fw.Header().Get("X-Kiwi-Snapshot-SHA256"); got != "abc" {
		t.Fatalf("legacy copy failure did not reach the copy stage: %q", got)
	}
}

// TestFlowSnapshotDBDownloadScopedDenial is the DB-mode counterpart of the
// scoped denial: a repository-scoped reader of another repository never
// reaches the archive, which is admin tier in both modes.
func TestFlowSnapshotDBDownloadScopedDenial(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	if w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t)); w.Code != http.StatusCreated {
		t.Fatalf("upload = %d", w.Code)
	}
	f.mu.Lock()
	rec := f.snapshots[len(f.snapshots)-1]
	f.mu.Unlock()
	if err := s.AuthStore.AddToken("outsider", auth.Principal{
		Subject: "outsider",
		Repositories: map[string]auth.RepositoryPermission{
			"github.com/o/repo-b": {Read: true},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/snapshots/"+rec.ID, "outsider", ""); w.Code != http.StatusForbidden {
		t.Fatalf("scoped db snapshot download = %d, want 403", w.Code)
	}
}

func TestFlowSnapshotRedaction(t *testing.T) {
	rec := redactSnapshot(model.SnapshotRecord{ID: "s", Path: "/secret/path"})
	if rec.Path != "" {
		t.Fatalf("redacted path = %q", rec.Path)
	}
}

func TestFlowSnapshotListMemoryRequiresRun(t *testing.T) {
	s, _ := fcMemoryBlobServer(t)
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/nope/snapshots", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("memory missing run list = %d, want 404", w.Code)
	}
}
