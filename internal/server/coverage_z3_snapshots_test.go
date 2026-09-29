package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// snapNoLeaseStore implements the snapshot record contract and the
// distributed digest fence by delegation but deliberately not the
// transactional lease-commit extension, pinning the upload path's late
// capability assertion (the startup check refuses such a store earlier; this
// is the defense in depth).
type snapNoLeaseStore struct {
	storage.Store
	inner *dbFakeStore
}

func (w snapNoLeaseStore) InsertSnapshotRecord(ctx context.Context, rec model.SnapshotRecord) error {
	return w.inner.InsertSnapshotRecord(ctx, rec)
}

func (w snapNoLeaseStore) GetSnapshot(ctx context.Context, runID, snapshotID string) (model.SnapshotRecord, bool, error) {
	return w.inner.GetSnapshot(ctx, runID, snapshotID)
}

func (w snapNoLeaseStore) ListSnapshotsByRun(ctx context.Context, runID string) ([]model.SnapshotRecord, error) {
	return w.inner.ListSnapshotsByRun(ctx, runID)
}

func (w snapNoLeaseStore) WithDigestFence(ctx context.Context, digest string, fn func() error) error {
	return w.inner.WithDigestFence(ctx, digest, fn)
}

func (w snapNoLeaseStore) AcquireDigestFence(ctx context.Context, digest string) (func(), error) {
	return w.inner.AcquireDigestFence(ctx, digest)
}

func (w snapNoLeaseStore) AcquireNamedFence(ctx context.Context, namespace, key string) (func(), error) {
	return w.inner.AcquireNamedFence(ctx, namespace, key)
}

// fenceOnlyStore keeps the Store and distributed digest-fence contracts of a
// delegate while omitting every extension the handler probes for by type
// assertion, so late capability gates can be exercised after the fence.
type fenceOnlyStore struct {
	storage.Store
	fence storage.DigestFenceStore
}

func (w fenceOnlyStore) WithDigestFence(ctx context.Context, digest string, fn func() error) error {
	return w.fence.WithDigestFence(ctx, digest, fn)
}

func (w fenceOnlyStore) AcquireDigestFence(ctx context.Context, digest string) (func(), error) {
	return w.fence.AcquireDigestFence(ctx, digest)
}

func (w fenceOnlyStore) AcquireNamedFence(ctx context.Context, namespace, key string) (func(), error) {
	return w.fence.AcquireNamedFence(ctx, namespace, key)
}

// artifactNoLeaseStore keeps every capability the artifact upload needs up to
// the record insert (Store, distributed digest fence, pending-sidecar store)
// while omitting the transactional lease-commit extension.
type artifactNoLeaseStore struct {
	storage.Store
	storage.DigestFenceStore
	storage.ArtifactSidecarStore
}

// LeaseLive keeps the database-clock liveness capability visible while the
// lease-commit extension is hidden: this fixture pins the commit-time
// capability refusal, not the liveness gate.
func (w artifactNoLeaseStore) LeaseLive(ctx context.Context, jobID, runnerID string, generation int64) (bool, error) {
	live, ok := w.Store.(storage.LiveLeaseStore)
	if !ok {
		return false, errors.New("test store has no LiveLeaseStore")
	}
	return live.LeaseLive(ctx, jobID, runnerID, generation)
}

// countErrStore keeps every lease-commit capability of the fake store but
// makes the optional preflight count fail, so the upload path must answer the
// server error instead of silently skipping the cap check.
type countErrStore struct {
	*dbFakeStore
}

func (countErrStore) CountSnapshotsForJob(ctx context.Context, runID, jobID string) (int, error) {
	return 0, errors.New("count store down")
}

// TestFlowSnapshotMemoryCommitLeaseLost pins the memory-mode commit
// predicate: a lease revoked while the archive body is being staged must be
// answered 409 and leave no record and no archive/manifest pair behind.
func TestFlowSnapshotMemoryCommitLeaseLost(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	archive := fcSnapshotArchive(t)
	reader := &fcHookReader{data: archive, hook: func() {
		s.mu.Lock()
		j := s.jobs["job-a"]
		past := time.Now().UTC().Add(-time.Hour)
		j.LeaseExpiresAt = &past
		s.jobs["job-a"] = j
		s.mu.Unlock()
	}}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-a/snapshots", reader)
	r.Header.Set("Authorization", "Bearer runner-tok")
	for k, v := range hdrs {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("revoked-at-commit snapshot = %d, want 409: %s", w.Code, w.Body.String())
	}
	s.mu.Lock()
	n := len(s.snapshots)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("snapshot records after a revoked lease = %d, want 0", n)
	}
	dir := filepath.Join(s.store.Root, "snapshots", "run-c", "job-a")
	if entries, err := os.ReadDir(dir); err == nil && len(entries) != 0 {
		t.Fatalf("archive files left after a revoked commit: %v", entries)
	}
}

// TestFlowSnapshotPreflightCountError proves a failing store-level count is a
// server error (never a skipped or guessed cap): the upload is refused before
// the body is read.
func TestFlowSnapshotPreflightCountError(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	s.DB = countErrStore{dbFakeStore: f}
	w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("preflight count failure = %d, want 500: %s", w.Code, w.Body.String())
	}
}

// TestFlowSnapshotDeleteSnapshotBranches covers the admin deletion path:
// empty identities are a no-op, a store without the durable deletion
// capability fails closed, a failed state write keeps the record, and a
// successful memory-mode deletion drops the record and its local files.
func TestFlowSnapshotDeleteSnapshotBranches(t *testing.T) {
	ctx := context.Background()

	if ok, err := New("tok").DeleteSnapshot(ctx, "", "s"); ok || err != nil {
		t.Fatalf("empty identity = (%v, %v), want a no-op", ok, err)
	}

	s, _, _, _ := cacheFixture(t)
	if ok, err := s.DeleteSnapshot(ctx, "run-c", "snap-1"); ok || err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("store without deletion support = (%v, %v), want a fail-closed error", ok, err)
	}

	mem, _ := fcMemoryBlobServer(t)
	dir := t.TempDir()
	archive := filepath.Join(dir, "snap.tar.gz")
	manifest := archive + ".manifest.json"
	if err := os.WriteFile(archive, []byte("bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := model.SnapshotRecord{ID: "snap-1", RunID: "run-c", JobID: "job-a", Path: archive, CreatedAt: time.Now().UTC()}
	mem.mu.Lock()
	mem.snapshots[rec.ID] = rec
	mem.mu.Unlock()

	mem.persistFailForTest = errors.New("state write down")
	if ok, err := mem.DeleteSnapshot(ctx, "run-c", "snap-1"); ok || err == nil {
		t.Fatalf("deletion with a failing state write = (%v, %v), want an error", ok, err)
	}
	mem.mu.Lock()
	_, still := mem.snapshots["snap-1"]
	mem.mu.Unlock()
	if !still {
		t.Fatal("record was dropped despite the failed state write")
	}
	if _, err := os.Stat(archive); err != nil {
		t.Fatalf("archive removed despite the failed state write: %v", err)
	}
	mem.persistFailForTest = nil

	if ok, err := mem.DeleteSnapshot(ctx, "other-run", "snap-1"); ok || err != nil {
		t.Fatalf("cross-run deletion = (%v, %v), want a no-op", ok, err)
	}
	if ok, err := mem.DeleteSnapshot(ctx, "run-c", "snap-1"); !ok || err != nil {
		t.Fatalf("memory deletion = (%v, %v), want success", ok, err)
	}
	if _, err := os.Stat(archive); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("archive survives the deletion: %v", err)
	}
	if _, err := os.Stat(manifest); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("manifest survives the deletion: %v", err)
	}
}

// TestValidateSnapshotFilesBranches exercises the restore-time validation each
// fs-mode record must pass: malformed identity, missing files, size/digest
// disagreement with the record, and a manifest that contradicts the record
// version/root are all rejected, while a complete pair is accepted.
func TestValidateSnapshotFilesBranches(t *testing.T) {
	payload := []byte("snapshot-archive-bytes")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	dir := t.TempDir()
	archive := filepath.Join(dir, "snap.tar.gz")
	if err := os.WriteFile(archive, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	good := model.SnapshotRecord{ID: "s1", Path: archive, Size: int64(len(payload)), SHA256: digest, Version: 1, RootSHA256: "root"}
	writeManifest := func(m snapshot.Manifest) {
		t.Helper()
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(archive+".manifest.json", raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeManifest(snapshot.Manifest{Version: 1, RootSHA256: "root"})
	if err := validateSnapshotFiles(good); err != nil {
		t.Fatalf("valid pair rejected: %v", err)
	}

	badID := good
	badID.ID = ""
	if err := validateSnapshotFiles(badID); err == nil {
		t.Fatal("empty snapshot id accepted")
	}
	badPath := good
	badPath.Path = ""
	if err := validateSnapshotFiles(badPath); err == nil {
		t.Fatal("empty archive path accepted")
	}
	missing := good
	missing.Path = filepath.Join(dir, "gone")
	if err := validateSnapshotFiles(missing); err == nil {
		t.Fatal("missing archive accepted")
	}
	badSize := good
	badSize.Size = int64(len(payload)) + 1
	if err := validateSnapshotFiles(badSize); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("wrong size = %v, want a size mismatch", err)
	}
	badDigest := good
	badDigest.SHA256 = strings.Repeat("0", 64)
	if err := validateSnapshotFiles(badDigest); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("wrong digest = %v, want a digest mismatch", err)
	}
	if err := os.Remove(archive + ".manifest.json"); err != nil {
		t.Fatal(err)
	}
	if err := validateSnapshotFiles(good); err == nil || !strings.Contains(err.Error(), "manifest sidecar") {
		t.Fatalf("missing manifest = %v", err)
	}
	writeManifest(snapshot.Manifest{Version: 2, RootSHA256: "root"})
	if err := validateSnapshotFiles(good); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("manifest disagreement = %v", err)
	}
	writeManifest(snapshot.Manifest{Version: 1, RootSHA256: "root"})

	// restoreSnapshots keeps the valid record and drops the broken one.
	s, _ := fcMemoryBlobServer(t)
	broken := badDigest
	broken.ID = "broken"
	s.restoreSnapshots(map[string]model.SnapshotRecord{good.ID: good, broken.ID: broken})
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.snapshots[good.ID]; !ok {
		t.Fatal("valid record dropped at restore")
	}
	if _, ok := s.snapshots[broken.ID]; ok {
		t.Fatal("broken record survived restore")
	}
}

// TestDecodeSnapshotsCursorBranches pins the opaque cursor grammar: a missing
// prefix, non-base64 body, non-JSON body and unparsable timestamp are all
// rejected, while a well-formed encoding round-trips.
func TestDecodeSnapshotsCursorBranches(t *testing.T) {
	if _, ok := decodeSnapshotsCursor("not-a-cursor"); ok {
		t.Fatal("cursor without the version prefix accepted")
	}
	if _, ok := decodeSnapshotsCursor(snapshotsCursorPrefix + "!!!"); ok {
		t.Fatal("non-base64 cursor body accepted")
	}
	put := func(raw []byte) string {
		return snapshotsCursorPrefix + base64.RawURLEncoding.EncodeToString(raw)
	}
	if _, ok := decodeSnapshotsCursor(put([]byte("{not json"))); ok {
		t.Fatal("non-JSON cursor body accepted")
	}
	if _, ok := decodeSnapshotsCursor(put([]byte(`["not a time","id"]`))); ok {
		t.Fatal("unparsable timestamp accepted")
	}
	when := time.Now().UTC().Truncate(time.Microsecond)
	raw, err := json.Marshal([2]string{when.Format(time.RFC3339Nano), "id/with:separators"})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := decodeSnapshotsCursor(put(raw))
	if !ok || got.id != "id/with:separators" || !got.createdAt.Equal(when) {
		t.Fatalf("round-trip = (%+v, %v)", got, ok)
	}
}

// TestFlowSnapshotDBLateCapabilityGates pins the uploadSnapshotDB assertions
// that normally fire before the body (the startup/request gates): a store
// without the snapshot record contract, and a store with the record contract
// but without transactional lease commits, are both refused with 503 after
// staging and nothing is committed by either.
func TestFlowSnapshotDBLateCapabilityGates(t *testing.T) {
	archive := fcSnapshotArchive(t)
	call := func(t *testing.T, db storage.Store) *httptest.ResponseRecorder {
		t.Helper()
		s, f, _, _ := cacheFixture(t)
		s.DB = db
		j := f.jobs["job-a"]
		r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-a/snapshots", strings.NewReader(string(archive)))
		w := httptest.NewRecorder()
		s.uploadSnapshotDB(w, r, j, "runner-a", 5)
		f.mu.Lock()
		records := len(f.snapshots)
		f.mu.Unlock()
		if records != 0 {
			t.Fatalf("late capability gate committed %d records", records)
		}
		return w
	}

	t.Run("no snapshot record contract", func(t *testing.T) {
		f := newDBFakeStore()
		w := call(t, fenceOnlyStore{Store: f, fence: f})
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "snapshot record storage unavailable") {
			t.Fatalf("store without SnapshotStore = %d: %s", w.Code, w.Body.String())
		}
	})
	t.Run("no transactional lease commits", func(t *testing.T) {
		f := newDBFakeStore()
		w := call(t, snapNoLeaseStore{Store: f, inner: f})
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "transactional lease commits") {
			t.Fatalf("store without LeaseCommitStore = %d: %s", w.Code, w.Body.String())
		}
	})
}

// TestFlowSnapshotDBChunkedBodyOverCap covers the DB staging bound for a body
// without a declared length: the spool's source probe refuses the byte past
// the reservation, so an over-cap chunked archive answers 413 and never
// reaches the CAS.
func TestFlowSnapshotDBChunkedBodyOverCap(t *testing.T) {
	s, _, mb, hdrs := cacheFixture(t)
	orig := snapshotUploadMaxBytes
	snapshotUploadMaxBytes = 64
	t.Cleanup(func() { snapshotUploadMaxBytes = orig })
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-a/snapshots", &fcHookReader{data: make([]byte, 256)})
	r.Header.Set("Authorization", "Bearer runner-tok")
	for k, v := range hdrs {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), "upload limit") {
		t.Fatalf("chunked snapshot over the cap = %d: %s", w.Code, w.Body.String())
	}
	mb.mu.Lock()
	objects := len(mb.objects)
	mb.mu.Unlock()
	if objects != 0 {
		t.Fatalf("over-cap chunked snapshot published %d objects", objects)
	}
}
