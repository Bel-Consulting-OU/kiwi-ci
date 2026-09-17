package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// casGCTestServer returns a persistent server whose CAS blob store is a
// filesystem store under the test data dir.
func casGCTestServer(t *testing.T) (*Server, *blob.FS) {
	t.Helper()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fs, ok := s.BlobStore.(*blob.FS)
	if !ok {
		t.Fatalf("blob store = %T, want *blob.FS", s.BlobStore)
	}
	return s, fs
}

func putCASBlob(t *testing.T, s *Server, payload string) blob.Object {
	t.Helper()
	obj, err := s.CAS.Put(context.Background(), strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	return obj
}

// ageCASBlob backdates an object's mtime so the GC age floor can be tested
// deterministically.
func ageCASBlob(t *testing.T, s *Server, digest string, age time.Duration) {
	t.Helper()
	fs := s.BlobStore.(*blob.FS)
	path := filepath.Join(fs.Root, "sha256", digest[:2], digest)
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}

func casBlobExists(t *testing.T, s *Server, digest string) bool {
	t.Helper()
	rc, _, err := s.CAS.Open(context.Background(), digest)
	if err != nil {
		if errors.Is(err, blob.ErrNotFound) {
			return false
		}
		t.Fatal(err)
	}
	_ = rc.Close()
	return true
}

func casGCMetric(t *testing.T, s *Server, name string) float64 {
	t.Helper()
	s.Metrics.mu.Lock()
	defer s.Metrics.mu.Unlock()
	return s.Metrics.counters[name][""]
}

// TestCASGCDeletesOnlyOldUnreferenced is the core policy test: referenced
// objects and fresh objects survive, an old unreferenced object is removed,
// and staging scratch files are never touched.
func TestCASGCDeletesOnlyOldUnreferenced(t *testing.T) {
	s, fs := casGCTestServer(t)
	referencedOld := putCASBlob(t, s, "referenced old payload")
	staleOrphan := putCASBlob(t, s, "stale orphan payload")
	freshOrphan := putCASBlob(t, s, "fresh orphan payload")
	referencedFresh := putCASBlob(t, s, "referenced fresh payload")

	s.mu.Lock()
	s.artifacts["a1"] = model.ArtifactRecord{ID: "a1", SHA256: referencedOld.SHA256}
	s.snapshots["sn1"] = model.SnapshotRecord{ID: "sn1", SHA256: referencedFresh.SHA256, RootSHA256: referencedFresh.SHA256}
	s.pendingSidecars["p1"] = referencedFresh.SHA256
	s.mu.Unlock()

	ageCASBlob(t, s, referencedOld.SHA256, 48*time.Hour)
	ageCASBlob(t, s, staleOrphan.SHA256, 48*time.Hour)
	// An old staging file must never be surfaced by enumeration, let alone
	// deleted: it is a partially written upload, not a content object.
	staging := filepath.Join(fs.Root, "sha256", staleOrphan.SHA256[:2], "."+staleOrphan.SHA256+".tmp-old")
	if err := os.WriteFile(staging, []byte("scratch"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(staging, old, old); err != nil {
		t.Fatal(err)
	}

	stats, err := s.runCASGC(context.Background(), casGCOptions{MinAge: 24 * time.Hour, Batch: 100})
	if err != nil {
		t.Fatalf("runCASGC: %v", err)
	}
	if stats.Deleted != 1 {
		t.Fatalf("deleted = %d, want 1 (%+v)", stats.Deleted, stats)
	}
	if stats.Bytes != staleOrphan.Size {
		t.Fatalf("deleted bytes = %d, want %d", stats.Bytes, staleOrphan.Size)
	}
	if casBlobExists(t, s, staleOrphan.SHA256) {
		t.Fatal("old unreferenced object must be deleted")
	}
	for name, digest := range map[string]string{
		"referenced old":   referencedOld.SHA256,
		"fresh orphan":     freshOrphan.SHA256,
		"referenced fresh": referencedFresh.SHA256,
	} {
		if !casBlobExists(t, s, digest) {
			t.Fatalf("%s object must survive", name)
		}
	}
	if _, err := os.Stat(staging); err != nil {
		t.Fatalf("staging file must survive: %v", err)
	}
	if got := casGCMetric(t, s, "kiwi_cas_gc_deleted_objects_total"); got != 1 {
		t.Fatalf("deleted-objects metric = %v, want 1", got)
	}
	if got := casGCMetric(t, s, "kiwi_cas_gc_deleted_bytes_total"); got != float64(staleOrphan.Size) {
		t.Fatalf("deleted-bytes metric = %v, want %d", got, staleOrphan.Size)
	}
}

// gcHookStore makes a deterministic interleaving point inside the
// enumeration: the hook runs once, during the first List callback, after the
// reference set was collected and before the walk finished.
type gcHookStore struct {
	*blob.FS
	once sync.Once
	hook func()
}

func (h *gcHookStore) List(ctx context.Context, fn func(blob.Object) error) error {
	return h.FS.List(ctx, func(o blob.Object) error {
		h.once.Do(h.hook)
		return fn(o)
	})
}

// TestCASGCConcurrentReferenceKeepsFreshObject proves the documented race
// bound: a reference created DURING a collection pass names a fresh object,
// and the age floor keeps it. The old orphan seeded first is still removed,
// so the pass really exercised its delete path.
func TestCASGCConcurrentReferenceKeepsFreshObject(t *testing.T) {
	s, fs := casGCTestServer(t)
	staleOrphan := putCASBlob(t, s, "stale orphan")
	ageCASBlob(t, s, staleOrphan.SHA256, 48*time.Hour)

	var concurrent blob.Object
	hook := &gcHookStore{FS: fs, hook: func() {
		var err error
		concurrent, err = s.CAS.Put(context.Background(), strings.NewReader("concurrent payload"))
		if err != nil {
			t.Errorf("concurrent put: %v", err)
			return
		}
		s.mu.Lock()
		s.artifacts["concurrent"] = model.ArtifactRecord{ID: "concurrent", SHA256: concurrent.SHA256}
		s.mu.Unlock()
	}}
	s.BlobStore = hook
	s.CAS = cas.New(hook)

	stats, err := s.runCASGC(context.Background(), casGCOptions{MinAge: 24 * time.Hour, Batch: 100})
	if err != nil {
		t.Fatalf("runCASGC: %v", err)
	}
	if stats.Deleted != 1 || casBlobExists(t, s, staleOrphan.SHA256) {
		t.Fatalf("stale orphan must be deleted (stats %+v)", stats)
	}
	if concurrent.SHA256 == "" {
		t.Fatal("hook did not create the concurrent object")
	}
	if !casBlobExists(t, s, concurrent.SHA256) {
		t.Fatal("object referenced concurrently during the pass must survive")
	}
}

// TestCASGCBatchBound proves one pass never removes more than the configured
// batch.
func TestCASGCBatchBound(t *testing.T) {
	s, _ := casGCTestServer(t)
	digests := make([]string, 0, 3)
	for _, payload := range []string{"orphan one", "orphan two", "orphan three"} {
		obj := putCASBlob(t, s, payload)
		ageCASBlob(t, s, obj.SHA256, 48*time.Hour)
		digests = append(digests, obj.SHA256)
	}
	stats, err := s.runCASGC(context.Background(), casGCOptions{MinAge: time.Hour, Batch: 2})
	if err != nil {
		t.Fatalf("runCASGC: %v", err)
	}
	if stats.Deleted != 2 {
		t.Fatalf("deleted = %d, want 2", stats.Deleted)
	}
	remaining := 0
	for _, digest := range digests {
		if casBlobExists(t, s, digest) {
			remaining++
		}
	}
	if remaining != 1 {
		t.Fatalf("remaining = %d, want 1", remaining)
	}
}

// TestCASGCLeaseSingleFlight proves a pass is skipped while the in-process
// collector mutex is held (memory-mode single flight).
func TestCASGCLeaseSingleFlight(t *testing.T) {
	s, _ := casGCTestServer(t)
	orphan := putCASBlob(t, s, "orphan")
	ageCASBlob(t, s, orphan.SHA256, 48*time.Hour)
	s.casGCMu.Lock()
	stats, err := s.runCASGC(context.Background(), casGCOptions{MinAge: time.Hour})
	s.casGCMu.Unlock()
	if err != nil {
		t.Fatalf("runCASGC: %v", err)
	}
	if stats.Deleted != 0 || !casBlobExists(t, s, orphan.SHA256) {
		t.Fatalf("a held lease must skip the pass: %+v", stats)
	}
	stats, err = s.runCASGC(context.Background(), casGCOptions{MinAge: time.Hour})
	if err != nil {
		t.Fatalf("runCASGC: %v", err)
	}
	if stats.Deleted != 1 || casBlobExists(t, s, orphan.SHA256) {
		t.Fatalf("released lease must collect: %+v", stats)
	}
}

// TestCASGCAdvisoryLeaseDBMode proves DB mode takes the store's advisory
// collector lease, that a lease held by another replica skips the pass, and
// that the collector re-reads references from the durable store.
func TestCASGCAdvisoryLeaseDBMode(t *testing.T) {
	s, _ := casGCTestServer(t)
	f := newDBFakeStore()
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	// A durable artifact row references one object; another old object is a
	// DB-only orphan; a third is fresh.
	referenced := putCASBlob(t, s, "db referenced")
	orphan := putCASBlob(t, s, "db orphan")
	fresh := putCASBlob(t, s, "db fresh")
	f.mu.Lock()
	f.artifacts = append(f.artifacts, model.ArtifactRecord{ID: "db-a1", SHA256: referenced.SHA256})
	f.mu.Unlock()
	ageCASBlob(t, s, referenced.SHA256, 48*time.Hour)
	ageCASBlob(t, s, orphan.SHA256, 48*time.Hour)

	stats, err := s.runCASGC(context.Background(), casGCOptions{MinAge: 24 * time.Hour, Batch: 100})
	if err != nil {
		t.Fatalf("runCASGC: %v", err)
	}
	if stats.Deleted != 1 || casBlobExists(t, s, orphan.SHA256) {
		t.Fatalf("DB-mode GC must delete only the durable orphan: %+v", stats)
	}
	if !casBlobExists(t, s, referenced.SHA256) || !casBlobExists(t, s, fresh.SHA256) {
		t.Fatal("DB-referenced and fresh objects must survive")
	}
	f.mu.Lock()
	claims := append([]string{}, f.casGCLeaseClaims...)
	outstanding := len(f.casGCLeases)
	f.mu.Unlock()
	if len(claims) == 0 || claims[len(claims)-1] != casGCLeaseKey {
		t.Fatalf("collector lease claims = %v, want %q", claims, casGCLeaseKey)
	}
	if outstanding != 0 {
		t.Fatalf("collector lease not released: %v", f.casGCLeases)
	}

	// Another replica holds the collector lease: the pass must be skipped.
	lease, acquired, err := f.TryAcquireCASGCLease(context.Background(), casGCLeaseKey)
	if err != nil || !acquired {
		t.Fatalf("second replica lease: held=%v err=%v", acquired, err)
	}
	orphan2 := putCASBlob(t, s, "db orphan two")
	ageCASBlob(t, s, orphan2.SHA256, 48*time.Hour)
	stats, err = s.runCASGC(context.Background(), casGCOptions{MinAge: time.Hour})
	if err != nil {
		t.Fatalf("runCASGC under held lease: %v", err)
	}
	if stats.Deleted != 0 || !casBlobExists(t, s, orphan2.SHA256) {
		t.Fatalf("a lease held by another replica must skip collection: %+v", stats)
	}
	if err := lease.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestCASGCFailsClosed pins the fail-closed contract: a store without
// enumeration, a failed reference read, or an unavailable advisory lease
// aborts the pass with nothing deleted.
func TestCASGCFailsClosed(t *testing.T) {
	t.Run("store without enumeration", func(t *testing.T) {
		s, fs := casGCTestServer(t)
		orphan := putCASBlob(t, s, "orphan")
		ageCASBlob(t, s, orphan.SHA256, 48*time.Hour)
		s.BlobStore = struct{ blob.Store }{Store: fs}
		s.CAS = cas.New(s.BlobStore)
		if _, err := s.runCASGC(context.Background(), casGCOptions{MinAge: time.Hour}); err == nil {
			t.Fatal("a non-enumerable store must fail closed")
		}
		if !casBlobExists(t, s, orphan.SHA256) {
			t.Fatal("nothing may be deleted when enumeration is unavailable")
		}
	})

	t.Run("reference read failure", func(t *testing.T) {
		s, _ := casGCTestServer(t)
		f := newDBFakeStore()
		if err := s.SwitchToDB(f); err != nil {
			t.Fatal(err)
		}
		orphan := putCASBlob(t, s, "orphan")
		ageCASBlob(t, s, orphan.SHA256, 48*time.Hour)
		f.mu.Lock()
		f.casRefErr = errors.New("db down")
		f.mu.Unlock()
		if _, err := s.runCASGC(context.Background(), casGCOptions{MinAge: time.Hour}); err == nil {
			t.Fatal("a reference read failure must abort the pass")
		}
		if !casBlobExists(t, s, orphan.SHA256) {
			t.Fatal("nothing may be deleted after a reference read failure")
		}
	})

	t.Run("lease failure", func(t *testing.T) {
		s, _ := casGCTestServer(t)
		f := newDBFakeStore()
		if err := s.SwitchToDB(f); err != nil {
			t.Fatal(err)
		}
		orphan := putCASBlob(t, s, "orphan")
		ageCASBlob(t, s, orphan.SHA256, 48*time.Hour)
		f.mu.Lock()
		f.casGCLeaseErr = errors.New("pool exhausted")
		f.mu.Unlock()
		if _, err := s.runCASGC(context.Background(), casGCOptions{MinAge: time.Hour}); err == nil {
			t.Fatal("a lease failure must abort the pass")
		}
		if !casBlobExists(t, s, orphan.SHA256) {
			t.Fatal("nothing may be deleted without the collector lease")
		}
	})
}

// TestCollectCASReferencesGathersEverySource proves the reference set
// includes payload, provenance, SBOM, sigstore, cas: locators, snapshot
// roots, pending sidecars, cache manifests and DB rows.
func TestCollectCASReferencesGathersEverySource(t *testing.T) {
	s, _ := casGCTestServer(t)
	digest := func(b byte) string { return strings.Repeat(string("0123456789abcdef"[b%16]), 64) }
	payload := digest(1)
	prov := digest(2)
	sbom := digest(3)
	sig := digest(4)
	casPath := digest(5)
	snapDigest := digest(6)
	root := digest(7)
	pending := digest(8)
	manifest := digest(9)
	dbArtifact := digest(10)
	dbPending := digest(11)
	cacheManifest := digest(12)

	s.mu.Lock()
	s.artifacts["a1"] = model.ArtifactRecord{ID: "a1", SHA256: payload, ProvenanceSHA256: prov, SBOMSHA256: sbom, SigstoreSHA256: sig, Path: "cas:" + casPath}
	s.snapshots["sn1"] = model.SnapshotRecord{ID: "sn1", SHA256: snapDigest, RootSHA256: root, Path: "cas:" + root}
	s.pendingSidecars["p1"] = pending
	s.mu.Unlock()

	// fs-mode cache manifest with a signed-envelope shape.
	cacheDir := filepath.Join(s.store.Root, "cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifestPayload, err := json.Marshal(cache.CacheManifest{Version: 1, BlobSHA256: manifest})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(map[string]string{"payload": base64.StdEncoding.EncodeToString(manifestPayload)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "repo.manifest.json"), envelope, 0o600); err != nil {
		t.Fatal(err)
	}

	f := newDBFakeStore()
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.artifacts = append(f.artifacts, model.ArtifactRecord{ID: "db-a1", SHA256: dbArtifact})
	f.cacheMans["k1"] = storage.CacheManifestRecord{Repo: "r", TrustDomain: "t", LogicalKey: "k", BlobSHA256: cacheManifest}
	f.pendingSidecars[fakePendingKey("job", "art", storage.ArtifactSidecarKindSBOM)] = fakePendingSidecar{digest: dbPending}
	f.mu.Unlock()

	refs, err := s.collectCASReferences(context.Background())
	if err != nil {
		t.Fatalf("collectCASReferences: %v", err)
	}
	for name, want := range map[string]string{
		"payload": payload, "provenance": prov, "sbom": sbom, "sigstore": sig,
		"cas path": casPath, "snapshot": snapDigest, "root": root, "pending": pending,
		"manifest": manifest, "db artifact": dbArtifact, "db pending": dbPending,
		"db cache manifest": cacheManifest,
	} {
		if _, ok := refs[want]; !ok {
			t.Fatalf("reference %s (%s) missing from %v", name, want, refs)
		}
	}
}

// TestCollectCASReferencesFailsOnBrokenManifest pins the fail-closed rule
// for an unreadable fs cache manifest: the pass aborts rather than risk
// deleting a payload whose manifest could not be read.
func TestCollectCASReferencesFailsOnBrokenManifest(t *testing.T) {
	s, _ := casGCTestServer(t)
	cacheDir := filepath.Join(s.store.Root, "cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "broken.manifest.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.collectCASReferences(context.Background()); err == nil {
		t.Fatal("a broken cache manifest must abort reference collection")
	}
}

// TestMaybeRunCASGCIntervalGating proves Maintain's hourly gate: the first
// tick arms the timer, an early tick is a no-op, and a tick past the
// interval collects.
func TestMaybeRunCASGCIntervalGating(t *testing.T) {
	s, _ := casGCTestServer(t)
	s.CASGCInterval = time.Hour
	s.CASGCMinAge = time.Hour
	orphan := putCASBlob(t, s, "orphan")
	ageCASBlob(t, s, orphan.SHA256, 48*time.Hour)
	ctx := context.Background()
	start := time.Now()

	s.maybeRunCASGC(ctx, start)
	if !casBlobExists(t, s, orphan.SHA256) {
		t.Fatal("the arming tick must not collect")
	}
	s.maybeRunCASGC(ctx, start.Add(30*time.Minute))
	if !casBlobExists(t, s, orphan.SHA256) {
		t.Fatal("a tick inside the interval must not collect")
	}
	s.maybeRunCASGC(ctx, start.Add(2*time.Hour))
	if casBlobExists(t, s, orphan.SHA256) {
		t.Fatal("a tick past the interval must collect")
	}
}

// TestCASGCEnumerationPauseRepublishKeepsBlob is the deterministic fence
// regression: the collector enumerates an old unreferenced digest, the test
// pauses it at exactly that point, a writer republishes the SAME digest and
// commits a durable reference (through the fence), the collector resumes,
// and the blob must survive. Without the fence + under-fence reference
// re-read the resumed pass would delete the now-live object, leaving durable
// metadata pointing at a missing blob.
func TestCASGCEnumerationPauseRepublishKeepsBlob(t *testing.T) {
	s, _ := casGCTestServer(t)
	orphan := putCASBlob(t, s, "resurrected payload")
	ageCASBlob(t, s, orphan.SHA256, 48*time.Hour)

	paused := make(chan struct{})
	resumed := make(chan struct{})
	oldHook := casGCAfterEnumeration
	casGCAfterEnumeration = func() {
		close(paused)
		<-resumed
	}
	t.Cleanup(func() { casGCAfterEnumeration = oldHook })

	type gcResult struct {
		stats casGCStats
		err   error
	}
	done := make(chan gcResult, 1)
	go func() {
		stats, err := s.runCASGC(context.Background(), casGCOptions{MinAge: 24 * time.Hour, Batch: 100})
		done <- gcResult{stats, err}
	}()

	<-paused
	// The dangerous real-world case is a DEDUPLICATED reference: a new
	// record pointing at the existing old blob WITHOUT rewriting its bytes,
	// so the object's mtime stays old and only the under-fence reference
	// re-read can save it. (A byte-level re-put would refresh the mtime and
	// the fresh-stat guard would mask the re-read path this test must
	// exercise.)
	if err := s.withDigestFence(context.Background(), orphan.SHA256, func() error {
		s.mu.Lock()
		s.artifacts["resurrected"] = model.ArtifactRecord{ID: "resurrected", SHA256: orphan.SHA256}
		s.mu.Unlock()
		return nil
	}); err != nil {
		t.Fatalf("reference the deduplicated digest under fence: %v", err)
	}
	// Prove the object is still old: the age guard alone must NOT be what
	// saves it.
	ageCASBlob(t, s, orphan.SHA256, 48*time.Hour)
	close(resumed)

	res := <-done
	if res.err != nil {
		t.Fatalf("runCASGC: %v", res.err)
	}
	if res.stats.Deleted != 0 {
		t.Fatalf("deleted = %d, want 0 (a concurrently referenced digest must survive)", res.stats.Deleted)
	}
	if !casBlobExists(t, s, orphan.SHA256) {
		t.Fatal("the re-referenced digest was deleted: durable metadata now points at a missing blob")
	}
}
