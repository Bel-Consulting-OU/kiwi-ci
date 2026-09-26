package server

// Cross-feature composition: reference-aware CAS garbage collection racing
// cache/artifact/snapshot publication.
//
// The scenarios combine the real enumerating filesystem CAS, the real digest
// fence (the process-wide cas.MemFencer this process's publication handlers
// and the collector share when the durable store has no advisory lock), the
// real reference sources (durable cache manifests, snapshot records, artifact
// records and the in-memory mirrors) and the real upload handlers. The
// asserted invariant is the same one the GC contract documents: after any
// interleaving, every digest named by a COMMITTED reference (cache manifest,
// snapshot record, artifact record, pending sidecar) must still be readable
// from the CAS, and an object whose publication failed after CAS.Put must not
// be named by any reference.
//
// The deterministic interleavings use the casGCAfterEnumeration seam, which
// runs between reference collection and the delete sweep. The fence test
// deliberately re-ages the freshly re-published object inside that window so
// the age floor cannot be the thing that protects it: only the fence's
// reference re-read can.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// composeGCWorld builds the DB-mode composition server: a persistent server
// (real data dir, real state persistence, real staging budget) switched to
// the fake durable store with a real enumerating filesystem CAS installed.
// Construction-time options (for example WithStagingBudget) are honoured, so
// a fixture that needs a specific staging budget supplies it to the
// constructor: staging is immutable after construction.
func composeGCWorld(t *testing.T, opts ...Option) (*Server, *dbFakeStore, *blob.FS) {
	t.Helper()
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir(), opts...)
	if err != nil {
		t.Fatalf("NewPersistent: %v", err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatalf("SwitchToDB: %v", err)
	}
	fs := blob.NewFS(filepath.Join(t.TempDir(), "cas"))
	s.SetBlobStore(fs)
	return s, f, fs
}

// composeSeedLeasedJob installs one running, leased job in BOTH the durable
// store and the in-memory mirror, exactly as a lease claim would.
func composeSeedLeasedJob(t *testing.T, s *Server, f *dbFakeStore, jobID, runnerID string) map[string]string {
	t.Helper()
	hdrs := seedCacheJob(t, s, jobID, runnerID, "https://github.com/o/repo-a.git", "o/repo-a", true)
	raw := "cache-lease-token"
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	f.mu.Lock()
	f.runs["run-c"] = model.Run{ID: "run-c", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", Status: model.StatusRunning}
	f.jobs[jobID] = model.Job{ID: jobID, RunID: "run-c", Key: "build", RepoURL: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a",
		Status: model.StatusRunning, Trusted: true, LeaseRunnerID: runnerID, LeaseTokenHash: hashLeaseToken(s.leaseKey, raw), LeaseGeneration: 5, LeaseExpiresAt: &exp}
	f.runners[runnerID] = model.Runner{ID: runnerID, Name: runnerID, Capacity: 1}
	f.mu.Unlock()
	return hdrs
}

// composeDanglingReferences walks every committed reference source and returns
// the references whose digest cannot be read back from the CAS — the exact
// "published reference names a deleted object" corruption the GC must never
// cause.
func composeDanglingReferences(t *testing.T, s *Server, f *dbFakeStore) []string {
	t.Helper()
	refs := map[string]struct{}{}
	// Only references that NAME a CAS object are collected: an artifact's
	// payload/provenance/SBOM/sigstore digests and locators, a snapshot's
	// archive digest and its cas: locator, a cache manifest's blob digest
	// and the durable pending-sidecar digests. A snapshot's manifest ROOT
	// digest is deliberately excluded: it is not a CAS key, and the
	// production collector already retains an object with that name
	// conservatively (addSnapshotRefs) if one ever exists.
	addRefs := func(rec model.ArtifactRecord) {
		for _, ref := range []string{rec.SHA256, rec.ProvenanceSHA256, rec.SBOMSHA256, rec.SigstoreSHA256, rec.Path, rec.ProvenancePath, rec.SBOMPath, rec.SigstorePath} {
			addCASRef(refs, ref)
		}
	}
	addSnap := func(rec model.SnapshotRecord) {
		addCASRef(refs, rec.SHA256)
		addCASRef(refs, rec.Path)
	}
	s.mu.Lock()
	for _, a := range s.artifacts {
		addRefs(a)
	}
	for _, rec := range s.snapshots {
		addSnap(rec)
	}
	for _, digest := range s.pendingSidecars {
		addCASRef(refs, digest)
	}
	s.mu.Unlock()

	f.mu.Lock()
	for _, a := range f.artifacts {
		addRefs(a)
	}
	for _, rec := range f.snapshots {
		addSnap(rec)
	}
	for _, rec := range f.cacheMans {
		addCASRef(refs, rec.BlobSHA256)
	}
	durablePending := make([]string, 0, len(f.pendingSidecars))
	for _, ps := range f.pendingSidecars {
		durablePending = append(durablePending, ps.digest)
	}
	f.mu.Unlock()
	for _, digest := range durablePending {
		addCASRef(refs, digest)
	}

	var dangling []string
	for digest := range refs {
		rc, _, err := s.CAS.Open(context.Background(), digest)
		if err != nil {
			dangling = append(dangling, digest)
			continue
		}
		_, readErr := io.Copy(io.Discard, rc)
		_ = rc.Close()
		if readErr != nil {
			dangling = append(dangling, digest)
		}
	}
	return dangling
}

// composeAgeCASBlob backdates one object's mtime on an explicit filesystem
// CAS, so the age floor can be exercised even when the server's installed
// blob store is a wrapper.
func composeAgeCASBlob(t *testing.T, fs *blob.FS, digest string, age time.Duration) {
	t.Helper()
	path := filepath.Join(fs.Root, "sha256", digest[:2], digest)
	when := time.Now().Add(-age)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatalf("age CAS blob %s: %v", digest, err)
	}
}

// composeDirectBody is a request body over exact bytes with no gate, so the
// snapshot upload path can be driven with an exact Content-Length.
type composeDirectBody struct {
	b []byte
}

func (r *composeDirectBody) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

// composeUploadSnapshot serves one snapshot upload request synchronously.
func composeUploadSnapshot(s *Server, jobID, bearer string, body []byte, hdrs map[string]string) int {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", &composeDirectBody{b: body})
	r.ContentLength = int64(len(body))
	r.Header.Set("Authorization", "Bearer "+bearer)
	for k, v := range hdrs {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Code
}

// TestComposeGCConcurrentPublicationRounds runs many rounds of "publish (cache
// or snapshot) racing one GC pass" under a fully hostile age floor (every
// object is a candidate), pausing the collector between reference collection
// and its sweep on every third round so publication lands exactly inside the
// documented residual-race window. After every round the full reference walk
// must find zero dangling digests, and a successful upload must always be
// resolvable.
func TestComposeGCConcurrentPublicationRounds(t *testing.T) {
	s, f, _ := composeGCWorld(t)
	hdrs := composeSeedLeasedJob(t, s, f, "job-rounds", "runner-rounds")
	archive, rootSHA := snapshotArchive(t)

	t.Cleanup(func() { casGCAfterEnumeration = nil })

	const rounds = 60
	for i := 0; i < rounds; i++ {
		payload := fmt.Sprintf("compose-round-payload-%d", i)
		sum := sha256.Sum256([]byte(payload))
		digest := hex.EncodeToString(sum[:])

		// Seed the digest as an OLD orphan first: the publication below
		// re-publishes content the collector has every reason to treat as
		// dead when it enumerates.
		orphan := putCASBlob(t, s, payload)
		ageCASBlob(t, s, orphan.SHA256, 48*time.Hour)

		useCache := i%2 == 0
		pauseGC := i%3 == 0
		casGCAfterEnumeration = nil
		var hookReady, hookResume chan struct{}
		if pauseGC {
			hookReady = make(chan struct{})
			hookResume = make(chan struct{})
			var once sync.Once
			casGCAfterEnumeration = func() {
				once.Do(func() {
					close(hookReady)
					<-hookResume
				})
			}
		}

		uploadDone := make(chan int, 1)
		go func() {
			var code int
			if useCache {
				key := fmt.Sprintf("%064x", i+1)
				code = doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-rounds/cache/"+key, "token", payload, hdrs).Code
			} else {
				code = composeUploadSnapshot(s, "job-rounds", "token", archive, hdrs)
			}
			uploadDone <- code
		}()

		gcDone := make(chan error, 1)
		go func() {
			_, err := s.runCASGC(context.Background(), casGCOptions{MinAge: time.Nanosecond, Batch: 1000})
			gcDone <- err
		}()

		if pauseGC {
			select {
			case <-hookReady:
			case <-time.After(10 * time.Second):
				t.Fatalf("round %d: collector never reached the post-enumeration seam", i)
			}
			select {
			case code := <-uploadDone:
				if code != http.StatusCreated {
					t.Fatalf("round %d: upload inside GC window = %d, want 201", i, code)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("round %d: upload never completed inside the GC window", i)
			}
			close(hookResume)
		} else {
			select {
			case code := <-uploadDone:
				if code != http.StatusCreated {
					t.Fatalf("round %d: upload = %d, want 201 (payload %s)", i, code, payload)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("round %d: upload never completed", i)
			}
		}
		if err := <-gcDone; err != nil {
			t.Fatalf("round %d: GC pass: %v", i, err)
		}

		// The published digest must be readable no matter what the collector
		// observed: the committed reference (cache manifest or snapshot
		// record) was written under the digest fence. The snapshot round
		// publishes the ARCHIVE bytes, not the seeded orphan payload.
		published := digest
		if !useCache {
			archiveSum := sha256.Sum256(archive)
			published = hex.EncodeToString(archiveSum[:])
		}
		rc, _, err := s.CAS.Open(context.Background(), published)
		if err != nil {
			t.Fatalf("round %d (%s): published digest %s unreadable after racing GC: %v", i, composeKindOf(useCache), published, err)
		}
		_, _ = io.Copy(io.Discard, rc)
		_ = rc.Close()
		if dangling := composeDanglingReferences(t, s, f); len(dangling) != 0 {
			t.Fatalf("round %d: %d dangling reference(s) after racing GC: %v", i, len(dangling), dangling)
		}
		if !useCache {
			f.mu.Lock()
			var found bool
			for _, rec := range f.snapshots {
				if rec.SHA256 == published {
					found = true
					if rec.RootSHA256 != rootSHA {
						t.Fatalf("round %d: snapshot root %s, want %s", i, rec.RootSHA256, rootSHA)
					}
				}
			}
			f.mu.Unlock()
			if !found {
				t.Fatalf("round %d: snapshot archive digest %s has no committed record", i, published)
			}
		}
	}
}

func composeKindOf(cache bool) string {
	if cache {
		return "cache"
	}
	return "snapshot"
}

// TestComposeGCReReadsReferencesUnderFence is the deterministic fence proof:
// the collector collects references, the seam publishes the SAME digest and
// then RE-AGES the object so the age floor cannot rescue it, and the sweep
// runs. The object must survive because the fence-guarded reference re-read
// sees the freshly committed manifest; a control orphan in the same pass is
// deleted, so the sweep demonstrably ran.
func TestComposeGCReReadsReferencesUnderFence(t *testing.T) {
	s, f, _ := composeGCWorld(t)
	hdrs := composeSeedLeasedJob(t, s, f, "job-fence", "runner-fence")

	payload := "compose-fence-payload"
	referenced := putCASBlob(t, s, payload)
	control := putCASBlob(t, s, "compose-fence-control-orphan")
	ageCASBlob(t, s, referenced.SHA256, 48*time.Hour)
	ageCASBlob(t, s, control.SHA256, 48*time.Hour)

	var once sync.Once
	casGCAfterEnumeration = func() {
		once.Do(func() {
			key := fmt.Sprintf("%064x", 1)
			if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-fence/cache/"+key, "token", payload, hdrs); w.Code != http.StatusCreated {
				t.Errorf("publication inside GC window = %d: %s", w.Code, w.Body.String())
				return
			}
			// Defeat the mtime protection: the reference re-read under the
			// fence is the only thing that can keep this object now.
			ageCASBlob(t, s, referenced.SHA256, 48*time.Hour)
		})
	}
	t.Cleanup(func() { casGCAfterEnumeration = nil })

	stats, err := s.runCASGC(context.Background(), casGCOptions{MinAge: 24 * time.Hour, Batch: 100})
	if err != nil {
		t.Fatalf("runCASGC: %v", err)
	}
	if !casBlobExists(t, s, referenced.SHA256) {
		t.Fatal("referenced object was deleted despite the committed manifest (fence re-read did not see it)")
	}
	if casBlobExists(t, s, control.SHA256) {
		t.Fatal("control orphan survived: the pass did not exercise its delete path")
	}
	if stats.Deleted != 1 {
		t.Fatalf("deleted = %d, want exactly the control orphan", stats.Deleted)
	}
	if dangling := composeDanglingReferences(t, s, f); len(dangling) != 0 {
		t.Fatalf("dangling references after fence pass: %v", dangling)
	}
}

// composeCorruptOpenFS is a filesystem CAS whose reads are silently corrupted
// (same length, different bytes) after the bytes are stored: the publication
// has already Put the object when the read-back verification runs, which is
// exactly the "publication fails after CAS.Put" window.
type composeCorruptOpenFS struct {
	*blob.FS
}

func (c *composeCorruptOpenFS) Open(ctx context.Context, key string) (io.ReadCloser, blob.Object, error) {
	rc, obj, err := c.FS.Open(ctx, key)
	if err != nil {
		return nil, blob.Object{}, err
	}
	b, readErr := io.ReadAll(rc)
	_ = rc.Close()
	if readErr != nil {
		return nil, blob.Object{}, readErr
	}
	for i := range b {
		b[i] ^= 0xff
	}
	return io.NopCloser(&composeBytesReader{b: b}), blob.Object{Key: obj.Key, SHA256: obj.SHA256, Size: int64(len(b))}, nil
}

type composeBytesReader struct {
	b []byte
}

func (r *composeBytesReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

// TestComposeGCIntegrityMismatchAfterPutLeavesNoDanglingReference drives the
// cache and snapshot integrity-mismatch paths (a backend whose stored bytes
// disagree with the staged digest) and proves the failed publication leaves no
// durable reference — and that the orphaned object, once aged, is exactly what
// the next GC pass reclaims.
func TestComposeGCIntegrityMismatchAfterPutLeavesNoDanglingReference(t *testing.T) {
	s, f, fs := composeGCWorld(t)
	hdrs := composeSeedLeasedJob(t, s, f, "job-integ", "runner-integ")
	s.SetBlobStore(&composeCorruptOpenFS{FS: fs})
	archive, _ := snapshotArchive(t)

	// Cache publication: CAS.Put succeeds, the read-back verification fails,
	// the handler answers 503 and no manifest may exist.
	cachePayload := "compose-integrity-cache-payload"
	cacheSum := sha256.Sum256([]byte(cachePayload))
	cacheDigest := hex.EncodeToString(cacheSum[:])
	cacheKey := fmt.Sprintf("%064x", 2)
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-integ/cache/"+cacheKey, "token", cachePayload, hdrs); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("cache integrity mismatch = %d, want 503: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	manifests := len(f.cacheMans)
	snapshotsBefore := len(f.snapshots)
	f.mu.Unlock()
	if manifests != 0 {
		t.Fatalf("failed cache publication committed %d manifest(s), want 0", manifests)
	}

	// Snapshot publication: same shape, record must not commit.
	if code := composeUploadSnapshot(s, "job-integ", "token", archive, hdrs); code != http.StatusServiceUnavailable {
		t.Fatalf("snapshot integrity mismatch = %d, want 503", code)
	}
	f.mu.Lock()
	if len(f.snapshots) != snapshotsBefore {
		t.Fatalf("failed snapshot publication committed a record: %d -> %d", snapshotsBefore, len(f.snapshots))
	}
	f.mu.Unlock()

	// Neither failed publication may be named by any reference.
	if dangling := composeDanglingReferences(t, s, f); len(dangling) != 0 {
		t.Fatalf("dangling references after failed publications: %v", dangling)
	}
	// The orphaned object (aged) is exactly what the collector reclaims: a
	// failed publication leaves an ORPHAN, never a dangling reference.
	// Restore the healthy backend first so the invariant walk reads the real
	// bytes again.
	s.SetBlobStore(fs)
	composeAgeCASBlob(t, fs, cacheDigest, 48*time.Hour)
	stats, err := s.runCASGC(context.Background(), casGCOptions{MinAge: 24 * time.Hour, Batch: 100})
	if err != nil {
		t.Fatalf("runCASGC: %v", err)
	}
	if stats.Deleted != 1 {
		t.Fatalf("GC deleted %d objects, want the single orphaned failed-publication object", stats.Deleted)
	}
	if casBlobExists(t, s, cacheDigest) {
		t.Fatal("orphaned failed-publication object was not reclaimed")
	}
	if dangling := composeDanglingReferences(t, s, f); len(dangling) != 0 {
		t.Fatalf("dangling references after orphan reclaim: %v", dangling)
	}
}

// TestComposeGCConcurrentPublishersStress is the many-round adversarial
// version: several publishers (cache and snapshot, deliberately re-publishing
// a mix of fresh content and the same archive bytes so dedup re-puts race
// deletions) run against two continuous collectors with a hostile age floor,
// and every acknowledged publication must remain resolvable afterwards.
func TestComposeGCConcurrentPublishersStress(t *testing.T) {
	// The stress scenario deliberately publishes far more snapshots than the
	// production per-job retention cap allows, so disable the cap at
	// construction here; the cap itself is covered by
	// TestSnapshotPerJobCapRejectsWithoutStaging. The cap is an immutable
	// per-server field, so it must be chosen when the world is built.
	s, f, _ := composeGCWorld(t, WithSnapshotMaxPerJob(0))
	hdrs := composeSeedLeasedJob(t, s, f, "job-stress", "runner-stress")
	archive, _ := snapshotArchive(t)

	const publishers = 6
	const iterations = 40
	stop := make(chan struct{})
	var gcWG sync.WaitGroup
	for i := 0; i < 2; i++ {
		gcWG.Add(1)
		go func() {
			defer gcWG.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := s.runCASGC(context.Background(), casGCOptions{MinAge: time.Nanosecond, Batch: 1000}); err != nil {
					t.Errorf("stress GC pass: %v", err)
					return
				}
			}
		}()
	}

	type published struct {
		digest   string
		snapshot bool
	}
	var mu sync.Mutex
	var successes []published
	var wg sync.WaitGroup
	for w := 0; w < publishers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				useCache := (w+i)%3 != 0
				if useCache {
					payload := fmt.Sprintf("compose-stress-%d-%d", w, i)
					key := fmt.Sprintf("%064x", w*1000+i+100)
					code := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-stress/cache/"+key, "token", payload, hdrs).Code
					if code != http.StatusCreated {
						t.Errorf("stress cache upload (%d,%d) = %d", w, i, code)
						return
					}
					sum := sha256.Sum256([]byte(payload))
					mu.Lock()
					successes = append(successes, published{digest: hex.EncodeToString(sum[:])})
					mu.Unlock()
					continue
				}
				if code := composeUploadSnapshot(s, "job-stress", "token", archive, hdrs); code != http.StatusCreated {
					t.Errorf("stress snapshot upload (%d,%d) = %d", w, i, code)
					return
				}
				sum := sha256.Sum256(archive)
				mu.Lock()
				successes = append(successes, published{digest: hex.EncodeToString(sum[:]), snapshot: true})
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	gcWG.Wait()

	if len(successes) != publishers*iterations {
		t.Fatalf("acknowledged publications = %d, want %d", len(successes), publishers*iterations)
	}
	for _, pub := range successes {
		rc, _, err := s.CAS.Open(context.Background(), pub.digest)
		if err != nil {
			t.Fatalf("acknowledged %s publication digest %s is unreadable after the stress run: %v",
				composeKindOf(!pub.snapshot), pub.digest, err)
		}
		_, _ = io.Copy(io.Discard, rc)
		_ = rc.Close()
	}
	if dangling := composeDanglingReferences(t, s, f); len(dangling) != 0 {
		t.Fatalf("dangling references after the stress run: %v", dangling)
	}
	// A final pass may only reclaim genuinely unreferenced objects; the
	// reference walk stays clean.
	if _, err := s.runCASGC(context.Background(), casGCOptions{MinAge: time.Nanosecond, Batch: 1000}); err != nil {
		t.Fatalf("final GC pass: %v", err)
	}
	if dangling := composeDanglingReferences(t, s, f); len(dangling) != 0 {
		t.Fatalf("dangling references after the final pass: %v", dangling)
	}
}

// TestComposeGCPendingSidecarReferenceSurvivesPass pins the pending-sidecar
// reference source in the same composition: a digest reserved by a durable
// pending SBOM/sigstore row (written before its artifact commit) is
// referenced, so an aged object must survive the pass that reclaims every
// other old orphan.
func TestComposeGCPendingSidecarReferenceSurvivesPass(t *testing.T) {
	s, f, _ := composeGCWorld(t)
	referenced := putCASBlob(t, s, "compose-sidecar-payload")
	orphan := putCASBlob(t, s, "compose-sidecar-orphan")
	ageCASBlob(t, s, referenced.SHA256, 72*time.Hour)
	ageCASBlob(t, s, orphan.SHA256, 72*time.Hour)

	f.mu.Lock()
	f.pendingSidecars[fakePendingKey("job-1", 1, "bin", "sbom")] = fakePendingSidecar{digest: referenced.SHA256}
	f.mu.Unlock()

	stats, err := s.runCASGC(context.Background(), casGCOptions{MinAge: 24 * time.Hour, Batch: 100})
	if err != nil {
		t.Fatalf("runCASGC: %v", err)
	}
	if !casBlobExists(t, s, referenced.SHA256) {
		t.Fatal("digest referenced by a durable pending sidecar was deleted")
	}
	if casBlobExists(t, s, orphan.SHA256) {
		t.Fatal("unreferenced aged orphan survived")
	}
	if stats.Deleted != 1 {
		t.Fatalf("deleted = %d, want 1", stats.Deleted)
	}
	if dangling := composeDanglingReferences(t, s, f); len(dangling) != 0 {
		t.Fatalf("dangling references: %v", dangling)
	}
}
