package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
)

// setTestStagingBudget installs a fresh staging budget on the server.
func setTestStagingBudget(t *testing.T, s *Server, dir string, max int64) *staging.Budget {
	t.Helper()
	b, err := staging.NewBudget(dir, max)
	if err != nil {
		t.Fatalf("staging budget: %v", err)
	}
	s.SetStagingBudget(b)
	return b
}

// doRawBody serves one request with an explicit body and Content-Length
// (negative = unknown/chunked), unlike doJSONHeaders which lets httptest
// infer the length.
func doRawBody(t *testing.T, s *Server, method, path, bearer string, body io.Reader, cl int64, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, body)
	r.ContentLength = cl
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

// brokenBody yields prefix bytes and then a hard error, simulating a client
// that disconnects mid-upload (unknown length).
type brokenBody struct {
	prefix []byte
	err    error
	done   bool
}

func (b *brokenBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, b.err
	}
	n := copy(p, b.prefix)
	b.prefix = b.prefix[n:]
	if len(b.prefix) == 0 {
		b.done = true
	}
	return n, nil
}

func (b *brokenBody) Close() error { return nil }

// lyingBlob is a blob.Store whose writes/reads disagree with the content in
// whichever way a broken or misconfigured backend could.
type lyingBlob struct {
	inner *memBlob
	mode  string
}

func (b *lyingBlob) Put(ctx context.Context, key string, r io.Reader, size int64) (blob.Object, error) {
	obj, err := b.inner.Put(ctx, key, r, size)
	if err != nil {
		return obj, err
	}
	switch b.mode {
	case "put-digest":
		// The backend reports a digest that is not the staged bytes.
		obj.SHA256 = strings.Repeat("f", 64)
	case "put-size":
		// The backend reports a size that is not the staged byte count
		// (the stored bytes are correct).
		obj.Size = obj.Size + 1
	case "put-key":
		// The backend reports a key other than the one it was asked to
		// store, even though the content is correct.
		obj.Key = strings.Repeat("0", 64)
	case "open-corrupt":
		// The object is stored under the right digest but with different
		// bytes of the same length, so only the read-back verification can
		// catch it.
		b.inner.mu.Lock()
		b.inner.objects[key] = bytes.Repeat([]byte{0}, len(b.inner.objects[key]))
		b.inner.mu.Unlock()
	case "open-longer":
		// The stored object is longer than the staged bytes (a backend that
		// silently appends/trailing-garbage); only the read-back length and
		// digest checks can catch it, because cas.Put normalizes the
		// returned size to the locally counted stream.
		b.inner.mu.Lock()
		b.inner.objects[key] = append(b.inner.objects[key], 0xff)
		b.inner.mu.Unlock()
	}
	return obj, nil
}

func (b *lyingBlob) Open(ctx context.Context, key string) (io.ReadCloser, blob.Object, error) {
	return b.inner.Open(ctx, key)
}

func (b *lyingBlob) Delete(ctx context.Context, key string) error { return b.inner.Delete(ctx, key) }

// TestCacheUploadStagesInsideBudgetDirectoryAndReleases proves the staging
// wiring: the body spools inside the configured budget directory (never a
// bare system temp directory), the reservation equals the request's
// Content-Length while the bytes are held, the reservation is released and
// the spool file removed on the success path, and the manifest records the
// verified digest/size.
func TestCacheUploadStagesInsideBudgetDirectoryAndReleases(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	dir := filepath.Join(t.TempDir(), "staging")
	b := setTestStagingBudget(t, s, dir, 1<<20)

	var (
		mu         sync.Mutex
		stagedPath string
		reserved   int64
	)
	oldHook := cacheStageHook
	cacheStageHook = func(path string, reservedBytes int64) {
		mu.Lock()
		stagedPath, reserved = path, reservedBytes
		mu.Unlock()
	}
	defer func() { cacheStageHook = oldHook }()

	key := strings.Repeat("a", 64)
	payload := "cache-payload-bytes"
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", payload, hdrs)
	if w.Code != http.StatusCreated {
		t.Fatalf("cache put = %d: %s", w.Code, w.Body.String())
	}
	mu.Lock()
	path, gotReserved := stagedPath, reserved
	mu.Unlock()
	if path == "" {
		t.Fatal("cache staging hook never ran: the body was not staged through SpoolFile")
	}
	if filepath.Dir(path) != dir {
		t.Fatalf("staged file %q is not inside the budget directory %q", path, dir)
	}
	if !strings.HasPrefix(filepath.Base(path), staging.FilePrefix) {
		t.Fatalf("staged file %q lacks the staging prefix", path)
	}
	if gotReserved != int64(len(payload)) {
		t.Fatalf("reserved %d bytes, want the Content-Length %d", gotReserved, len(payload))
	}
	if b.Used() != 0 {
		t.Fatalf("budget used after upload = %d, want 0 (reservation released)", b.Used())
	}
	if leftovers := stageFiles(t, dir); len(leftovers) != 0 {
		t.Fatalf("staging directory kept %d spool file(s) after upload: %v", len(leftovers), leftovers)
	}
	// The manifest commits the verified digest and exact size.
	sum := sha256.Sum256([]byte(payload))
	digest := hex.EncodeToString(sum[:])
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.cacheMans) != 1 {
		t.Fatalf("cache manifests = %d, want 1", len(f.cacheMans))
	}
	for _, rec := range f.cacheMans {
		if rec.BlobSHA256 != digest || rec.BlobSize != int64(len(payload)) {
			t.Fatalf("manifest = %s/%d, want %s/%d", rec.BlobSHA256, rec.BlobSize, digest, len(payload))
		}
	}
}

// TestCacheUploadNoBareTempStaging pins the defect: the cache staging path
// must not create scratch files in an unbounded system temp directory.
func TestCacheUploadNoBareTempStaging(t *testing.T) {
	src, err := os.ReadFile("blobs.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(src)
	for _, forbidden := range []string{`os.CreateTemp(""`, "os.TempDir()"} {
		if strings.Contains(code, forbidden) {
			t.Fatalf("blobs.go still stages in an unbounded temp location: contains %q", forbidden)
		}
	}
	if !strings.Contains(code, "staging.SpoolFile") {
		t.Fatal("blobs.go does not stage through staging.SpoolFile")
	}
}

// TestCacheUploadWaitsForStagingBudget proves the endpoint CHARGES the
// shared budget: while the budget is fully reserved by another upload, a
// valid cache upload blocks instead of staging concurrently.
func TestCacheUploadWaitsForStagingBudget(t *testing.T) {
	s, _, _, hdrs := cacheFixture(t)
	dir := filepath.Join(t.TempDir(), "staging")
	b := setTestStagingBudget(t, s, dir, 1024)

	hold, err := b.Acquire(context.Background(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	payload := "0123456789"
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+strings.Repeat("b", 64), "runner-tok", payload, hdrs)
	}()
	select {
	case w := <-done:
		t.Fatalf("upload completed (%d) while the budget was fully reserved", w.Code)
	case <-time.After(75 * time.Millisecond):
	}
	hold.Release()
	select {
	case w := <-done:
		if w.Code != http.StatusCreated {
			t.Fatalf("upload after release = %d: %s", w.Code, w.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upload never proceeded after the budget was released")
	}
	if b.Used() != 0 {
		t.Fatalf("budget used after upload = %d, want 0", b.Used())
	}
}

// TestCacheUploadRefusesReservationAboveStagingBudget: a request that can
// never fit the budget is refused up front (known Content-Length) or with a
// fail-closed 503 (unknown length, where the endpoint maximum is reserved),
// and nothing is staged.
func TestCacheUploadRefusesReservationAboveStagingBudget(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	dir := filepath.Join(t.TempDir(), "staging")
	b := setTestStagingBudget(t, s, dir, 16)
	key := strings.Repeat("c", 64)
	payload := strings.Repeat("x", 64)

	// Known Content-Length above the budget: 413, no staging.
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", payload, hdrs)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized reservation = %d, want 413: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "staging capacity") {
		t.Fatalf("413 body = %q, want the staging capacity reason", w.Body.String())
	}
	if b.Used() != 0 {
		t.Fatalf("refused upload left %d bytes reserved", b.Used())
	}
	if leftovers := stageFiles(t, dir); len(leftovers) != 0 {
		t.Fatalf("refused upload left %d staged file(s)", len(leftovers))
	}

	// Unknown length with an endpoint maximum above the budget: the
	// reservation itself cannot succeed, so the upload fails closed 503.
	oldLimit := cacheUploadMaxBytes
	cacheUploadMaxBytes = 64
	defer func() { cacheUploadMaxBytes = oldLimit }()
	w = doRawBody(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", bytes.NewReader([]byte(payload)), -1, hdrs)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unreservable chunked upload = %d, want 503: %s", w.Code, w.Body.String())
	}
	if b.Used() != 0 {
		t.Fatalf("failed upload left %d bytes reserved", b.Used())
	}
	f.mu.Lock()
	manifests := len(f.cacheMans)
	f.mu.Unlock()
	if manifests != 0 {
		t.Fatalf("refused upload committed %d manifest(s)", manifests)
	}
}

// TestCacheUpload413Matrix covers the exact-limit/limit+1 boundary for both
// a declared Content-Length and a chunked (unknown-length) body, plus the
// early-disconnect case: 413 is the fixed client-visible rejection, and
// every path releases the staging reservation and removes the spool file.
func TestCacheUpload413Matrix(t *testing.T) {
	const limit = 64
	oldLimit := cacheUploadMaxBytes
	cacheUploadMaxBytes = limit
	defer func() { cacheUploadMaxBytes = oldLimit }()

	setup := func(t *testing.T) (*Server, *dbFakeStore, *staging.Budget, map[string]string, string) {
		s, f, _, hdrs := cacheFixture(t)
		dir := filepath.Join(t.TempDir(), "staging")
		b := setTestStagingBudget(t, s, dir, 1<<20)
		return s, f, b, hdrs, dir
	}
	assertClean := func(t *testing.T, b *staging.Budget, dir string) {
		t.Helper()
		if b.Used() != 0 {
			t.Fatalf("budget used = %d, want 0", b.Used())
		}
		if leftovers := stageFiles(t, dir); len(leftovers) != 0 {
			t.Fatalf("staging spool files = %v, want none", leftovers)
		}
	}

	t.Run("exact-limit accepted", func(t *testing.T) {
		s, f, b, hdrs, dir := setup(t)
		payload := strings.Repeat("e", limit)
		w := doRawBody(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+strings.Repeat("d", 64), "runner-tok", strings.NewReader(payload), limit, hdrs)
		if w.Code != http.StatusCreated {
			t.Fatalf("exact-limit upload = %d: %s", w.Code, w.Body.String())
		}
		f.mu.Lock()
		manifests := len(f.cacheMans)
		f.mu.Unlock()
		if manifests != 1 {
			t.Fatalf("exact-limit upload committed %d manifests, want 1", manifests)
		}
		assertClean(t, b, dir)
	})

	t.Run("limit+1 with Content-Length rejected 413", func(t *testing.T) {
		s, f, b, hdrs, dir := setup(t)
		payload := strings.Repeat("o", limit+1)
		w := doRawBody(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+strings.Repeat("d", 64), "runner-tok", strings.NewReader(payload), limit+1, hdrs)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("limit+1 upload = %d, want 413: %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "64-byte upload limit") {
			t.Fatalf("413 body = %q, want the fixed limit message", w.Body.String())
		}
		f.mu.Lock()
		manifests := len(f.cacheMans)
		f.mu.Unlock()
		if manifests != 0 {
			t.Fatalf("rejected upload committed %d manifests", manifests)
		}
		assertClean(t, b, dir)
	})

	t.Run("limit+1 chunked rejected 413", func(t *testing.T) {
		s, f, b, hdrs, dir := setup(t)
		payload := strings.Repeat("k", limit+1)
		w := doRawBody(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+strings.Repeat("d", 64), "runner-tok", bytes.NewReader([]byte(payload)), -1, hdrs)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("chunked limit+1 upload = %d, want 413: %s", w.Code, w.Body.String())
		}
		f.mu.Lock()
		manifests := len(f.cacheMans)
		f.mu.Unlock()
		if manifests != 0 {
			t.Fatalf("rejected chunked upload committed %d manifests", manifests)
		}
		assertClean(t, b, dir)
	})

	t.Run("early disconnect releases reservation", func(t *testing.T) {
		s, f, b, hdrs, dir := setup(t)
		body := &brokenBody{prefix: []byte("partial"), err: errors.New("client disconnected mid-body")}
		w := doRawBody(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+strings.Repeat("d", 64), "runner-tok", body, -1, hdrs)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("disconnected upload = %d, want the opaque 500: %s", w.Code, w.Body.String())
		}
		f.mu.Lock()
		manifests := len(f.cacheMans)
		f.mu.Unlock()
		if manifests != 0 {
			t.Fatalf("disconnected upload committed %d manifests", manifests)
		}
		assertClean(t, b, dir)
	})
}

// TestCacheCASIntegrityMismatchCommitsNoManifest: a backend whose published
// object disagrees with the staged bytes (wrong reported digest, wrong
// reported size, or silently different stored content) must be answered 503
// and must never leave a signed manifest behind.
func TestCacheCASIntegrityMismatchCommitsNoManifest(t *testing.T) {
	for _, mode := range []string{"put-digest", "put-size", "put-key", "open-corrupt", "open-longer"} {
		t.Run(mode, func(t *testing.T) {
			s, f, _, hdrs := cacheFixture(t)
			setTestStagingBudget(t, s, filepath.Join(t.TempDir(), "staging"), 1<<20)
			s.SetBlobStore(&lyingBlob{inner: newMemBlob(), mode: mode})
			key := strings.Repeat("a", 64)
			w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "cache-integrity-payload", hdrs)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("integrity mismatch (%s) = %d, want 503: %s", mode, w.Code, w.Body.String())
			}
			f.mu.Lock()
			manifests := len(f.cacheMans)
			f.mu.Unlock()
			if manifests != 0 {
				t.Fatalf("integrity mismatch (%s) committed %d manifest(s), want 0", mode, manifests)
			}
			// No manifest means the entry must not resolve on download.
			if got := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "", hdrs); got.Code != http.StatusNotFound {
				t.Fatalf("download after integrity failure = %d, want 404", got.Code)
			}
		})
	}
}

// TestCacheUploadReopenVerifiesHappyPath proves the published object is
// reopened and re-hashed before the manifest commits: reads through CAS.Open
// return the exact payload bytes and digest.
func TestCacheUploadReopenVerifiesHappyPath(t *testing.T) {
	s, _, _, hdrs := cacheFixture(t)
	setTestStagingBudget(t, s, filepath.Join(t.TempDir(), "staging"), 1<<20)
	payload := "reopen-verify-payload"
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+strings.Repeat("a", 64), "runner-tok", payload, hdrs)
	if w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	sum := sha256.Sum256([]byte(payload))
	digest := hex.EncodeToString(sum[:])
	rc, obj, err := s.CAS.Open(context.Background(), digest)
	if err != nil {
		t.Fatalf("CAS.Open: %v", err)
	}
	got, err := io.ReadAll(rc)
	closeErr := rc.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("read back: %v / %v", err, closeErr)
	}
	if !bytes.Equal(got, []byte(payload)) || obj.Size != int64(len(payload)) {
		t.Fatalf("read back %q (%d bytes), want %q (%d)", got, obj.Size, payload, len(payload))
	}
}

// TestArtifactCASIntegrityMismatchCommitsNoRecord: the artifact publication
// path applies the same invariant as the cache path — a CAS Put that
// disagrees with the streamed bytes fails the upload with 503 and commits no
// artifact record (and therefore no provenance statement for it).
func TestArtifactCASIntegrityMismatchCommitsNoRecord(t *testing.T) {
	for _, mode := range []string{"put-digest", "put-size", "put-key", "open-corrupt", "open-longer"} {
		t.Run(mode, func(t *testing.T) {
			f := newDBFakeStore()
			s, err := NewPersistent("token", "token", t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := s.SwitchToDB(f); err != nil {
				t.Fatal(err)
			}
			runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
			s.SetBlobStore(&lyingBlob{inner: newMemBlob(), mode: mode})
			path := "/api/v1/jobs/" + task.Job.ID + "/artifacts/bin"
			w := doJSONHeaders(t, s, http.MethodPut, path, "token", "artifact-integrity-payload", leaseHeaders(task, runnerID))
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("artifact integrity mismatch (%s) = %d, want 503: %s", mode, w.Code, w.Body.String())
			}
			f.mu.Lock()
			records := len(f.artifacts)
			f.mu.Unlock()
			if records != 0 {
				t.Fatalf("integrity mismatch (%s) committed %d artifact record(s), want 0", mode, records)
			}
		})
	}
}
