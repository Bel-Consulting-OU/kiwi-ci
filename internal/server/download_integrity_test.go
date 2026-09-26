package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
)

// corruptSameLength replaces the stored bytes under key with different
// content of the SAME length, modelling a backend that returns the right byte
// count with wrong content (the exact defect that used to produce a
// complete-length corrupt body with HTTP 200).
func corruptSameLength(t *testing.T, mb *memBlob, key string) []byte {
	t.Helper()
	mb.mu.Lock()
	defer mb.mu.Unlock()
	orig, ok := mb.objects[key]
	if !ok {
		t.Fatalf("no CAS object under %s to corrupt", key)
	}
	wrong := make([]byte, len(orig))
	for i := range wrong {
		wrong[i] = 'Z'
	}
	for i := range wrong {
		if i < len(orig) && orig[i] == 'Z' {
			wrong[i] = 'Q'
		}
	}
	mb.objects[key] = wrong
	return wrong
}

// TestArtifactDownloadCorruptBackendNoSilent200 is the T2-2 regression: a
// backend that returns the right byte count with wrong content must NOT yield
// a 200 with a complete-length corrupt body. The preverify path refuses it
// with 503 and serves no payload bytes.
func TestArtifactDownloadCorruptBackendNoSilent200(t *testing.T) {
	s, _, mb, hdrs := artifactIdentityFixture(t)
	up := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if up.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", up.Code, up.Body.String())
	}
	var rec struct {
		ID     string `json:"id"`
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(up.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	wrong := corruptSameLength(t, mb, rec.SHA256)

	w := doJSON(t, s, http.MethodGet, "/api/v1/artifacts/"+rec.ID, "admin-tok", "")
	if w.Code == http.StatusOK {
		t.Fatalf("corrupt backend served a 200 with %d bytes", w.Body.Len())
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("corrupt backend download = %d, want 503: %s", w.Code, w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), wrong) {
		t.Fatal("response body contains the corrupt bytes")
	}
	// No Content-Length header is committed for a refused download.
	if got := w.Header().Get("Content-Length"); got != "" {
		t.Fatalf("refused download committed Content-Length %q", got)
	}
}

// TestArtifactDownloadValidByteIdentical proves the preverify path does not
// alter a valid download.
func TestArtifactDownloadValidByteIdentical(t *testing.T) {
	s, _, _, hdrs := artifactIdentityFixture(t)
	payload := "payload-bytes-identical"
	up := fcUploadBlobArtifact(t, s, hdrs, payload)
	if up.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", up.Code, up.Body.String())
	}
	var rec struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(up.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodGet, "/api/v1/artifacts/"+rec.ID, "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("valid download = %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != payload {
		t.Fatalf("download body = %q, want %q", w.Body.String(), payload)
	}
	if got := w.Header().Get("Content-Length"); got != "23" {
		t.Fatalf("Content-Length = %q, want 23", got)
	}
}

// TestSnapshotDownloadCorruptBackendNoSilent200 is the snapshot counterpart:
// a corrupted CAS archive is refused (503) instead of streamed as a 200.
func TestSnapshotDownloadCorruptBackendNoSilent200(t *testing.T) {
	f := newDBFakeStore()
	s, runnerID, jobID, task, c := snapshotCASServer(t, f, t.TempDir())
	mb := newMemBlob()
	s.SetBlobStore(mb)
	runID := task.Job.RunID
	body, _ := snapshotArchive(t)
	up := uploadSnapshotCAS(t, c, jobID, runnerID, task, body)
	if up.Code != http.StatusCreated {
		t.Fatalf("snapshot upload = %d: %s", up.Code, up.Body.String())
	}
	var rec struct {
		ID     string `json:"id"`
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(up.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	corruptSameLength(t, mb, rec.SHA256)

	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/"+runID+"/snapshots/"+rec.ID, "token", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("corrupt snapshot download = %d, want 503: %s", w.Code, w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), bytes.Repeat([]byte{'Z'}, 8)) {
		t.Fatal("response body contains the corrupt archive bytes")
	}
}

// TestSnapshotDownloadValidByteIdentical proves a valid snapshot download is
// byte-identical under the preverify path.
func TestSnapshotDownloadValidByteIdentical(t *testing.T) {
	f := newDBFakeStore()
	s, runnerID, jobID, task, c := snapshotCASServer(t, f, t.TempDir())
	mb := newMemBlob()
	s.SetBlobStore(mb)
	runID := task.Job.RunID
	body, _ := snapshotArchive(t)
	up := uploadSnapshotCAS(t, c, jobID, runnerID, task, body)
	if up.Code != http.StatusCreated {
		t.Fatalf("snapshot upload = %d: %s", up.Code, up.Body.String())
	}
	var rec struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(up.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/"+runID+"/snapshots/"+rec.ID, "token", "")
	if w.Code != http.StatusOK {
		t.Fatalf("valid snapshot download = %d: %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), body) {
		t.Fatalf("snapshot download differs: got %d bytes, want %d", w.Body.Len(), len(body))
	}
}

// failingResponseWriter always fails the body write and cannot be hijacked,
// forcing the abort to take the panic(http.ErrAbortHandler) branch.
type failingResponseWriter struct{ header http.Header }

func (w *failingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}
func (w *failingResponseWriter) WriteHeader(int) {}
func (w *failingResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("client gone")
}

// TestDownloadCopyErrorAborts proves the copy-error path is no longer
// discarded: a body write failure aborts the response (ErrAbortHandler when
// the writer cannot be hijacked) and increments the integrity metric.
func TestDownloadCopyErrorAborts(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Metrics = NewMetrics()
	payload := []byte("verified-payload")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/x", nil)

	func() {
		defer func() {
			if r := recover(); r != http.ErrAbortHandler {
				t.Fatalf("recover = %v, want http.ErrAbortHandler", r)
			}
		}()
		s.serveVerifiedDownload(&failingResponseWriter{}, req, "artifact", io.NopCloser(bytes.NewReader(payload)), int64(len(payload)), digest, nil)
	}()
	s.Metrics.mu.Lock()
	got := 0.0
	for _, v := range s.Metrics.counters[metricDownloadIntegrityFailures] {
		got += v
	}
	s.Metrics.mu.Unlock()
	if got != 1 {
		t.Fatalf("integrity failure metric = %v, want 1", got)
	}
}

// readSeekCloser adapts an in-memory byte slice to an io.ReadSeeker plus
// io.Closer, i.e. the shape of an open local file: the seekable fallback can
// hash the handle and rewind it. io.NopCloser would hide the Seeker and force
// the non-seekable refusal path.
type readSeekCloser struct{ *bytes.Reader }

func (readSeekCloser) Close() error { return nil }

func newReadSeekCloser(b []byte) readSeekCloser { return readSeekCloser{bytes.NewReader(b)} }

// TestDownloadOversizedObjectFallbackAborts covers the fallback when the
// object cannot be staged (larger than the whole budget). A SEEKABLE source
// is verified on its own handle and rewound, so a valid object streams
// byte-identically and a corrupt one is refused with 503 BEFORE any bytes are
// committed — a complete-length corrupt body can never be served. A
// NON-seekable source is refused with 503 for both valid and corrupt bytes:
// staging is unavailable and there is no handle to trust.
func TestDownloadOversizedObjectFallbackAborts(t *testing.T) {
	b, err := staging.NewBudget(t.TempDir(), 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	s, err := NewPersistent("token", "token", t.TempDir(), WithStagingBudget(b))
	if err != nil {
		t.Fatal(err)
	}
	s.Metrics = NewMetrics()
	payload := []byte("this-payload-is-larger-than-the-budget")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	req := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts/x", nil)

	// Valid seekable source: the fallback verifies the same handle, rewinds
	// it and streams byte-identically.
	rec := httptest.NewRecorder()
	s.serveVerifiedDownload(rec, req, "artifact", newReadSeekCloser(payload), int64(len(payload)), digest, nil)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), payload) {
		t.Fatalf("oversized valid download = %d, %q", rec.Code, rec.Body.String())
	}

	// Corrupt seekable source: the first verification pass fails, so nothing
	// is served (503).
	corrupt := bytes.Repeat([]byte{'Z'}, len(payload))
	rec2 := httptest.NewRecorder()
	s.serveVerifiedDownload(rec2, req, "artifact", newReadSeekCloser(corrupt), int64(len(payload)), digest, nil)
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("oversized corrupt download = %d, want 503 (no bytes served)", rec2.Code)
	}
	if bytes.Equal(rec2.Body.Bytes(), corrupt) {
		t.Fatal("oversized corrupt download served its bytes")
	}

	// Non-seekable source: even a VALID object is refused with 503 before any
	// header is committed, because there is no handle to verify AND serve.
	rec3 := httptest.NewRecorder()
	s.serveVerifiedDownload(rec3, req, "artifact", io.NopCloser(bytes.NewReader(payload)), int64(len(payload)), digest, nil)
	if rec3.Code != http.StatusServiceUnavailable {
		t.Fatalf("oversized non-seekable valid download = %d, want 503", rec3.Code)
	}
	if bytes.Contains(rec3.Body.Bytes(), payload) {
		t.Fatal("non-seekable unverified bytes were served")
	}
}

// TestCacheDownloadCopyErrorAborts pins the cache download contract: it keeps
// the runner-side hashing (no preverification staging) but the copy error is
// surfaced and a digest mismatch aborts the connection.
func TestCacheDownloadCopyErrorAborts(t *testing.T) {
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Metrics = NewMetrics()
	payload := []byte("cache-bytes")
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/j/cache/k", nil)
	func() {
		defer func() {
			if r := recover(); r != http.ErrAbortHandler {
				t.Fatalf("recover = %v, want http.ErrAbortHandler", r)
			}
		}()
		s.serveStreamCheckedWithDigest(&failingResponseWriter{}, req, "cache", digest, io.NopCloser(bytes.NewReader(payload)))
	}()
}

// TestVerifiedDownloadKeepsReservationWhileStreaming pins the staging
// invariant: the byte reservation is charged for as long as the verified
// spool is on disk, so a second download cannot over-admit the directory.
func TestVerifiedDownloadKeepsReservationWhileStreaming(t *testing.T) {
	dir := t.TempDir()
	budget, err := staging.NewBudget(dir, 150)
	if err != nil {
		t.Fatal(err)
	}
	s := New("tok", WithStagingBudget(budget))
	payload := bytes.Repeat([]byte("x"), 100)
	digest := sha256Hex(payload)

	entered := make(chan struct{})
	release := make(chan struct{})
	prev := downloadAfterPreverifyHook
	downloadAfterPreverifyHook = func() {
		close(entered)
		<-release
	}
	t.Cleanup(func() { downloadAfterPreverifyHook = prev })

	src := io.NopCloser(bytes.NewReader(payload))
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.serveVerifiedDownload(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil), "artifact", src, int64(len(payload)), digest, nil)
	}()
	<-entered
	if used := budget.Used(); used != 100 {
		t.Fatalf("reservation released too early: Used()=%d, want 100", used)
	}
	// A second download of the same size cannot fit: the first 100 bytes are
	// physically present and still charged, so Acquire waits for capacity
	// rather than admitting an over-budget reservation.
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if res, err := budget.Acquire(ctx, 100); err == nil {
		res.Release()
		t.Fatal("second acquisition admitted past the bound while the first spool is live")
	}
	close(release)
	<-done
	if used := budget.Used(); used != 0 {
		t.Fatalf("reservation leaked after the download: Used()=%d, want 0", used)
	}
}

// TestCorruptCompleteBodyNeverSucceeds pins that a backend returning the exact
// advertised length with wrong bytes cannot produce a successful complete
// response: over real HTTP/1 the client sees a 503, never a complete 200 body.
func TestCorruptCompleteBodyNeverSucceeds(t *testing.T) {
	good := []byte("the-real-archive-bytes")
	corrupt := bytes.Repeat([]byte("z"), len(good))
	digest := sha256Hex(good)
	s := New("tok") // no staging budget: the two-pass path must still fail closed
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.serveVerifiedDownload(w, r, "artifact", io.NopCloser(bytes.NewReader(corrupt)), int64(len(good)), digest, func(w http.ResponseWriter) {
			w.Header().Set("Content-Length", strconv.Itoa(len(good)))
		})
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK && len(body) == len(good) {
		t.Fatalf("corrupt complete body accepted: %d bytes with 200", len(body))
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (no bytes served)", resp.StatusCode)
	}
}

// TestVerifiedSpoolCloseKeepsChargeWhenRemovalFails is the server-level X1-B
// integration: a verified spool whose file cannot be removed (a read-only
// staging directory) must keep its bytes charged and stay registered as
// cleanup-required, and the maintenance retry must release them once the
// filesystem allows the removal. The filesystem may ignore the permission
// (root), in which case the case is skipped.
func TestVerifiedSpoolCloseKeepsChargeWhenRemovalFails(t *testing.T) {
	dir := t.TempDir()
	b, err := staging.NewBudget(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	s := New("tok", WithStagingBudget(b))
	payload := []byte("0123456789abcdef")
	sp, err := s.preverifyToSpool(context.Background(), bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod staging dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700)
		_ = b.Close()
	})
	sp.Close()
	if _, err := os.Stat(sp.path); err != nil {
		// The removal succeeded despite the permission bits (for example a
		// root-run test): there is no cleanup debt to prove.
		return
	}
	if used := b.Used(); used != int64(len(payload)) {
		t.Fatalf("failed cleanup dropped the charge: Used()=%d, want %d", used, len(payload))
	}
	if got := b.PendingCleanup(); got != 1 {
		t.Fatalf("PendingCleanup() = %d, want 1", got)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// The maintenance helper (the exact call Maintain performs each tick)
	// reclaims the debt once the filesystem allows the removal.
	s.retryStagingCleanup(context.Background())
	if used := b.Used(); used != 0 {
		t.Fatalf("Used() after retry = %d, want 0", used)
	}
	if got := b.PendingCleanup(); got != 0 {
		t.Fatalf("PendingCleanup() after retry = %d, want 0", got)
	}
}

// TestVerifiedDownloadSameHandleBeatsPathnameSwap is the X1-A regression: a
// pathname replacement between verification and serving must not change what
// the client receives. The source is opened once, the SAME handle is hashed
// and then rewound for serving, so a same-length replacement renamed over the
// verified path is invisible to the response. Real HTTP/1 proves the complete
// 200 body is the VERIFIED bytes, and the pathname really was replaced.
func TestVerifiedDownloadSameHandleBeatsPathnameSwap(t *testing.T) {
	dir := t.TempDir()
	verified := []byte("the-verified-artifact-bytes")
	digest := sha256Hex(verified)
	verifiedPath := filepath.Join(dir, "object.bin")
	if err := os.WriteFile(verifiedPath, verified, 0o600); err != nil {
		t.Fatal(err)
	}
	replacement := bytes.Repeat([]byte("R"), len(verified))
	replacementPath := filepath.Join(dir, "replacement.bin")
	if err := os.WriteFile(replacementPath, replacement, 0o600); err != nil {
		t.Fatal(err)
	}

	s := New("tok") // no staging budget: forces the same-handle verify+seek fallback
	swapped := make(chan struct{})
	prev := downloadBetweenVerifyAndServeHook
	downloadBetweenVerifyAndServeHook = func() {
		// Pathname replacement: same-length different bytes, atomically
		// renamed over the verified path between verification and serving.
		if err := os.Rename(replacementPath, verifiedPath); err != nil {
			t.Errorf("pathname swap: %v", err)
		}
		close(swapped)
	}
	t.Cleanup(func() { downloadBetweenVerifyAndServeHook = prev })

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(verifiedPath)
		if err != nil {
			http.Error(w, "missing", http.StatusNotFound)
			return
		}
		s.serveVerifiedDownload(w, r, "artifact", f, int64(len(verified)), digest, func(w http.ResponseWriter) {
			w.Header().Set("Content-Length", strconv.Itoa(len(verified)))
		})
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	select {
	case <-swapped:
	case <-time.After(5 * time.Second):
		t.Fatal("between-verify-and-serve hook was never invoked")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, body)
	}
	if !bytes.Equal(body, verified) {
		t.Fatalf("client received %q, want the verified bytes %q", body, verified)
	}
	onDisk, err := os.ReadFile(verifiedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, replacement) {
		t.Fatalf("pathname was not actually replaced: %q", onDisk)
	}
}

// TestNonSeekableNoStagingRefusedBeforeHeaders pins the second X1-A
// requirement: a non-seekable source with staging unavailable is refused with
// 503 BEFORE any header is committed, so no unverified byte can be part of a
// complete response.
func TestNonSeekableNoStagingRefusedBeforeHeaders(t *testing.T) {
	good := []byte("would-be-complete-body")
	digest := sha256Hex(good)
	s := New("tok") // no staging budget
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.serveVerifiedDownload(w, r, "artifact", io.NopCloser(bytes.NewReader(good)), int64(len(good)), digest, func(w http.ResponseWriter) {
			w.Header().Set("Content-Length", strconv.Itoa(len(good)))
		})
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (no unverified streaming)", resp.StatusCode)
	}
	if bytes.Equal(body, good) {
		t.Fatal("unverified bytes were served as a complete body")
	}
	if got := resp.Header.Get("Content-Length"); got == strconv.Itoa(len(good)) {
		t.Fatalf("refusal committed the advertised Content-Length %s", got)
	}
}
