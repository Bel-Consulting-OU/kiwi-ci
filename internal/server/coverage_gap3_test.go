package server

// Third coverage round: unit assertions for error and alternate branches that
// the existing handlers already exercise on their happy paths. Every test
// drives the real handler over the shipped fakes (fcStore/dbFakeStore,
// eventsRetentionFakeStore) and asserts status codes plus persisted state.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// gapFenceFailStore fails the SECOND AcquireDigestFence (the provenance
// envelope's fence: the payload publication took the first).
type gapFenceFailStore struct {
	*dbFakeStore
	calls int
}

func (g *gapFenceFailStore) AcquireDigestFence(ctx context.Context, digest string) (func(), error) {
	g.calls++
	if g.calls >= 2 {
		return nil, errors.New("injected digest fence failure")
	}
	return g.dbFakeStore.AcquireDigestFence(ctx, digest)
}

// gapNthPutBlob fails the SECOND Put: the payload Put succeeds, the
// provenance PutKnown fails.
type gapNthPutBlob struct {
	*memBlob
	calls int
}

func (b *gapNthPutBlob) Put(ctx context.Context, key string, r io.Reader, size int64) (blob.Object, error) {
	b.calls++
	if b.calls >= 2 {
		return blob.Object{}, errors.New("injected provenance put failure")
	}
	return b.memBlob.Put(ctx, key, r, size)
}

// gapNthGetJobStore fails the SECOND GetJob: the lease authorization read
// succeeds, the commit-time jobForLease re-read fails.
type gapNthGetJobStore struct {
	*dbFakeStore
	calls int
}

func (g *gapNthGetJobStore) GetJob(ctx context.Context, id string) (model.Job, error) {
	g.calls++
	if g.calls >= 2 {
		return model.Job{}, errors.New("injected job lookup failure")
	}
	return g.dbFakeStore.GetJob(ctx, id)
}

// gapNthLiveStore fails the SECOND LeaseLive: authorization liveness succeeds,
// the commit-time liveness re-check fails.
type gapNthLiveStore struct {
	*dbFakeStore
	calls int
}

func (g *gapNthLiveStore) LeaseLive(ctx context.Context, jobID, runnerID string, generation int64) (bool, error) {
	g.calls++
	if g.calls >= 2 {
		return false, errors.New("injected lease liveness failure")
	}
	return g.dbFakeStore.LeaseLive(ctx, jobID, runnerID, generation)
}

func gapSeedRequiredContract(t *testing.T, f *dbFakeStore) {
	t.Helper()
	c := fcBinContract()
	c.Provenance = storage.ArtifactProvenanceRequired
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": c}
	f.mu.Unlock()
}

func gapArtifactCount(f *dbFakeStore) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.artifacts)
}

func TestGapBlobUploadCASIntegrityFailsClosed(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	gapSeedRequiredContract(t, f)
	s.SetBlobStore(&fcErrBlob{memBlob: newMemBlob(), putErr: cas.ErrBackendIntegrity})
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("cas backend integrity failure = %d, want 503: %s", w.Code, w.Body.String())
	}
	if n := gapArtifactCount(f); n != 0 {
		t.Fatalf("integrity failure committed %d artifact record(s), want 0", n)
	}
}

func TestGapBlobUploadProvenanceFenceFailure(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	gapSeedRequiredContract(t, f)
	s.DB = &gapFenceFailStore{dbFakeStore: f}
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("provenance fence failure = %d, want 503: %s", w.Code, w.Body.String())
	}
	if n := gapArtifactCount(f); n != 0 {
		t.Fatalf("provenance fence failure committed %d artifact record(s), want 0", n)
	}
}

func TestGapBlobUploadProvenancePutKnownFailure(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	gapSeedRequiredContract(t, f)
	s.SetBlobStore(&gapNthPutBlob{memBlob: newMemBlob()})
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("provenance publication failure = %d, want 503: %s", w.Code, w.Body.String())
	}
	if n := gapArtifactCount(f); n != 0 {
		t.Fatalf("provenance publication failure committed %d artifact record(s), want 0", n)
	}
}

// TestGapBlobUploadUnknownLengthOverLimit drives the exact-effective-limit
// check: an unknown-length (chunked) body of effectiveLimit+1 bytes spools
// successfully (the reader is capped at limitPlusOne) and is rejected by the
// post-spool size check instead of any earlier Content-Length gate.
func TestGapBlobUploadUnknownLengthOverLimit(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	c := fcBinContract()
	c.MaxSize = 4
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": c}
	f.mu.Unlock()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", strings.NewReader("12345"))
	r.Header.Set("Authorization", "Bearer runner-tok")
	for k, v := range hdrs {
		r.Header.Set(k, v)
	}
	r.ContentLength = -1
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("unknown-length over-limit upload = %d, want 413: %s", w.Code, w.Body.String())
	}
	if n := gapArtifactCount(f); n != 0 {
		t.Fatalf("over-limit upload committed %d artifact record(s), want 0", n)
	}
}

func TestGapBlobUploadCommitJobLookupFailure(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	gapSeedRequiredContract(t, f)
	s.DB = &gapNthGetJobStore{dbFakeStore: f}
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("commit-time job lookup failure = %d, want 500: %s", w.Code, w.Body.String())
	}
	if n := gapArtifactCount(f); n != 0 {
		t.Fatalf("failed commit committed %d artifact record(s), want 0", n)
	}
}

func TestGapBlobUploadCommitLeaseLiveFailure(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	gapSeedRequiredContract(t, f)
	s.DB = &gapNthLiveStore{dbFakeStore: f}
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("commit-time liveness failure = %d, want 500: %s", w.Code, w.Body.String())
	}
	if n := gapArtifactCount(f); n != 0 {
		t.Fatalf("failed commit committed %d artifact record(s), want 0", n)
	}
}

// TestGapStreamExecutionEventsNonFlusher covers the transport guard: a
// ResponseWriter that cannot flush is refused with 500 before any frame.
func TestGapStreamExecutionEventsNonFlusher(t *testing.T) {
	s, err := NewPersistent("runner", "admin", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/events/stream?after=0", nil)
	w := &gapNoFlushWriter{}
	s.streamExecutionEvents(w, r)
	if w.code != http.StatusInternalServerError {
		t.Fatalf("non-flusher stream = %d, want 500", w.code)
	}
	if !strings.Contains(w.body.String(), "streaming unsupported") {
		t.Fatalf("non-flusher body = %q, want streaming unsupported", w.body.String())
	}
}

type gapNoFlushWriter struct {
	hdr  http.Header
	code int
	body bytes.Buffer
}

func (w *gapNoFlushWriter) Header() http.Header {
	if w.hdr == nil {
		w.hdr = http.Header{}
	}
	return w.hdr
}

func (w *gapNoFlushWriter) WriteHeader(code int) { w.code = code }

func (w *gapNoFlushWriter) Write(b []byte) (int, error) { return w.body.Write(b) }

// gapStreamReadStore lets the establishment read (called first) succeed and
// then either fails or advances the retention watermark on the live-tail
// read, exercising the in-stream error and cursor_expired frames.
type gapStreamReadStore struct {
	*eventsRetentionFakeStore
	calls    int
	readErr  error
	retained int64
}

func (g *gapStreamReadStore) ReadExecutionEventsRetention(ctx context.Context, afterSeq int64, limit int, runID string) ([]model.ExecutionEvent, int64, int64, int64, error) {
	g.calls++
	if g.calls >= 2 {
		if g.readErr != nil {
			return nil, afterSeq, 0, 0, g.readErr
		}
		return []model.ExecutionEvent{}, afterSeq, g.retained, g.retained, nil
	}
	return g.eventsRetentionFakeStore.ReadExecutionEventsRetention(ctx, afterSeq, limit, runID)
}

func TestGapStreamExecutionEventsLiveReadError(t *testing.T) {
	f := &gapStreamReadStore{eventsRetentionFakeStore: &eventsRetentionFakeStore{eventsFakeStore: &eventsFakeStore{dbFakeStore: newDBFakeStore()}}, readErr: errors.New("injected stream read failure")}
	s := New("admin-tok")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/events/stream?after=0", nil)
	w := httptest.NewRecorder()
	s.streamExecutionEvents(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("stream status = %d, want 200 (established before the error)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "event: error") || !strings.Contains(w.Body.String(), "injected stream read failure") {
		t.Fatalf("stream body = %q, want an event: error frame", w.Body.String())
	}
}

func TestGapStreamExecutionEventsLiveCursorExpired(t *testing.T) {
	f := &gapStreamReadStore{eventsRetentionFakeStore: &eventsRetentionFakeStore{eventsFakeStore: &eventsFakeStore{dbFakeStore: newDBFakeStore()}}, retained: 2}
	s := New("admin-tok")
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/events/stream?after=0", nil)
	w := httptest.NewRecorder()
	s.streamExecutionEvents(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("stream status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "event: cursor_expired") || !strings.Contains(body, `"retained_from":"2"`) {
		t.Fatalf("stream body = %q, want a cursor_expired frame with the watermark", body)
	}
}

// TestGapEnqueueIDPolicyIdentityMissing: an identity-bound submission with no
// resolvable repository identity is refused before any compile or ID mint.
func TestGapEnqueueIDPolicyIdentityMissing(t *testing.T) {
	s := New("secret")
	_, err := s.enqueueID(context.Background(), SubmitRun{identityBound: true, Ref: "main", Pipeline: testPipeline}, "")
	var adm *admissionError
	if !errors.As(err, &adm) || adm.Status != http.StatusBadRequest || adm.Reason != "repo_identity_required" {
		t.Fatalf("missing identity = %v, want repo_identity_required", err)
	}
}

// TestGapEnqueueIDIdempotencyReceiptGhost: a receipt whose run is no longer
// retained cannot replay; the key stays conflicted instead of silently
// enqueueing a duplicate.
func TestGapEnqueueIDIdempotencyReceiptGhost(t *testing.T) {
	s := New("secret")
	in := gapSubmitInput()
	in.idempotencyKey = "retry-key"
	in.idempotencyDigest = "digest-1"
	policyID := submittedPolicyRepoID(in)
	s.mu.Lock()
	s.idempotency[runIdempotencyReceiptKey(policyID, in.idempotencyKey)] = storage.IdempotencyReceipt{
		RepoID: policyID, Key: in.idempotencyKey, Digest: in.idempotencyDigest, RunID: "gone-run",
	}
	s.mu.Unlock()
	_, err := s.enqueueID(context.Background(), in, "")
	if !errors.Is(err, errIdempotencyKeyConflict) || !strings.Contains(err.Error(), "no longer retained") {
		t.Fatalf("ghost receipt = %v, want errIdempotencyKeyConflict no longer retained", err)
	}
}

// TestGapEnqueueIDScheduleClaimLost: a nominal already claimed by another run
// aborts before any mutation.
func TestGapEnqueueIDScheduleClaimLost(t *testing.T) {
	s := New("secret")
	in := gapSubmitInput()
	nominal := time.Now().UTC().Truncate(time.Minute)
	in.ScheduleClaim = &storage.ScheduleClaim{ScheduleID: "sc-1", Nominal: nominal}
	s.mu.Lock()
	s.occurrences["sc-1"] = map[int64]string{nominal.Unix(): "other-run"}
	s.mu.Unlock()
	_, err := s.enqueueID(context.Background(), in, "")
	if !errors.Is(err, storage.ErrScheduleClaimLost) {
		t.Fatalf("claimed nominal = %v, want ErrScheduleClaimLost", err)
	}
}

// TestGapEnqueueIDWebhookBodyReplay: the same authenticated body digest under
// a different delivery header returns the original run (the body-claim
// dedupe), without mutating anything.
func TestGapEnqueueIDWebhookBodyReplay(t *testing.T) {
	s := New("secret")
	in := gapSubmitInput()
	in.deliveryDigest = "body-digest"
	in.Metadata = map[string]string{"github_delivery": "delivery-2"}
	policyID := submittedPolicyRepoID(in)
	prior := model.Run{ID: "prior-run", PolicyRepoID: policyID, Status: model.StatusQueued, CreatedAt: time.Now().UTC()}
	s.mu.Lock()
	s.runs[prior.ID] = prior
	s.deliveries[webhookBodyKey("github", policyID, in.deliveryDigest)] = prior.ID
	s.mu.Unlock()
	got, err := s.enqueueID(context.Background(), in, "")
	if err != nil || got.ID != prior.ID {
		t.Fatalf("body replay = %+v, %v; want prior run", got, err)
	}
	if _, mutated := s.runs[""]; mutated {
		t.Fatal("body replay mutated run state")
	}
}

// TestGapEnqueueIDWebhookDeliveryDigestMismatch: a replayed delivery header
// with different authenticated bytes is a conflict, never a silent dedupe.
func TestGapEnqueueIDWebhookDeliveryDigestMismatch(t *testing.T) {
	s := New("secret")
	in := gapSubmitInput()
	in.deliveryDigest = "new-digest"
	in.Metadata = map[string]string{"github_delivery": "delivery-1"}
	policyID := submittedPolicyRepoID(in)
	prior := model.Run{ID: "prior-run", PolicyRepoID: policyID, Status: model.StatusQueued, CreatedAt: time.Now().UTC(),
		Metadata: map[string]string{webhookDeliveryDigestKey("github"): "old-digest"}}
	s.mu.Lock()
	s.runs[prior.ID] = prior
	s.deliveries["delivery-1"] = prior.ID
	s.mu.Unlock()
	_, err := s.enqueueID(context.Background(), in, "")
	if !errors.Is(err, errDeliveryDigestMismatch) {
		t.Fatalf("digest mismatch = %v, want errDeliveryDigestMismatch", err)
	}
}

// TestGapEnqueueDBContextCanceled: the DB enqueue refuses a canceled origin
// before issuing any store call.
func TestGapEnqueueDBContextCanceled(t *testing.T) {
	s := New("secret")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.enqueueDB(ctx, SubmitRun{}, model.Run{}, nil, nil, "", false, time.Now().UTC()); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled enqueueDB = %v, want context.Canceled", err)
	}
}

func gapSubmitInput() SubmitRun {
	return SubmitRun{
		RepoURL: "https://github.com/o/r.git", RepoFullName: "o/r",
		RepoID: "github.com/o/r", PolicyRepoID: "github.com/o/r",
		CheckoutRepoURL: "https://github.com/o/r.git",
		identityBound:   true, Ref: "main", Pipeline: testPipeline,
	}
}
