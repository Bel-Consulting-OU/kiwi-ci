package server

// Cross-feature composition: request-context cancellation at each lifecycle
// boundary the round touched.
//
// Every scenario drives the real handler with a cancellable request context
// and a deterministic seam (a blocking blob store, a gated body reader, a
// store that blocks or fails after committing) so no test sleeps to create
// the interleaving. The asserted contract is uniform: a cancelled request may
// commit nothing and acknowledge nothing, the resource it held (staging
// reservation, spool file, lease/reservation row) returns to baseline, and
// the NEXT request through the same path succeeds cleanly. The
// post-persistence report case asserts the opposite direction — durable but
// unacknowledged state — which must converge to exactly one report and one
// history fold when the runner resends.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/staging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// composeBlockingPutBlob blocks every Put until the request context ends and
// then fails with the context error: it holds a publication exactly at its
// CAS write, the boundary a cancelled request must not leave state behind.
type composeBlockingPutBlob struct {
	inner   blob.Store
	started chan struct{}
	once    sync.Once
}

func newComposeBlockingPutBlob(inner blob.Store) *composeBlockingPutBlob {
	return &composeBlockingPutBlob{inner: inner, started: make(chan struct{})}
}

func (b *composeBlockingPutBlob) Put(ctx context.Context, key string, r io.Reader, size int64) (blob.Object, error) {
	b.once.Do(func() { close(b.started) })
	<-ctx.Done()
	return blob.Object{}, ctx.Err()
}

func (b *composeBlockingPutBlob) Open(ctx context.Context, key string) (io.ReadCloser, blob.Object, error) {
	return b.inner.Open(ctx, key)
}

func (b *composeBlockingPutBlob) Delete(ctx context.Context, key string) error {
	return b.inner.Delete(ctx, key)
}

// List and Stat delegate to the wrapped store so the collector can still
// enumerate the same backend while a publication is blocked.
func (b *composeBlockingPutBlob) List(ctx context.Context, fn func(blob.Object) error) error {
	enum, ok := b.inner.(blob.Enumerator)
	if !ok {
		return fmt.Errorf("compose: inner store does not enumerate")
	}
	return enum.List(ctx, fn)
}

func (b *composeBlockingPutBlob) Stat(ctx context.Context, key string) (blob.Object, error) {
	st, ok := b.inner.(blob.Statter)
	if !ok {
		return blob.Object{}, blob.ErrNotFound
	}
	return st.Stat(ctx, key)
}

// composeBlockingReportStore is the fake durable store with two injectable
// report-delivery boundaries: a pre-persistence block that fails with the
// cancelled context (the store call never ran), and a commit-then-lose-the-ack
// mode where the report and fold are durable but the caller sees a failure,
// exactly like a response lost after commit.
type composeBlockingReportStore struct {
	*dbFakeStore
	blockBefore chan struct{}
	blockOnce   sync.Once
	loseAck     bool
}

var errComposeLostAck = errors.New("compose: response lost after commit")

func (s *composeBlockingReportStore) InsertTestReportWithHistoryDelivery(ctx context.Context, rep model.TestReport, repoID string, delivery storage.TestReportDelivery) (storage.TestReportInsertOutcome, error) {
	if s.blockBefore != nil {
		s.blockOnce.Do(func() { close(s.blockBefore) })
		<-ctx.Done()
		return storage.TestReportInsertOutcome{}, ctx.Err()
	}
	out, err := s.dbFakeStore.InsertTestReportWithHistoryDelivery(ctx, rep, repoID, delivery)
	if err != nil {
		return out, err
	}
	if s.loseAck {
		// The transaction committed; the acknowledgment never reached the
		// runner. The durable state is the source of truth.
		return out, errComposeLostAck
	}
	return out, nil
}

// composeReportPost serves one /tests upload with an explicit context.
func composeReportPost(ctx context.Context, s *Server, jobID, body string) int {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+jobID+"/tests", strings.NewReader(body)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer token")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w.Code
}

// TestComposeCancelDuringCacheCASPublication cancels the request while the CAS
// Put of a cache entry is in flight: the upload must not be acknowledged, no
// manifest may commit, the staged bytes and the staging reservation must be
// gone, and the next upload of the same key must succeed.
func TestComposeCancelDuringCacheCASPublication(t *testing.T) {
	watched := composeTmpWatcher(t)
	dir := filepath.Join(t.TempDir(), "staging")
	b, err := staging.NewBudget(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	s, f, _ := composeGCWorld(t, WithStagingBudget(b))
	hdrs := composeSeedLeasedJob(t, s, f, "job-cancel-cache", "runner-cancel-cache")

	blocking := newComposeBlockingPutBlob(s.BlobStore)
	s.SetBlobStore(blocking)
	key := fmt.Sprintf("%064x", 11)
	payload := "compose-cancelled-cache-payload"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-cancel-cache/cache/"+key, strings.NewReader(payload)).WithContext(ctx)
		r.ContentLength = int64(len(payload))
		r.Header.Set("Authorization", "Bearer token")
		for k, v := range hdrs {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		done <- w.Code
	}()
	select {
	case <-blocking.started:
	case <-time.After(10 * time.Second):
		t.Fatal("cache upload never reached CAS.Put")
	}
	cancel()
	if code := <-done; code == http.StatusCreated {
		t.Fatalf("cancelled cache publication was acknowledged with %d", code)
	}
	f.mu.Lock()
	manifests := len(f.cacheMans)
	f.mu.Unlock()
	if manifests != 0 {
		t.Fatalf("cancelled cache publication committed %d manifest(s)", manifests)
	}
	if got := b.Used(); got != 0 {
		t.Fatalf("cancelled cache publication left %d staged bytes reserved", got)
	}
	if leftovers := stageFiles(t, b.Dir()); len(leftovers) != 0 {
		t.Fatalf("cancelled cache publication left spool files: %v", leftovers)
	}

	// The next request through the same path succeeds cleanly.
	s.SetBlobStore(blocking.inner)
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-cancel-cache/cache/"+key, "token", payload, hdrs)
	if w.Code != http.StatusCreated {
		t.Fatalf("next cache upload after cancellation = %d, want 201: %s", w.Code, w.Body.String())
	}
	if got := b.Used(); got != 0 {
		t.Fatalf("staging used after the next upload = %d, want 0", got)
	}
	if entries := composeTempEntries(t, watched); len(entries) != 0 {
		t.Fatalf("cache staging fell back to the bare system temp directory: %v", entries)
	}
}

// TestComposeCancelDuringSnapshotStagingCopy cancels the request in the middle
// of the snapshot staging copy: no record may commit, the reservation and
// spool file must be released, and the next snapshot upload must succeed.
func TestComposeCancelDuringSnapshotStagingCopy(t *testing.T) {
	watched := composeTmpWatcher(t)
	archive, _ := snapshotArchive(t)
	dir := filepath.Join(t.TempDir(), "staging")
	b, err := staging.NewBudget(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	s, f, _ := composeGCWorld(t, WithStagingBudget(b))
	hdrs := composeSeedLeasedJob(t, s, f, "job-cancel-snap", "runner-cancel-snap")

	ctx, cancel := context.WithCancel(context.Background())
	reader := newGatedBodyReader(archive)
	req := composeSnapshotRequest("job-cancel-snap", reader, int64(len(archive)), hdrs).WithContext(ctx)
	done := uploadSnapshotAsync(s, req)
	<-reader.started
	if got := b.Used(); got == 0 {
		t.Fatal("snapshot staging copy held no reservation")
	}
	cancel()
	reader.releaseBody()
	w := <-done
	if w.Code == http.StatusCreated {
		t.Fatalf("cancelled snapshot staging was acknowledged with %d", w.Code)
	}
	f.mu.Lock()
	snapshots := len(f.snapshots)
	f.mu.Unlock()
	if snapshots != 0 {
		t.Fatalf("cancelled snapshot publication committed %d record(s)", snapshots)
	}
	if got := b.Used(); got != 0 {
		t.Fatalf("cancelled snapshot staging left %d reserved bytes", got)
	}
	if leftovers := stageFiles(t, b.Dir()); len(leftovers) != 0 {
		t.Fatalf("cancelled snapshot staging left spool files: %v", leftovers)
	}

	if code := composeUploadSnapshot(s, "job-cancel-snap", "token", archive, hdrs); code != http.StatusCreated {
		t.Fatalf("next snapshot upload after cancellation = %d, want 201", code)
	}
	if got := b.Used(); got != 0 {
		t.Fatalf("staging used after the next snapshot = %d, want 0", got)
	}
	if entries := composeTempEntries(t, watched); len(entries) != 0 {
		t.Fatalf("snapshot staging fell back to the bare system temp directory: %v", entries)
	}
}

// TestComposeCancelDuringArtifactCASPublication cancels an artifact upload
// while its CAS Put is in flight: no artifact record and no provenance
// statement may commit, no staged artifact file may remain, and the retry
// succeeds exactly once.
func TestComposeCancelDuringArtifactCASPublication(t *testing.T) {
	watched := composeTmpWatcher(t)
	f := newDBFakeStore()
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	runnerID, task := leaseArtifactJob(t, s, artifactsPipeline)
	blocking := newComposeBlockingPutBlob(s.BlobStore)
	s.SetBlobStore(blocking)

	artifactDir := filepath.Join(s.store.Root, "artifacts", task.Job.RunID, task.Job.ID)
	payload := "compose-cancelled-artifact-payload"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/bin", strings.NewReader(payload)).WithContext(ctx)
		r.ContentLength = int64(len(payload))
		r.Header.Set("Authorization", "Bearer token")
		for k, v := range leaseHeaders(task, runnerID) {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		done <- w.Code
	}()
	select {
	case <-blocking.started:
	case <-time.After(10 * time.Second):
		t.Fatal("artifact upload never reached CAS.Put")
	}
	cancel()
	if code := <-done; code == http.StatusCreated || code == http.StatusOK {
		t.Fatalf("cancelled artifact publication was acknowledged with %d", code)
	}
	f.mu.Lock()
	records := len(f.artifacts)
	f.mu.Unlock()
	if records != 0 {
		t.Fatalf("cancelled artifact publication committed %d record(s)", records)
	}
	if entries, err := os.ReadDir(artifactDir); err == nil {
		for _, e := range entries {
			t.Fatalf("cancelled artifact publication left staged file %s", e.Name())
		}
	}
	s.SetBlobStore(blocking.inner)
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/"+task.Job.ID+"/artifacts/bin", "token", payload, leaseHeaders(task, runnerID))
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("artifact retry after cancellation = %d, want 2xx: %s", w.Code, w.Body.String())
	}
	f.mu.Lock()
	records = len(f.artifacts)
	f.mu.Unlock()
	if records != 1 {
		t.Fatalf("artifact records after the retry = %d, want exactly 1", records)
	}
	if entries := composeTempEntries(t, watched); len(entries) != 0 {
		t.Fatalf("artifact staging fell back to the bare system temp directory: %v", entries)
	}
}

// TestComposeCancelDuringReportDeliveryBeforePersistence cancels the request
// while the durable delivery transaction is blocked: nothing may be
// acknowledged or committed, and the resend must insert exactly one report
// with one history fold.
func TestComposeCancelDuringReportDeliveryBeforePersistence(t *testing.T) {
	store := &composeBlockingReportStore{dbFakeStore: newDBFakeStore()}
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(store); err != nil {
		t.Fatal(err)
	}
	composeSeedLeasedJob(t, s, store.dbFakeStore, "job-cancel-report", "runner-cancel-report")

	body, _ := explicitDeliveryBody("job-cancel-report", "runner-cancel-report", "cache-lease-token", 5, "compose-delivery-1",
		model.TestResult{Name: "case-a", Class: "C", Duration: 1, Passed: true})
	store.blockBefore = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- composeReportPost(ctx, s, "job-cancel-report", body) }()
	select {
	case <-store.blockBefore:
	case <-time.After(10 * time.Second):
		t.Fatal("report delivery never reached the durable store")
	}
	cancel()
	if code := <-done; code == http.StatusCreated || code == http.StatusOK {
		t.Fatalf("cancelled report delivery was acknowledged with %d", code)
	}
	store.mu.Lock()
	reports := len(store.reports)
	receipts := len(store.reportDeliveries)
	folded := totalFoldedRuns(store.historyAggregates)
	store.mu.Unlock()
	if reports != 0 || receipts != 0 || folded != 0 {
		t.Fatalf("cancelled-before-persistence delivery committed reports=%d receipts=%d folded=%d", reports, receipts, folded)
	}

	// The resend (same delivery identity) succeeds exactly once.
	store.blockBefore = nil
	if code := composeReportPost(context.Background(), s, "job-cancel-report", body); code != http.StatusCreated {
		t.Fatalf("report resend after cancellation = %d, want 201", code)
	}
	store.mu.Lock()
	reports = len(store.reports)
	receipts = len(store.reportDeliveries)
	folded = totalFoldedRuns(store.historyAggregates)
	store.mu.Unlock()
	if reports != 1 || receipts != 1 || folded != 1 {
		t.Fatalf("after the resend reports=%d receipts=%d folded=%d, want 1/1/1", reports, receipts, folded)
	}
}

// TestComposeCancelAfterReportPersistenceConvergesExactlyOnce is the
// durable-but-unacknowledged boundary: the report transaction commits and the
// acknowledgment is lost. The resend of the same delivery must be an
// idempotent success (no second report, no second fold) — exactly-once
// semantics across the crash window.
func TestComposeCancelAfterReportPersistenceConvergesExactlyOnce(t *testing.T) {
	store := &composeBlockingReportStore{dbFakeStore: newDBFakeStore()}
	s, err := NewPersistent("token", "token", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SwitchToDB(store); err != nil {
		t.Fatal(err)
	}
	composeSeedLeasedJob(t, s, store.dbFakeStore, "job-ack-loss", "runner-ack-loss")

	body, _ := explicitDeliveryBody("job-ack-loss", "runner-ack-loss", "cache-lease-token", 5, "compose-delivery-2",
		model.TestResult{Name: "case-a", Class: "C", Duration: 2, Passed: false})

	store.loseAck = true
	if code := composeReportPost(context.Background(), s, "job-ack-loss", body); code == http.StatusCreated || code == http.StatusOK {
		t.Fatalf("delivery whose ack was lost was acknowledged with %d", code)
	}
	store.loseAck = false
	store.mu.Lock()
	reports := len(store.reports)
	receipts := len(store.reportDeliveries)
	folded := totalFoldedRuns(store.historyAggregates)
	version := store.historyVersions[storage.RepoIDForRun(store.runs["run-c"])]
	store.mu.Unlock()
	if reports != 1 || receipts != 1 || folded != 1 {
		t.Fatalf("lost-ack delivery left reports=%d receipts=%d folded=%d, want 1/1/1", reports, receipts, folded)
	}

	// The runner resends the same delivery after the ack was lost.
	if code := composeReportPost(context.Background(), s, "job-ack-loss", body); code != http.StatusOK {
		t.Fatalf("replay of a committed delivery = %d, want idempotent 200", code)
	}
	store.mu.Lock()
	reports2 := len(store.reports)
	receipts2 := len(store.reportDeliveries)
	folded2 := totalFoldedRuns(store.historyAggregates)
	version2 := store.historyVersions[storage.RepoIDForRun(store.runs["run-c"])]
	store.mu.Unlock()
	if reports2 != 1 || receipts2 != 1 || folded2 != 1 {
		t.Fatalf("replay changed durable state: reports=%d receipts=%d folded=%d", reports2, receipts2, folded2)
	}
	if version2 != version {
		t.Fatalf("replay bumped the history version %d -> %d", version, version2)
	}
}

// totalFoldedRuns sums the folded run counters across a fake store's history
// aggregates.
func totalFoldedRuns(aggs map[string]map[string]storage.TestHistoryAggregate) int {
	total := int64(0)
	for _, rows := range aggs {
		for _, row := range rows {
			total += row.Runs
		}
	}
	return int(total)
}

// TestComposeCancelLeavesDigestAbsentAndBudgetBaseline composes the cancelled
// publication with the CAS GC: the cancelled cache entry never becomes a
// reference, so the digest the request would have published is either absent
// (the blocking backend stored nothing) and the full invariant walk is clean.
func TestComposeCancelLeavesDigestAbsentAndBudgetBaseline(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "staging")
	b, err := staging.NewBudget(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	s, f, _ := composeGCWorld(t, WithStagingBudget(b))
	hdrs := composeSeedLeasedJob(t, s, f, "job-cancel-gc", "runner-cancel-gc")

	blocking := newComposeBlockingPutBlob(s.BlobStore)
	s.SetBlobStore(blocking)
	payload := "compose-cancel-gc-payload"
	sum := sha256.Sum256([]byte(payload))
	digest := hex.EncodeToString(sum[:])
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-cancel-gc/cache/"+fmt.Sprintf("%064x", 12), strings.NewReader(payload)).WithContext(ctx)
		r.ContentLength = int64(len(payload))
		r.Header.Set("Authorization", "Bearer token")
		for k, v := range hdrs {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		done <- w.Code
	}()
	<-blocking.started
	cancel()
	<-done

	if _, _, err := s.CAS.Open(context.Background(), digest); err == nil {
		t.Fatal("cancelled publication stored an object")
	}
	if dangling := composeDanglingReferences(t, s, f); len(dangling) != 0 {
		t.Fatalf("cancelled publication left dangling references: %v", dangling)
	}
	if got := b.Used(); got != 0 {
		t.Fatalf("cancelled publication left staging reserved: %d", got)
	}
	// A GC pass over the whole store is a no-op on the cancelled digest:
	// there is nothing to reclaim, and no reference claims it.
	stats, err := s.runCASGC(context.Background(), casGCOptions{MinAge: time.Nanosecond, Batch: 1000})
	if err != nil {
		t.Fatalf("runCASGC: %v", err)
	}
	if stats.Deleted != 0 {
		t.Fatalf("GC deleted %d objects after a cancelled publication, want 0", stats.Deleted)
	}
}
