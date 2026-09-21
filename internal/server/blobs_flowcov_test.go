package server

import (
	"context"
	"errors"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// fcErrBlob is an observable in-memory blob.Store with injectable failures.
type fcErrBlob struct {
	*memBlob
	putErr  error
	openErr error
}

func (b *fcErrBlob) Put(ctx context.Context, key string, r io.Reader, size int64) (blob.Object, error) {
	if b.putErr != nil {
		return blob.Object{}, b.putErr
	}
	return b.memBlob.Put(ctx, key, r, size)
}

func (b *fcErrBlob) Open(ctx context.Context, key string) (io.ReadCloser, blob.Object, error) {
	if b.openErr != nil {
		return nil, blob.Object{}, b.openErr
	}
	return b.memBlob.Open(ctx, key)
}

// fcStore wraps dbFakeStore with per-method fault injection.
type fcStore struct {
	*dbFakeStore
	getContractsErr    error
	insertContractsErr error
	listArtifactsErr   error
	listJobsErr        error
	getRunErr          error
	getRunErrFor       map[string]error
	consumeSidecarErr  error
	getCacheManErr     error
	listSnapshotsErr   error
	fragmentGetErr     error
	fragmentGetMiss    bool

	getJobErr               error
	listDeploymentsErr      error
	getDownstreamLinkErr    error
	insertDownstreamLinkErr error
	reserveDownstreamErr    error
	releaseDownstreamErr    error
	appendDownstreamErr     error
	reopenRunErr            error
	updateRunStatusErr      error
	expireReservationsErr   error
	listQueuedErr           error
	listJobsByEnvErr        error
	setQueueReasonsErr      error
	listRunsErr             error
	listSchedulesErr        error
	upsertScheduleErr       error
	listReportsAllErr       error
	insertReportErr         error
	listReportsErr          error
	loadHistoryErr          error
	insertReportHistErr     error
	loadRepoHistoryErr      error
	resolveRepoIDsErr       error
	reportTotalsErr         error
	flakyNamesErr           error
	listHistoryRepoIDsErr   error
	rebuildRepoHistoryErr   error
	readLogsErr             error
	appendAuditErr          error
	queuedOverride          []model.Job
	pendingSidecarReadErr   error
}

func (f *fcStore) ListRuns(ctx context.Context, limit int) ([]model.Run, error) {
	if f.listRunsErr != nil {
		return nil, f.listRunsErr
	}
	return f.dbFakeStore.ListRuns(ctx, limit)
}

func (f *fcStore) AppendAudit(ctx context.Context, e model.AuditEvent) error {
	if f.appendAuditErr != nil {
		return f.appendAuditErr
	}
	return f.dbFakeStore.AppendAudit(ctx, e)
}

func (f *fcStore) ReadLogs(ctx context.Context, runID string, after int64, limit int) ([]model.LogEntry, error) {
	if f.readLogsErr != nil {
		return nil, f.readLogsErr
	}
	return f.dbFakeStore.ReadLogs(ctx, runID, after, limit)
}

func (f *fcStore) ListTestReportsAll(ctx context.Context) ([]model.TestReport, error) {
	if f.listReportsAllErr != nil {
		return nil, f.listReportsAllErr
	}
	return f.dbFakeStore.ListTestReportsAll(ctx)
}

func (f *fcStore) ListTestReports(ctx context.Context, runID string) ([]model.TestReport, error) {
	if f.listReportsErr != nil {
		return nil, f.listReportsErr
	}
	return f.dbFakeStore.ListTestReports(ctx, runID)
}

func (f *fcStore) InsertTestReport(ctx context.Context, rep model.TestReport) error {
	if f.insertReportErr != nil {
		return f.insertReportErr
	}
	return f.dbFakeStore.InsertTestReport(ctx, rep)
}

func (f *fcStore) LoadTestHistory(ctx context.Context) (int64, []byte, error) {
	if f.loadHistoryErr != nil {
		return 0, nil, f.loadHistoryErr
	}
	return f.dbFakeStore.LoadTestHistory(ctx)
}

func (f *fcStore) InsertTestReportWithHistory(ctx context.Context, rep model.TestReport, repoID string) (int64, error) {
	if f.insertReportHistErr != nil {
		return 0, f.insertReportHistErr
	}
	return f.dbFakeStore.InsertTestReportWithHistory(ctx, rep, repoID)
}

func (f *fcStore) LoadRepoTestHistory(ctx context.Context, repoID string) (int64, []byte, error) {
	if f.loadRepoHistoryErr != nil {
		return 0, nil, f.loadRepoHistoryErr
	}
	return f.dbFakeStore.LoadRepoTestHistory(ctx, repoID)
}

func (f *fcStore) ResolveTestHistoryRepoIDs(ctx context.Context, query string, limit int) ([]string, error) {
	if f.resolveRepoIDsErr != nil {
		return nil, f.resolveRepoIDsErr
	}
	return f.dbFakeStore.ResolveTestHistoryRepoIDs(ctx, query, limit)
}

func (f *fcStore) TestReportTotals(ctx context.Context, repoIDs []string, repoQuery string) (int, int, int, error) {
	if f.reportTotalsErr != nil {
		return 0, 0, 0, f.reportTotalsErr
	}
	return f.dbFakeStore.TestReportTotals(ctx, repoIDs, repoQuery)
}

func (f *fcStore) FlakyTestNames(ctx context.Context, repoIDs []string, limit int) ([]string, error) {
	if f.flakyNamesErr != nil {
		return nil, f.flakyNamesErr
	}
	return f.dbFakeStore.FlakyTestNames(ctx, repoIDs, limit)
}

func (f *fcStore) ListTestHistoryRepoIDs(ctx context.Context, limit int) ([]string, error) {
	if f.listHistoryRepoIDsErr != nil {
		return nil, f.listHistoryRepoIDsErr
	}
	return f.dbFakeStore.ListTestHistoryRepoIDs(ctx, limit)
}

func (f *fcStore) RebuildRepoTestHistory(ctx context.Context, repoID string) (int64, error) {
	if f.rebuildRepoHistoryErr != nil {
		return 0, f.rebuildRepoHistoryErr
	}
	return f.dbFakeStore.RebuildRepoTestHistory(ctx, repoID)
}

func (f *fcStore) ListSchedules(ctx context.Context) ([]storage.Schedule, error) {
	if f.listSchedulesErr != nil {
		return nil, f.listSchedulesErr
	}
	return f.dbFakeStore.ListSchedules(ctx)
}

func (f *fcStore) UpsertSchedule(ctx context.Context, sc storage.Schedule) error {
	if f.upsertScheduleErr != nil {
		return f.upsertScheduleErr
	}
	return f.dbFakeStore.UpsertSchedule(ctx, sc)
}

func (f *fcStore) GetJob(ctx context.Context, id string) (model.Job, error) {
	if f.getJobErr != nil {
		return model.Job{}, f.getJobErr
	}
	return f.dbFakeStore.GetJob(ctx, id)
}

func (f *fcStore) ListDeploymentsByRun(ctx context.Context, runID string) ([]model.Deployment, error) {
	if f.listDeploymentsErr != nil {
		return nil, f.listDeploymentsErr
	}
	return f.dbFakeStore.ListDeploymentsByRun(ctx, runID)
}

func (f *fcStore) GetDownstreamLink(ctx context.Context, parentJobID, targetRepo, targetRef string) (storage.DownstreamLink, bool, error) {
	if f.getDownstreamLinkErr != nil {
		return storage.DownstreamLink{}, false, f.getDownstreamLinkErr
	}
	return f.dbFakeStore.GetDownstreamLink(ctx, parentJobID, targetRepo, targetRef)
}

func (f *fcStore) InsertDownstreamLink(ctx context.Context, l storage.DownstreamLink) error {
	if f.insertDownstreamLinkErr != nil {
		return f.insertDownstreamLinkErr
	}
	return f.dbFakeStore.InsertDownstreamLink(ctx, l)
}

func (f *fcStore) ReserveDownstreamLaunch(ctx context.Context, parentJobID, targetRepo, targetRef, launchToken string) (bool, error) {
	if f.reserveDownstreamErr != nil {
		return false, f.reserveDownstreamErr
	}
	return f.dbFakeStore.ReserveDownstreamLaunch(ctx, parentJobID, targetRepo, targetRef, launchToken)
}

func (f *fcStore) ReleaseDownstreamReservation(ctx context.Context, parentJobID, targetRepo, targetRef string) error {
	if f.releaseDownstreamErr != nil {
		return f.releaseDownstreamErr
	}
	return f.dbFakeStore.ReleaseDownstreamReservation(ctx, parentJobID, targetRepo, targetRef)
}

func (f *fcStore) ExpireDownstreamReservations(ctx context.Context, olderThan time.Time) (int, error) {
	if f.expireReservationsErr != nil {
		return 0, f.expireReservationsErr
	}
	return f.dbFakeStore.ExpireDownstreamReservations(ctx, olderThan)
}

func (f *fcStore) AppendDownstreamRun(ctx context.Context, runID, childRunID string) error {
	if f.appendDownstreamErr != nil {
		return f.appendDownstreamErr
	}
	return f.dbFakeStore.AppendDownstreamRun(ctx, runID, childRunID)
}

// The leader-fenced variants delegate to the fake's unfenced implementations:
// the double models a store without a leadership epoch (fs-mode semantics),
// so there is nothing to fence.
func (f *fcStore) ReserveDownstreamLaunchLeader(ctx context.Context, parentJobID, targetRepo, targetRef, launchToken string) (bool, error) {
	return f.ReserveDownstreamLaunch(ctx, parentJobID, targetRepo, targetRef, launchToken)
}

func (f *fcStore) ReleaseDownstreamReservationLeader(ctx context.Context, parentJobID, targetRepo, targetRef string) error {
	return f.ReleaseDownstreamReservation(ctx, parentJobID, targetRepo, targetRef)
}

func (f *fcStore) AppendDownstreamRunLeader(ctx context.Context, runID, childRunID string) error {
	return f.AppendDownstreamRun(ctx, runID, childRunID)
}

func (f *fcStore) ReopenRunForChildren(ctx context.Context, runID string) error {
	if f.reopenRunErr != nil {
		return f.reopenRunErr
	}
	return f.dbFakeStore.ReopenRunForChildren(ctx, runID)
}

func (f *fcStore) UpdateRunStatus(ctx context.Context, id string, status model.Status, startedAt, finishedAt *time.Time) error {
	if f.updateRunStatusErr != nil {
		return f.updateRunStatusErr
	}
	return f.dbFakeStore.UpdateRunStatus(ctx, id, status, startedAt, finishedAt)
}

func (f *fcStore) ListQueuedJobs(ctx context.Context) ([]model.Job, error) {
	if f.listQueuedErr != nil {
		return nil, f.listQueuedErr
	}
	if f.queuedOverride != nil {
		return append([]model.Job(nil), f.queuedOverride...), nil
	}
	return f.dbFakeStore.ListQueuedJobs(ctx)
}

func (f *fcStore) ListJobsByEnvironment(ctx context.Context, repoID, environment string) ([]model.Job, error) {
	if f.listJobsByEnvErr != nil {
		return nil, f.listJobsByEnvErr
	}
	if f.queuedOverride != nil {
		out := []model.Job{}
		for _, j := range f.queuedOverride {
			if storage.RepoIDForJob(j) == repoID && j.Environment == environment {
				out = append(out, j)
			}
		}
		return out, nil
	}
	return f.dbFakeStore.ListJobsByEnvironment(ctx, repoID, environment)
}

func (f *fcStore) SetQueueReasons(ctx context.Context, reasons map[string]string) error {
	if f.setQueueReasonsErr != nil {
		return f.setQueueReasonsErr
	}
	return f.dbFakeStore.SetQueueReasons(ctx, reasons)
}

func (f *fcStore) PendingSidecar(ctx context.Context, jobID, artifactName, kind string) (string, bool, error) {
	if f.pendingSidecarReadErr != nil {
		return "", false, f.pendingSidecarReadErr
	}
	return f.dbFakeStore.PendingSidecar(ctx, jobID, artifactName, kind)
}

func (f *fcStore) GetGeneratedFragment(ctx context.Context, parentJobID string, generation int64, fragmentID string) (storage.GeneratedFragmentReceipt, bool, error) {
	if f.fragmentGetErr != nil {
		return storage.GeneratedFragmentReceipt{}, false, f.fragmentGetErr
	}
	if f.fragmentGetMiss {
		return storage.GeneratedFragmentReceipt{}, false, nil
	}
	return f.dbFakeStore.GetGeneratedFragment(ctx, parentJobID, generation, fragmentID)
}

func (f *fcStore) ListSnapshotsByRun(ctx context.Context, runID string) ([]model.SnapshotRecord, error) {
	if f.listSnapshotsErr != nil {
		return nil, f.listSnapshotsErr
	}
	return f.dbFakeStore.ListSnapshotsByRun(ctx, runID)
}

func (f *fcStore) GetJobContracts(ctx context.Context, jobID string) (map[string]storage.ArtifactContract, bool, error) {
	if f.getContractsErr != nil {
		return nil, false, f.getContractsErr
	}
	return f.dbFakeStore.GetJobContracts(ctx, jobID)
}

func (f *fcStore) InsertJobContracts(ctx context.Context, jobID string, contracts map[string]storage.ArtifactContract) error {
	if f.insertContractsErr != nil {
		return f.insertContractsErr
	}
	return f.dbFakeStore.InsertJobContracts(ctx, jobID, contracts)
}

func (f *fcStore) ListArtifacts(ctx context.Context, runID string) ([]model.ArtifactRecord, error) {
	if f.listArtifactsErr != nil {
		return nil, f.listArtifactsErr
	}
	return f.dbFakeStore.ListArtifacts(ctx, runID)
}

func (f *fcStore) ListJobsByRun(ctx context.Context, runID string) ([]model.Job, error) {
	if f.listJobsErr != nil {
		return nil, f.listJobsErr
	}
	return f.dbFakeStore.ListJobsByRun(ctx, runID)
}

func (f *fcStore) GetRun(ctx context.Context, id string) (model.Run, error) {
	if f.getRunErr != nil {
		return model.Run{}, f.getRunErr
	}
	if err, ok := f.getRunErrFor[id]; ok && err != nil {
		return model.Run{}, err
	}
	return f.dbFakeStore.GetRun(ctx, id)
}

func (f *fcStore) ConsumePendingSidecar(ctx context.Context, jobID, artifactName, kind, digest string) error {
	if f.consumeSidecarErr != nil {
		return f.consumeSidecarErr
	}
	return f.dbFakeStore.ConsumePendingSidecar(ctx, jobID, artifactName, kind, digest)
}

func (f *fcStore) DeletePendingSidecars(ctx context.Context, jobID string) error {
	if f.consumeSidecarErr != nil {
		return f.consumeSidecarErr
	}
	return f.dbFakeStore.DeletePendingSidecars(ctx, jobID)
}

func (f *fcStore) GetCacheManifest(ctx context.Context, repo, trustDomain, logicalKey string) (storage.CacheManifestRecord, bool, error) {
	if f.getCacheManErr != nil {
		return storage.CacheManifestRecord{}, false, f.getCacheManErr
	}
	return f.dbFakeStore.GetCacheManifest(ctx, repo, trustDomain, logicalKey)
}

// fcPlainStore exposes only the base storage.Store surface of dbFakeStore,
// hiding every extension interface (idempotent insert, contract store,
// cache manifest store, ...).
type fcPlainStore struct{ storage.Store }

// fcNoIdemIface is the exact method surface of a store that supports
// contracts and sidecars but NOT the idempotent artifact insert.
type fcNoIdemIface interface {
	storage.Store
	storage.ArtifactContractStore
	storage.ArtifactSidecarStore
}

// fcNoIdemStore hides InsertArtifactOnce while keeping the sidecar and
// contract extensions visible.
type fcNoIdemStore struct{ fcNoIdemIface }

// fcExpireStore flips a job's lease into the past on the Nth GetJob.
type fcExpireStore struct {
	*fcStore
	calls      int
	expireFrom int
}

func (f *fcExpireStore) GetJob(ctx context.Context, id string) (model.Job, error) {
	f.mu.Lock()
	f.calls++
	n := f.calls
	j, ok := f.jobs[id]
	if ok && n >= f.expireFrom {
		past := time.Now().UTC().Add(-time.Hour)
		j.LeaseExpiresAt = &past
		f.jobs[id] = j
	}
	f.mu.Unlock()
	if !ok {
		return model.Job{}, storage.ErrNotFound
	}
	return j, nil
}

// fcHookReader invokes hook once before yielding its payload.
type fcHookReader struct {
	data []byte
	hook func()
	done bool
	off  int
}

func (r *fcHookReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		if r.hook != nil {
			r.hook()
		}
	}
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

// fcErrReader yields a few bytes and then fails.
type fcErrReader struct{ served bool }

func (r *fcErrReader) Read(p []byte) (int, error) {
	if r.served {
		return 0, errors.New("injected body read failure")
	}
	r.served = true
	n := copy(p, "abc")
	return n, nil
}

// fcFailWriter fails Write after limit bytes.
type fcFailWriter struct {
	hdr   http.Header
	code  int
	limit int
	n     int
}

func (w *fcFailWriter) Header() http.Header {
	if w.hdr == nil {
		w.hdr = http.Header{}
	}
	return w.hdr
}
func (w *fcFailWriter) WriteHeader(code int) { w.code = code }
func (w *fcFailWriter) Write(b []byte) (int, error) {
	if w.n >= w.limit {
		return 0, errors.New("injected write failure")
	}
	w.n += len(b)
	return len(b), nil
}

func fcBinContract() storage.ArtifactContract {
	return storage.ArtifactContract{Name: "bin", Paths: []string{"out/"}, Retention: time.Hour}
}

func fcSeedContract(s *Server, jobID string, c storage.ArtifactContract) {
	s.mu.Lock()
	if s.contracts == nil {
		s.contracts = map[string]map[string]storage.ArtifactContract{}
	}
	s.contracts[jobID] = map[string]storage.ArtifactContract{c.Name: c}
	s.mu.Unlock()
}

func fcMemoryBlobServer(t *testing.T) (*Server, map[string]string) {
	t.Helper()
	s, err := NewPersistent("runner-tok", "admin-tok", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	hdrs := seedCacheJob(t, s, "job-a", "runner-a", "https://github.com/o/repo-a.git", "o/repo-a", true)
	return s, hdrs
}

func fcUploadBlobArtifact(t *testing.T, s *Server, hdrs map[string]string, body string) *httptest.ResponseRecorder {
	t.Helper()
	return doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", "runner-tok", body, hdrs)
}

func TestFlowBlobUploadArtifactRequiresStore(t *testing.T) {
	s := New("tok")
	r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/j/artifacts/bin", strings.NewReader("x"))
	r.SetPathValue("id", "j")
	r.SetPathValue("name", "bin")
	w := httptest.NewRecorder()
	s.uploadArtifact(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no-store upload = %d, want 503", w.Code)
	}
}

func TestFlowBlobUploadArtifactInvalidName(t *testing.T) {
	s, _ := fcMemoryBlobServer(t)
	r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-a/artifacts/x", strings.NewReader("x"))
	r.SetPathValue("id", "job-a")
	r.SetPathValue("name", "   ")
	w := httptest.NewRecorder()
	s.uploadArtifact(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty name upload = %d, want 400", w.Code)
	}
}

func TestFlowBlobUploadArtifactContractLookupError(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": fcBinContract()}
	f.mu.Unlock()
	s.DB = &fcStore{dbFakeStore: f, getContractsErr: errors.New("contract store down")}
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("contract lookup error = %d, want 500: %s", w.Code, w.Body.String())
	}
}

func TestFlowBlobUploadArtifactMkdirFailure(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	fcSeedContract(s, "job-a", fcBinContract())
	if err := os.WriteFile(filepath.Join(s.store.Root, "artifacts"), []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("mkdir failure = %d, want 500: %s", w.Code, w.Body.String())
	}
}

// seamFixedReader is an endless deterministic entropy source for newID:
// every Read yields zeros, so every identifier minted while it is installed
// is the same all-zero hex id and a test can derive the exact staging path a
// handler will use.
type seamFixedReader struct{}

func (seamFixedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// TestFlowBlobUploadArtifactStagingOpenFailure covers the staging open
// failing after the directory has been created: the fixed entropy makes the
// exact staging filename known and a directory placed there refuses the
// O_CREATE|O_EXCL open with EEXIST for any euid (path existence, not
// permission bits), so the assertion stays active as root.
func TestFlowBlobUploadArtifactStagingOpenFailure(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	fcSeedContract(s, "job-a", fcBinContract())
	restore := seamRand(t, seamFixedReader{})
	defer restore()
	id, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(s.store.Root, "artifacts", "run-c", "job-a")
	if err := os.MkdirAll(filepath.Join(dir, "."+id+".tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("staging open failure = %d, want 500: %s", w.Code, w.Body.String())
	}
}

func TestFlowBlobUploadArtifactBodyCopyFailure(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	fcSeedContract(s, "job-a", fcBinContract())
	r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", &fcErrReader{})
	r.Header.Set("Authorization", "Bearer runner-tok")
	for k, v := range hdrs {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("body copy failure = %d, want 500: %s", w.Code, w.Body.String())
	}
}

func TestFlowBlobUploadArtifactMaxSize(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	c := fcBinContract()
	c.MaxSize = 4
	fcSeedContract(s, "job-a", c)
	w := fcUploadBlobArtifact(t, s, hdrs, "0123456789")
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("max size violation = %d, want 413: %s", w.Code, w.Body.String())
	}
	dir := filepath.Join(s.store.Root, "artifacts", "run-c", "job-a")
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("staging file left behind after size rejection: %v", entries)
	}
}

func TestFlowBlobUploadArtifactListLookupError(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": fcBinContract()}
	f.mu.Unlock()
	s.DB = &fcStore{dbFakeStore: f, listArtifactsErr: errors.New("artifact table down")}
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("artifact lookup error = %d, want 500: %s", w.Code, w.Body.String())
	}
}

func TestFlowBlobUploadArtifactCASPutFailure(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": fcBinContract()}
	f.mu.Unlock()
	s.SetBlobStore(&fcErrBlob{memBlob: newMemBlob(), putErr: errors.New("cas put down")})
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("cas put error = %d, want 500: %s", w.Code, w.Body.String())
	}
}

func TestFlowBlobUploadArtifactLeaseExpiresDuringDBCommit(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": fcBinContract()}
	f.mu.Unlock()
	s.DB = &fcExpireStore{fcStore: &fcStore{dbFakeStore: f}, expireFrom: 2}
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusConflict {
		t.Fatalf("lease expiry at commit = %d, want 409: %s", w.Code, w.Body.String())
	}
}

func TestFlowBlobUploadArtifactLeaseExpiresDuringMemoryCommit(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	fcSeedContract(s, "job-a", fcBinContract())
	reader := &fcHookReader{data: []byte("payload"), hook: func() {
		s.mu.Lock()
		j := s.jobs["job-a"]
		past := time.Now().UTC().Add(-time.Hour)
		j.LeaseExpiresAt = &past
		s.jobs["job-a"] = j
		s.mu.Unlock()
	}}
	r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", reader)
	r.Header.Set("Authorization", "Bearer runner-tok")
	for k, v := range hdrs {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("memory lease expiry at commit = %d, want 409: %s", w.Code, w.Body.String())
	}
}

func TestFlowBlobUploadArtifactRenameFailure(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	fcSeedContract(s, "job-a", fcBinContract())
	dir := filepath.Join(s.store.Root, "artifacts", "run-c", "job-a")
	reader := &fcHookReader{data: []byte("payload"), hook: func() {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
		_ = os.Remove(dir)
		_ = os.WriteFile(dir, []byte("not a dir"), 0o600)
	}}
	r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", reader)
	r.Header.Set("Authorization", "Bearer runner-tok")
	for k, v := range hdrs {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("rename failure = %d, want 500: %s", w.Code, w.Body.String())
	}
}

func TestFlowBlobUploadArtifactCASTempOpenFailure(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": fcBinContract()}
	f.mu.Unlock()
	dir := filepath.Join(s.store.Root, "artifacts", "run-c", "job-a")
	reader := &fcHookReader{data: []byte("payload"), hook: func() {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}}
	r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/job-a/artifacts/bin", reader)
	r.Header.Set("Authorization", "Bearer runner-tok")
	for k, v := range hdrs {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("cas staging open failure = %d, want 500: %s", w.Code, w.Body.String())
	}
}

func TestFlowBlobUploadArtifactNonCASLeaseExpiryRemovesFile(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": fcBinContract()}
	f.mu.Unlock()
	s.CAS = nil
	s.DB = &fcExpireStore{fcStore: &fcStore{dbFakeStore: f}, expireFrom: 2}
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusConflict {
		t.Fatalf("non-cas lease expiry = %d, want 409: %s", w.Code, w.Body.String())
	}
	dir := filepath.Join(s.store.Root, "artifacts", "run-c", "job-a")
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("non-cas expired upload left staged bytes: %v", entries)
	}
}

func fcScopedAuthServer(t *testing.T, s *Server) {
	t.Helper()
	if err := s.AuthStore.AddToken("viewer", auth.Principal{
		Subject: "viewer",
		Roles:   []auth.Role{auth.RoleRead},
		Repositories: map[string]auth.RepositoryPermission{
			"github.com/o/repo-a": {Read: true},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

// fcOutsiderPrincipal may read repo-b only.
func fcOutsiderPrincipal() auth.Principal {
	return auth.Principal{
		Subject: "outsider",
		Roles:   []auth.Role{auth.RoleRead},
		Repositories: map[string]auth.RepositoryPermission{
			"github.com/o/repo-b": {Read: true},
		},
	}
}

func TestFlowBlobListArtifactsDBScopedDenial(t *testing.T) {
	s, _, _, _ := cacheFixture(t)
	fcScopedAuthServer(t, s)
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/artifacts", "viewer", ""); w.Code != http.StatusForbidden {
		t.Fatalf("scoped artifact list = %d, want 403", w.Code)
	}
}

func TestFlowBlobListArtifactsDBSuccess(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": fcBinContract()}
	f.mu.Unlock()
	if w := fcUploadBlobArtifact(t, s, hdrs, "payload"); w.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", w.Code, w.Body.String())
	}
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/artifacts", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("db artifact list = %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "bin") {
		t.Fatalf("db artifact list missing record: %s", w.Body.String())
	}
}

func TestFlowBlobListArtifactsDBRunNotFound(t *testing.T) {
	s, _, _, _ := cacheFixture(t)
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/missing/artifacts", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("missing db run artifact list = %d, want 404", w.Code)
	}
}

func TestFlowBlobDownloadProvenanceScopedDenial(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	fcScopedAuthServer(t, s)
	f.mu.Lock()
	f.artifacts = append(f.artifacts, model.ArtifactRecord{ID: "art-prov", RunID: "run-c", JobID: "job-a", Name: "bin", ProvenanceSHA256: "abc", ProvenancePath: "cas:abc"})
	f.mu.Unlock()
	if w := doJSON(t, s, http.MethodGet, "/api/v1/artifacts/art-prov/provenance", "viewer", ""); w.Code != http.StatusForbidden {
		t.Fatalf("scoped provenance read = %d, want 403", w.Code)
	}
}

func TestFlowBlobUploadArtifactSidecarLookupFailure(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": fcBinContract()}
	f.pendingErr = errors.New("pending sidecar table down")
	f.mu.Unlock()
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("sidecar lookup failure = %d, want 500: %s", w.Code, w.Body.String())
	}
}

func TestFlowBlobUploadArtifactDBInsertFailure(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": fcBinContract()}
	f.artifactInsertErr = errors.New("insert blown")
	f.mu.Unlock()
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("artifact insert failure = %d, want 500: %s", w.Code, w.Body.String())
	}
}

func TestFlowBlobUploadArtifactDBDigestConflict(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": fcBinContract()}
	// Same (job, generation, name) key exists but under another run, so the
	// pre-flight lookup misses it while the authoritative insert conflicts.
	f.artifacts = append(f.artifacts, model.ArtifactRecord{ID: "other", RunID: "other-run", JobID: "job-a", Name: "bin", LeaseGeneration: 5, SHA256: strings.Repeat("d", 64)})
	f.mu.Unlock()
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusConflict {
		t.Fatalf("db digest conflict = %d, want 409: %s", w.Code, w.Body.String())
	}
}

func TestFlowBlobUploadArtifactDBIdempotentRaceWinner(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	digest := sha256Hex([]byte("payload"))
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": fcBinContract()}
	f.artifacts = append(f.artifacts, model.ArtifactRecord{ID: "other", RunID: "other-run", JobID: "job-a", Name: "bin", LeaseGeneration: 5, SHA256: digest, Path: "cas:" + digest})
	f.mu.Unlock()
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusOK {
		t.Fatalf("db idempotent race winner = %d, want 200: %s", w.Code, w.Body.String())
	}
	var rec model.ArtifactRecord
	if err := jsonUnmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.ID != "other" {
		t.Fatalf("winner record id = %q, want other", rec.ID)
	}
}

func TestFlowBlobUploadArtifactNoIdempotentStore(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	f.mu.Lock()
	j := f.jobs["job-a"]
	j.Pipeline = "jobs:\n  build:\n    artifacts:\n      - name: bin\n        paths:\n          - out/\n"
	f.jobs["job-a"] = j
	f.mu.Unlock()
	var iface fcNoIdemIface = f
	s.DB = fcNoIdemStore{iface}
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("no idempotent store = %d, want 500: %s", w.Code, w.Body.String())
	}
}

func TestFlowBlobUploadArtifactConsumeCleanupFailure(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	f.mu.Lock()
	f.contracts["job-a"] = map[string]storage.ArtifactContract{"bin": fcBinContract()}
	f.mu.Unlock()
	s.DB = &fcStore{dbFakeStore: f, consumeSidecarErr: errors.New("cleanup down")}
	w := fcUploadBlobArtifact(t, s, hdrs, "payload")
	if w.Code != http.StatusCreated {
		t.Fatalf("cleanup failure must not fail the upload: %d %s", w.Code, w.Body.String())
	}
}

func TestFlowBlobInsertArtifactMemoryLocked(t *testing.T) {
	s := New("tok")
	first := model.ArtifactRecord{ID: "1", JobID: "job", LeaseGeneration: 1, Name: "bin", SHA256: "aaa"}
	stored, created, err := s.insertArtifactMemoryLocked(first)
	if err != nil || !created || stored.ID != "1" {
		t.Fatalf("fresh insert = %+v created=%v err=%v", stored, created, err)
	}
	same := model.ArtifactRecord{ID: "2", JobID: "job", LeaseGeneration: 1, Name: "bin", SHA256: "aaa"}
	stored, created, err = s.insertArtifactMemoryLocked(same)
	if err != nil || created || stored.ID != "1" {
		t.Fatalf("same-digest insert = %+v created=%v err=%v", stored, created, err)
	}
	conflict := model.ArtifactRecord{ID: "3", JobID: "job", LeaseGeneration: 1, Name: "bin", SHA256: "bbb"}
	stored, created, err = s.insertArtifactMemoryLocked(conflict)
	if !errors.Is(err, storage.ErrArtifactDigestConflict) || created || stored.SHA256 != "aaa" {
		t.Fatalf("digest conflict = %+v created=%v err=%v", stored, created, err)
	}
	otherGen := model.ArtifactRecord{ID: "4", JobID: "job", LeaseGeneration: 2, Name: "bin", SHA256: "bbb"}
	if _, created, err = s.insertArtifactMemoryLocked(otherGen); err != nil || !created {
		t.Fatalf("other generation insert created=%v err=%v", created, err)
	}
	jobless := model.ArtifactRecord{ID: "5", SHA256: "ccc"}
	if _, created, err = s.insertArtifactMemoryLocked(jobless); err != nil || !created {
		t.Fatalf("jobless insert created=%v err=%v", created, err)
	}
}

func TestFlowBlobRemoveStagedArtifact(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "a.tar.gz")
	prov := dst + ".intoto.json"
	if err := os.WriteFile(dst, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(prov, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	removeStagedArtifact(dst, true)
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("casMode must keep the blob: %v", err)
	}
	removeStagedArtifact(dst, false)
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("non-cas removal left %v", err)
	}
	if _, err := os.Stat(prov); !os.IsNotExist(err) {
		t.Fatalf("provenance removal left %v", err)
	}
}

func TestFlowBlobJobStart(t *testing.T) {
	if got := jobStart(model.Job{}); got.IsZero() {
		t.Fatal("nil StartedAt must yield now")
	}
	started := time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)
	j := model.Job{StartedAt: &started}
	if got := jobStart(j); !got.Equal(started) {
		t.Fatalf("jobStart = %v, want %v", got, started)
	}
}

func TestFlowBlobListArtifactsMemory(t *testing.T) {
	s, _ := fcMemoryBlobServer(t)
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/artifacts", "admin-tok", ""); w.Code != http.StatusOK {
		t.Fatalf("empty artifact list = %d: %s", w.Code, w.Body.String())
	}
	base := time.Now().UTC()
	s.mu.Lock()
	s.artifacts["a1"] = model.ArtifactRecord{ID: "a1", RunID: "run-c", JobID: "job-a", Name: "bin", CreatedAt: base.Add(time.Minute), Path: "/tmp/x"}
	s.artifacts["a2"] = model.ArtifactRecord{ID: "a2", RunID: "run-c", JobID: "job-a", Name: "lib", CreatedAt: base, Path: "/tmp/y"}
	s.mu.Unlock()
	w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/artifacts", "admin-tok", "")
	if w.Code != http.StatusOK {
		t.Fatalf("artifact list = %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "a2") || !strings.Contains(w.Body.String(), "a1") {
		t.Fatalf("artifact list missing records: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "/tmp/") {
		t.Fatalf("artifact paths must be redacted: %s", w.Body.String())
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/nope/artifacts", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("missing run artifact list = %d, want 404", w.Code)
	}
}

func TestFlowBlobListArtifactsDBFailures(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	s.DB = &fcStore{dbFakeStore: f, getRunErr: errors.New("run table down")}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/artifacts", "admin-tok", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("get run error = %d, want 500", w.Code)
	}
	s.DB = &fcStore{dbFakeStore: f, listArtifactsErr: errors.New("artifact table down")}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/artifacts", "admin-tok", ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("list artifacts error = %d, want 500", w.Code)
	}
}

func TestFlowBlobDownloadArtifactNotFound(t *testing.T) {
	s, _ := fcMemoryBlobServer(t)
	if w := doJSON(t, s, http.MethodGet, "/api/v1/artifacts/nope", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("missing artifact = %d, want 404", w.Code)
	}
}

func TestFlowBlobArtifactRecordWithoutLookupStore(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	s.DB = fcPlainStore{f}
	if _, err := s.artifactRecord(context.Background(), "a1"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("artifactRecord without lookup store = %v, want ErrNotFound", err)
	}
}

func TestFlowBlobOpenArtifactEmptyPath(t *testing.T) {
	s := New("tok")
	if _, err := s.openArtifact(context.Background(), model.ArtifactRecord{}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("openArtifact empty path = %v, want ErrNotExist", err)
	}
}

func TestFlowBlobUploadJobCachePreconditions(t *testing.T) {
	s := New("tok")
	r := httptest.NewRequest(http.MethodPut, "/api/v1/jobs/j/cache/"+strings.Repeat("a", 64), strings.NewReader("x"))
	r.SetPathValue("id", "j")
	r.SetPathValue("key", strings.Repeat("a", 64))
	w := httptest.NewRecorder()
	s.uploadJobCache(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("cache put without store = %d, want 503", w.Code)
	}

	s2, hdrs := fcMemoryBlobServer(t)
	s2.CAS = nil
	if w := doJSONHeaders(t, s2, http.MethodPut, "/api/v1/jobs/job-a/cache/"+strings.Repeat("a", 64), "runner-tok", "x", hdrs); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("cache put without CAS = %d, want 503", w.Code)
	}
}

func TestFlowBlobUploadJobCacheInvalidKey(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/not-hex", "runner-tok", "x", hdrs); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid cache key put = %d, want 400", w.Code)
	}
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/cache/not-hex", "runner-tok", "", hdrs); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid cache key get = %d, want 400", w.Code)
	}
}

func TestFlowBlobUploadJobCacheCASPutFailure(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	s.SetBlobStore(&fcErrBlob{memBlob: newMemBlob(), putErr: errors.New("cas down")})
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+strings.Repeat("a", 64), "runner-tok", "x", hdrs)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("cache cas put failure = %d, want 500: %s", w.Code, w.Body.String())
	}
}

func TestFlowBlobUploadJobCacheManifestStoreUnavailable(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	s.DB = fcPlainStore{f}
	w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+strings.Repeat("a", 64), "runner-tok", "x", hdrs)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("cache manifest store unavailable = %d, want 500: %s", w.Code, w.Body.String())
	}
}

func TestFlowBlobUploadJobCacheFSPersistFailures(t *testing.T) {
	key := strings.Repeat("a", 64)

	// A regular file where the cache directory belongs: MkdirAll fails.
	t.Run("cache path is a file", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t)
		if err := os.WriteFile(filepath.Join(s.store.Root, "cache"), []byte("block"), 0o600); err != nil {
			t.Fatal(err)
		}
		if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "x", hdrs); w.Code != http.StatusInternalServerError {
			t.Fatalf("cache mkdir failure = %d, want 500: %s", w.Code, w.Body.String())
		}
	})

	// A directory where the manifest file belongs: the atomic write's rename
	// is rejected by the OS for every euid, so the manifest-persist failure
	// branch is still asserted when the suite runs as root.
	t.Run("manifest path is a directory", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t)
		dir := filepath.Join(s.store.Root, "cache")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		s.mu.Lock()
		j := s.jobs["job-a"]
		s.mu.Unlock()
		repo, trust := cacheNamespace(j)
		if err := os.Mkdir(filepath.Join(dir, cacheFileKey(repo, trust, key)+".manifest.json"), 0o700); err != nil {
			t.Fatal(err)
		}
		if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "x", hdrs); w.Code != http.StatusInternalServerError {
			t.Fatalf("cache write failure = %d, want 500: %s", w.Code, w.Body.String())
		}
	})

	// A read-only cache directory: the atomic manifest write fails. Only a
	// non-root euid can assert this, since root bypasses the mode bits.
	t.Run("read-only cache directory", func(t *testing.T) {
		testutil.RequireNonRoot(t)
		s, hdrs := fcMemoryBlobServer(t)
		dir := filepath.Join(s.store.Root, "cache")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "x", hdrs); w.Code != http.StatusInternalServerError {
			t.Fatalf("cache write failure = %d, want 500: %s", w.Code, w.Body.String())
		}
	})
}

func TestFlowBlobDownloadJobCachePreconditions(t *testing.T) {
	s := New("tok")
	r := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/j/cache/"+strings.Repeat("a", 64), nil)
	r.SetPathValue("id", "j")
	r.SetPathValue("key", strings.Repeat("a", 64))
	w := httptest.NewRecorder()
	s.downloadJobCache(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("cache get without store = %d, want 503", w.Code)
	}
	s2, hdrs := fcMemoryBlobServer(t)
	s2.CAS = nil
	if w := doJSONHeaders(t, s2, http.MethodGet, "/api/v1/jobs/job-a/cache/"+strings.Repeat("a", 64), "runner-tok", "", hdrs); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("cache get without CAS = %d, want 503", w.Code)
	}
}

func TestFlowBlobDownloadJobCacheDBErrors(t *testing.T) {
	s, f, _, hdrs := cacheFixture(t)
	key := strings.Repeat("a", 64)
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "payload", hdrs); w.Code != http.StatusCreated {
		t.Fatalf("cache put = %d: %s", w.Code, w.Body.String())
	}
	// Manifest read failure: 500.
	s.DB = &fcStore{dbFakeStore: f, getCacheManErr: errors.New("manifest table down")}
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "", hdrs); w.Code != http.StatusInternalServerError {
		t.Fatalf("cache manifest read error = %d, want 500", w.Code)
	}
	// Blob missing: 404 miss.
	s.DB = f
	s.SetBlobStore(&fcErrBlob{memBlob: newMemBlob()})
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "", hdrs); w.Code != http.StatusNotFound {
		t.Fatalf("cache miss after blob loss = %d, want 404", w.Code)
	}
	// Backend failure (not a miss): 500.
	s.SetBlobStore(&fcErrBlob{memBlob: newMemBlob(), openErr: errors.New("backend down")})
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "", hdrs); w.Code != http.StatusInternalServerError {
		t.Fatalf("cache backend error = %d, want 500", w.Code)
	}
}

func TestFlowBlobDownloadJobCacheFSVerificationFailure(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	key := strings.Repeat("b", 64)
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "payload", hdrs); w.Code != http.StatusCreated {
		t.Fatalf("cache put = %d: %s", w.Code, w.Body.String())
	}
	fileKey := cacheFileKey("github.com/o/repo-a", "trusted", key)
	path := filepath.Join(s.store.Root, "cache", fileKey+".manifest.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 0xff
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if w := doJSONHeaders(t, s, http.MethodGet, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "", hdrs); w.Code != http.StatusNotFound {
		t.Fatalf("tampered fs manifest = %d, want 404", w.Code)
	}
}

func TestFlowBlobDownloadProvenanceBranches(t *testing.T) {
	s, _ := fcMemoryBlobServer(t)
	if w := doJSON(t, s, http.MethodGet, "/api/v1/artifacts/missing/provenance", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("missing provenance record = %d, want 404", w.Code)
	}
	s.mu.Lock()
	s.artifacts["a1"] = model.ArtifactRecord{ID: "a1", RunID: "run-c", JobID: "job-a", Name: "bin", ProvenanceSHA256: "abc", ProvenancePath: filepath.Join(s.store.Root, "nope.intoto.json")}
	s.mu.Unlock()
	if w := doJSON(t, s, http.MethodGet, "/api/v1/artifacts/a1/provenance", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("unreadable provenance = %d, want 404", w.Code)
	}
	// No provenance digest at all: 404.
	s.mu.Lock()
	s.artifacts["a2"] = model.ArtifactRecord{ID: "a2", RunID: "run-c", JobID: "job-a", Name: "lib"}
	s.mu.Unlock()
	if w := doJSON(t, s, http.MethodGet, "/api/v1/artifacts/a2/provenance", "admin-tok", ""); w.Code != http.StatusNotFound {
		t.Fatalf("digestless provenance = %d, want 404", w.Code)
	}
}

func TestFlowBlobOpenSidecarBranches(t *testing.T) {
	s, _ := fcMemoryBlobServer(t)
	if _, err := s.openSidecar(context.Background(), "", ""); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty sidecar ref = %v, want ErrNotExist", err)
	}
	mb := newMemBlob()
	mb.objects["abc"] = []byte("sidecar")
	s.SetBlobStore(mb)
	rc, err := s.openSidecar(context.Background(), "cas:", "abc")
	if err != nil {
		t.Fatalf("cas: sidecar with digest fallback: %v", err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	if string(body) != "sidecar" {
		t.Fatalf("sidecar bytes = %q", body)
	}
}

func TestFlowBlobCleanupExpiredArtifacts(t *testing.T) {
	s, _ := fcMemoryBlobServer(t)
	dir := t.TempDir()
	live := filepath.Join(dir, "live.tar.gz")
	prov := filepath.Join(dir, "live.tar.gz.intoto.json")
	if err := os.WriteFile(live, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(prov, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().Add(-time.Hour)
	future := time.Now().UTC().Add(time.Hour)
	s.mu.Lock()
	s.artifacts["expired"] = model.ArtifactRecord{ID: "expired", RunID: "run-c", JobID: "job-a", Name: "bin", Path: live, ProvenancePath: prov, ExpiresAt: &past}
	s.artifacts["kept"] = model.ArtifactRecord{ID: "kept", RunID: "run-c", JobID: "job-a", Name: "lib", Path: live, ExpiresAt: &future}
	s.artifacts["cas"] = model.ArtifactRecord{ID: "cas", RunID: "run-c", JobID: "job-a", Name: "cas", Path: "cas:deadbeef", ExpiresAt: &past}
	removed := s.cleanupExpiredArtifactsLocked(time.Now().UTC())
	s.mu.Unlock()
	if removed != 2 {
		t.Fatalf("cleanup removed %d, want 2", removed)
	}
	if _, err := os.Stat(live); !os.IsNotExist(err) {
		t.Fatalf("expired archive not removed: %v", err)
	}
	if _, err := os.Stat(prov); !os.IsNotExist(err) {
		t.Fatalf("expired provenance not removed: %v", err)
	}
}

func TestFlowBlobCleanBlobName(t *testing.T) {
	long := strings.Repeat("x", 200)
	if got := cleanBlobName(long); len(got) != 160 {
		t.Fatalf("long name length = %d, want 160", len(got))
	}
	if got := cleanBlobName(" a/b\\c..d "); got != "a_b_c_d" {
		t.Fatalf("cleanBlobName = %q", got)
	}
}

func TestFlowBlobFirstErr(t *testing.T) {
	if err := firstErr(nil, nil, nil); err != nil {
		t.Fatalf("firstErr all nil = %v", err)
	}
	want := errors.New("boom")
	if err := firstErr(nil, want, errors.New("later")); !errors.Is(err, want) {
		t.Fatalf("firstErr = %v, want %v", err, want)
	}
}
