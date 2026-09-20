package server

// Coverage for the remaining individually-listed branches: fixtures that
// reach a specific handler/helper state, plus deterministic filesystem faults
// (long paths, file-in-place-of-directory, fault stores). No production
// behavior is changed for any of these.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/auth"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/blob"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestLeftoverResolvePipelineUnknownInputReference covers the
// ResolveInputs error branch: the raw spec passes run-input validation but
// references an input the spec never declares, which the resolution pass
// rejects.
func TestLeftoverResolvePipelineUnknownInputReference(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	pipeline := `version: 1
inputs:
  target: {type: string, default: prod}
jobs:
  build:
    runtime: container
    image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: echo ${{ inputs.target }} ${{ inputs.missing }}
`
	w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/o/r.git", Ref: "main", Pipeline: pipeline}, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "missing") {
		t.Fatalf("unresolved input reference = %d %s; want 400 missing-input error", w.Code, w.Body.String())
	}
}

// TestLeftoverArtifactMemoryReplayAndConflict covers the memory-mode artifact
// idempotency branches: a byte-identical re-upload is acknowledged with 200,
// a same-generation different-digest upload is a 409 contract violation.
func TestLeftoverArtifactMemoryReplayAndConflict(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	fcSeedContract(s, "job-a", fcBinContract())
	if w := fcUploadBlobArtifact(t, s, hdrs, "payload"); w.Code != http.StatusCreated {
		t.Fatalf("first upload = %d: %s", w.Code, w.Body.String())
	}
	if w := fcUploadBlobArtifact(t, s, hdrs, "payload"); w.Code != http.StatusOK {
		t.Fatalf("identical replay = %d: %s; want 200", w.Code, w.Body.String())
	}
	if w := fcUploadBlobArtifact(t, s, hdrs, "different-payload"); w.Code != http.StatusConflict {
		t.Fatalf("digest conflict = %d: %s; want 409", w.Code, w.Body.String())
	}
}

// TestLeftoverCacheManifestSignerFailure covers the manifest-signing error
// branch: a signer whose key material cannot sign fails the upload closed.
func TestLeftoverCacheManifestSignerFailure(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	s.mu.Lock()
	s.cacheSigner = &cacheSigner{Private: nil, Public: nil, KID: "broken"}
	s.mu.Unlock()
	key := strings.Repeat("a", 64)
	if w := doJSONHeaders(t, s, http.MethodPut, "/api/v1/jobs/job-a/cache/"+key, "runner-tok", "payload", hdrs); w.Code != http.StatusInternalServerError {
		t.Fatalf("unsigned manifest = %d: %s; want 500", w.Code, w.Body.String())
	}
}

func TestLeftoverDeploymentScopedReadDenial(t *testing.T) {
	s, _, _, _ := cacheFixture(t)
	if err := s.AuthStore.AddToken("outsider", fcOutsiderPrincipal()); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, http.MethodGet, "/api/v1/runs/run-c/deployments", "outsider", ""); w.Code != http.StatusForbidden {
		t.Fatalf("scoped deployment list = %d; want 403", w.Code)
	}
}

// deploymentStatusFaultStore fails UpdateDeploymentStatus only.
type deploymentStatusFaultStore struct {
	*dbFakeStore
	updateErr error
}

func (f deploymentStatusFaultStore) UpdateDeploymentStatus(ctx context.Context, id string, status model.Status, finishedAt *time.Time) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	return f.dbFakeStore.UpdateDeploymentStatus(ctx, id, status, finishedAt)
}

// TestLeftoverDeploymentStatusUpdateFailure covers the finish path's
// durability contract: a failed durable status update is returned to the
// caller (so the effect stays pending and is retried), and neither the
// in-memory marker nor the completion audit is touched.
func TestLeftoverDeploymentStatusUpdateFailure(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	fault := deploymentStatusFaultStore{dbFakeStore: f, updateErr: errors.New("deployment update down")}
	s.DB = fault
	j := model.Job{ID: "job-a", RunID: "run-c", Environment: "production"}
	d0 := model.Deployment{ID: "dep-1", RunID: j.RunID, JobID: j.ID, Environment: j.Environment, Status: model.StatusRunning, CreatedAt: time.Now().UTC()}
	s.mu.Lock()
	s.deployments[j.ID] = d0
	s.mu.Unlock()
	if err := f.InsertDeployment(context.Background(), d0); err != nil {
		t.Fatal(err)
	}
	if err := s.finishDeploymentDB(context.Background(), j, model.StatusFailure, time.Now().UTC()); err == nil {
		t.Fatal("failed durable update must be returned, not swallowed")
	}
	s.mu.Lock()
	d := s.deployments[j.ID]
	s.mu.Unlock()
	if d.Status != model.StatusRunning || d.FinishedAt != nil {
		t.Fatalf("failed update advanced the in-memory marker: %+v", d)
	}
	f.mu.Lock()
	stored := f.deployments[j.ID]
	audited := false
	for _, e := range f.audit {
		if e.Action == "deployment.completed" {
			audited = true
		}
	}
	f.mu.Unlock()
	if stored.FinishedAt != nil {
		t.Fatalf("failed update reached the store: %+v", stored)
	}
	if audited {
		t.Fatal("failed update emitted the completion audit")
	}
	// Once the store recovers the same call converges the record.
	s.DB = f
	if err := s.finishDeploymentDB(context.Background(), j, model.StatusFailure, time.Now().UTC()); err != nil {
		t.Fatalf("recovered finish = %v", err)
	}
	s.mu.Lock()
	d = s.deployments[j.ID]
	s.mu.Unlock()
	if d.Status != model.StatusFailure || d.FinishedAt == nil {
		t.Fatalf("deployment not finished after recovery: %+v", d)
	}
}

// TestLeftoverLeaseAuthErrorDefault covers the internal-error arm of the
// shared lease auth renderer.
func TestLeftoverLeaseAuthErrorDefault(t *testing.T) {
	s := New("secret")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/x/heartbeat", nil)
	s.writeLeaseAuthError(w, r, errors.New("store exploded"))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("internal lease error = %d; want 500", w.Code)
	}
}

// TestLeftoverRunnerTokensZeroValue covers the lazy map init on a bare
// Server (no constructor).
func TestLeftoverRunnerTokensZeroValue(t *testing.T) {
	s := &Server{}
	s.LoadRunnerTokens(nil)
	if s.runnerTokens == nil {
		t.Fatal("LoadRunnerTokens did not initialize the token map")
	}
	s.LoadRunnerTokens(nil)
	if _, ok := s.runnerBearerID(httptest.NewRequest(http.MethodGet, "/", nil)); ok {
		t.Fatal("empty token map must not resolve a bearer")
	}
}

// TestLeftoverOIDCKeyRingWriteFailure covers the key-ring persistence error
// branch (the ring cannot be encoded): rotation fails closed.
func TestLeftoverOIDCKeyRingWriteFailure(t *testing.T) {
	s := New("secret")
	restore := jsonIndentSeam(t)
	defer restore()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.oidc = newOIDCSigner()
	s.oidc.ringPath = filepath.Join(t.TempDir(), "oidc-keys.json")
	s.rotateOIDCKeyLocked(time.Now().UTC())
	// The ring file must not have been created from a failed encode.
	if _, err := os.Stat(s.oidc.ringPath); err == nil {
		t.Fatal("failed key-ring encode still wrote a ring file")
	}
}

// jsonIndentSeam overrides the indenting encoder seam for one test.
func jsonIndentSeam(t *testing.T) func() {
	t.Helper()
	old := jsonMarshalIndent
	jsonMarshalIndent = func(any, string, string) ([]byte, error) { return nil, errSeamJSON }
	return func() { jsonMarshalIndent = old }
}

// TestLeftoverScheduleDBUpsertEntropyFailure covers the DB-mode schedule
// creation id mint.
func TestLeftoverScheduleDBUpsertEntropyFailure(t *testing.T) {
	s, f, _, _ := cacheFixture(t)
	body, err := json.Marshal(map[string]string{"repository": "https://github.com/o/repo-a.git", "spec": scheduleSpec})
	if err != nil {
		t.Fatal(err)
	}
	restore := seamRand(t, seamErrReader{})
	defer restore()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/schedules", strings.NewReader(string(body)))
	r.Header.Set("Authorization", "Bearer admin-tok")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("db schedule upsert with failing entropy = %d: %s; want 500", w.Code, w.Body.String())
	}
	_ = f
}

// TestLeftoverSchedulePersistenceFailure covers fireSchedule's best-effort
// persistence of the last-run marker: the occurrence claim write succeeds,
// the durable marker advance write fails, and the run still fires (the
// persisted claim already prevents a refire; the next tick converges the
// marker through the durable advance path).
func TestLeftoverSchedulePersistenceFailure(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	old := writeSchedulesFile
	calls := 0
	writeSchedulesFile = func(path string, v any) error {
		calls++
		if calls >= 2 {
			return errors.New("schedules file unwritable")
		}
		return old(path, v)
	}
	t.Cleanup(func() { writeSchedulesFile = old })

	sc := storage.Schedule{ID: "sc-1", Repository: "o/r", RepoID: "github.com/o/r", RepoURL: "https://github.com/o/r.git",
		Spec: scheduleSpec, Enabled: true, CreatedAt: time.Now().UTC()}
	s.mu.Lock()
	s.schedules[sc.ID] = sc
	s.mu.Unlock()
	run, fired, err := s.fireSchedule(context.Background(), sc, time.Now().UTC())
	if err != nil || !fired {
		t.Fatalf("fireSchedule with failing marker write = %v, %v; want fired run", err, fired)
	}
	if run.ID == "" {
		t.Fatal("fired run has no id")
	}
	if calls != 2 {
		t.Fatalf("schedules writes = %d; want 2 (claim + best-effort marker)", calls)
	}
}

// TestLeftoverSnapshotDigestVerificationFailure covers the upload's stored-
// object verification branch: a store reporting a different digest than the
// streamed bytes fails the upload instead of acknowledging corruption.
func TestLeftoverSnapshotDigestVerificationFailure(t *testing.T) {
	s, _, _, hdrs := cacheFixture(t)
	s.SetBlobStore(wrongDigestBlob{memBlob: newMemBlob()})
	if w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t)); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("digest mismatch upload = %d: %s; want 503", w.Code, w.Body.String())
	}
}

// wrongDigestBlob stores correctly but reports a zero digest, simulating a
// store that corrupts or misreports the content address.
type wrongDigestBlob struct {
	*memBlob
}

func (b wrongDigestBlob) Put(ctx context.Context, key string, r io.Reader, size int64) (blob.Object, error) {
	obj, err := b.memBlob.Put(ctx, key, r, size)
	if err != nil {
		return obj, err
	}
	obj.SHA256 = strings.Repeat("0", 64)
	return obj, nil
}

// TestLeftoverNewPanicsWithoutEntropy covers the constructor's fail-closed
// panic when the lease key cannot be generated.
func TestLeftoverNewPanicsWithoutEntropy(t *testing.T) {
	restore := seamRand(t, seamErrReader{})
	defer restore()
	defer func() {
		r := recover()
		if r == nil || !strings.Contains(fmt.Sprint(r), "failed to generate lease key") {
			t.Fatalf("New without entropy panic = %v; want lease-key panic", r)
		}
	}()
	New("secret")
}

// TestLeftoverLeaseKeyLoadErrors covers loadLeaseKey's error branches: a
// malformed key file, an unreadable path and a failed persist.
func TestLeftoverLeaseKeyLoadErrors(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "lease.key")
	if err := os.WriteFile(path, []byte("not-hex"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLeaseKey(root); err == nil {
		t.Fatal("non-hex lease key must fail to load")
	}
	if err := os.WriteFile(path, []byte("00ff"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLeaseKey(root); err == nil {
		t.Fatal("short lease key must fail to load")
	}
	// A directory in place of the key file fails the read (not IsNotExist).
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLeaseKey(root); err == nil {
		t.Fatal("unreadable lease key path must fail to load")
	}
}

// TestLeftoverLeaseKeyPersistFailure covers the persist failure branches: a
// parent that is not a directory makes MkdirAll fail, and a directory at the
// temp-key path makes the key write fail. Both fail closed, and both
// injections are rejected by the OS for any euid (no chmod assumption).
func TestLeftoverLeaseKeyPersistFailure(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLeaseKey(filepath.Join(blocker, "child")); err == nil {
		t.Fatal("lease key dir creation under a non-directory parent must fail")
	}

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "lease.key.tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLeaseKey(root); err == nil {
		t.Fatal("lease key write with a directory at the temp path must fail")
	}
}

// TestLeftoverOPAConfigureFailure covers the OPA configuration error branch:
// a policy whose OPA program cannot be compiled fails closed.
func TestLeftoverOPAConfigureFailure(t *testing.T) {
	s, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.Policy = &policy.Config{OPAFile: filepath.Join(t.TempDir(), "missing.rego")}
	if err := s.ConfigureOPA(); err == nil {
		t.Fatal("uncompilable policy must fail ConfigureOPA")
	}
}

// TestLeftoverEnvironmentCapacityScope covers the repo+environment scoping
// of the in-memory environment gate: a running job in another repository or
// environment never consumes this job's slot.
func TestLeftoverEnvironmentCapacityScope(t *testing.T) {
	j := model.Job{ID: "j", RepoURL: "https://github.com/o/a.git", Environment: "prod", EnvironmentConcurrency: 1}
	same := model.Job{ID: "same", RepoURL: "https://github.com/o/a.git", Environment: "prod", Status: model.StatusRunning}
	otherRepo := model.Job{ID: "repo", RepoURL: "https://github.com/o/b.git", Environment: "prod", Status: model.StatusRunning}
	otherEnv := model.Job{ID: "env", RepoURL: "https://github.com/o/a.git", Environment: "staging", Status: model.StatusRunning}
	if environmentAtCapacityScoped(j, map[string]model.Job{"repo": otherRepo, "env": otherEnv}) {
		t.Fatal("another repository/environment must not consume the slot")
	}
	if !environmentAtCapacityScoped(j, map[string]model.Job{"repo": otherRepo, "env": otherEnv, "same": same}) {
		t.Fatal("same repo+environment must consume the slot")
	}
}

// TestLeftoverRerunTrustedLegacyMode covers rerunTrusted's no-principal
// branch: legacy mode keeps the source run's trust.
func TestLeftoverRerunTrustedLegacyMode(t *testing.T) {
	s := New("")
	s.mu.Lock()
	s.runs["run-trusted"] = model.Run{ID: "run-trusted", Repo: "https://github.com/o/r.git", RepoFullName: "o/r", RepoID: "github.com/o/r",
		Ref: "main", Event: "push", Trusted: true, Status: model.StatusSuccess, CreatedAt: time.Now().UTC()}
	s.jobs["job-trusted"] = model.Job{ID: "job-trusted", RunID: "run-trusted", Pipeline: testPipeline, Status: model.StatusSuccess}
	s.mu.Unlock()
	c := newTestClient(t, s.Handler(), "")
	w := c.do(http.MethodPost, "/api/v1/runs/run-trusted/rerun", nil, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("legacy trusted rerun = %d: %s; want 202", w.Code, w.Body.String())
	}
	var run model.Run
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	if !run.Trusted {
		t.Fatal("legacy rerun of a trusted run must stay trusted")
	}
}

// repoScopedRunnerServer installs a repo-scoped principal (read on repo-b
// only): it passes the tier gate (it is an authenticated store principal) and
// the handler's per-action check denies it for repo-a.
func repoScopedRunnerServer(t *testing.T) *Server {
	t.Helper()
	s := New("secret")
	if err := s.AuthStore.AddToken("runner-tok", auth.Principal{
		Subject:      "runner-scoped",
		Roles:        []auth.Role{auth.RoleRead},
		Repositories: map[string]auth.RepositoryPermission{"github.com/o/repo-b": {Read: true}},
	}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.runs["run-a"] = model.Run{ID: "run-a", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", RepoID: "github.com/o/repo-a",
		Ref: "main", Event: "push", Status: model.StatusRunning, CreatedAt: time.Now().UTC(), Trusted: true}
	s.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-a", Pipeline: testPipeline, Status: model.StatusRunning}
	s.mu.Unlock()
	return s
}

// repoScopedRunnerServerDB is the DB-mode variant: the run and its pipeline
// live in the store, and the scoped principal is denied by the DB handlers.
func repoScopedRunnerServerDB(t *testing.T) *Server {
	t.Helper()
	s, f, _, _ := cacheFixture(t)
	if err := s.AuthStore.AddToken("runner-tok", auth.Principal{
		Subject:      "runner-scoped",
		Roles:        []auth.Role{auth.RoleRead},
		Repositories: map[string]auth.RepositoryPermission{"github.com/o/repo-b": {Read: true}},
	}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.runs["run-a"] = model.Run{ID: "run-a", Repo: "https://github.com/o/repo-a.git", RepoFullName: "o/repo-a", RepoID: "github.com/o/repo-a",
		Ref: "main", Event: "push", Status: model.StatusRunning, CreatedAt: time.Now().UTC(), Trusted: true}
	f.jobs["job-a"] = model.Job{ID: "job-a", RunID: "run-a", Pipeline: testPipeline, Status: model.StatusRunning}
	f.mu.Unlock()
	return s
}

// TestLeftoverRerunScopedRunnerDenied covers the rerun requireAction denial
// in both storage modes: a repo-scoped principal passes the tier but cannot
// rerun another repository.
func TestLeftoverRerunScopedRunnerDenied(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    *Server
	}{
		{"memory", repoScopedRunnerServer(t)},
		{"db", repoScopedRunnerServerDB(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, tc.s.Handler(), "runner-tok")
			if w := c.do(http.MethodPost, "/api/v1/runs/run-a/rerun", nil, nil); w.Code != http.StatusForbidden {
				t.Fatalf("scoped rerun = %d: %s; want 403", w.Code, w.Body.String())
			}
		})
	}
}

// TestLeftoverCancelScopedRunnerDenied covers the cancel requireAction denial
// for the same scoped principal in both storage modes.
func TestLeftoverCancelScopedRunnerDenied(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    *Server
	}{
		{"memory", repoScopedRunnerServer(t)},
		{"db", repoScopedRunnerServerDB(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, tc.s.Handler(), "runner-tok")
			if w := c.do(http.MethodPost, "/api/v1/runs/run-a/cancel", nil, nil); w.Code != http.StatusForbidden {
				t.Fatalf("scoped cancel = %d: %s; want 403", w.Code, w.Body.String())
			}
		})
	}
}

// TestLeftoverInternalSchedulingError covers the DB STARTUP path when the
// store hides InsertCompiledRun: SwitchToDB must fail closed (the control
// plane never starts in a mode that would enqueue non-atomically).
type baseOnlyStore struct {
	storage.Store
}

// TestLeftoverInternalSchedulingError covers the fail-closed contract for a
// store that hides InsertCompiledRun: DB startup is refused instead of
// silently degrading the enqueue to a non-atomic scheduler path.
func TestLeftoverInternalSchedulingError(t *testing.T) {
	s := New("secret")
	err := s.SwitchToDB(baseOnlyStore{newDBFakeStore()})
	if err == nil || !strings.Contains(err.Error(), "atomic") {
		t.Fatalf("SwitchToDB without the atomic store = %v; want fail-closed startup", err)
	}
}

// TestLeftoverApproveUnknownJob covers the approve handler's unknown-job
// branch: a job that does not exist is reported as not found without reaching
// the approval state machine.
func TestLeftoverApproveUnknownJob(t *testing.T) {
	s := New("secret")
	r := httptest.NewRequest(http.MethodPost, "/api/v1/jobs/job-missing/approve", nil)
	r.SetPathValue("id", "job-missing")
	w := httptest.NewRecorder()
	s.approveJob(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("approve unknown job = %d; want 404", w.Code)
	}
}

// dbMirrorServer builds the "DB authoritative, memory mirror" fixture: the
// scheduler handle is nil (memory-mode handlers), but the lease is
// authorized against the DB, so the memory mirror decides the branch.
func dbMirrorServer(t *testing.T, mirror func(f *dbFakeStore) model.Job) *Server {
	t.Helper()
	s := New("secret")
	f := newDBFakeStore()
	exp := time.Now().UTC().Add(time.Hour)
	f.mu.Lock()
	f.runs["run-x"] = model.Run{ID: "run-x", Repo: "https://github.com/o/r.git", RepoID: "github.com/o/r", Status: model.StatusRunning}
	f.jobs["job-x"] = model.Job{ID: "job-x", RunID: "run-x", Key: "build", Status: model.StatusRunning, LeaseRunnerID: "r-1",
		LeaseTokenHash: hashLeaseToken(s.leaseKey, "lease-tok"), LeaseGeneration: 5, LeaseExpiresAt: &exp}
	f.mu.Unlock()
	s.DB = f
	if mirror != nil {
		s.mu.Lock()
		s.jobs["job-x"] = mirror(f)
		s.mu.Unlock()
	}
	return s
}

func hbBody() map[string]any {
	return map[string]any{"runner_id": "r-1", "lease_token": "lease-tok", "lease_generation": 5}
}

// TestLeftoverHeartbeatStaleMirror covers the heartbeat branches decided by
// the memory mirror while DB authorization succeeds: a missing mirror job is
// not found, a cancelled mirror reports the cancellation, and a mirror with a
// different lease is a conflict.
func TestLeftoverHeartbeatStaleMirror(t *testing.T) {
	s := dbMirrorServer(t, nil)
	c := newTestClient(t, s.Handler(), "secret")
	if w := c.do(http.MethodPost, "/api/v1/jobs/job-x/heartbeat", hbBody(), nil); w.Code != http.StatusNotFound {
		t.Fatalf("heartbeat with no mirror = %d; want 404", w.Code)
	}

	s = dbMirrorServer(t, func(*dbFakeStore) model.Job {
		return model.Job{ID: "job-x", RunID: "run-x", Status: model.StatusCancelled}
	})
	c = newTestClient(t, s.Handler(), "secret")
	w := c.do(http.MethodPost, "/api/v1/jobs/job-x/heartbeat", hbBody(), nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "true") {
		t.Fatalf("cancelled mirror heartbeat = %d: %s; want cancel response", w.Code, w.Body.String())
	}

	s = dbMirrorServer(t, func(*dbFakeStore) model.Job {
		other := time.Now().UTC().Add(time.Hour)
		return model.Job{ID: "job-x", RunID: "run-x", Status: model.StatusRunning, LeaseRunnerID: "r-1",
			LeaseTokenHash: hashLeaseToken(s.leaseKey, "different"), LeaseGeneration: 5, LeaseExpiresAt: &other}
	})
	c = newTestClient(t, s.Handler(), "secret")
	if w := c.do(http.MethodPost, "/api/v1/jobs/job-x/heartbeat", hbBody(), nil); w.Code != http.StatusConflict {
		t.Fatalf("stale mirror heartbeat = %d; want 409", w.Code)
	}
}

// TestLeftoverCompleteStaleMirror covers the completion handler's memory
// mirror branches: a missing job, a stale mirror without a receipt, a stale
// mirror with a matching receipt (reconciled and acknowledged), and a
// receipt whose reconciliation fails.
func TestLeftoverCompleteStaleMirror(t *testing.T) {
	now := time.Now().UTC()
	hash := completionResultHash("success", "", nil)
	body := map[string]any{"runner_id": "r-1", "lease_token": "lease-tok", "lease_generation": 5, "status": "success"}

	s := dbMirrorServer(t, nil)
	c := newTestClient(t, s.Handler(), "secret")
	if w := c.do(http.MethodPost, "/api/v1/jobs/job-x/complete", body, nil); w.Code != http.StatusNotFound {
		t.Fatalf("complete with no mirror = %d; want 404", w.Code)
	}

	s = dbMirrorServer(t, func(*dbFakeStore) model.Job {
		return model.Job{ID: "job-x", RunID: "run-x", Status: model.StatusRunning}
	})
	c = newTestClient(t, s.Handler(), "secret")
	if w := c.do(http.MethodPost, "/api/v1/jobs/job-x/complete", body, nil); w.Code != http.StatusConflict {
		t.Fatalf("stale mirror complete = %d; want 409", w.Code)
	}

	// Matching receipt: the duplicate delivery is acknowledged with 204.
	s = dbMirrorServer(t, func(*dbFakeStore) model.Job {
		return model.Job{ID: "job-x", RunID: "run-x", Status: model.StatusSuccess}
	})
	s.mu.Lock()
	s.completions[completionReceiptKey("job-x", 5, "r-1")] = model.CompletionReceipt{JobID: "job-x", Generation: 5, RunnerID: "r-1", ResultHash: hash}
	s.mu.Unlock()
	c = newTestClient(t, s.Handler(), "secret")
	if w := c.do(http.MethodPost, "/api/v1/jobs/job-x/complete", body, nil); w.Code != http.StatusNoContent {
		t.Fatalf("receipt replay = %d: %s; want 204", w.Code, w.Body.String())
	}

	// Matching receipt with a failing reconciliation: the error surfaces.
	s = dbMirrorServer(t, func(*dbFakeStore) model.Job {
		return model.Job{ID: "job-x", RunID: "run-x", Status: model.StatusSuccess}
	})
	s.mu.Lock()
	s.completions[completionReceiptKey("job-x", 5, "r-1")] = model.CompletionReceipt{JobID: "job-x", Generation: 5, RunnerID: "r-1", ResultHash: hash}
	s.mu.Unlock()
	f := s.DB.(*dbFakeStore)
	f.mu.Lock()
	f.getRunErr = errors.New("run read down")
	f.mu.Unlock()
	c = newTestClient(t, s.Handler(), "secret")
	if w := c.do(http.MethodPost, "/api/v1/jobs/job-x/complete", body, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("receipt replay with failing reconciliation = %d: %s; want 500", w.Code, w.Body.String())
	}
	_ = now
}

// TestLeftoverNextSecondTokenEntropyFailure covers the second lease-token id
// in the runner next handler.
func TestLeftoverNextSecondTokenEntropyFailure(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	if w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/o/r.git", Ref: "main", Pipeline: testPipeline}, nil); w.Code != http.StatusAccepted {
		t.Fatalf("seed submit = %d: %s", w.Code, w.Body.String())
	}
	w := c.do(http.MethodPost, "/api/v1/runners/register", map[string]any{"name": "r", "capacity": 1, "labels": []string{"container"}, "protocol_min": 3, "protocol_max": 3}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("seed register = %d: %s", w.Code, w.Body.String())
	}
	var reg struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reg); err != nil {
		t.Fatal(err)
	}
	restore := seamRand(t, &seamPartialReader{n: 16})
	defer restore()
	hdr := map[string]string{"X-Kiwi-Request-ID": "seam-next-fixed"}
	if w := c.do(http.MethodPost, "/api/v1/runners/"+reg.ID+"/next", map[string]any{}, hdr); w.Code != http.StatusInternalServerError {
		t.Fatalf("next with second token entropy failure = %d; want 500", w.Code)
	}
}

// TestLeftoverLoadLeaseKeyEntropyFailure covers loadLeaseKey's key-generation
// failure: a fresh data dir with no entropy fails closed instead of writing a
// partial key.
func TestLeftoverLoadLeaseKeyEntropyFailure(t *testing.T) {
	root := t.TempDir()
	restore := seamRand(t, seamErrReader{})
	defer restore()
	if _, err := loadLeaseKey(root); err == nil {
		t.Fatal("loadLeaseKey without entropy must fail")
	}
	if _, err := os.Stat(filepath.Join(root, "lease.key")); err == nil {
		t.Fatal("failed lease key generation must not leave a key file")
	}
}

// listJobsFaultStore fails ListJobsByRun only.
type listJobsFaultStore struct {
	*dbFakeStore
	listErr error
}

func (f listJobsFaultStore) ListJobsByRun(ctx context.Context, runID string) ([]model.Job, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.dbFakeStore.ListJobsByRun(ctx, runID)
}

// TestLeftoverActiveJobsListFailure covers the drain accounting's new shape:
// the aggregate running count is authoritative and independent of per-run job
// reads, so an unreadable ListJobsByRun can no longer hide a running job; a
// failed aggregate count is UNKNOWN and reported fail-closed (never zero).
func TestLeftoverActiveJobsListFailure(t *testing.T) {
	s := New("secret")
	f := newDBFakeStore()
	f.mu.Lock()
	f.runs["run-x"] = model.Run{ID: "run-x", Status: model.StatusRunning}
	f.jobs["job-x"] = model.Job{ID: "job-x", RunID: "run-x", Status: model.StatusRunning}
	f.mu.Unlock()
	s.DB = listJobsFaultStore{dbFakeStore: f, listErr: errors.New("jobs read down")}
	if n := s.ActiveJobs(); n != 1 {
		t.Fatalf("ActiveJobs with unreadable per-run jobs = %d; want 1 (aggregate is authoritative)", n)
	}
	f.countRunningErr = errors.New("count read down")
	if n := s.ActiveJobs(); n != unknownActiveJobs {
		t.Fatalf("ActiveJobs with unreadable count = %d; want fail-closed %d", n, unknownActiveJobs)
	}
	if n, known := s.activeJobCount(); n != 0 || known {
		t.Fatalf("activeJobCount with unreadable count = %d,%v; want 0,false", n, known)
	}
}

// TestLeftoverScheduleUpdateUnknownID covers the upsert branches for an
// explicit schedule id that does not exist: the request creates a schedule
// under that id in both storage modes.
func TestLeftoverScheduleUpdateUnknownID(t *testing.T) {
	body, err := json.Marshal(map[string]string{"id": "missing-id", "repository": "https://github.com/o/repo-a.git", "spec": scheduleSpec})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		s     *Server
		token string
	}{
		{"memory", New("secret"), "secret"},
		{"db", func() *Server { s, _, _, _ := cacheFixture(t); return s }(), "admin-tok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "/api/v1/schedules", strings.NewReader(string(body)))
			r.Header.Set("Authorization", "Bearer "+tc.token)
			w := httptest.NewRecorder()
			tc.s.Handler().ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("upsert with unknown id = %d: %s; want 200", w.Code, w.Body.String())
			}
			var sc storage.Schedule
			if err := json.Unmarshal(w.Body.Bytes(), &sc); err != nil {
				t.Fatal(err)
			}
			if sc.ID != "missing-id" {
				t.Fatalf("created schedule id = %q; want missing-id", sc.ID)
			}
		})
	}
}

// TestLeftoverTLSConfig covers the listener configuration: a bad key pair
// fails closed, a good pair without a client CA pool uses no client auth, a
// pool switches the handshake to VerifyClientCertIfGiven, and requiring
// client certs without a pool is refused.
func TestLeftoverTLSConfig(t *testing.T) {
	s := New("secret")
	if _, err := s.TLSConfig(filepath.Join(t.TempDir(), "missing.crt"), filepath.Join(t.TempDir(), "missing.key")); err == nil {
		t.Fatal("missing certificate pair must fail")
	}

	certFile, keyFile := writeSelfSignedPair(t)
	cfg, err := s.TLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatalf("TLSConfig with a valid pair: %v", err)
	}
	if len(cfg.Certificates) != 1 || cfg.ClientAuth != 0 {
		t.Fatalf("pool-less config = %+v", cfg)
	}
	pool := x509.NewCertPool()
	s.RunnerClientCAPool = pool
	cfg, err = s.TLSConfig(certFile, keyFile)
	if err != nil {
		t.Fatalf("TLSConfig with a client CA pool: %v", err)
	}
	if cfg.ClientCAs != pool || cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("pool config = %+v", cfg)
	}
	s.RunnerClientCAPool = nil
	s.RequireRunnerClientCerts = true
	if _, err := s.TLSConfig(certFile, keyFile); err == nil {
		t.Fatal("requiring client certs without a pool must fail")
	}
}

// writeSelfSignedPair writes a throwaway self-signed certificate/key pair and
// returns their paths.
func writeSelfSignedPair(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kiwi-test"}}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "server.crt")
	keyFile = filepath.Join(dir, "server.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// TestLeftoverGitHubStatusTokenHeader covers the commit-status request
// carrying the forge's resolved API token.
func TestLeftoverGitHubStatusTokenHeader(t *testing.T) {
	var gotAuth string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
	}))
	defer api.Close()
	s := New("secret")
	s.gitHubAPIBase = api.URL
	s.GitHubToken = "gh-token"
	if err := s.publishGitHubStatusFromPayload(context.Background(), forge.StatusPayload{RepoFullName: "acme/backend", SHA: "sha", State: "success", Context: "kiwi"}); err != nil {
		t.Fatalf("dispatch = %v", err)
	}
	if gotAuth != "Bearer gh-token" {
		t.Fatalf("status authorization = %q; want Bearer gh-token", gotAuth)
	}
}
