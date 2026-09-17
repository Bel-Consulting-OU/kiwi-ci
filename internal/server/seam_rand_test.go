package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// errSeamEntropy is the failure every overridden entropy source reports.
var errSeamEntropy = errors.New("seam: entropy source failed")

// seamErrReader fails every Read.
type seamErrReader struct{}

func (seamErrReader) Read([]byte) (int, error) { return 0, errSeamEntropy }

// seamPartialReader serves n zero bytes and then fails, so callers that
// consume a fixed seed prefix (ed25519.GenerateKey reads exactly 32 bytes)
// reach the NEXT generation step before the failure.
type seamPartialReader struct{ n int }

func (r *seamPartialReader) Read(b []byte) (int, error) {
	if r.n <= 0 {
		return 0, errSeamEntropy
	}
	k := len(b)
	if k > r.n {
		k = r.n
	}
	for i := 0; i < k; i++ {
		b[i] = 0
	}
	r.n -= k
	return k, nil
}

// seamRand overrides the package entropy seam for the duration of a test and
// returns the restore function. Seam tests are deliberately sequential:
// parallel tests only resume after every sequential test in the package has
// finished, so the process-wide override cannot race a parallel reader.
func seamRand(t *testing.T, r io.Reader) func() {
	t.Helper()
	old := randReader
	randReader = r
	restored := false
	restore := func() {
		if !restored {
			randReader = old
			restored = true
		}
	}
	t.Cleanup(restore)
	return restore
}

func TestSeamRandIdentifierHelpersFailClosed(t *testing.T) {
	s := New("secret")
	restore := seamRand(t, seamErrReader{})
	defer restore()

	if id, err := newID(); err == nil || id != "" {
		t.Fatalf("newID with failing entropy = %q, %v; want empty, error", id, err)
	}
	if k, err := newLeaseKey(); err == nil || k != nil {
		t.Fatalf("newLeaseKey with failing entropy = %v, %v; want nil, error", k, err)
	}
	if kid, err := newOIDCKID(); err == nil || kid != "" {
		t.Fatalf("newOIDCKID with failing entropy = %q, %v; want empty, error", kid, err)
	}
	if v, exp, err := newWebToken([]byte("secret"), "web"); err == nil || v != "" || exp != 0 {
		t.Fatalf("newWebToken with failing entropy = %q, %d, %v; want empty, 0, error", v, exp, err)
	}
	if b, err := createWebSessionKey(); err == nil || b != nil {
		t.Fatalf("createWebSessionKey with failing entropy = %v, %v; want nil, error", b, err)
	}
	for _, kind := range []string{clusterKindProvenance, clusterKindCacheSigning} {
		if b, err := createClusterKey(kind); err == nil || b != nil {
			t.Fatalf("createClusterKey(%s) with failing entropy = %v, %v; want nil, error", kind, b, err)
		}
	}
	if b, err := createClusterKey(clusterKindWebSession); err == nil || b != nil {
		t.Fatalf("createClusterKey(web-session) with failing entropy = %v, %v; want nil, error", b, err)
	}
	if _, err := s.CreateEnrollGrant(time.Minute, nil); err == nil || !strings.Contains(err.Error(), "generate enroll grant") {
		t.Fatalf("CreateEnrollGrant with failing entropy = %v; want generate error", err)
	}
}

// TestSeamRandPanicPaths covers the constructors that treat missing entropy as
// an unrecoverable startup condition: they must panic (fail closed) rather
// than silently start with a predictable key.
func TestSeamRandPanicPaths(t *testing.T) {
	t.Setenv("KIWI_WEB_SESSION_SECRET", "")
	restore := seamRand(t, seamErrReader{})
	defer restore()

	assertPanics := func(name, want string, fn func()) {
		t.Helper()
		defer func() {
			r := recover()
			if r == nil {
				t.Fatalf("%s did not panic on entropy failure", name)
			}
			if !strings.Contains(r.(string), want) {
				t.Fatalf("%s panic = %v; want containing %q", name, r, want)
			}
		}()
		fn()
	}
	assertPanics("newEphemeralEd25519", "failed to generate Ed25519 key", func() { newEphemeralEd25519() })
	assertPanics("webSessionSecret", "failed to generate web session secret", func() { webSessionSecret() })
	assertPanics("newOIDCSigner", "failed to generate OIDC signing key", func() { newOIDCSigner() })

	restore()
	// A reader that satisfies the 32-byte ed25519 seed and then fails reaches
	// the key-id generation panic in the same constructor.
	restore2 := seamRand(t, &seamPartialReader{n: 32})
	defer restore2()
	assertPanics("newOIDCSigner/kid", "failed to generate OIDC key id", func() { newOIDCSigner() })
}

func TestSeamRandLoadWebSessionSecretFailsClosed(t *testing.T) {
	t.Setenv("KIWI_WEB_SESSION_SECRET", "")
	s := New("secret")
	restore := seamRand(t, seamErrReader{})
	defer restore()
	if err := s.loadWebSessionSecret(t.TempDir()); err == nil {
		t.Fatal("loadWebSessionSecret with failing entropy must fail")
	}
	if len(s.WebSessionSecret) != 0 {
		t.Fatal("loadWebSessionSecret left a partial secret")
	}
}

// TestSeamRandOutboxFailures covers Outbox identifier generation: Enqueue
// fails closed on the item id, and the claim identity degrades to the
// documented timestamp fallback so flush still has a unique per-process name.
func TestSeamRandOutboxFailures(t *testing.T) {
	restore := seamRand(t, seamErrReader{})
	defer restore()
	o := &Outbox{}
	if err := o.Enqueue(forge.OutboxItem{}); err == nil {
		t.Fatal("Outbox.Enqueue with failing entropy must fail")
	}
	if id := o.claimerID(); !strings.HasPrefix(id, "outbox-") || id == "outbox-" {
		t.Fatalf("claimerID fallback = %q; want outbox-<nano>", id)
	}
}

// TestSeamRandAuditLockedDropsEvent covers the audit funnel's entropy-failure
// branch: the event is dropped with a log, never panicking the caller.
func TestSeamRandAuditLockedDropsEvent(t *testing.T) {
	s, err := NewPersistent("runner", "admin", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	restore := seamRand(t, seamErrReader{})
	defer restore()
	s.auditLocked("test.action", "actor", "run", "job", "message", nil)
	if events, err := s.store.ReadAudit(100); err != nil || len(events) != 0 {
		t.Fatalf("audit events = %d, %v; want 0, nil", len(events), err)
	}
}

// TestSeamRandHTTPHandlers drives the handlers whose identifier mint fails.
func TestSeamRandHTTPHandlers(t *testing.T) {
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

	restore := seamRand(t, seamErrReader{})
	defer restore()
	if w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/o/r.git", Ref: "main", Pipeline: testPipeline}, nil); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "generate run id") {
		t.Fatalf("submit with failing entropy = %d %s; want 400 generate run id", w.Code, w.Body.String())
	}
	if w := c.do(http.MethodPost, "/api/v1/runners/register", map[string]any{"name": "r2", "capacity": 1, "labels": []string{"container"}, "protocol_min": 3, "protocol_max": 3}, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("register with failing entropy = %d; want 500", w.Code)
	}
	if w := c.do(http.MethodPost, "/api/v1/runners/"+reg.ID+"/next", map[string]any{}, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("next with failing entropy = %d; want 500", w.Code)
	}
	spec, err := json.Marshal(map[string]string{"repository": "https://github.com/o/r.git", "spec": scheduleSpec})
	if err != nil {
		t.Fatal(err)
	}
	if w := c.do(http.MethodPut, "/api/v1/schedules", spec, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("schedule upsert with failing entropy = %d; want 500: %s", w.Code, w.Body.String())
	}
	if w := c.do(http.MethodPost, "/api/v1/runner-profiles", model.RunnerProfile{Labels: []string{"container"}}, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("profile create with failing entropy = %d; want 500: %s", w.Code, w.Body.String())
	}

	restore()
	// The second identifier in a two-id sequence fails. A fixed request ID
	// keeps the request-ID middleware from consuming entropy first.
	restore2 := seamRand(t, &seamPartialReader{n: 16})
	defer restore2()
	hdr := map[string]string{"X-Kiwi-Request-ID": "seam-fixed-id"}
	if w := c.do(http.MethodPost, "/api/v1/runs", SubmitRun{RepoURL: "https://github.com/o/r.git", Ref: "main", Pipeline: testPipeline}, hdr); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "generate job id") {
		t.Fatalf("submit with job-id entropy failure = %d %s; want 400 generate job id", w.Code, w.Body.String())
	}
}

// TestSeamRandScheduleTrigger covers fireSchedule's pre-run identifier.
func TestSeamRandScheduleTrigger(t *testing.T) {
	s := New("secret")
	restore := seamRand(t, seamErrReader{})
	defer restore()
	sc := storage.Schedule{
		ID: "sc-1", Repository: "o/r", RepoID: "github.com/o/r",
		RepoURL: "https://github.com/o/r.git",
		Spec:    sanitizeScheduleSpec(testPipeline),
	}
	if _, fired, err := s.fireSchedule(context.Background(), sc, time.Now()); err == nil || fired {
		t.Fatalf("fireSchedule with failing entropy = %v, %v; want error, false", err, fired)
	}
}

// TestSeamRandDownstreamIntents covers the downstream launch-token mint.
func TestSeamRandDownstreamIntents(t *testing.T) {
	s, run := downstreamServer(t, downstreamPipeline)
	s.mu.Lock()
	var j model.Job
	for _, cand := range s.jobs {
		if cand.RunID == run.ID {
			j = cand
			break
		}
	}
	s.mu.Unlock()
	if j.ID == "" {
		t.Fatal("no parent job for the downstream run")
	}
	restore := seamRand(t, seamErrReader{})
	defer restore()
	if err := s.recordDownstreamIntents(context.Background(), j, run); err == nil {
		t.Fatal("recordDownstreamIntents with failing entropy must fail")
	}
}

// TestSeamRandGeneratedFragment covers the generated child job-id mint.
func TestSeamRandGeneratedFragment(t *testing.T) {
	s, _ := trustedGenerateServer(t)
	runnerID, task := leaseRunJob(t, s)
	frag := `{"jobs":{"child-a":{"runtime":"container","image":"alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","steps":[{"run":"echo child"}]}},"deps":{}}`
	restore := seamRand(t, seamErrReader{})
	defer restore()
	w := doJSONHeaders(t, s, http.MethodPost, "/api/v1/jobs/"+task.Job.ID+"/generated", "token", fragmentBody(t, frag), leaseHeaders(task, runnerID))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "generate job id") {
		t.Fatalf("generated with failing entropy = %d %s; want 400 generate job id", w.Code, w.Body.String())
	}
}

// TestSeamRandRunnerPayloadUploads covers the runner-side upload endpoints
// whose record identifier cannot be minted: artifacts, snapshots (both
// storage modes) and test reports.
func TestSeamRandRunnerPayloadUploads(t *testing.T) {
	t.Run("artifact", func(t *testing.T) {
		s, hdrs := fcMemoryBlobServer(t)
		fcSeedContract(s, "job-a", fcBinContract())
		restore := seamRand(t, seamErrReader{})
		defer restore()
		if w := fcUploadBlobArtifact(t, s, hdrs, "payload"); w.Code != http.StatusInternalServerError {
			t.Fatalf("artifact upload with failing entropy = %d; want 500", w.Code)
		}
	})
	t.Run("snapshot-memory", func(t *testing.T) {
		s, err := NewPersistent("secret", "secret", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		c := newTestClient(t, s.Handler(), "secret")
		_, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)
		headers := map[string]string{
			"X-Kiwi-Runner-ID":        runnerID,
			"X-Kiwi-Lease-Token":      token,
			"X-Kiwi-Lease-Generation": strconv.FormatInt(gen, 10),
			"Content-Type":            "application/gzip",
		}
		restore := seamRand(t, seamErrReader{})
		defer restore()
		if w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/snapshots", fcSnapshotArchive(t), headers); w.Code != http.StatusInternalServerError {
			t.Fatalf("snapshot upload with failing entropy = %d; want 500", w.Code)
		}
	})
	t.Run("snapshot-db", func(t *testing.T) {
		s, _, _, hdrs := cacheFixture(t)
		restore := seamRand(t, seamErrReader{})
		defer restore()
		if w := fcUploadSnapshot(t, s, hdrs, fcSnapshotArchive(t)); w.Code != http.StatusInternalServerError {
			t.Fatalf("db snapshot upload with failing entropy = %d; want 500", w.Code)
		}
	})
	t.Run("test-report", func(t *testing.T) {
		s, err := NewPersistent("secret", "secret", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		c := newTestClient(t, s.Handler(), "secret")
		_, jobID, runnerID, token, gen := leaseNativeJob(t, c, testPipeline)
		restore := seamRand(t, seamErrReader{})
		defer restore()
		body := map[string]any{"runner_id": runnerID, "lease_token": token, "lease_generation": gen,
			"report": map[string]any{"path": "results.xml", "tests": 1}}
		if w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/tests", body, nil); w.Code != http.StatusInternalServerError {
			t.Fatalf("test report upload with failing entropy = %d: %s; want 500", w.Code, w.Body.String())
		}
	})
}

// TestSeamRandWebLoginFailsClosed covers the login handler's session-token
// mint: no cookie is issued when the nonce entropy source fails.
func TestSeamRandWebLoginFailsClosed(t *testing.T) {
	s := New("secret")
	// A pre-initialized session secret keeps ensureWebSessionSecret from
	// generating (and panicking on) the key, so the request reaches the
	// session-token mint under test.
	s.WebSessionSecret = make([]byte, 32)
	c := newTestClient(t, s.Handler(), "")
	restore := seamRand(t, seamErrReader{})
	defer restore()
	if w := c.do(http.MethodPost, "/api/v1/login", map[string]string{"token": "secret"}, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("login with failing entropy = %d; want 500", w.Code)
	}
}

// TestSeamRandOIDCIssuance covers the jti mint and the audit-event mint on the
// OIDC issuance path.
func TestSeamRandOIDCIssuance(t *testing.T) {
	s := newOIDCTestServer(t, true)
	_, jobID := seedOIDCJob(t, s, "lease-1")
	c := newTestClient(t, s.Handler(), "secret")
	// Initialize the signer while entropy still works.
	if got := issueOIDCToken(t, s, jobID, "lease-1", "https://audience.example"); got == "" {
		t.Fatal("seed OIDC token empty")
	}
	restore := seamRand(t, seamErrReader{})
	defer restore()
	w := c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/oidc", map[string]any{"audience": "https://audience.example"}, map[string]string{"Authorization": "Bearer lease-1"})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("oidc issue with failing entropy = %d: %s; want 500", w.Code, w.Body.String())
	}

	restore()
	// A 16-byte prefix satisfies the jti and fails the audit event mint: the
	// issuance must fail closed rather than return an unaudited token. The
	// fixed request ID keeps the middleware from consuming entropy first.
	restore2 := seamRand(t, &seamPartialReader{n: 16})
	defer restore2()
	hdr := map[string]string{"Authorization": "Bearer lease-1", "X-Kiwi-Request-ID": "seam-fixed-id"}
	w = c.do(http.MethodPost, "/api/v1/jobs/"+jobID+"/oidc", map[string]any{"audience": "https://audience.example"}, hdr)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "audit failed") {
		t.Fatalf("oidc audit failure = %d %s; want 500 audit failed", w.Code, w.Body.String())
	}
}
