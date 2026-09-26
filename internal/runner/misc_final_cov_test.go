package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// --- payload.go -----------------------------------------------------------

func TestFinalVerifyCompiledPayloadNilAndPipelineDigestError(t *testing.T) {
	spec, err := pipeline.Parse([]byte(payloadPipeline))
	if err != nil {
		t.Fatal(err)
	}
	cj, _, policyOK, err := verifyCompiledPayload(spec, nil, true)
	if err != nil || policyOK || cj.ID != "" {
		t.Fatalf("nil payload = %+v %v %v", cj, policyOK, err)
	}
	payload := buildPayload(t, payloadPipeline, "build")
	if _, _, _, err := verifyCompiledPayload(nil, payload, true); err == nil || !strings.Contains(err.Error(), "pipeline digest") {
		t.Fatalf("nil spec = %v", err)
	}
}

func TestFinalVerifyCompiledPayloadEncodeDecodeErrors(t *testing.T) {
	testutil.UnixChmod(t)
	spec, err := pipeline.Parse([]byte(payloadPipeline))
	if err != nil {
		t.Fatal(err)
	}
	// EffectiveJob is not valid JSON: the encode of the effective job fails.
	p := buildPayload(t, payloadPipeline, "build")
	p.EffectiveJob = json.RawMessage("{")
	if _, _, _, err := verifyCompiledPayload(spec, p, true); err == nil || !strings.Contains(err.Error(), "encode effective job") {
		t.Fatalf("invalid effective job = %v", err)
	}
	// EffectiveJob is valid JSON but not a compiled job object.
	p = buildPayload(t, payloadPipeline, "build")
	p.EffectiveJob = json.RawMessage("[]")
	if _, _, _, err := verifyCompiledPayload(spec, p, true); err == nil || !strings.Contains(err.Error(), "decode effective job") {
		t.Fatalf("array effective job = %v", err)
	}
	// EffectivePolicy is not valid JSON: the encode of the effective policy fails.
	p = buildPayload(t, payloadPipeline, "build")
	p.EffectivePolicy = json.RawMessage("{")
	if _, _, _, err := verifyCompiledPayload(spec, p, true); err == nil || !strings.Contains(err.Error(), "encode effective policy") {
		t.Fatalf("invalid effective policy = %v", err)
	}
	// EffectivePolicy is valid JSON but not a capabilities object.
	p = buildPayload(t, payloadPipeline, "build")
	p.EffectivePolicy = json.RawMessage("[]")
	if _, _, _, err := verifyCompiledPayload(spec, p, true); err == nil || !strings.Contains(err.Error(), "decode effective policy") {
		t.Fatalf("array effective policy = %v", err)
	}
}

func TestFinalPayloadSandboxRequirementsErrors(t *testing.T) {
	out, err := payloadSandboxRequirements(nil)
	if err != nil || out != (effectivePolicySandbox{}) {
		t.Fatalf("nil payload = %+v %v", out, err)
	}
	out, err = payloadSandboxRequirements(&model.CompiledJobPayload{})
	if err != nil || out != (effectivePolicySandbox{}) {
		t.Fatalf("nil policy = %+v %v", out, err)
	}
	// A policy value that cannot be marshalled.
	if _, err := payloadSandboxRequirements(&model.CompiledJobPayload{EffectivePolicy: json.RawMessage("{")}); err == nil || !strings.Contains(err.Error(), "encode effective policy") {
		t.Fatalf("invalid policy encode = %v", err)
	}
	// A policy value that cannot be decoded into the sandbox record.
	if _, err := payloadSandboxRequirements(&model.CompiledJobPayload{EffectivePolicy: json.RawMessage("[]")}); err == nil || !strings.Contains(err.Error(), "decode effective policy") {
		t.Fatalf("invalid policy decode = %v", err)
	}
	// Requirements decode and apply additively.
	req, err := payloadSandboxRequirements(&model.CompiledJobPayload{
		EffectivePolicy: json.RawMessage(`{"rootless":true,"read_only_rootfs":true,"non_root":true}`),
	})
	if err != nil || !req.Rootless || !req.ReadOnlyRootFS || !req.NonRoot {
		t.Fatalf("requirements = %+v %v", req, err)
	}
	cj := &pipeline.CompiledJob{}
	applyEffectiveSandbox(cj, req)
	if !cj.Job.Sandbox.Rootless || !cj.Job.Sandbox.ReadOnlyRootFS {
		t.Fatalf("sandbox not applied: %+v", cj.Job.Sandbox)
	}
	// An existing explicit request is never weakened.
	cj = &pipeline.CompiledJob{Job: pipeline.Job{Sandbox: pipeline.Sandbox{Rootless: true}}}
	applyEffectiveSandbox(cj, effectivePolicySandbox{})
	if !cj.Job.Sandbox.Rootless {
		t.Fatal("job-level rootless request weakened")
	}
}

// --- cache.go -------------------------------------------------------------

func TestFinalNewJobCacheTransportSeams(t *testing.T) {
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}}, nil
	})
	r := &Runner{ID: "runner-1", Cfg: Config{Server: "http://127.0.0.1:1", CacheRoot: t.TempDir()},
		Client: &http.Client{Transport: transport, Timeout: 5 * time.Second}, Metrics: NewMetrics()}
	task := basicTask(payloadPipeline)
	store := r.newJobCache(task, r.Metrics)
	tr, ok := store.Client.Transport.(*cacheTransport)
	if !ok {
		t.Fatalf("store transport = %T", store.Client.Transport)
	}
	// The runner's own transport is reused for the cache client.
	if tr.client.HTTP.Transport == nil || fmt.Sprintf("%T", tr.client.HTTP.Transport) != fmt.Sprintf("%T", transport) {
		t.Fatalf("cache client transport = %T, want the runner transport", tr.client.HTTP.Transport)
	}
	if tr.client.HTTP.Timeout != 5*time.Second {
		t.Fatalf("cache client timeout = %v", tr.client.HTTP.Timeout)
	}
	// Both redirect policies refuse to follow redirects.
	if err := store.Client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("store CheckRedirect = %v", err)
	}
	if err := tr.client.HTTP.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("cache client CheckRedirect = %v", err)
	}
}

func TestFinalNewJobCacheLogfAndRestore(t *testing.T) {
	body := []byte("cached-bytes")
	sum := sha256.Sum256(body)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(cache.HeaderCacheSHA256, hex.EncodeToString(sum[:]))
		_, _ = w.Write(body)
	}))
	defer ts.Close()
	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL, CacheRoot: t.TempDir()},
		Client: ts.Client(), Metrics: NewMetrics()}
	task := basicTask(payloadPipeline)
	store := r.newJobCache(task, r.Metrics)
	req := httptest.NewRequest(http.MethodGet, ts.URL+cacheRoutePrefix+"key", nil)
	resp, err := store.Client.Transport.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("cache restore = %v %v", resp, err)
	}
	b, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || string(b) != "cached-bytes" {
		t.Fatalf("cache body = %q %v", b, err)
	}

	// A digest-less response is refused by the job-scoped restore path: the
	// modern route must always claim integrity.
	tsNoDigest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer tsNoDigest.Close()
	r2 := &Runner{ID: "runner-1", Cfg: Config{Server: tsNoDigest.URL, CacheRoot: t.TempDir()},
		Client: tsNoDigest.Client(), Metrics: NewMetrics()}
	store2 := r2.newJobCache(task, r2.Metrics)
	req2 := httptest.NewRequest(http.MethodGet, tsNoDigest.URL+cacheRoutePrefix+"key", nil)
	if _, err := store2.Client.Transport.RoundTrip(req2); !errors.Is(err, cache.ErrMissingOrInvalidDigest) {
		t.Fatalf("digest-less job-scoped restore = %v, want ErrMissingOrInvalidDigest", err)
	}
}

// --- identity.go ----------------------------------------------------------

func TestFinalIdentityStoreWriteFailures(t *testing.T) {
	full := Identity{ID: "runner-1", KeyPEM: []byte("key"), CertPEM: []byte("cert"), CACertPEM: []byte("ca")}

	// The first write (runner id) fails: a directory is in the way, which the
	// OS rejects for every euid (a chmod 0500 dir is bypassed by root). The
	// error is the same first-write return the read-only case exercises.
	idBlocked := t.TempDir()
	if err := os.Mkdir(filepath.Join(idBlocked, identityIDFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := (IdentityStore{Dir: idBlocked}).Save(full); err == nil {
		t.Fatal("write onto an identity-id directory succeeded")
	}

	certBlocked := t.TempDir()
	if err := os.Mkdir(filepath.Join(certBlocked, identityCertFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := (IdentityStore{Dir: certBlocked}).Save(full); err == nil {
		t.Fatal("write onto a certificate directory succeeded")
	}

	caBlocked := t.TempDir()
	if err := os.Mkdir(filepath.Join(caBlocked, identityCAFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := (IdentityStore{Dir: caBlocked}).Save(full); err == nil {
		t.Fatal("write onto a CA directory succeeded")
	}
}

// --- snapshots.go ---------------------------------------------------------

func TestFinalUploadJobSnapshotErrorPaths(t *testing.T) {
	task := basicTask(payloadPipeline)
	ws := t.TempDir()
	// A temp directory that is actually a file fails the archive create.
	tmpAsFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(tmpAsFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmpAsFile)
	r := &Runner{ID: "r", Cfg: Config{Server: "http://127.0.0.1:1"}, Client: &http.Client{Timeout: time.Second}, Metrics: NewMetrics()}
	if err := r.uploadJobSnapshot(context.Background(), task, ws, 0); err == nil {
		t.Fatal("temp failure accepted")
	}
	t.Setenv("TMPDIR", "")

	bad := &Runner{ID: "r", Cfg: Config{Server: "http://[::1"}, Client: &http.Client{Timeout: time.Second}, Metrics: NewMetrics()}
	if err := bad.uploadJobSnapshot(context.Background(), task, ws, 0); err == nil {
		t.Fatal("malformed snapshot URL accepted")
	}
	closed := &Runner{ID: "r", Cfg: Config{Server: "http://127.0.0.1:1"}, Client: &http.Client{Timeout: time.Second}, Metrics: NewMetrics()}
	if err := closed.uploadJobSnapshot(context.Background(), task, ws, 0); err == nil {
		t.Fatal("snapshot transport failure accepted")
	}
}

// --- prewarm.go -----------------------------------------------------------

func TestFinalPrewarmLogfAndSkippedBinary(t *testing.T) {
	p := newPrewarmer(Config{})
	p.logf("prewarm: seam %d", 1)
	logger := &covLogger{}
	// No docker binary: the parsed reference is skipped without a pull.
	p2 := &prewarmer{refs: []string{"img@sha256:" + strings.Repeat("a", 64)},
		stateFile: filepath.Join(t.TempDir(), "state.json"), maxTracked: prewarmMaxTracked,
		dockerPath: "", tartPath: "", logf: logger.logf}
	if err := p2.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := logger.joined(); got != "" {
		t.Fatalf("unexpected logs: %s", got)
	}
	if st := p2.loadState(); len(st.Items) != 0 {
		t.Fatalf("state = %+v", st)
	}
}

func TestFinalPrewarmStaleTartDeleteFailure(t *testing.T) {
	bin := installRunnerFakes(t)
	digest := strings.Repeat("4", 64)
	t.Setenv("FAKE_TART_LIST_JSON", fmt.Sprintf(`[{"name":"kiwi-prewarm-stale","source":"old@sha256:%s"}]`, strings.Repeat("9", 64)))
	t.Setenv("FAKE_TART_DELETE_FAIL", "1")
	logger := &covLogger{}
	p := &prewarmer{refs: []string{"tart://img@sha256:" + digest}, stateFile: filepath.Join(t.TempDir(), "state.json"),
		maxTracked: prewarmMaxTracked, tartPath: filepath.Join(bin, "tart"), logf: logger.logf}
	if err := p.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(logger.joined(), "remove stale tart VM") {
		t.Fatalf("stale delete failure not logged: %s", logger.joined())
	}
}

func TestFinalPrewarmSaveStateWriteFailure(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "state.json")
	// The durable writer renames a unique temp file over stateFile; a
	// non-empty directory at that path makes the rename fail, so the
	// failure is surfaced instead of silently dropped.
	if err := os.MkdirAll(filepath.Join(stateFile, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &prewarmer{stateFile: stateFile}
	if err := p.saveState(prewarmState{Version: 1}); err == nil {
		t.Fatal("write onto a directory succeeded")
	}
}
