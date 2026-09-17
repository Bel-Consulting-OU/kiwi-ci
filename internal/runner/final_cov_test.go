package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/runnerpki"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// --- decodeProfileCapabilities / register ---------------------------------

func TestFinalDecodeProfileCapabilities(t *testing.T) {
	caps, claimed, err := decodeProfileCapabilities(nil)
	if err != nil || claimed || caps != nil {
		t.Fatalf("absent key = %v %v %v", caps, claimed, err)
	}
	caps, claimed, err = decodeProfileCapabilities(json.RawMessage(`["native","tart"]`))
	if err != nil || !claimed || len(caps) != 2 || caps[0] != "native" || caps[1] != "tart" {
		t.Fatalf("list claim = %v %v %v", caps, claimed, err)
	}
	caps, claimed, err = decodeProfileCapabilities(json.RawMessage(`null`))
	if err != nil || !claimed || caps != nil {
		t.Fatalf("null claim = %v %v %v", caps, claimed, err)
	}
	if _, claimed, err = decodeProfileCapabilities(json.RawMessage(`{"native":true}`)); err == nil || !claimed {
		t.Fatalf("malformed claim = %v %v", claimed, err)
	}
}

func TestFinalRegisterServerErrorsAndCapabilityClaim(t *testing.T) {
	var status atomic.Int32
	var body atomic.Value
	body.Store("")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	defer ts.Close()

	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL}, Client: ts.Client(), Metrics: NewMetrics()}
	status.Store(http.StatusInternalServerError)
	body.Store("boom")
	if err := r.register(context.Background()); err == nil || !isHTTPStatus(err, http.StatusInternalServerError) {
		t.Fatalf("generic register failure = %v", err)
	}
	// A malformed capabilities claim is refused after a successful register.
	status.Store(http.StatusOK)
	body.Store(`{"id":"runner-1","capabilities":{"native":true}}`)
	if err := r.register(context.Background()); err == nil || !strings.Contains(err.Error(), "capabilities claim") {
		t.Fatalf("malformed capabilities claim = %v", err)
	}
	// An explicit empty claim enforces an empty intersection.
	body.Store(`{"id":"runner-1","capabilities":[]}`)
	if err := r.register(context.Background()); err != nil {
		t.Fatalf("register with empty claim: %v", err)
	}
	if !r.capEnforced || r.effectiveCapabilities != nil {
		t.Fatalf("empty claim = enforced=%v caps=%v", r.capEnforced, r.effectiveCapabilities)
	}
	// A legacy server without the key keeps the restriction off.
	r = &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL}, Client: ts.Client(), Metrics: NewMetrics()}
	body.Store(`{"id":"runner-1"}`)
	if err := r.register(context.Background()); err != nil {
		t.Fatalf("legacy register: %v", err)
	}
	if r.capEnforced {
		t.Fatal("absent capabilities key must not enforce")
	}
}

func TestFinalDiscoveredCapabilities(t *testing.T) {
	testutil.UnixShell(t)
	t.Setenv("PATH", t.TempDir())
	if got := discoveredCapabilities(); len(got) != 1 || got[0] != "native" {
		t.Fatalf("bare host caps = %v", got)
	}
	bin := t.TempDir()
	for _, name := range []string{"docker", "tart"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	got := discoveredCapabilities()
	want := []string{"native", "container"}
	if runtime.GOOS == "darwin" {
		want = append(want, "tart")
	}
	if len(got) != len(want) {
		t.Fatalf("caps = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("caps = %v, want %v", got, want)
		}
	}
}

func TestFinalClientCertSerialInvalidPEM(t *testing.T) {
	r := &Runner{}
	if got := r.clientCertSerial(); got != "" {
		t.Fatalf("no cert = %q", got)
	}
	r.clientCertPEM = []byte("this is not a certificate")
	if got := r.clientCertSerial(); got != "" {
		t.Fatalf("garbage cert = %q", got)
	}
	ca, err := runnerpki.NewCA("serial test ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, certPEM := signIdentity(t, ca, "runner-1", time.Hour, 0)
	r.clientCertPEM = certPEM
	if got := r.clientCertSerial(); got == "" {
		t.Fatal("real certificate serial not extracted")
	}
}

// --- next / onDisabled ----------------------------------------------------

func TestFinalNextTransportErrorServerErrorAndTask(t *testing.T) {
	closed := &Runner{ID: "r", Cfg: Config{Server: "http://127.0.0.1:1"}, Client: &http.Client{Timeout: time.Second}, Metrics: NewMetrics()}
	if _, _, err := closed.next(context.Background()); err == nil {
		t.Fatal("transport failure not surfaced")
	}
	var status atomic.Int32
	var body atomic.Value
	body.Store("")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	defer ts.Close()
	r := &Runner{ID: "r", Cfg: Config{Server: ts.URL}, Client: ts.Client(), Metrics: NewMetrics()}
	status.Store(http.StatusBadGateway)
	body.Store("upstream gone")
	if _, _, err := r.next(context.Background()); err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("non-200 next = %v", err)
	}
	status.Store(http.StatusOK)
	body.Store(`{"job":{"id":"job-1"},"lease_token":"lease","lease_generation":2}`)
	task, drain, err := r.next(context.Background())
	if err != nil || drain || task == nil || task.Job.ID != "job-1" || task.LeaseToken != "lease" {
		t.Fatalf("next task = %+v drain=%v err=%v", task, drain, err)
	}
}

func TestFinalOnDisabledClearCertFailureIsLogged(t *testing.T) {
	dir := t.TempDir()
	// A non-empty directory at the certificate path cannot be removed.
	certDir := filepath.Join(dir, identityCertFile)
	if err := os.Mkdir(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "keep"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Runner{ID: "r", store: IdentityStore{Dir: dir}}
	err := r.onDisabled(ErrRunnerDisabledOrRevoked)
	if !errors.Is(err, ErrRunnerDisabledOrRevoked) {
		t.Fatalf("onDisabled = %v", err)
	}
}

// --- execute --------------------------------------------------------------

func TestFinalExecuteMkdirTempFailure(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	tmpAsFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(tmpAsFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmpAsFile)
	r := testRunnerFor(t, ts, Config{})
	r.execute(context.Background(), basicTask(payloadPipeline))
	c, ok := fsrv.lastComplete()
	if !ok || c.Status != model.StatusFailure || c.Error == "" {
		t.Fatalf("complete = %+v ok=%v", c, ok)
	}
}

func TestFinalExecuteParseFailure(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }
	r.execute(context.Background(), basicTask("version: 1\njobs: ["))
	c, ok := fsrv.lastComplete()
	if !ok || c.Status != model.StatusFailure {
		t.Fatalf("parse failure complete = %+v", c)
	}
}

func TestFinalExecuteLegacyCompileFailure(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	// The matrix hole interpolates into an escaping artifact path, so Parse
	// accepts the raw spec but Compile's post-interpolation validation
	// refuses the compiled job.
	text := "version: 1\njobs:\n  build:\n    matrix:\n      dir: [\"../escape\"]\n    steps:\n      - run: echo hi\n    artifacts:\n      - name: a\n        paths: [\"${{ matrix.dir }}\"]\n"
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }
	r.execute(context.Background(), basicTask(text))
	c, ok := fsrv.lastComplete()
	if !ok || c.Status != model.StatusFailure || !strings.Contains(c.Error, "escape") {
		t.Fatalf("compile failure complete = %+v", c)
	}
}

func TestFinalExecuteLegacyUnknownJobKey(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	text := "version: 1\njobs:\n  other:\n    steps:\n      - run: echo hi\n"
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }
	r.execute(context.Background(), basicTask(text))
	c, ok := fsrv.lastComplete()
	if !ok || c.Status != model.StatusFailure || !strings.Contains(c.Error, "not found") {
		t.Fatalf("unknown job complete = %+v", c)
	}
}

func TestFinalExecuteLegacyNetworkAssignmentRuns(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	marker := filepath.Join(t.TempDir(), "legacy-ran")
	text := "version: 1\njobs:\n  build:\n    network: none\n    steps:\n      - run: " + makeFileScript(marker) + "\n"
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }
	task := basicTask(text)
	task.Job.Network = "none"
	r.execute(context.Background(), task)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("legacy job did not run: %v", err)
	}
	if c, _ := fsrv.lastComplete(); c.Status != model.StatusSuccess {
		t.Fatalf("complete = %+v", c)
	}
}

// payloadWithEffectiveJob rebuilds a payload whose EffectiveJob is the
// compiled job for key after mutate runs on it, keeping the digests coherent.
func payloadWithEffectiveJob(t *testing.T, text, key string, mutate func(*pipeline.CompiledJob)) *model.CompiledJobPayload {
	t.Helper()
	payload := buildPayload(t, text, key)
	raw, ok := payload.EffectiveJob.(json.RawMessage)
	if !ok {
		t.Fatalf("payload effective job = %T, want json.RawMessage", payload.EffectiveJob)
	}
	var eff pipeline.CompiledJob
	if err := json.Unmarshal(raw, &eff); err != nil {
		t.Fatal(err)
	}
	mutate(&eff)
	effJSON := mustJSON(t, eff)
	sum := sha256.Sum256(effJSON)
	payload.EffectiveJob = effJSON
	payload.JobDigest = hex.EncodeToString(sum[:])
	return payload
}

func TestFinalExecutePayloadNetworkCeilingRefusal(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	marker := filepath.Join(t.TempDir(), "must-not-run")
	// The pipeline job requests nothing, so the spec-level admission check
	// passes; the effective job's explicit internet request then trips the
	// payload-level network ceiling.
	text := "version: 1\njobs:\n  build:\n    steps:\n      - run: " + makeFileScript(marker) + "\n"
	payload := payloadWithEffectiveJob(t, text, "build", func(cj *pipeline.CompiledJob) {
		cj.Job.Network = "bridge"
		cj.Job.Sandbox.Network = pipeline.NetworkPolicyInternet
	})
	payload.EffectivePolicy = mustJSON(t, policy.Capabilities{
		NativeExecution: true,
		Network:         pipeline.NetworkPolicyNone,
		Secrets:         map[string]bool{},
		OIDC:            []string{},
	})
	task := basicTask(text)
	task.Job.CompiledJobPayload = payload
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }
	r.execute(context.Background(), task)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("job ran despite the payload network ceiling")
	}
	c, ok := fsrv.lastComplete()
	if !ok || c.Status != model.StatusFailure || !strings.Contains(c.Error, "exceeds the compiled policy ceiling") {
		t.Fatalf("complete = %+v", c)
	}
}

func TestFinalExecuteCapabilityIntersectionRefusal(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }
	r.capEnforced = true
	r.effectiveCapabilities = nil
	r.execute(context.Background(), basicTask(payloadPipeline))
	c, ok := fsrv.lastComplete()
	if !ok || c.Status != model.StatusFailure || !strings.Contains(c.Error, "capability intersection") {
		t.Fatalf("capability refusal complete = %+v", c)
	}
}

func TestFinalExecuteOIDCEnvInjection(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	// The spec job does not request id_token so admission passes; the
	// effective job does, so the runner injects the lease-bound OIDC env.
	payload := payloadWithEffectiveJob(t, payloadPipeline, "build", func(cj *pipeline.CompiledJob) {
		cj.Job.Permissions.IDToken = true
	})
	payload.EffectivePolicy = mustJSON(t, policy.Capabilities{
		NativeExecution: true,
		Network:         pipeline.NetworkPolicyInternet,
		Secrets:         map[string]bool{},
		OIDC:            []string{},
	})
	task := basicTask(payloadPipeline)
	task.Job.CompiledJobPayload = payload
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }
	r.execute(context.Background(), task)
	if c, _ := fsrv.lastComplete(); c.Status != model.StatusSuccess {
		t.Fatalf("oidc job complete = %+v", c)
	}
}

func TestFinalExecuteDownloadFailure(t *testing.T) {
	complete := make(chan server.Complete, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/dependencies/"):
			http.Error(w, "undeclared download", http.StatusNotFound)
			return
		case strings.HasSuffix(r.URL.Path, "/complete"):
			var c server.Complete
			_ = json.NewDecoder(r.Body).Decode(&c)
			complete <- c
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	payload := payloadWithEffectiveJob(t, payloadPipeline, "build", func(cj *pipeline.CompiledJob) {
		cj.Job.Downloads = []pipeline.ArtifactInput{{From: "producer", Name: "pkg", Path: "in"}}
	})
	task := basicTask(payloadPipeline)
	task.Job.CompiledJobPayload = payload
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }
	r.execute(context.Background(), task)
	select {
	case c := <-complete:
		if c.Status != model.StatusFailure || !strings.Contains(c.Error, "download dependency") {
			t.Fatalf("download failure complete = %+v", c)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no completion recorded")
	}
}

func TestFinalExecuteUntrustedNativeRefusal(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }
	task := basicTask(payloadPipeline)
	task.Job.Trusted = false
	r.execute(context.Background(), task)
	c, ok := fsrv.lastComplete()
	if !ok || c.Status != model.StatusFailure || !strings.Contains(c.Error, "native host execution is forbidden") {
		t.Fatalf("untrusted native refusal = %+v", c)
	}
}

func TestFinalApplyEffectiveNetworkAndNameDefaults(t *testing.T) {
	// A default ceiling is treated as internet for the comparison.
	cj := &pipeline.CompiledJob{ID: "build", Job: pipeline.Job{Sandbox: pipeline.Sandbox{Network: pipeline.NetworkPolicyInternet}}}
	if err := applyEffectiveNetwork(cj, policy.Capabilities{}); err != nil {
		t.Fatalf("internet request under a default ceiling: %v", err)
	}
	if cj.Job.Sandbox.Network != pipeline.NetworkPolicyInternet {
		t.Fatalf("sandbox.network = %v", cj.Job.Sandbox.Network)
	}
	// networkPolicyName's default branch.
	if got := networkPolicyName(pipeline.NetworkPolicy(99)); got != "default" {
		t.Fatalf("networkPolicyName(99) = %q", got)
	}
	if got := networkPolicyName(pipeline.NetworkPolicyInternet); got != "internet" {
		t.Fatalf("networkPolicyName(internet) = %q", got)
	}
	if got := networkPolicyStrength(pipeline.NetworkPolicy(99)); got != 2 {
		t.Fatalf("networkPolicyStrength(99) = %d", got)
	}
}

func TestFinalChangedFilesInRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git not available: %v", err)
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-q")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "test")
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-q", "-m", "first")
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-q", "-m", "second")
	got := changedFiles(dir)
	if len(got) != 1 || got[0] != "b.txt" {
		t.Fatalf("changedFiles = %v, want [b.txt]", got)
	}
}

// reportServer answers the control-plane routes execute() touches, with
// per-path overrides for the test-report and snapshot upload endpoints.
type reportServer struct {
	mu          sync.Mutex
	complete    []server.Complete
	logs        []string
	tests       int
	snapshots   int
	testsStatus int
	snapStatus  int
}

func (s *reportServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/complete"):
			var c server.Complete
			_ = json.NewDecoder(r.Body).Decode(&c)
			s.complete = append(s.complete, c)
		case strings.HasSuffix(r.URL.Path, "/log"):
			var l server.LogLine
			_ = json.NewDecoder(r.Body).Decode(&l)
			s.logs = append(s.logs, l.Step+": "+l.Line)
		case strings.HasSuffix(r.URL.Path, "/tests"):
			s.tests++
			if s.testsStatus != 0 {
				w.WriteHeader(s.testsStatus)
				return
			}
		case strings.HasSuffix(r.URL.Path, "/snapshots"):
			s.snapshots++
			if s.snapStatus != 0 {
				w.WriteHeader(s.snapStatus)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	})
}

func (s *reportServer) joinedLogs() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.logs, "\n")
}

const junitOK = `<?xml version="1.0"?><testsuite name="s" tests="1"><testcase name="t" classname="c"/></testsuite>`
const junitBad = `<?xml version="1.0"?><testsuite`

func TestFinalExecuteTestReportPaths(t *testing.T) {
	text := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n"
	cases := []struct {
		name       string
		report     string
		status     int
		wantLog    string
		wantUpload int
	}{
		{"malformed report warns", junitBad, 0, "report warning:", 0},
		{"valid report uploads", junitOK, 0, "", 1},
		{"failed upload warns", junitOK, http.StatusInternalServerError, "upload warning:", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rsrv := &reportServer{testsStatus: tc.status}
			ts := httptest.NewServer(rsrv.handler())
			defer ts.Close()
			payload := payloadWithEffectiveJob(t, text, "build", func(cj *pipeline.CompiledJob) {
				cj.Job.TestReports = []string{"report.xml"}
			})
			task := basicTask(text)
			task.Job.CompiledJobPayload = payload
			r := testRunnerFor(t, ts, Config{})
			r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
				return os.WriteFile(filepath.Join(dir, "report.xml"), []byte(tc.report), 0o644)
			}
			r.execute(context.Background(), task)
			if tc.wantLog != "" && !strings.Contains(rsrv.joinedLogs(), tc.wantLog) {
				t.Fatalf("logs = %q, want %q", rsrv.joinedLogs(), tc.wantLog)
			}
			if tc.wantLog == "" && strings.Contains(rsrv.joinedLogs(), "warning") {
				t.Fatalf("unexpected warning: %q", rsrv.joinedLogs())
			}
			if rsrv.tests != tc.wantUpload {
				t.Fatalf("test uploads = %d, want %d", rsrv.tests, tc.wantUpload)
			}
			if c := rsrv.complete[len(rsrv.complete)-1]; c.Status != model.StatusSuccess {
				t.Fatalf("complete = %+v", c)
			}
		})
	}
}

func TestFinalExecuteSnapshotUploadWarning(t *testing.T) {
	rsrv := &reportServer{snapStatus: http.StatusBadGateway}
	ts := httptest.NewServer(rsrv.handler())
	defer ts.Close()
	r := testRunnerFor(t, ts, Config{CaptureSnapshots: true})
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }
	r.execute(context.Background(), basicTask(payloadPipeline))
	if rsrv.snapshots != 1 {
		t.Fatalf("snapshot uploads = %d", rsrv.snapshots)
	}
	if !strings.Contains(rsrv.joinedLogs(), "snapshot: upload warning:") {
		t.Fatalf("snapshot warning missing: %q", rsrv.joinedLogs())
	}
	if c := rsrv.complete[len(rsrv.complete)-1]; c.Status != model.StatusSuccess {
		t.Fatalf("snapshot failure must not fail the job: %+v", c)
	}
}

// --- Run loop -------------------------------------------------------------

func TestFinalRunExecutesTaskAndDrains(t *testing.T) {
	var nextCalls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/register"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
		case strings.HasSuffix(r.URL.Path, "/next"):
			if nextCalls.Add(1) == 1 {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(server.Task{Job: model.Job{ID: "job-1", Key: "build", Trusted: true, Pipeline: payloadPipeline}})
				return
			}
			w.Header().Set("X-Kiwi-Draining", "true")
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()
	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL, Poll: time.Millisecond, Concurrency: 1,
		WorkDir: t.TempDir(), GCInterval: time.Hour, PrewarmInterval: time.Hour, IdentityDir: t.TempDir()},
		Client: ts.Client(), Metrics: NewMetrics()}
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return fmt.Errorf("checkout refused") }
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("draining Run = %v", err)
	}
	if nextCalls.Load() < 2 {
		t.Fatalf("next calls = %d", nextCalls.Load())
	}
}

// runMaintenance drives one Run loop whose next() always answers 204 without
// a drain signal; the test cancels the context once the loop reached n next
// calls, so the maintenance branches between polls are exercised
// deterministically.
func runMaintenance(t *testing.T, cfg Config, n int32) error {
	t.Helper()
	var calls atomic.Int32
	reached := make(chan struct{})
	var once sync.Once
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/register"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
		case strings.HasSuffix(r.URL.Path, "/next"):
			if calls.Add(1) >= n {
				once.Do(func() { close(reached) })
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-reached
		cancel()
	}()
	cfg.Server = ts.URL
	cfg.Concurrency = 1
	cfg.Poll = time.Millisecond
	if cfg.WorkDir == "" {
		cfg.WorkDir = t.TempDir()
	}
	if cfg.IdentityDir == "" {
		cfg.IdentityDir = t.TempDir()
	}
	r := &Runner{ID: "runner-1", Cfg: cfg, Client: ts.Client(), Metrics: NewMetrics()}
	return r.Run(ctx)
}

func TestFinalRunPrewarmMaintenanceBranch(t *testing.T) {
	err := runMaintenance(t, Config{GCInterval: time.Hour, PrewarmInterval: time.Nanosecond}, 3)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context cancellation", err)
	}
}

func TestFinalRunGCMaintenanceBranch(t *testing.T) {
	// An empty PATH keeps executor.GC to its LookPath probes: no docker or
	// tart subprocesses are spawned.
	t.Setenv("PATH", t.TempDir())
	err := runMaintenance(t, Config{GCInterval: time.Nanosecond, PrewarmInterval: time.Hour}, 3)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context cancellation", err)
	}
}

func TestFinalMetricsServerListenError(t *testing.T) {
	old := os.Stderr
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = pw
	defer func() {
		os.Stderr = old
		_ = pw.Close()
		_ = pr.Close()
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A listener with no port is rejected synchronously by ListenAndServe.
	r := &Runner{Metrics: NewMetrics(), Cfg: Config{MetricsListen: "not-a-listen-address"}}
	r.startMetricsServer(ctx)
	read := make(chan string, 1)
	go func() {
		buf := make([]byte, 512)
		n, _ := pr.Read(buf)
		read <- string(buf[:n])
	}()
	select {
	case got := <-read:
		if !strings.Contains(got, "metrics") {
			t.Fatalf("stderr = %q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("metrics listen failure was not logged")
	}
	cancel()
}

// --- heartbeat ------------------------------------------------------------

func TestFinalHeartbeatClampAndContextCancel(t *testing.T) {
	r := &Runner{ID: "r", Cfg: Config{Server: "http://127.0.0.1:1", Heartbeat: time.Minute},
		Client: &http.Client{Timeout: time.Second}, Metrics: NewMetrics()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	finished := make(chan struct{})
	go func() {
		r.heartbeatLoop(ctx, cancel, basicTask(payloadPipeline), make(chan struct{}))
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("heartbeatLoop ignored a cancelled context")
	}
}

func TestFinalHeartbeatCancelsExpiredLease(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()
	r := &Runner{ID: "r", Cfg: Config{Server: ts.URL, Heartbeat: time.Millisecond},
		Client: ts.Client(), Metrics: NewMetrics()}
	task := basicTask(payloadPipeline)
	task.LeaseExpiresAt = time.Now().Add(-time.Minute)
	cancelled := make(chan struct{})
	var once sync.Once
	go r.heartbeatLoop(context.Background(), func() { once.Do(func() { close(cancelled) }) }, task, make(chan struct{}))
	select {
	case <-cancelled:
	case <-time.After(10 * time.Second):
		t.Fatal("expired lease was not cancelled")
	}
}

// --- small helpers --------------------------------------------------------

func TestFinalChangedFilesFailureAndBranchRef(t *testing.T) {
	if got := changedFiles(t.TempDir()); got != nil {
		t.Fatalf("changedFiles outside a repository = %v", got)
	}
	if got := branchFromRef("refs/heads/main"); got != "main" {
		t.Fatalf("branchFromRef heads = %q", got)
	}
	if got := branchFromRef("refs/tags/v1"); got != "tags/v1" {
		t.Fatalf("branchFromRef refs = %q", got)
	}
}

// --- restoreDownloads -----------------------------------------------------

func TestFinalRestoreDownloadsRequestAndTransportErrors(t *testing.T) {
	task := basicTask(payloadPipeline)
	ws := t.TempDir()
	inputs := []pipeline.ArtifactInput{{From: "producer", Name: "pkg", Path: "in"}}

	bad := &Runner{ID: "r", Cfg: Config{Server: "http://[::1"}, Client: &http.Client{Timeout: time.Second}, Metrics: NewMetrics()}
	if err := bad.restoreDownloads(context.Background(), task, inputs, ws); err == nil {
		t.Fatal("malformed server URL accepted")
	}
	closed := &Runner{ID: "r", Cfg: Config{Server: "http://127.0.0.1:1"}, Client: &http.Client{Timeout: time.Second}, Metrics: NewMetrics()}
	if err := closed.restoreDownloads(context.Background(), task, inputs, ws); err == nil {
		t.Fatal("transport failure accepted")
	}
}

func TestFinalRestoreDownloadsTempFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("archive"))
	}))
	defer ts.Close()
	tmpAsFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(tmpAsFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmpAsFile)
	r := &Runner{ID: "r", Cfg: Config{Server: ts.URL}, Client: ts.Client(), Metrics: NewMetrics()}
	err := r.restoreDownloads(context.Background(), basicTask(payloadPipeline), []pipeline.ArtifactInput{{From: "producer", Name: "pkg"}}, t.TempDir())
	if err == nil {
		t.Fatal("temp-file failure accepted")
	}
}

func TestFinalRestoreDownloadsTruncatedBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\npartial")
		_ = buf.Flush()
		_ = conn.Close()
	}))
	defer ts.Close()
	r := &Runner{ID: "r", Cfg: Config{Server: ts.URL}, Client: ts.Client(), Metrics: NewMetrics()}
	err := r.restoreDownloads(context.Background(), basicTask(payloadPipeline), []pipeline.ArtifactInput{{From: "producer", Name: "pkg"}}, t.TempDir())
	if err == nil {
		t.Fatal("truncated dependency body accepted")
	}
}

// --- uploadArtifact / uploadGeneratedFragmentData / post ------------------

func TestFinalUploadArtifactRequestAndTransportErrors(t *testing.T) {
	art := filepath.Join(t.TempDir(), "art.tar.gz")
	if err := os.WriteFile(art, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	task := basicTask(payloadPipeline)
	bad := &Runner{ID: "r", Cfg: Config{Server: "http://[::1"}, Client: &http.Client{Timeout: time.Second}, Metrics: NewMetrics()}
	if err := bad.uploadArtifact(context.Background(), task, "a", art); err == nil {
		t.Fatal("malformed artifact upload URL accepted")
	}
	closed := &Runner{ID: "r", Cfg: Config{Server: "http://127.0.0.1:1"}, Client: &http.Client{Timeout: time.Second}, Metrics: NewMetrics()}
	if err := closed.uploadArtifact(context.Background(), task, "a", art); err == nil {
		t.Fatal("artifact upload transport failure accepted")
	}
}

func TestFinalUploadFragmentRequestAndTransportErrors(t *testing.T) {
	task := basicTask(payloadPipeline)
	data := []byte(`{"jobs":{"child":{"steps":[{"run":"echo hi"}]}},"deps":{}}`)
	bad := &Runner{ID: "r", Cfg: Config{Server: "http://[::1"}, Client: &http.Client{Timeout: time.Second}, Metrics: NewMetrics()}
	if err := bad.uploadGeneratedFragmentData(context.Background(), task, "frag.json", data); err == nil {
		t.Fatal("malformed fragment upload URL accepted")
	}
	closed := &Runner{ID: "r", Cfg: Config{Server: "http://127.0.0.1:1"}, Client: &http.Client{Timeout: time.Second}, Metrics: NewMetrics()}
	if err := closed.uploadGeneratedFragmentData(context.Background(), task, "frag.json", data); err == nil {
		t.Fatal("fragment upload transport failure accepted")
	}
}

func TestFinalPostRequestBuildAndTransportErrors(t *testing.T) {
	r := &Runner{Cfg: Config{Server: "http://[::1"}, Client: &http.Client{Timeout: time.Second}}
	if err := r.post(context.Background(), "/x", map[string]any{}, nil); err == nil {
		t.Fatal("malformed post URL accepted")
	}
	closed := &Runner{Cfg: Config{Server: "http://127.0.0.1:1"}, Client: &http.Client{Timeout: time.Second}}
	if err := closed.post(context.Background(), "/x", map[string]any{}, nil); err == nil {
		t.Fatal("post transport failure accepted")
	}
}

// flakyPolicy marshals successfully once and then fails, modelling an
// effective-policy value whose re-encoding is not stable. It forces the
// defensive sandbox-requirement branch in execute: the payload passes the
// verification re-encode but fails the second decode into the sandbox record.
type flakyPolicy struct{ calls int }

func (f *flakyPolicy) MarshalJSON() ([]byte, error) {
	f.calls++
	if f.calls > 1 {
		return nil, fmt.Errorf("policy re-encode refused")
	}
	return []byte(`{"NativeExecution":true,"Network":3}`), nil
}

func TestFinalExecuteSandboxRequirementRefusal(t *testing.T) {
	complete := make(chan server.Complete, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/complete") {
			var c server.Complete
			_ = json.NewDecoder(r.Body).Decode(&c)
			complete <- c
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	payload := buildPayload(t, payloadPipeline, "build")
	payload.EffectivePolicy = &flakyPolicy{}
	task := basicTask(payloadPipeline)
	task.Job.CompiledJobPayload = payload
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.CheckoutFn = func(context.Context, model.Job, string) error { return nil }
	r.execute(context.Background(), task)
	select {
	case c := <-complete:
		if c.Status != model.StatusFailure || !strings.Contains(c.Error, "sandbox requirements") {
			t.Fatalf("sandbox requirement refusal = %+v", c)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no completion recorded")
	}
}

// --- identity dir / client preparation ------------------------------------

func TestFinalResolveIdentityDirDefaultsToHome(t *testing.T) {
	r := &Runner{Cfg: Config{EnrollToken: "grant"}}
	r.resolveIdentityDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if r.Cfg.IdentityDir != filepath.Join(home, ".kiwi", "runner") || r.store.Dir != r.Cfg.IdentityDir {
		t.Fatalf("identity dir = %q store=%q", r.Cfg.IdentityDir, r.store.Dir)
	}
	plain := &Runner{}
	plain.resolveIdentityDir()
	if plain.Cfg.IdentityDir != "" || plain.store.Dir != "" {
		t.Fatalf("identity store installed without enrollment: %+v", plain)
	}
}

func TestFinalPrepareClientMaterialErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.pem")
	cases := []struct {
		name string
		cfg  Config
	}{
		{"invalid server URL", Config{Server: "http://[::1", CACert: "x"}},
		{"missing CA file", Config{Server: "https://127.0.0.1:1", CACert: missing}},
		{"missing certificate file", Config{Server: "https://127.0.0.1:1", Cert: missing}},
		{"missing key file", Config{Server: "https://127.0.0.1:1", Cert: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----", Key: missing}},
		{"invalid key pair", Config{Server: "https://127.0.0.1:1",
			Cert: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----",
			Key:  "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Runner{Cfg: tc.cfg}
			if err := r.prepareClient(context.Background()); err == nil {
				t.Fatal("invalid material accepted")
			}
		})
	}
}

func TestFinalPrepareClientTeamsUpFreshEnrollment(t *testing.T) {
	ca, ts, enrollCalls, _ := enrollCountingServer(t)
	dir := t.TempDir()
	r := &Runner{Cfg: Config{Server: ts.URL, Token: "runner-token", EnrollToken: "enroll-secret",
		CACert: string(caCertPEM(t, ca)), IdentityDir: dir}}
	if err := r.prepareClient(context.Background()); err != nil {
		t.Fatalf("prepareClient: %v", err)
	}
	if enrollCalls.Load() != 1 {
		t.Fatalf("enroll calls = %d, want 1", enrollCalls.Load())
	}
	if r.ID == "" {
		t.Fatal("fresh enrollment did not assign a runner ID")
	}
	if _, ok := (IdentityStore{Dir: dir}).Load(); !ok {
		t.Fatal("enrolled identity not persisted")
	}
	if r.clientCertSerial() == "" {
		t.Fatal("enrolled certificate serial not captured")
	}
}

func TestFinalPrepareClientPersistFailure(t *testing.T) {
	ca, ts, _, _ := enrollCountingServer(t)
	blocked := filepath.Join(t.TempDir(), "identity-file")
	if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Runner{Cfg: Config{Server: ts.URL, Token: "runner-token", EnrollToken: "enroll-secret",
		CACert: string(caCertPEM(t, ca)), IdentityDir: blocked}}
	if err := r.prepareClient(context.Background()); err == nil {
		t.Fatal("enrollment into an unwritable identity dir accepted")
	}
}

func TestFinalEnrollErrorPaths(t *testing.T) {
	// Empty token.
	r := &Runner{Cfg: Config{Server: "https://127.0.0.1:1"}}
	if _, err := r.enroll(context.Background(), nil, []byte("csr")); err == nil {
		t.Fatal("empty enroll token accepted")
	}
	// Malformed server URL fails the request build.
	r = &Runner{Cfg: Config{Server: "http://[::1", EnrollToken: "t"}}
	if _, err := r.enroll(context.Background(), nil, []byte("csr")); err == nil {
		t.Fatal("malformed enroll URL accepted")
	}
	// Transport failure.
	r = &Runner{Cfg: Config{Server: "http://127.0.0.1:1", EnrollToken: "t"}}
	if _, err := r.enroll(context.Background(), nil, []byte("csr")); err == nil {
		t.Fatal("enroll transport failure accepted")
	}
	// Non-200 response.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer ts.Close()
	r = &Runner{Cfg: Config{Server: ts.URL, EnrollToken: "t"}}
	if _, err := r.enroll(context.Background(), nil, []byte("csr")); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("enroll refusal = %v", err)
	}
	// Malformed response body.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{"))
	}))
	defer bad.Close()
	r = &Runner{Cfg: Config{Server: bad.URL, EnrollToken: "t"}}
	if _, err := r.enroll(context.Background(), nil, []byte("csr")); err == nil {
		t.Fatal("malformed enroll response accepted")
	}
}

func TestFinalServerName(t *testing.T) {
	r := &Runner{Cfg: Config{Server: "https://control.example:8443", ServerName: "override.example"}}
	if got := r.serverName(); got != "override.example" {
		t.Fatalf("explicit server name = %q", got)
	}
	r = &Runner{Cfg: Config{Server: "https://control.example:8443"}}
	if got := r.serverName(); got != "control.example" {
		t.Fatalf("derived server name = %q", got)
	}
	r = &Runner{Cfg: Config{Server: "http://[::1"}}
	if got := r.serverName(); got != "" {
		t.Fatalf("unparsable server URL name = %q", got)
	}
}

// TestFinalMetricsServerAddrInUseLogs exercises the ErrorLog-free listen
// failure through a listener that holds the address.
func TestFinalMetricsServerAddrInUseLogs(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	old := os.Stderr
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = pw
	defer func() {
		os.Stderr = old
		_ = pw.Close()
		_ = pr.Close()
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &Runner{Metrics: NewMetrics(), Cfg: Config{MetricsListen: ln.Addr().String()}}
	r.startMetricsServer(ctx)
	read := make(chan string, 1)
	go func() {
		buf := make([]byte, 512)
		n, _ := pr.Read(buf)
		read <- string(buf[:n])
	}()
	select {
	case got := <-read:
		if !strings.Contains(got, "metrics") {
			t.Fatalf("stderr = %q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("metrics address-in-use failure was not logged")
	}
}
