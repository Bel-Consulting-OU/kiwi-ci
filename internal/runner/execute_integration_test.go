package runner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/policy"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
)

// fakeRunnerServer records the requests a runner makes during execute() and
// answers with the minimal control-plane responses.
type fakeRunnerServer struct {
	mu       sync.Mutex
	requests []recordedRequest
	complete []server.Complete
	// snapshotBodies holds the raw bytes of every snapshot upload.
	snapshotBodies [][]byte
	// generatedBodies holds the raw bytes of every generated-fragment POST.
	generatedBodies [][]byte
	// logLines records the step/line pairs posted to /log.
	logLines []string
	// generatedStatus, when non-zero, is the status the fake returns for
	// POST /api/v1/jobs/{id}/generated (default: 200 OK).
	generatedStatus int
}

type recordedRequest struct {
	Method  string
	Path    string
	Header  http.Header
	BodyLen int64
}

func (f *fakeRunnerServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		isSnapshot := r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/snapshots")
		isGenerated := r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/generated")
		if isSnapshot || isGenerated {
			body, _ = io.ReadAll(r.Body)
		}
		f.mu.Lock()
		if isSnapshot {
			f.snapshotBodies = append(f.snapshotBodies, body)
		}
		if isGenerated {
			f.generatedBodies = append(f.generatedBodies, body)
		}
		f.requests = append(f.requests, recordedRequest{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone()})
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/complete") {
			var c server.Complete
			_ = json.NewDecoder(r.Body).Decode(&c)
			f.complete = append(f.complete, c)
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/log/batch") {
			var b struct {
				Lines []server.LogLine `json:"lines"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			for _, l := range b.Lines {
				f.logLines = append(f.logLines, l.Step+": "+l.Line)
			}
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/log") {
			var l server.LogLine
			_ = json.NewDecoder(r.Body).Decode(&l)
			f.logLines = append(f.logLines, l.Step+": "+l.Line)
		}
		f.mu.Unlock()
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/jobs/") && strings.Contains(r.URL.Path, "/cache/") && r.Method == http.MethodGet:
			http.NotFound(w, r)
		case f.generatedStatus != 0 && isGenerated:
			w.WriteHeader(f.generatedStatus)
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
	return mux
}

func (f *fakeRunnerServer) pathsFor(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, req := range f.requests {
		if strings.HasPrefix(req.Path, prefix) {
			out = append(out, strings.TrimPrefix(req.Path, prefix))
		}
	}
	return out
}

func (f *fakeRunnerServer) headerOf(method, pathPrefix string) http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, req := range f.requests {
		if req.Method == method && strings.HasPrefix(req.Path, pathPrefix) {
			return req.Header
		}
	}
	return nil
}

func (f *fakeRunnerServer) lastComplete() (server.Complete, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.complete) == 0 {
		return server.Complete{}, false
	}
	return f.complete[len(f.complete)-1], true
}

func testRunnerFor(t *testing.T, ts *httptest.Server, cfg Config) *Runner {
	t.Helper()
	if cfg.Server == "" {
		cfg.Server = ts.URL
	}
	if cfg.CacheRoot == "" {
		cfg.CacheRoot = t.TempDir()
	}
	return &Runner{Cfg: cfg, ID: "runner-1", Client: &http.Client{Timeout: 30 * time.Second}, Metrics: NewMetrics()}
}

func basicTask(pipelineText string) server.Task {
	return server.Task{
		Job: model.Job{
			ID: "job-1", RunID: "run-1", Key: "build", BaseKey: "build",
			RepoURL: "https://github.com/acme/app.git", Ref: "refs/heads/main",
			Trusted: true, Pipeline: pipelineText, Attempts: 1,
		},
		LeaseToken: "lease-token", LeaseGeneration: 3,
	}
}

func TestExecuteCompiledPayloadRunsEffectiveJob(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	base := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n"
	spec, err := pipeline.Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	evil := g.Jobs["build"]
	marker := filepath.Join(t.TempDir(), "effective-ran")
	evil.Job.Steps = append(evil.Job.Steps, pipeline.Step{Run: makeFileScript(marker)})
	evilJSON, err := json.Marshal(evil)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(evilJSON)
	pd, err := pipeline.PipelineDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	payload := &model.CompiledJobPayload{
		SchemaVersion:  1,
		PipelineDigest: pd,
		JobDigest:      hex.EncodeToString(sum[:]),
		EffectiveJob:   json.RawMessage(evilJSON),
	}
	task := basicTask(base)
	task.Job.CompiledJobPayload = payload

	r := testRunnerFor(t, ts, Config{CaptureSnapshots: false})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644)
	}
	r.execute(context.Background(), task)

	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("payload's EffectiveJob did not run (marker missing): %v", err)
	}
	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded")
	}
	if c.Status != model.StatusSuccess {
		t.Fatalf("status = %s (%s), want success", c.Status, c.Error)
	}
}

func TestExecuteTamperedPayloadRefuses(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	base := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n"
	payload := buildPayload(t, base, "build")
	payload.PipelineDigest = strings.Repeat("0", 64)
	task := basicTask(base)
	task.Job.CompiledJobPayload = payload

	r := testRunnerFor(t, ts, Config{CaptureSnapshots: false})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644)
	}
	r.execute(context.Background(), task)

	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded")
	}
	if c.Status != model.StatusFailure {
		t.Fatalf("status = %s, want failure", c.Status)
	}
	if !strings.Contains(c.Error, "compiled payload digest mismatch") {
		t.Fatalf("error = %q, want digest mismatch", c.Error)
	}
}

func TestExecuteUploadsAttestationsBeforePayloadAndSnapshot(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	keyPath := writeTestSigstoreKey(t)
	// The pipeline YAML schema does not yet admit artifact sbom/sigstore
	// keys, so the effective compiled job (which carries them as JSON,
	// exactly like the control plane's compiled payload does) declares the
	// attestation contract. The step fixture writes the artifact and cache
	// payloads with the native shell (POSIX on Unix, PowerShell on Windows).
	buildStep := nativeScript(
		"mkdir -p out .cache && echo hello > out/app.txt && echo c > .cache/f.txt",
		"New-Item -ItemType Directory -Force -Path out,.cache | Out-Null; 'hello' | Out-File -Encoding utf8 out/app.txt; 'c' | Out-File -Encoding utf8 .cache/f.txt",
	)
	base := "version: 1\njobs:\n  build:\n    steps:\n      - run: " + buildStep + "\n    cache:\n      - name: deps\n        paths: [.cache]\n        key: v1\n    artifacts:\n      - name: app\n        paths: [out]\n"
	payload := buildPayload(t, base, "build")
	var eff pipeline.CompiledJob
	if err := json.Unmarshal(mustJSON(t, payload.EffectiveJob), &eff); err != nil {
		t.Fatal(err)
	}
	eff.Job.Artifacts[0].SBOM = "spdx-json"
	eff.Job.Artifacts[0].Sigstore = &pipeline.SigstoreConfig{Required: true, Issuer: "https://ci.acme.example", Identity: "build@acme.example"}
	effJSON := mustJSON(t, eff)
	sum := sha256.Sum256(effJSON)
	payload.EffectiveJob = json.RawMessage(effJSON)
	payload.JobDigest = hex.EncodeToString(sum[:])

	task := basicTask(base)
	task.Job.CompiledJobPayload = payload

	r := testRunnerFor(t, ts, Config{CaptureSnapshots: true, SigstoreKeyPath: keyPath})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644)
	}
	r.execute(context.Background(), task)

	// Attestations must precede the payload upload.
	uploads := fsrv.pathsFor("/api/v1/jobs/job-1/artifacts/")
	want := []string{"app.sbom", "app.sigstore", "app"}
	if len(uploads) != len(want) {
		t.Fatalf("artifact uploads = %v, want %v", uploads, want)
	}
	for i, w := range want {
		if uploads[i] != w {
			t.Fatalf("artifact uploads = %v, want %v (sbom/sigstore before payload)", uploads, want)
		}
	}

	// The snapshot upload must be a valid workspace archive.
	fsrv.mu.Lock()
	bodies := append([][]byte{}, fsrv.snapshotBodies...)
	fsrv.mu.Unlock()
	if len(bodies) == 0 {
		t.Fatal("no snapshot uploaded")
	}
	m, err := snapshot.Parse(bytes.NewReader(bodies[len(bodies)-1]))
	if err != nil {
		t.Fatalf("snapshot archive invalid: %v", err)
	}
	if len(m.Entries) == 0 {
		t.Fatal("snapshot archive has no entries")
	}

	// Cache PUT targets the job-scoped route with the runner lease
	// contract headers. The old repository/trust-domain contract headers
	// must never be sent (the server derives them from the job).
	h := fsrv.headerOf(http.MethodPut, "/api/v1/jobs/job-1/cache/")
	if h == nil {
		t.Fatal("no cache PUT recorded on the job-scoped route")
	}
	if got := h.Get("X-Kiwi-Runner-ID"); got != "runner-1" {
		t.Fatalf("cache PUT X-Kiwi-Runner-ID = %q, want runner-1", got)
	}
	if got := h.Get("X-Kiwi-Lease-Token"); got != "lease-token" {
		t.Fatalf("cache PUT X-Kiwi-Lease-Token = %q, want lease-token", got)
	}
	if got := h.Get("X-Kiwi-Lease-Generation"); got != "3" {
		t.Fatalf("cache PUT X-Kiwi-Lease-Generation = %q, want 3", got)
	}
	if got := h.Get("X-Kiwi-Repository"); got != "" {
		t.Fatalf("cache PUT must not send X-Kiwi-Repository, got %q", got)
	}
	if got := h.Get("X-Kiwi-Trust-Domain"); got != "" {
		t.Fatalf("cache PUT must not send X-Kiwi-Trust-Domain, got %q", got)
	}

	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded")
	}
	if c.Status != model.StatusSuccess {
		t.Fatalf("job status = %s (%s)", c.Status, c.Error)
	}
}

// TestCompileExpandsShardedJobIntoVariants asserts the compile-time shard
// reality: tests.shards expands into N compiled jobs, each with the shard
// matrix key and the env contract baked in. No runtime endpoint exists.
func TestCompileExpandsShardedJobIntoVariants(t *testing.T) {
	base := "version: 1\njobs:\n  build:\n    tests:\n      shards: 3\n    steps:\n      - run: echo shard $KIWI_TEST_SHARD_INDEX/$KIWI_TEST_SHARD_TOTAL\n"
	spec, err := pipeline.Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Jobs) != 3 {
		t.Fatalf("compiled %d jobs, want 3 shard variants", len(g.Jobs))
	}
	for i := 0; i < 3; i++ {
		id := "build[test_shard=" + strconv.Itoa(i) + "]"
		cj, ok := g.Jobs[id]
		if !ok {
			t.Fatalf("missing compiled variant %q", id)
		}
		if got := cj.Matrix["test_shard"]; got != strconv.Itoa(i) {
			t.Errorf("%s matrix test_shard = %q, want %d", id, got, i)
		}
		if got := cj.Job.Env["KIWI_TEST_SHARD_TOTAL"]; got != "3" {
			t.Errorf("%s KIWI_TEST_SHARD_TOTAL = %q, want 3", id, got)
		}
		if got := cj.Job.Env["KIWI_TEST_SHARD_INDEX"]; got != strconv.Itoa(i) {
			t.Errorf("%s KIWI_TEST_SHARD_INDEX = %q, want %d", id, got, i)
		}
	}
}

func TestExecuteInjectsTestShardEnv(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	// The compile-time reality: tests.shards expands into variants and each
	// variant carries the shard env contract. The runner executes the
	// variant the control plane leased; no runtime shard endpoint exists.
	// The probe asserts the env contract in the native shell (POSIX on
	// Unix, PowerShell on Windows).
	shardProbe := nativeScript(
		`test "$KIWI_TEST_SHARD_TOTAL" = "2" && test "$KIWI_TEST_SHARD_INDEX" = "1"`,
		`if ($env:KIWI_TEST_SHARD_TOTAL -ne '2') { exit 1 }; if ($env:KIWI_TEST_SHARD_INDEX -ne '1') { exit 1 }`,
	)
	base := "version: 1\njobs:\n  build:\n    tests:\n      shards: 2\n    steps:\n      - run: " + shardProbe + "\n"
	spec, err := pipeline.Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	g, err := pipeline.Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Jobs) != 2 {
		t.Fatalf("compiled %d jobs, want 2 shard variants", len(g.Jobs))
	}
	variant := "build[test_shard=1]"
	cj, ok := g.Jobs[variant]
	if !ok {
		t.Fatalf("no compiled variant %q", variant)
	}
	if got := cj.Job.Env["KIWI_TEST_SHARD_TOTAL"]; got != "2" || cj.Job.Env["KIWI_TEST_SHARD_INDEX"] != "1" {
		t.Fatalf("variant env = %v, want KIWI_TEST_SHARD_TOTAL=2 KIWI_TEST_SHARD_INDEX=1", cj.Job.Env)
	}

	task := basicTask(base)
	task.Job.Key = variant
	task.Job.CompiledJobPayload = buildPayload(t, base, variant)

	r := testRunnerFor(t, ts, Config{CaptureSnapshots: false})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644)
	}
	r.execute(context.Background(), task)

	for _, p := range fsrv.pathsFor("/api/v1/jobs/job-1/") {
		if strings.Contains(p, "test-shards") {
			t.Fatalf("runner called the retired test-shards endpoint: %s", p)
		}
	}
	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded")
	}
	if c.Status != model.StatusSuccess {
		t.Fatalf("shard env not honored: status=%s error=%s", c.Status, c.Error)
	}
}

func TestExecuteRefusesCompiledJobWithoutShardAssignment(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	base := "version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n"
	payload := buildPayload(t, base, "build")
	var eff pipeline.CompiledJob
	if err := json.Unmarshal(mustJSON(t, payload.EffectiveJob), &eff); err != nil {
		t.Fatal(err)
	}
	eff.Job.Tests.Shards = 2
	eff.Job.Env = nil
	effJSON := mustJSON(t, eff)
	sum := sha256.Sum256(effJSON)
	payload.EffectiveJob = json.RawMessage(effJSON)
	payload.JobDigest = hex.EncodeToString(sum[:])

	task := basicTask(base)
	task.Job.CompiledJobPayload = payload

	r := testRunnerFor(t, ts, Config{CaptureSnapshots: false})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644)
	}
	r.execute(context.Background(), task)

	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded")
	}
	if c.Status != model.StatusFailure {
		t.Fatalf("status = %s, want failure", c.Status)
	}
	if !strings.Contains(c.Error, "compiled job lacks shard assignment") {
		t.Fatalf("error = %q, want shard assignment refusal", c.Error)
	}
}

func TestApplyEffectiveNetwork(t *testing.T) {
	cases := []struct {
		name       string
		jobNetwork string
		sandbox    pipeline.NetworkPolicy
		ceiling    pipeline.NetworkPolicy
		want       pipeline.NetworkPolicy
		wantErr    bool
	}{
		{"default inherits services-only ceiling", "", pipeline.NetworkPolicyDefault, pipeline.NetworkPolicyServicesOnly, pipeline.NetworkPolicyServicesOnly, false},
		{"default inherits none ceiling", "", pipeline.NetworkPolicyDefault, pipeline.NetworkPolicyNone, pipeline.NetworkPolicyNone, false},
		{"explicit none stays none", "none", pipeline.NetworkPolicyDefault, pipeline.NetworkPolicyInternet, pipeline.NetworkPolicyNone, false},
		{"internet request stays under internet ceiling", "", pipeline.NetworkPolicyInternet, pipeline.NetworkPolicyInternet, pipeline.NetworkPolicyInternet, false},
		{"default under internet ceiling stays default", "", pipeline.NetworkPolicyDefault, pipeline.NetworkPolicyInternet, pipeline.NetworkPolicyDefault, false},
		{"services-only stays under internet ceiling", "", pipeline.NetworkPolicyServicesOnly, pipeline.NetworkPolicyInternet, pipeline.NetworkPolicyServicesOnly, false},
		{"internet request under none ceiling refused", "", pipeline.NetworkPolicyInternet, pipeline.NetworkPolicyNone, 0, true},
		{"internet request under services-only ceiling refused", "", pipeline.NetworkPolicyInternet, pipeline.NetworkPolicyServicesOnly, 0, true},
		{"services-only request under none ceiling refused", "", pipeline.NetworkPolicyServicesOnly, pipeline.NetworkPolicyNone, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cj := &pipeline.CompiledJob{ID: "build", Job: pipeline.Job{Network: tc.jobNetwork, Sandbox: pipeline.Sandbox{Network: tc.sandbox}}}
			err := applyEffectiveNetwork(cj, policy.Capabilities{Network: tc.ceiling})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("network request accepted, want refusal")
				}
				return
			}
			if err != nil {
				t.Fatalf("applyEffectiveNetwork: %v", err)
			}
			if cj.Job.Sandbox.Network != tc.want {
				t.Fatalf("sandbox.network = %d, want %d", cj.Job.Sandbox.Network, tc.want)
			}
		})
	}
}

// TestExecutePayloadNetworkCeilingRefused exercises the payload-path
// refusal end to end: a compiled payload whose effective policy disallows
// the network the job requests must fail the job, never execute it.
func TestExecutePayloadNetworkCeilingRefused(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	marker := filepath.Join(t.TempDir(), "must-not-run")
	base := "version: 1\njobs:\n  build:\n    sandbox:\n      network: internet\n    steps:\n      - run: " + makeFileScript(marker) + "\n"
	payload := buildPayload(t, base, "build")
	payload.EffectivePolicy = mustJSON(t, policy.Capabilities{
		NativeExecution: true,
		Container:       true,
		Tart:            true,
		Network:         pipeline.NetworkPolicyNone,
		Secrets:         map[string]bool{},
		OIDC:            []string{},
		CacheRead:       true,
		CacheWrite:      true,
	})
	task := basicTask(base)
	task.Job.CompiledJobPayload = payload

	r := testRunnerFor(t, ts, Config{CaptureSnapshots: false})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644)
	}
	r.execute(context.Background(), task)

	if _, err := os.Stat(marker); err == nil {
		t.Fatal("job ran despite the network policy ceiling refusing it")
	}
	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded")
	}
	if c.Status != model.StatusFailure {
		t.Fatalf("status = %s, want failure", c.Status)
	}
	if !strings.Contains(c.Error, "egress") {
		t.Fatalf("error = %q, want egress refusal", c.Error)
	}
}

func writeTestSigstoreKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sigstore.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
