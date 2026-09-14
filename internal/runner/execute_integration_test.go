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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
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
	testShardQuery []string
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
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/snapshots") {
			body, _ = io.ReadAll(r.Body)
		}
		f.mu.Lock()
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/snapshots") {
			f.snapshotBodies = append(f.snapshotBodies, body)
		}
		if strings.Contains(r.URL.Path, "/test-shards") {
			f.testShardQuery = append(f.testShardQuery, r.URL.RawQuery)
		}
		f.requests = append(f.requests, recordedRequest{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone()})
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/complete") {
			var c server.Complete
			_ = json.NewDecoder(r.Body).Decode(&c)
			f.complete = append(f.complete, c)
		}
		f.mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/test-shards"):
			idx := "1"
			total := "4"
			_, _ = io.WriteString(w, `{"env_contract":{"KIWI_TEST_SHARD_TOTAL":"`+total+`","KIWI_TEST_SHARD_INDEX":"`+idx+`"}}`)
		case strings.HasPrefix(r.URL.Path, "/api/v1/cache/") && r.Method == http.MethodGet:
			http.NotFound(w, r)
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
	evil.Job.Steps = append(evil.Job.Steps, pipeline.Step{Run: "touch " + marker})
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
	// attestation contract.
	base := "version: 1\njobs:\n  build:\n    steps:\n      - run: mkdir -p out .cache && echo hello > out/app.txt && echo c > .cache/f.txt\n    cache:\n      - name: deps\n        paths: [.cache]\n        key: v1\n    artifacts:\n      - name: app\n        paths: [out]\n"
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
	var uploads []string
	for _, p := range fsrv.pathsFor("/api/v1/jobs/job-1/artifacts/") {
		uploads = append(uploads, p)
	}
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

	// Cache PUT carries the repository/trust-domain contract headers.
	h := fsrv.headerOf(http.MethodPut, "/api/v1/cache/")
	if h == nil {
		t.Fatal("no cache PUT recorded")
	}
	if got := h.Get("X-Kiwi-Repository"); got != "https://github.com/acme/app.git" {
		t.Fatalf("cache PUT X-Kiwi-Repository = %q", got)
	}
	if got := h.Get("X-Kiwi-Trust-Domain"); got != "trusted" {
		t.Fatalf("cache PUT X-Kiwi-Trust-Domain = %q", got)
	}

	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded")
	}
	if c.Status != model.StatusSuccess {
		t.Fatalf("job status = %s (%s)", c.Status, c.Error)
	}
}

func TestExecuteInjectsTestShardEnv(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	base := "version: 1\njobs:\n  build:\n    tests:\n      shards: 4\n    steps:\n      - run: test \"$KIWI_TEST_SHARD_TOTAL\" = \"4\" && test \"$KIWI_TEST_SHARD_INDEX\" = \"1\"\n"
	task := basicTask(base)
	task.Job.CompiledJobPayload = buildPayload(t, base, "build")

	r := testRunnerFor(t, ts, Config{CaptureSnapshots: false})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644)
	}
	r.execute(context.Background(), task)

	fsrv.mu.Lock()
	queries := append([]string{}, fsrv.testShardQuery...)
	fsrv.mu.Unlock()
	if len(queries) != 1 || !strings.Contains(queries[0], "shards=4") || !strings.Contains(queries[0], "shard=1") {
		t.Fatalf("test-shards queries = %v, want shards=4 shard=1", queries)
	}
	c, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded")
	}
	if c.Status != model.StatusSuccess {
		t.Fatalf("shard env not honored: status=%s error=%s", c.Status, c.Error)
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
