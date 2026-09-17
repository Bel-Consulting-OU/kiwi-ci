package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// cacheFake is a job-scoped cache endpoint backed by memory.
type cacheFake struct {
	mu     sync.Mutex
	bodies map[string][]byte
	puts   int
}

func (c *cacheFake) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		key := strings.TrimPrefix(r.URL.Path, "/api/v1/jobs/job-1/cache/")
		if key == r.URL.Path {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodPut:
			c.puts++
			body, _ := io.ReadAll(r.Body)
			if c.bodies == nil {
				c.bodies = map[string][]byte{}
			}
			c.bodies[key] = body
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			body, ok := c.bodies[key]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(body)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	})
}

func TestJobCacheStoreRoundTrip(t *testing.T) {
	cf := &cacheFake{}
	ts := httptest.NewServer(cf.handler(t))
	defer ts.Close()
	metrics := NewMetrics()
	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL, CacheRoot: t.TempDir()},
		Client: &http.Client{Timeout: 10 * time.Second}, Metrics: metrics}
	task := server.Task{Job: model.Job{ID: "job-1"}, LeaseToken: "lease", LeaseGeneration: 2}
	store := r.newJobCache(task, metrics)
	if store.RemoteURL != ts.URL || store.Root == "" || store.Client == nil {
		t.Fatalf("store = %+v", store)
	}
	wsA := canonicalRunnerDir(t)
	if err := os.MkdirAll(filepath.Join(wsA, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wsA, "data", "f"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(strings.Repeat("a", 64), wsA, []string{"data"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if cf.puts != 1 {
		t.Fatalf("puts = %d", cf.puts)
	}
	wsB := canonicalRunnerDir(t)
	hit, err := store.Restore(strings.Repeat("a", 64), wsB, []string{"data"})
	if err != nil || !hit {
		t.Fatalf("restore = %v, %v", hit, err)
	}
	if b, err := os.ReadFile(filepath.Join(wsB, "data", "f")); err != nil || string(b) != "payload" {
		t.Fatalf("restored file = %q, %v", b, err)
	}
	// A missing key is a remote 404 and counts as a miss.
	hit, err = store.Restore(strings.Repeat("b", 64), canonicalRunnerDir(t), []string{"data"})
	if err != nil || hit {
		t.Fatalf("absent restore = %v, %v", hit, err)
	}
}

func TestCacheTransportPassthroughAndErrors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("passthrough"))
	}))
	defer ts.Close()
	// nil client: the default transport handles the request.
	tr := &cacheTransport{}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/other", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("nil-client passthrough = %v, %v", resp, err)
	}
	_ = resp.Body.Close()
	// A client with its own transport is used instead.
	seen := false
	inner := roundTripFunc(func(*http.Request) (*http.Response, error) {
		seen = true
		return &http.Response{StatusCode: http.StatusTeapot, Body: http.NoBody, Header: http.Header{}}, nil
	})
	tr = &cacheTransport{client: &cache.Client{HTTP: &http.Client{Transport: inner}}}
	resp, err = tr.RoundTrip(req)
	if err != nil || !seen || resp.StatusCode != http.StatusTeapot {
		t.Fatalf("client passthrough = %v, %v, seen=%v", resp, err, seen)
	}
	// A GET preflight failure surfaces as an error.
	rootAsFile := filepath.Join(t.TempDir(), "root")
	if err := os.WriteFile(rootAsFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr = &cacheTransport{client: &cache.Client{Server: ts.URL, Token: "t"}, jobID: "j", root: rootAsFile, maxDisk: 1 << 62}
	req, _ = http.NewRequest(http.MethodGet, ts.URL+cacheRoutePrefix+"key", nil)
	if _, err := tr.RoundTrip(req); err == nil {
		t.Fatal("preflight failure not surfaced")
	}
	// An unsupported method falls through to the passthrough.
	tr = &cacheTransport{client: &cache.Client{HTTP: &http.Client{Transport: inner}}}
	req, _ = http.NewRequest(http.MethodDelete, ts.URL+cacheRoutePrefix+"key", nil)
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("DELETE passthrough: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCacheTransportUploadAndRestoreFailures(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer failing.Close()
	metrics := NewMetrics()
	tr := &cacheTransport{
		client:  &cache.Client{Server: failing.URL, Token: "t", HTTP: &http.Client{Timeout: time.Second}},
		jobID:   "j",
		lease:   map[string]string{cache.HeaderRunnerID: "r"},
		root:    t.TempDir(),
		metrics: metrics,
	}
	req, _ := http.NewRequest(http.MethodPut, failing.URL+cacheRoutePrefix+"key", strings.NewReader("x"))
	if _, err := tr.RoundTrip(req); err == nil {
		t.Fatal("failing upload accepted")
	}
	req, _ = http.NewRequest(http.MethodGet, failing.URL+cacheRoutePrefix+"key", nil)
	if _, err := tr.RoundTrip(req); err == nil {
		t.Fatal("failing restore accepted")
	}
}

func TestCheckoutViaFakeGit(t *testing.T) {
	bin := t.TempDir()
	script := `#!/bin/sh
echo "$@" >> "${FAKE_GIT_LOG:-/dev/null}"
if [ "$1" = "clone" ]; then
  if [ -n "$FAKE_GIT_FAIL_CLONE" ]; then echo "clone refused" >&2; exit 1; fi
  exit 0
fi
if [ "$3" = "checkout" ] && [ -n "$FAKE_GIT_FAIL_CHECKOUT" ]; then echo "checkout refused" >&2; exit 1; fi
exit 0
`
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("FAKE_GIT_LOG", filepath.Join(t.TempDir(), "git.log"))
	t.Setenv("KIWI_GIT_ALLOWED_HTTPS_HOSTS", "example.com")
	r := &Runner{ID: "r", Cfg: Config{}, Client: &http.Client{Timeout: 30 * time.Second}, Metrics: NewMetrics()}
	job := model.Job{RepoURL: "https://example.com/acme/app.git", Ref: "main"}
	if err := r.checkout(context.Background(), job, filepath.Join(t.TempDir(), "clone")); err != nil {
		t.Fatalf("checkout: %v", err)
	}
	// SHA is preferred over ref.
	if err := r.checkout(context.Background(), model.Job{RepoURL: job.RepoURL, SHA: "deadbeef"}, filepath.Join(t.TempDir(), "clone2")); err != nil {
		t.Fatalf("sha checkout: %v", err)
	}
	// Neither ref nor SHA defaults to HEAD.
	if err := r.checkout(context.Background(), model.Job{RepoURL: job.RepoURL}, filepath.Join(t.TempDir(), "clone3")); err != nil {
		t.Fatalf("HEAD checkout: %v", err)
	}
	log, _ := os.ReadFile(os.Getenv("FAKE_GIT_LOG"))
	if !strings.Contains(string(log), "checkout --force main") || !strings.Contains(string(log), "checkout --force deadbeef") || !strings.Contains(string(log), "checkout --force HEAD") {
		t.Fatalf("git invocations = %s", log)
	}
	// The clone URL scheme is validated before git runs.
	if err := r.checkout(context.Background(), model.Job{RepoURL: "http://[::1"}, filepath.Join(t.TempDir(), "bad")); err == nil {
		t.Fatal("invalid repo URL accepted")
	}
	// Clone failure.
	t.Setenv("FAKE_GIT_FAIL_CLONE", "1")
	if err := r.checkout(context.Background(), job, filepath.Join(t.TempDir(), "clone4")); err == nil {
		t.Fatal("clone failure accepted")
	}
	// Checkout failure.
	t.Setenv("FAKE_GIT_FAIL_CLONE", "")
	t.Setenv("FAKE_GIT_FAIL_CHECKOUT", "1")
	if err := r.checkout(context.Background(), job, filepath.Join(t.TempDir(), "clone5")); err == nil {
		t.Fatal("checkout failure accepted")
	}
	// checkoutTask routes through the same path.
	t.Setenv("FAKE_GIT_FAIL_CHECKOUT", "")
	if err := r.checkoutTask(context.Background(), job, filepath.Join(t.TempDir(), "clone6")); err != nil {
		t.Fatalf("checkoutTask: %v", err)
	}
}

func TestRunRejectsInvalidConfiguration(t *testing.T) {
	r := &Runner{ID: "r", Cfg: Config{Prewarm: []string{"mutable:latest"}}}
	if err := r.Run(context.Background()); err == nil {
		t.Fatal("unpinned prewarm ref accepted")
	}
	r = &Runner{ID: "r", Cfg: Config{Server: "http://[::1"}}
	if err := r.Run(context.Background()); err == nil {
		t.Fatal("invalid server URL accepted")
	}
	r = &Runner{ID: "r", Cfg: Config{Server: "http://127.0.0.1:1", Cert: "missing.pem", Key: "missing.key"}}
	if err := r.Run(context.Background()); err == nil {
		t.Fatal("missing runner certificate accepted")
	}
	r = &Runner{ID: "r", Cfg: Config{Server: "http://127.0.0.1:1", CACert: "missing.pem"}}
	if err := r.Run(context.Background()); err == nil {
		t.Fatal("missing runner CA accepted")
	}
	r = &Runner{ID: "r", Cfg: Config{Server: "http://127.0.0.1:1", Cert: "missing.pem"}}
	if err := r.Run(context.Background()); err == nil {
		t.Fatal("certificate without a key accepted")
	}
}

func TestRunMetricsListenerAndCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Registration succeeds; the task long-poll returns no content.
		if strings.HasSuffix(r.URL.Path, "/tasks/next") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/heartbeat") {
			_, _ = w.Write([]byte(`{"lease_expires_at":"` + time.Now().Add(time.Minute).UTC().Format(time.RFC3339) + `"}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/register") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"runner-1"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	addr := freeRunnerAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL, Name: "cov", MetricsListen: addr,
		WorkDir: t.TempDir(), IdentityDir: t.TempDir(), Poll: 10 * time.Millisecond,
		GCInterval: 0, PrewarmInterval: 0}, Client: &http.Client{Timeout: 5 * time.Second}, Metrics: NewMetrics()}
	errCh := make(chan error, 1)
	go func() { errCh <- r.Run(ctx) }()
	waitRunnerTCP(t, addr)
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	_ = resp.Body.Close()
	cancel()
	select {
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestExecuteErrorBranches(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	sink := &covRunnerSink{}
	r := testRunnerFor(t, ts, Config{})
	r.Cfg.WorkDir = t.TempDir()
	// The pipeline does not compile.
	task := basicTask("version: 1\njobs:\n  build:\n    steps: []\n")
	r.execute(context.Background(), task)
	if c, ok := fsrv.lastComplete(); !ok || c.Status == model.StatusSuccess {
		t.Fatalf("uncompilable job complete = %+v", c)
	}
	// The job key is not in the pipeline.
	task = basicTask("version: 1\njobs:\n  other:\n    steps:\n      - run: echo hi\n")
	r.execute(context.Background(), task)
	if c, _ := fsrv.lastComplete(); c.Status == model.StatusSuccess {
		t.Fatalf("unknown job complete = %+v", c)
	}
	// A sandbox payload that cannot decode is refused.
	task = basicTask("version: 1\njobs:\n  build:\n    steps:\n      - run: echo hi\n")
	task.Job.CompiledJobPayload = &model.CompiledJobPayload{SchemaVersion: 1, EffectivePolicy: json.RawMessage(`"not-an-object"`)}
	r.execute(context.Background(), task)
	if c, _ := fsrv.lastComplete(); c.Status == model.StatusSuccess {
		t.Fatalf("bad sandbox payload complete = %+v", c)
	}
	_ = sink
}

type covRunnerSink struct{}

func (covRunnerSink) WriteLine(string, string, string) {}

func TestRestoreDownloadsErrors(t *testing.T) {
	server500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no dependency", http.StatusNotFound)
	}))
	defer server500.Close()
	r := &Runner{ID: "r", Cfg: Config{Server: server500.URL}, Client: server500.Client(), Metrics: NewMetrics()}
	task := server.Task{Job: model.Job{ID: "job-1"}, LeaseToken: "lease", LeaseGeneration: 1}
	ws := t.TempDir()
	if err := r.restoreDownloads(context.Background(), task, []pipeline.ArtifactInput{{From: "a", Name: "b", Path: "../escape"}}, ws); err == nil {
		t.Fatal("unsafe dest accepted")
	}
	if err := r.restoreDownloads(context.Background(), task, []pipeline.ArtifactInput{{Name: "b"}}, ws); err == nil {
		t.Fatal("missing producer accepted")
	}
	if err := r.restoreDownloads(context.Background(), task, []pipeline.ArtifactInput{{From: "a", Name: "b"}}, ws); err == nil {
		t.Fatal("404 dependency accepted")
	}
	// An integrity mismatch is refused.
	body := []byte("not really an archive")
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Kiwi-Content-SHA256", strings.Repeat("0", 64))
		_, _ = w.Write(body)
	}))
	defer bad.Close()
	r = &Runner{ID: "r", Cfg: Config{Server: bad.URL}, Client: bad.Client(), Metrics: NewMetrics()}
	if err := r.restoreDownloads(context.Background(), task, []pipeline.ArtifactInput{{From: "a", Name: "b"}}, ws); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	// A non-archive body without digest headers fails extraction.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer plain.Close()
	r = &Runner{ID: "r", Cfg: Config{Server: plain.URL}, Client: plain.Client(), Metrics: NewMetrics()}
	if err := r.restoreDownloads(context.Background(), task, []pipeline.ArtifactInput{{From: "a", Name: "b"}}, ws); err == nil {
		t.Fatal("non-archive accepted")
	}
}

func TestUploadArtifactAndFragmentErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	r := &Runner{ID: "r", Cfg: Config{Server: srv.URL}, Client: srv.Client(), Metrics: NewMetrics()}
	task := server.Task{Job: model.Job{ID: "job-1"}}
	if err := r.uploadArtifact(context.Background(), task, "a", filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing artifact file accepted")
	}
	art := filepath.Join(t.TempDir(), "art.tar.gz")
	if err := os.WriteFile(art, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.uploadArtifact(context.Background(), task, "a", art); err == nil {
		t.Fatal("failing artifact upload accepted")
	}
	// Generated fragments: invalid JSON, missing id, escaping path.
	if err := r.uploadGeneratedFragmentData(context.Background(), task, "../x", []byte("{}")); err == nil {
		t.Fatal("escaping fragment path accepted")
	}
	if err := r.uploadGeneratedFragmentData(context.Background(), task, "frag.json", []byte("{")); err == nil {
		t.Fatal("malformed fragment accepted")
	}
	if err := r.uploadGeneratedFragmentData(context.Background(), task, "frag.json", []byte(`{}`)); err == nil {
		t.Fatal("fragment without an id accepted")
	}
	_ = sha256.Sum256
	_ = hex.EncodeToString
	_ = fmt.Sprint
	_ = bytes.NewReader
}

func TestUploadJobSnapshotErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer srv.Close()
	r := &Runner{ID: "r", Cfg: Config{Server: srv.URL}, Client: srv.Client(), Metrics: NewMetrics()}
	task := server.Task{Job: model.Job{ID: "job-1"}}
	if err := r.uploadJobSnapshot(context.Background(), task, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing workspace accepted")
	}
	if err := r.uploadJobSnapshot(context.Background(), task, t.TempDir()); err == nil {
		t.Fatal("failing snapshot upload accepted")
	}
}

func TestNextResponses(t *testing.T) {
	status := http.StatusNoContent
	var body string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()
	r := &Runner{ID: "r", Cfg: Config{Server: ts.URL}, Client: ts.Client(), Metrics: NewMetrics()}
	if task, ok, err := r.next(context.Background()); err != nil || task != nil || ok {
		t.Fatalf("204 next = %v %v %v", task, ok, err)
	}
	status = http.StatusUnauthorized
	body = "gone"
	if _, _, err := r.next(context.Background()); err == nil {
		t.Fatal("401 next accepted")
	}
	status = http.StatusOK
	body = "{"
	if _, _, err := r.next(context.Background()); err == nil {
		t.Fatal("malformed task accepted")
	}
	// A malformed server URL fails the request build.
	bad := &Runner{ID: "r", Cfg: Config{Server: "http://[::1"}, Client: ts.Client(), Metrics: NewMetrics()}
	if _, _, err := bad.next(context.Background()); err == nil {
		t.Fatal("malformed URL accepted")
	}
}

func TestRegisterDisabledClearsCert(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "revoked", http.StatusForbidden)
	}))
	defer ts.Close()
	dir := t.TempDir()
	store := IdentityStore{Dir: dir}
	if err := store.Save(Identity{ID: "runner-1", KeyPEM: []byte("k"), CertPEM: []byte("c")}); err != nil {
		t.Fatal(err)
	}
	r := &Runner{ID: "runner-1", Cfg: Config{Server: ts.URL, IdentityDir: dir}, Client: ts.Client(), Metrics: NewMetrics(),
		store: IdentityStore{Dir: dir}}
	err := r.register(context.Background())
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("register = %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, identityCertFile)); !os.IsNotExist(serr) {
		t.Fatal("revoked registration did not clear the certificate")
	}
	if _, ok := store.LoadID(); !ok {
		t.Fatal("clear-cert dropped the runner ID")
	}
}

func TestHeartbeatLoopTransientErrorKeepsGoing(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer ts.Close()
	r := &Runner{ID: "r", Cfg: Config{Server: ts.URL, Heartbeat: 10 * time.Millisecond}, Client: ts.Client(), Metrics: NewMetrics()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go r.heartbeatLoop(ctx, cancel, basicTask("version: 1\njobs: {}\n"), done)
	time.Sleep(60 * time.Millisecond)
	close(done)
	cancel()
}

func canonicalRunnerDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		return resolved
	}
	return dir
}
