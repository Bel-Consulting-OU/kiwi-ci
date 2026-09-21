package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cas"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/components"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/storage"
)

// TestSqueezeResolvePipelineLimit covers the oversized-pipeline guard.
func TestSqueezeResolvePipelineLimit(t *testing.T) {
	s := New("secret")
	if _, _, _, err := s.resolvePipeline(context.Background(), SubmitRun{Pipeline: strings.Repeat("x", maxPipelineBytes+1)}); err == nil {
		t.Fatal("oversized pipeline = nil error")
	}
}

// TestSqueezeComponentRegistrySkips covers the registry skip and unknown
// input type branches.
func TestSqueezeComponentRegistrySkips(t *testing.T) {
	t.Run("job without component", func(t *testing.T) {
		s := New("secret")
		s.ComponentRegistry = components.NewLocalRegistry()
		spec := pipeline.Spec{Jobs: map[string]pipeline.Job{"build": {Runtime: "native"}}}
		if _, err := s.resolveComponents(context.Background(), &spec); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("optional input without default", func(t *testing.T) {
		raw, err := pipeline.Parse([]byte(`version: 1
inputs:
  opt:
    type: string
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`))
		if err != nil {
			t.Fatal(err)
		}
		out, err := validateRunInputs(raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := out["opt"]; ok {
			t.Fatalf("optional input materialized: %v", out)
		}
	})
	t.Run("unknown input type", func(t *testing.T) {
		spec := pipeline.Spec{Jobs: map[string]pipeline.Job{"build": {Runtime: "native"}}, Inputs: map[string]pipeline.Input{"odd": {Type: "weird"}}}
		if _, err := validateRunInputs(&spec, map[string]string{"input.odd": "x"}); err == nil {
			t.Fatal("unknown input type = nil error")
		}
	})
}

// TestSqueezeStreamLogsReadError covers the no-store stream read refusal.
func TestSqueezeStreamLogsReadError(t *testing.T) {
	s := New("secret")
	c := newTestClient(t, s.Handler(), "secret")
	w := c.do(http.MethodGet, "/api/v1/runs/unknown-run/logs/stream", nil, nil)
	if w.Code == http.StatusOK {
		t.Fatalf("stream without storage = %d, want an error", w.Code)
	}
}

// TestSqueezeDanglingSymlinkKeyLoaders drives the MkdirAll refusals of the
// web-session and OIDC key loaders.
func TestSqueezeDanglingSymlinkKeyLoaders(t *testing.T) {
	root := t.TempDir()
	dangling := filepath.Join(root, "dangling")
	if err := os.Symlink(filepath.Join(root, "missing"), dangling); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	s := New("secret")
	if err := s.loadWebSessionSecret(dangling); err == nil {
		t.Fatal("loadWebSessionSecret over a dangling directory = nil error")
	}
	if _, err := loadOIDCSigner(dangling); err == nil {
		t.Fatal("loadOIDCSigner over a dangling directory = nil error")
	}
}

// TestSqueezeNoRedirectClient covers the default base client.
func TestSqueezeNoRedirectClient(t *testing.T) {
	c := NoRedirectClient(nil)
	if c == nil {
		t.Fatal("nil client")
	}
	resp := &http.Response{StatusCode: http.StatusOK}
	if err := c.CheckRedirect(httptest.NewRequest(http.MethodGet, "/", nil), []*http.Request{httptest.NewRequest(http.MethodGet, "/", nil)}); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy = %v, want ErrUseLastResponse", err)
	}
	_ = resp
}

// errTokenStore fails the per-runner bearer token surface.
type errTokenStore struct {
	*dbFakeStore
	lookupErr error
	hasErr    error
	upsertErr error
}

func (e errTokenStore) RunnerIDForToken(ctx context.Context, digest string) (string, bool, error) {
	if e.lookupErr != nil {
		return "", false, e.lookupErr
	}
	return e.dbFakeStore.RunnerIDForToken(ctx, digest)
}

func (e errTokenStore) HasRunnerTokens(ctx context.Context) (bool, error) {
	if e.hasErr != nil {
		return false, e.hasErr
	}
	return e.dbFakeStore.HasRunnerTokens(ctx)
}

func (e errTokenStore) UpsertRunnerToken(ctx context.Context, runnerID, digest string) error {
	if e.upsertErr != nil {
		return e.upsertErr
	}
	return e.dbFakeStore.UpsertRunnerToken(ctx, runnerID, digest)
}

// TestSqueezeRunnerTokenBranches covers the loader, the DB lookup failures
// and the provisioning refusals.
func TestSqueezeRunnerTokenBranches(t *testing.T) {
	s := New("secret")
	s.LoadRunnerTokens(map[string]string{"runner-1": "digest-1"})
	if s.runnerTokens["digest-1"] != "runner-1" {
		t.Fatalf("tokens = %v", s.runnerTokens)
	}
	if err := s.ProvisionRunnerTokensDB(context.Background(), nil); err == nil {
		t.Fatal("provision without DB = nil error")
	}

	ps, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := newDBFakeStore()
	if err := ps.SwitchToDB(f); err != nil {
		t.Fatal(err)
	}
	ps.DB = errTokenStore{dbFakeStore: f, lookupErr: errors.New("token table down")}
	if _, ok, lerr := ps.runnerBearerID(runnerTokenRequest("tok")); ok || lerr == nil {
		t.Fatalf("failing token lookup = ok=%v err=%v, want no identity and a hard error", ok, lerr)
	}

	ps2, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f2 := newDBFakeStore()
	if err := ps2.SwitchToDB(f2); err != nil {
		t.Fatal(err)
	}
	configured, cerr := ps2.runnerTokensConfigured(runnerTokenRequest("tok"))
	if cerr != nil || configured {
		t.Fatalf("no tokens configured = %v, %v", configured, cerr)
	}
	ps2.DB = errTokenStore{dbFakeStore: f2, hasErr: errors.New("token table down")}
	ps2.runnerTokensDBAt = time.Time{}
	configured, cerr = ps2.runnerTokensConfigured(runnerTokenRequest("tok"))
	if cerr == nil || configured {
		t.Fatalf("failing existence check = %v, %v; want a hard error that is never cached as not configured", configured, cerr)
	}

	ps3, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f3 := newDBFakeStore()
	if err := ps3.SwitchToDB(f3); err != nil {
		t.Fatal(err)
	}
	ps3.DB = struct{ storage.Store }{Store: f3}
	if err := ps3.ProvisionRunnerTokensDB(context.Background(), map[string]string{"r": "d"}); err == nil {
		t.Fatal("provision against a store without the token surface = nil error")
	}
	ps4, err := NewPersistent("secret", "secret", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f4 := newDBFakeStore()
	if err := ps4.SwitchToDB(f4); err != nil {
		t.Fatal(err)
	}
	ps4.DB = errTokenStore{dbFakeStore: f4, upsertErr: errors.New("insert down")}
	if err := ps4.ProvisionRunnerTokensDB(context.Background(), map[string]string{"r": "d"}); err == nil {
		t.Fatal("provision with a failing upsert = nil error")
	}
}

func runnerTokenRequest(tok string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}

// TestSqueezeMemoryArtifactReplayAndConflict covers the memory-mode artifact
// dedupe branches.
func TestSqueezeMemoryArtifactReplayAndConflict(t *testing.T) {
	s, hdrs := fcMemoryBlobServer(t)
	fcSeedContract(s, "job-a", fcBinContract())
	if w := fcUploadBlobArtifact(t, s, hdrs, "payload"); w.Code != http.StatusCreated {
		t.Fatalf("first upload = %d: %s", w.Code, w.Body.String())
	}
	if w := fcUploadBlobArtifact(t, s, hdrs, "payload"); w.Code != http.StatusOK {
		t.Fatalf("identical replay = %d, want 200: %s", w.Code, w.Body.String())
	}
	if w := fcUploadBlobArtifact(t, s, hdrs, "different-bytes"); w.Code != http.StatusConflict {
		t.Fatalf("digest conflict = %d, want 409: %s", w.Code, w.Body.String())
	}
}

// TestSqueezeStoredSnapshotVerification covers the read-back verification
// refusals.
func TestSqueezeStoredSnapshotVerification(t *testing.T) {
	mb := newMemBlob()
	c := cas.New(mb)
	obj, err := c.Put(context.Background(), strings.NewReader("snapshot-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyStoredSnapshot(context.Background(), c, strings.Repeat("0", 64), obj.Size); err == nil {
		t.Fatal("digest mismatch = nil error")
	}
	if err := verifyStoredSnapshot(context.Background(), c, obj.SHA256, obj.Size+5); err == nil {
		t.Fatal("size mismatch = nil error")
	}
	if err := verifyStoredSnapshot(context.Background(), c, obj.SHA256, obj.Size); err != nil {
		t.Fatalf("valid snapshot = %v", err)
	}

}

// TestSqueezeScheduleSpecEdges covers the spec parser and sanitizer edges.
func TestSqueezeScheduleSpecEdges(t *testing.T) {
	if _, _, err := parseScheduleSpec("jobs: {}\n"); err == nil {
		t.Fatal("schedule without jobs = nil error")
	}
	raw := `on:
  schedule: "@daily"
jobs:
  build:
    runtime: native
    steps:
      - run: echo hi
`
	sanitized := sanitizeScheduleSpec(raw)
	if strings.Contains(sanitized, "schedule") {
		t.Fatalf("sanitizer kept the schedule trigger: %s", sanitized)
	}
	if got := sanitizeScheduleSpec("{{not yaml"); got != "{{not yaml" {
		t.Fatalf("unparseable spec = %q", got)
	}
}

// TestSqueezeSweepTempFiles covers the temp-file sweep guards.
func TestSqueezeSweepTempFiles(t *testing.T) {
	root := t.TempDir()
	artifacts := filepath.Join(root, "artifacts")
	deep := filepath.Join(artifacts, "run-1", "job-1")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	stale := filepath.Join(artifacts, "stale.tmp")
	if err := os.WriteFile(stale, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	// A non-temp file and a fresh temp file are both left alone.
	if err := os.WriteFile(filepath.Join(artifacts, "keep.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(artifacts, "fresh.tmp")
	if err := os.WriteFile(fresh, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The recursive walk finds stale scratch files two levels down.
	deepStale := filepath.Join(deep, ".upload.tmp")
	if err := os.WriteFile(deepStale, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(deepStale, old, old); err != nil {
		t.Fatal(err)
	}
	removed := sweepTempFiles(root, time.Now())
	if removed != 2 {
		t.Fatalf("sweep removed %d entries, want 2", removed)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale temp survived: %v", err)
	}
	if _, err := os.Stat(deepStale); !os.IsNotExist(err) {
		t.Fatalf("deep stale temp survived: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("fresh temp removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(artifacts, "keep.txt")); err != nil {
		t.Fatalf("non-temp file removed: %v", err)
	}
}

// TestSqueezeLoadLeaseKeyEdges covers the temporary-file refusal.
func TestSqueezeLoadLeaseKeyEdges(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "lease.key.tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLeaseKey(dir); err == nil {
		t.Fatal("lease key write over a directory = nil error")
	}
}

// TestSqueezeClusterLoaderErrors drives the per-kind cluster loader error
// returns with valid preceding material.
func TestSqueezeClusterLoaderErrors(t *testing.T) {
	valid := map[string][]byte{}
	for _, kind := range []string{clusterKindOIDC, clusterKindLease, clusterKindProvenance, clusterKindCacheSigning, clusterKindWebSession, clusterKindRunnerCA} {
		b, err := createClusterKey(kind)
		if err != nil {
			t.Fatal(err)
		}
		valid[kind] = b
	}
	cases := []struct {
		name  string
		kind  string
		bytes []byte
	}{
		{"lease load error", clusterKindLease, []byte("short")},
		{"runner ca error", clusterKindRunnerCA, []byte("junk")},
		{"provenance pem error", clusterKindProvenance, []byte("junk")},
		{"cache pem error", clusterKindCacheSigning, []byte("junk")},
		{"web session error", clusterKindWebSession, []byte("short")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := map[string][]byte{}
			for k, v := range valid {
				m[k] = v
			}
			m[tc.kind] = tc.bytes
			store := mapClusterStore{m}
			if _, err := NewPersistentWithCluster("t", "t", t.TempDir(), store); err == nil {
				t.Fatalf("%s = nil error", tc.name)
			}
		})
	}
}

// mapClusterStore returns per-kind material from a map (missing kinds fail).
type mapClusterStore struct{ m map[string][]byte }

func (s mapClusterStore) LoadOrCreate(kind string) ([]byte, error) {
	if b, ok := s.m[kind]; ok {
		return b, nil
	}
	return nil, errors.New("cluster key kind missing")
}
