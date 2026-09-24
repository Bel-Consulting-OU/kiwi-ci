package executor

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/cache"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

func TestRunJobContainerFullPath(t *testing.T) {
	installFakeBins(t)
	ws := canonicalTempDir(t)
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	sink := &covSink{}
	ex := &Executor{Opt: Options{Workspace: ws, Logs: sink, RunID: "run-c"}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "cj", Job: pipeline.Job{
			Runtime: "container", Image: "alpine:3.19",
			Resources: pipeline.Resources{CPU: 1, Memory: 1 << 20},
			Services:  []pipeline.Service{{Name: "redis", Image: "redis:7"}},
			Outputs:   map[string]string{"OUT": "${{ steps.out.outputs.K }}"},
			Steps:     []pipeline.Step{{ID: "out", Run: `printf 'K=v\n' > "$KIWI_OUTPUT"`}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess {
		t.Fatalf("container job = %+v", res)
	}
	if res.Outputs["OUT"] != "v" {
		t.Fatalf("container outputs = %+v", res.Outputs)
	}
	if !sink.has("service redis started") {
		t.Fatalf("service start not logged: %v", sink.lines)
	}
}

func TestRunJobContainerRootlessGuards(t *testing.T) {
	ws := t.TempDir()
	// Docker is not on PATH.
	t.Setenv("PATH", t.TempDir())
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r"}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "cj", Job: pipeline.Job{Runtime: "container", Image: "alpine:3.19", Sandbox: pipeline.Sandbox{Rootless: true},
			Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || !strings.Contains(res.Error, "docker not found") {
		t.Fatalf("rootless without docker = %+v", res)
	}
	// A rootful daemon is refused before services start.
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_INFO", "[name=seccomp,profile=builtin]")
	res = ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "cj", Job: pipeline.Job{Runtime: "container", Image: "alpine:3.19", Sandbox: pipeline.Sandbox{Rootless: true},
			Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || !strings.Contains(res.Error, "not rootless") {
		t.Fatalf("rootful daemon job = %+v", res)
	}
	t.Setenv("FAKE_DOCKER_INFO", "")
}

func TestRunJobContainerStartAndCloseFailures(t *testing.T) {
	installFakeBins(t)
	ws := canonicalTempDir(t)
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	sink := &covSink{}
	ex := &Executor{Opt: Options{Workspace: ws, Logs: sink, RunID: "r"}, Masker: &secrets.Masker{}}
	// A missing image fails StartJob.
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "cj", Job: pipeline.Job{Runtime: "container", Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || !strings.Contains(res.Error, "job.image") {
		t.Fatalf("container without image = %+v", res)
	}
	// A failing CloseJob is only a warning.
	t.Setenv("FAKE_DOCKER_RM_EXIT", "1")
	res = ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "cj", Job: pipeline.Job{Runtime: "container", Image: "alpine:3.19", Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess || !sink.has("cleanup warning") {
		t.Fatalf("close failure = %+v (%v)", res, sink.lines)
	}
}

func TestRunJobUnknownRuntimeAndNetworkNone(t *testing.T) {
	ws := t.TempDir()
	sink := &covSink{}
	ex := &Executor{Opt: Options{Workspace: ws, Logs: sink, RunID: "r"}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "cj", Job: pipeline.Job{Runtime: "bogus", Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || !strings.Contains(res.Error, "unknown backend") {
		t.Fatalf("unknown runtime = %+v", res)
	}
	// A native job with network "none" disables networking and logs the
	// unenforceable resource requests.
	res = ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "cj", Job: pipeline.Job{
			Runtime: "native", Network: "none",
			Resources: pipeline.Resources{CPU: 1, Memory: 1 << 20, Disk: 1 << 20, PIDs: 2},
			Steps:     []pipeline.Step{{Run: "true"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess || !sink.has("advisory") {
		t.Fatalf("native advisory = %+v (%v)", res, sink.lines)
	}
}

func TestRunJobTartFullPath(t *testing.T) {
	if runtime.GOOS != "darwin" {
		// The tart backend is refused on every other platform before a VM
		// can be started, so the end-to-end path is darwin-only.
		t.Skip("tart backend is darwin-only")
	}
	installFakeBins(t)
	ws := canonicalTempDir(t)
	t.Setenv("FAKE_WS", ws)
	ln, agentPort := listenTartAgentBootstrap(t)
	agent := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = agent.Serve(ln) }()
	t.Cleanup(func() { _ = agent.Close() })
	t.Setenv("FAKE_TART_RUN_SLEEP", "1")
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", TartAgentPort: agentPort}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "tj", Job: pipeline.Job{
			Runtime: "tart", VM: "ghcr.io/x/macos:latest", Resources: pipeline.Resources{CPU: 2},
			Steps: []pipeline.Step{{Run: "echo tart-step-ok"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess {
		t.Fatalf("tart job = %+v", res)
	}
}

func TestRunJobContainerGenerateAndOutputReads(t *testing.T) {
	installFakeBins(t)
	ws := canonicalTempDir(t)
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	var uploaded []byte
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r",
		GenerateUpload: func(jobID, path string, data []byte) error { uploaded = data; return nil }}, Masker: &secrets.Masker{}, sessions: &sessionRegistry{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "cj", Job: pipeline.Job{
			Runtime: "container", Image: "alpine:3.19",
			Generate: pipeline.GenerateSpec{Path: "frag.yaml"},
			Outputs:  map[string]string{"OUT": "${{ steps.gen.outputs.A }}"},
			Steps: []pipeline.Step{{
				ID:  "gen",
				Run: `printf 'child: 1\n' > frag.yaml; printf 'A=b\n' > "$KIWI_OUTPUT"`,
			}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess || string(uploaded) != "child: 1\n" || res.Outputs["OUT"] != "b" {
		t.Fatalf("container generate = %+v uploaded=%q", res, uploaded)
	}
}

func TestRunJobCacheFallbackAndWarnings(t *testing.T) {
	ws1 := canonicalTempDir(t)
	ws2 := canonicalTempDir(t)
	store := cacheStoreAt(t)
	sink := &covSink{}
	ex1 := &Executor{Opt: Options{Workspace: ws1, Logs: sink, RunID: "r", Cache: store}, Masker: &secrets.Masker{}}
	res := ex1.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j1", Job: pipeline.Job{
			Cache: []pipeline.Cache{{Name: "fb", Key: "fallback-key", Paths: []string{"data"}}},
			Steps: []pipeline.Step{{Run: "mkdir -p data && echo x > data/f"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess {
		t.Fatalf("seeding cache = %+v", res)
	}
	// The primary key misses and the restore key hits (fallback label).
	sink.lines = nil
	ex2 := &Executor{Opt: Options{Workspace: ws2, Logs: sink, RunID: "r", Cache: store}, Masker: &secrets.Masker{}}
	res = ex2.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j2", Job: pipeline.Job{
			Cache: []pipeline.Cache{{Name: "fb", Key: "primary-key", RestoreKeys: []string{"fallback-key"}, Paths: []string{"data"}}},
			Steps: []pipeline.Step{{Run: "test -f data/f"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess || !sink.has("via fallback") {
		t.Fatalf("cache fallback = %+v (%v)", res, sink.lines)
	}
	// A restore error logs a warning and falls through to a miss + save.
	sink.lines = nil
	fileAsRoot := filepath.Join(t.TempDir(), "cache-root")
	if err := os.WriteFile(fileAsRoot, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ex3 := &Executor{Opt: Options{Workspace: canonicalTempDir(t), Logs: sink, RunID: "r", Cache: &cache.Store{Root: fileAsRoot}}, Masker: &secrets.Masker{}}
	res = ex3.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j3", Job: pipeline.Job{
			Cache: []pipeline.Cache{{Name: "bad", Key: "k", Paths: []string{"data"}}},
			Steps: []pipeline.Step{{Run: "true"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess || !sink.has("restore warning") || !sink.has("save warning") {
		t.Fatalf("cache warning paths = %+v (%v)", res, sink.lines)
	}
}

func TestRunJobStepRetryCancelDuringBackoff(t *testing.T) {
	ws := t.TempDir()
	sink := &covSink{}
	ex := &Executor{Opt: Options{Workspace: ws, Logs: sink, RunID: "r"}, Masker: &secrets.Masker{}}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	res := ex.runJob(ctx, &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{{
			Name:  "flaky",
			Run:   "exit 1",
			Retry: pipeline.Retry{Max: 3, Backoff: pipeline.Duration{Duration: 10 * time.Second}},
		}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusCancelled {
		t.Fatalf("retry cancel = %+v", res)
	}
}

func TestRunJobSnapshotFailures(t *testing.T) {
	// TMPDIR unavailable: the snapshot mkdir fails.
	ws := t.TempDir()
	sink := &covSink{}
	ex := &Executor{Opt: Options{Workspace: ws, Logs: sink, RunID: "snap1", CaptureSnapshot: true}, Masker: &secrets.Masker{}}
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing-root"))
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess || !sink.has("snapshot") {
		t.Fatalf("snapshot mkdir failure = %+v", res)
	}
	// The snapshot destination is a directory: os.Create fails.
	installRealTmp(t)
	sink.lines = nil
	runID := "snap2"
	dest := filepath.Join(os.TempDir(), "kiwi-snapshots", runID, "j.tar.gz")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(os.TempDir(), "kiwi-snapshots", runID)) })
	ex2 := &Executor{Opt: Options{Workspace: ws, Logs: sink, RunID: runID, CaptureSnapshot: true}, Masker: &secrets.Masker{}}
	res = ex2.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess || !sink.has("snapshot") {
		t.Fatalf("snapshot create failure = %+v", res)
	}
	// The workspace is not a directory: snapshot.Create fails.
	sink.lines = nil
	missingWs := filepath.Join(t.TempDir(), "gone")
	ex3 := &Executor{Opt: Options{Workspace: missingWs, Logs: sink, RunID: "snap3", CaptureSnapshot: true}, Masker: &secrets.Masker{}}
	res = ex3.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || !sink.has("snapshot") {
		t.Fatalf("snapshot capture failure = %+v", res)
	}
}

// installRealTmp restores a working TMPDIR for the rest of the test.
func installRealTmp(t *testing.T) {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
}

func TestRunJobArtifactSaveWarning(t *testing.T) {
	ws := t.TempDir()
	sink := &covSink{}
	rootAsFile := filepath.Join(t.TempDir(), "artifacts")
	if err := os.WriteFile(rootAsFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ex := &Executor{Opt: Options{Workspace: ws, Logs: sink, RunID: "r", Artifacts: artifactStoreAt(t, rootAsFile)}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{
			Artifacts: []pipeline.Artifact{{Name: "a", Paths: []string{"out.txt"}}},
			Steps:     []pipeline.Step{{Run: "echo x > out.txt"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess || !sink.has("save warning") {
		t.Fatalf("artifact save warning = %+v (%v)", res, sink.lines)
	}
}

func TestRunJobStepOutputReadError(t *testing.T) {
	ws := t.TempDir()
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r"}, Masker: &secrets.Masker{}}
	// A directory at the output path makes the read fail (native reads
	// refuse directories).
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{{ID: "out", Run: "mkdir -p \"$KIWI_OUTPUT\""}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || !strings.Contains(res.Error, "step outputs") {
		t.Fatalf("directory output = %+v", res)
	}
}

func TestRunJobDependencyOutputInterpolation(t *testing.T) {
	ws := t.TempDir()
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r"}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{
			Env:     map[string]string{"FROM_DEP": "${{ needs.build.outputs.VERSION }}"},
			Outputs: map[string]string{"COPY": "${{ steps.gen.outputs.V }}"},
			Steps: []pipeline.Step{{
				ID:  "gen",
				Run: `printf 'V=42\n' > "$KIWI_OUTPUT"; test "$FROM_DEP" = "1.2.3"`,
			}},
		},
	}, model.StatusSuccess, map[string]map[string]string{"build": {"VERSION": "1.2.3"}})
	if res.Status != model.StatusSuccess || res.Outputs["COPY"] != "42" {
		t.Fatalf("interpolation = %+v", res)
	}
}

func TestRunJobSecretProviderError(t *testing.T) {
	ws := t.TempDir()
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", SecretProvider: errorProvider{}}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{
		Secrets: []string{"missing"},
	}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusFailure || !strings.Contains(res.Error, "provider down") {
		t.Fatalf("secret provider error = %+v", res)
	}
}

type errorProvider struct{}

func (errorProvider) Get(context.Context, string) (string, error) {
	return "", errors.New("provider down")
}
