package executor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
)

func TestContainerObservedRuntimeCapture(t *testing.T) {
	testutil.UnixShell(t)
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_VERSION", "27.1.2")
	t.Setenv("FAKE_DOCKER_IMAGE_DIGEST", "alpine@sha256:"+strings.Repeat("b", 64))
	ws := t.TempDir()
	b := &ContainerBackend{
		Image: "alpine:3.19", RunID: "r", JobID: "j",
		ServiceImages: map[string]string{"db": "postgres:16", "cache": "redis:7", "mirror": "postgres:16"},
	}
	if err := b.StartJob(context.Background(), ws, func(string) {}); err != nil {
		t.Fatalf("StartJob: %v", err)
	}
	obs := b.ObservedRuntime()
	if obs == nil {
		t.Fatal("ObservedRuntime = nil after a successful start")
	}
	if obs.OS != runtime.GOOS || obs.Arch != runtime.GOARCH || obs.RuntimeName != "docker" {
		t.Fatalf("platform facts = %+v", obs)
	}
	if obs.RuntimeVersion != "27.1.2" {
		t.Fatalf("runtime version = %q, want the fake docker server version", obs.RuntimeVersion)
	}
	if obs.MainImage != "alpine:3.19" {
		t.Fatalf("main image = %q", obs.MainImage)
	}
	if obs.MainImageDigest != "alpine@sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("main image digest = %q", obs.MainImageDigest)
	}
	if obs.ServiceImages["db"] != "postgres:16" || obs.ServiceImages["cache"] != "redis:7" || obs.ServiceImages["mirror"] != "postgres:16" {
		t.Fatalf("service images = %v", obs.ServiceImages)
	}
	// The deduplicated ref is inspected exactly once: db and mirror share
	// postgres:16, so the run inspects main + postgres + redis = 3 times.
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	if got := strings.Count(log, "image inspect"); got != 3 {
		t.Fatalf("image inspect calls = %d, want 3 (main + 2 distinct services):\n%s", got, log)
	}
}

func TestContainerObservedRuntimePinnedRefNeedsNoInspect(t *testing.T) {
	testutil.UnixShell(t)
	installFakeBins(t)
	pinned := "alpine@sha256:" + strings.Repeat("c", 64)
	b := &ContainerBackend{Image: pinned, RunID: "r", JobID: "j"}
	if err := b.StartJob(context.Background(), t.TempDir(), func(string) {}); err != nil {
		t.Fatalf("StartJob: %v", err)
	}
	obs := b.ObservedRuntime()
	if obs.MainImageDigest != "sha256:"+strings.Repeat("c", 64) {
		t.Fatalf("pinned main digest = %q, want the pinned digest recorded", obs.MainImageDigest)
	}
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	if strings.Contains(log, "image inspect") {
		t.Fatalf("a digest-pinned main image must not be inspected:\n%s", log)
	}
}

func TestContainerObservedRuntimeInspectOmission(t *testing.T) {
	testutil.UnixShell(t)
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_INSPECT_FAIL", "1")
	b := &ContainerBackend{
		Image: "alpine:3.19", RunID: "r", JobID: "j",
		ServiceImages: map[string]string{"db": "postgres:16"},
	}
	if err := b.StartJob(context.Background(), t.TempDir(), func(string) {}); err != nil {
		t.Fatalf("StartJob: %v", err)
	}
	obs := b.ObservedRuntime()
	if obs.MainImageDigest != "" {
		t.Fatalf("failed inspect must omit the digest, got %q", obs.MainImageDigest)
	}
	if len(obs.ServiceImageDigests) != 0 {
		t.Fatalf("failed service inspect must omit the digest, got %v", obs.ServiceImageDigests)
	}
	// The reference itself is still recorded (it is what was requested), and
	// the capture never failed the job.
	if obs.MainImage != "alpine:3.19" || obs.ServiceImages["db"] != "postgres:16" {
		t.Fatalf("references must survive an inspect failure: %+v", obs)
	}
}

func TestNativeObservedRuntime(t *testing.T) {
	obs := (&NativeBackend{}).ObservedRuntime()
	if obs == nil || obs.RuntimeName != "native" || obs.OS != runtime.GOOS || obs.Arch != runtime.GOARCH {
		t.Fatalf("native ObservedRuntime = %+v", obs)
	}
	if obs.MainImageDigest != "" || len(obs.ServiceImageDigests) != 0 {
		t.Fatalf("native must not report image digests: %+v", obs)
	}
}

func TestTartObservedRuntimeVersion(t *testing.T) {
	testutil.UnixShell(t)
	installFakeBins(t)
	t.Setenv("FAKE_TART_VERSION", "tart 2.24.1")
	tart := filepath.Join(fakeBinDir(t), "tart")
	obs := captureTartObservedRuntime(context.Background(), tart)
	if obs == nil || obs.RuntimeName != "tart" || obs.RuntimeVersion != "tart 2.24.1" {
		t.Fatalf("tart ObservedRuntime = %+v", obs)
	}
	if obs.OS != runtime.GOOS || obs.Arch != runtime.GOARCH {
		t.Fatalf("tart platform facts = %+v", obs)
	}
}

// observerFakeBackend is a Backend that reports a fixed ObservedRuntime, used
// to prove runJob surfaces the optional capture capability on the result.
type observerFakeBackend struct {
	obs *model.ObservedRuntime
}

func (*observerFakeBackend) Name() string { return "fake-observer" }

func (*observerFakeBackend) Run(context.Context, Command, func(string)) error { return nil }

func (*observerFakeBackend) ReadFile(context.Context, string, int64) ([]byte, error) {
	return nil, os.ErrNotExist
}

func (f *observerFakeBackend) ObservedRuntime() *model.ObservedRuntime { return f.obs }

func TestRunJobReturnsObservedRuntime(t *testing.T) {
	want := &model.ObservedRuntime{OS: "linux", Arch: "amd64", RuntimeName: "fake"}
	fake := &observerFakeBackend{obs: want}
	orig := backendForNetwork
	backendForNetwork = func(string, string, string, string) (Backend, error) { return fake, nil }
	t.Cleanup(func() { backendForNetwork = orig })

	ws := t.TempDir()
	ex := &Executor{Opt: Options{Workspace: ws, RunID: "r", Logs: &covSink{}}, Masker: &secrets.Masker{}}
	res := ex.RunCompiledJob(context.Background(), &pipeline.Spec{Version: 1}, pipeline.CompiledJob{
		ID:  "j",
		Job: pipeline.Job{Runtime: "native", Steps: []pipeline.Step{{Run: "true"}}},
	})
	if res.Status != model.StatusSuccess {
		t.Fatalf("runJob = %+v, want success", res)
	}
	if res.ObservedRuntime != want {
		t.Fatalf("ObservedRuntime = %+v, want the backend's captured facts", res.ObservedRuntime)
	}
}

func TestRunJobOmittedObservedRuntimeWithoutObserver(t *testing.T) {
	fake := &fakeLifecycleBackend{}
	orig := backendForNetwork
	backendForNetwork = func(string, string, string, string) (Backend, error) { return fake, nil }
	t.Cleanup(func() { backendForNetwork = orig })

	ex := &Executor{Opt: Options{Workspace: t.TempDir(), RunID: "r", Logs: &covSink{}}, Masker: &secrets.Masker{}}
	res := ex.RunCompiledJob(context.Background(), &pipeline.Spec{Version: 1}, pipeline.CompiledJob{
		ID:  "j",
		Job: pipeline.Job{Runtime: "native", Steps: []pipeline.Step{{Run: "true"}}},
	})
	if res.Status != model.StatusSuccess {
		t.Fatalf("runJob = %+v, want success", res)
	}
	if res.ObservedRuntime != nil {
		t.Fatalf("ObservedRuntime = %+v, want nil for a backend without the capability", res.ObservedRuntime)
	}
}
