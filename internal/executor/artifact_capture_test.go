package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/artifact"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

// writeCaptureFile creates an incompressible workspace file so capture-size
// assertions do not depend on gzip ratios.
func writeCaptureFile(t *testing.T, dir, name string, n int) {
	t.Helper()
	data := make([]byte, n)
	state := uint32(0x9e3779b9)
	for i := range data {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		data[i] = byte(state)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// filesUnder lists regular files under root.
func filesUnder(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestArtifactCaptureBoundsReservesAndCleansUp pins the distributed capture
// contract end to end: the reservation is min(global ceiling, declared
// max_size), the archive exists while the reporter runs, and both the archive
// and its manifest are gone (and the reservation released) when runJob
// returns.
func TestArtifactCaptureBoundsReservesAndCleansUp(t *testing.T) {
	ws := t.TempDir()
	writeCaptureFile(t, ws, "out.bin", 2048)
	artRoot := t.TempDir()
	sink := &covSink{}
	var (
		mu       sync.Mutex
		reserved []int64
		released int
		archived string
	)
	ex := &Executor{Opt: Options{
		Workspace: ws, Logs: sink, RunID: "run-cap", Artifacts: artifactStoreAt(t, artRoot),
		ArtifactCapture: &ArtifactCapture{
			Context:  context.Background(),
			MaxBytes: 1 << 20,
			Reserve: func(_ context.Context, n int64) (func(string) error, error) {
				mu.Lock()
				reserved = append(reserved, n)
				mu.Unlock()
				return func(path string) error {
					if path != "" {
						if err := artifact.RemoveCaptured(path); err != nil {
							return err
						}
					}
					mu.Lock()
					released++
					mu.Unlock()
					return nil
				}, nil
			},
		},
		ArtifactReporter: func(_ string, _ string, path string) error {
			archived = path
			if _, err := os.Stat(path); err != nil {
				return err
			}
			if _, err := os.Stat(path + ".manifest.json"); err != nil {
				return err
			}
			return nil
		},
	}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{
			Artifacts: []pipeline.Artifact{{Name: "art", Paths: []string{"out.bin"}, MaxSize: pipeline.ByteSize(4096)}},
			Steps:     []pipeline.Step{{Run: "true"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess {
		t.Fatalf("capture job = %+v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reserved) != 1 || reserved[0] != 4096 {
		t.Fatalf("reservations = %v, want exactly [4096] (min(global, declared))", reserved)
	}
	if released != 1 {
		t.Fatalf("releases = %d, want 1", released)
	}
	if archived == "" {
		t.Fatal("artifact was never delivered")
	}
	if _, err := os.Stat(archived); !os.IsNotExist(err) {
		t.Fatalf("archive survived delivery: %v", err)
	}
	if _, err := os.Stat(archived + ".manifest.json"); !os.IsNotExist(err) {
		t.Fatalf("manifest survived delivery: %v", err)
	}
	if left := filesUnder(t, artRoot); len(left) != 0 {
		t.Fatalf("capture tree not empty after delivery: %v", left)
	}
}

// TestArtifactCaptureDeclaredMaxSizeRefused pins the declaration contract:
// an artifact larger than its declared max_size is never archived, reported
// or left behind, and the reservation (taken for the declared bound) is
// released.
func TestArtifactCaptureDeclaredMaxSizeRefused(t *testing.T) {
	ws := t.TempDir()
	writeCaptureFile(t, ws, "out.bin", 64<<10)
	artRoot := t.TempDir()
	sink := &covSink{}
	reporterCalled := false
	var reserved int64
	released := 0
	ex := &Executor{Opt: Options{
		Workspace: ws, Logs: sink, RunID: "run-cap", Artifacts: artifactStoreAt(t, artRoot),
		ArtifactCapture: &ArtifactCapture{
			Context:  context.Background(),
			MaxBytes: 1 << 20,
			Reserve: func(_ context.Context, n int64) (func(string) error, error) {
				reserved = n
				return func(path string) error {
					if path != "" {
						t.Errorf("finalize received a path for a refused archive: %q", path)
					}
					released++
					return nil
				}, nil
			},
		},
		ArtifactReporter: func(string, string, string) error { reporterCalled = true; return nil },
	}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{
			Artifacts: []pipeline.Artifact{{Name: "art", Paths: []string{"out.bin"}, MaxSize: pipeline.ByteSize(1024)}},
			Steps:     []pipeline.Step{{Run: "true"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess {
		t.Fatalf("capture job = %+v", res)
	}
	if reserved != 1024 {
		t.Fatalf("reserved = %d, want the declared 1024", reserved)
	}
	if released != 1 {
		t.Fatalf("releases = %d, want 1", released)
	}
	if reporterCalled {
		t.Fatal("an over-limit archive was delivered")
	}
	if !sink.has("save warning") {
		t.Fatalf("refusal not surfaced: %v", sink.lines)
	}
	if left := filesUnder(t, artRoot); len(left) != 0 {
		t.Fatalf("refused capture left files behind: %v", left)
	}
}

// TestArtifactCaptureGlobalCeilingRefused pins the global ceiling when the
// declaration sets none: an archive above MaxBytes is refused before any
// upload, with the reservation taken for the global bound.
func TestArtifactCaptureGlobalCeilingRefused(t *testing.T) {
	ws := t.TempDir()
	writeCaptureFile(t, ws, "out.bin", 64<<10)
	artRoot := t.TempDir()
	sink := &covSink{}
	var reserved int64
	ex := &Executor{Opt: Options{
		Workspace: ws, Logs: sink, RunID: "run-cap", Artifacts: artifactStoreAt(t, artRoot),
		ArtifactCapture: &ArtifactCapture{
			Context:  context.Background(),
			MaxBytes: 2048,
			Reserve: func(_ context.Context, n int64) (func(string) error, error) {
				reserved = n
				return func(string) error { return nil }, nil
			},
		},
		ArtifactReporter: func(string, string, string) error { return errors.New("must not be called") },
	}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{
			Artifacts: []pipeline.Artifact{{Name: "art", Paths: []string{"out.bin"}}},
			Steps:     []pipeline.Step{{Run: "true"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess {
		t.Fatalf("capture job = %+v", res)
	}
	if reserved != 2048 {
		t.Fatalf("reserved = %d, want the global 2048", reserved)
	}
	if !sink.has("save warning") {
		t.Fatalf("refusal not surfaced: %v", sink.lines)
	}
	if left := filesUnder(t, artRoot); len(left) != 0 {
		t.Fatalf("refused capture left files behind: %v", left)
	}
}

// TestArtifactCaptureReserveFailureIsWarning pins fail-closed accounting: if
// the staging budget cannot be charged, the archive is never created and the
// failure stays a warning (artifact delivery is best-effort intelligence).
func TestArtifactCaptureReserveFailureIsWarning(t *testing.T) {
	ws := t.TempDir()
	writeCaptureFile(t, ws, "out.bin", 1024)
	artRoot := t.TempDir()
	sink := &covSink{}
	ex := &Executor{Opt: Options{
		Workspace: ws, Logs: sink, RunID: "run-cap", Artifacts: artifactStoreAt(t, artRoot),
		ArtifactCapture: &ArtifactCapture{
			Context:  context.Background(),
			MaxBytes: 1 << 20,
			Reserve:  func(context.Context, int64) (func(string) error, error) { return nil, errors.New("budget exhausted") },
		},
		ArtifactReporter: func(string, string, string) error { return errors.New("must not be called") },
	}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{
			Artifacts: []pipeline.Artifact{{Name: "art", Paths: []string{"out.bin"}}},
			Steps:     []pipeline.Step{{Run: "true"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess || !sink.has("capture failed") {
		t.Fatalf("reserve failure = %+v lines=%v", res, sink.lines)
	}
	if left := filesUnder(t, artRoot); len(left) != 0 {
		t.Fatalf("unaccounted archive was created: %v", left)
	}
}

// TestArtifactCaptureCancelledJobUsesBoundedFallback pins the diagnostic
// path: an `if: cancelled()` artifact on a job whose context already ended is
// still captured and delivered, under the bounded fallback that survives the
// JOB deadline (the lifecycle context stays alive here).
func TestArtifactCaptureCancelledJobUsesBoundedFallback(t *testing.T) {
	ws := t.TempDir()
	writeCaptureFile(t, ws, "out.bin", 1024)
	artRoot := t.TempDir()
	sink := &covSink{}
	lifecycle, lifecycleCancel := context.WithCancel(context.Background())
	defer lifecycleCancel()
	jobCtx, jobCancel := context.WithCancel(lifecycle)
	jobCancel()

	var archived string
	ex := &Executor{Opt: Options{
		Workspace: ws, Logs: sink, RunID: "run-cap", Artifacts: artifactStoreAt(t, artRoot),
		LifecycleContext: lifecycle,
		ArtifactCapture: &ArtifactCapture{
			Context:  jobCtx,
			MaxBytes: 1 << 20,
			Reserve: func(context.Context, int64) (func(string) error, error) {
				return func(path string) error { return artifact.RemoveCaptured(path) }, nil
			},
		},
		ArtifactReporter: func(_ string, _ string, path string) error { archived = path; return nil },
	}, Masker: &secrets.Masker{}}
	res := ex.runJob(jobCtx, &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{
			Artifacts: []pipeline.Artifact{{Name: "diag", If: "cancelled()", Paths: []string{"out.bin"}}},
			Steps:     []pipeline.Step{{Run: "true"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusCancelled {
		t.Fatalf("job status = %+v, want cancelled", res)
	}
	if archived == "" {
		t.Fatalf("cancelled-job diagnostic was not captured: %v", sink.lines)
	}
	if _, err := os.Stat(archived); !os.IsNotExist(err) {
		t.Fatalf("diagnostic archive survived delivery: %v", err)
	}
}

// TestArtifactCaptureFallbackSkippedOnRunnerShutdown pins the other side of
// the same axis: when the LIFECYCLE context is canceled (runner shutdown),
// the cancelled-job diagnostic capture is not attempted at all — a shutdown
// must not be delayed by optional artifact packaging.
func TestArtifactCaptureFallbackSkippedOnRunnerShutdown(t *testing.T) {
	ws := t.TempDir()
	writeCaptureFile(t, ws, "out.bin", 1024)
	lifecycle, lifecycleCancel := context.WithCancel(context.Background())
	jobCtx, jobCancel := context.WithCancel(lifecycle)
	jobCancel()
	lifecycleCancel()

	reserveCalled := false
	ex := &Executor{Opt: Options{
		Workspace: ws, Logs: &covSink{}, RunID: "run-cap", Artifacts: artifactStoreAt(t, t.TempDir()),
		LifecycleContext: lifecycle,
		ArtifactCapture: &ArtifactCapture{
			Context:  jobCtx,
			MaxBytes: 1 << 20,
			Reserve: func(context.Context, int64) (func(string) error, error) {
				reserveCalled = true
				return func(string) error { return nil }, nil
			},
		},
	}, Masker: &secrets.Masker{}}
	res := ex.runJob(jobCtx, &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{
			Artifacts: []pipeline.Artifact{{Name: "diag", If: "cancelled()", Paths: []string{"out.bin"}}},
			Steps:     []pipeline.Step{{Run: "true"}},
		},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusCancelled {
		t.Fatalf("job status = %+v, want cancelled", res)
	}
	if reserveCalled {
		t.Fatal("shutdown-time diagnostic capture was attempted")
	}
}
