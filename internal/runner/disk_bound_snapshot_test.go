package runner

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"math"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executor"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/server"
)

// incompressible returns n bytes of random data: snapshot archives are
// compressed, so a cap on the archive is only tripped by content gzip cannot
// shrink.
func incompressible(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// captureExecutorOptions installs the executor-options test seam for one test
// and returns an accessor for the last observed options.
func captureExecutorOptions(t *testing.T) func() (executor.Options, bool) {
	t.Helper()
	orig := executorOptionsSeam
	var got executor.Options
	var seen bool
	executorOptionsSeam = func(o executor.Options) {
		got, seen = o, true
	}
	t.Cleanup(func() { executorOptionsSeam = orig })
	return func() (executor.Options, bool) { return got, seen }
}

// TestExecuteDeclaredDiskSetsWorkspaceMaxBytesBound proves the declared
// resources.disk flows into executor.Options.WorkspaceMaxBytes as bytes
// ("2Gi" is 2<<30), and that an undeclared disk leaves the bound at zero: the
// documented default preserves the previous behavior for pipelines without a
// disk declaration.
func TestExecuteDeclaredDiskSetsWorkspaceMaxBytesBound(t *testing.T) {
	cases := []struct {
		name string
		text string
		want int64
	}{
		{
			"declared disk is the workspace bound",
			"version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine:3.19\n    resources:\n      disk: 2Gi\n    steps:\n      - run: echo hi\n",
			2 << 30,
		},
		{
			"undeclared disk leaves the bound unset",
			"version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine:3.19\n    steps:\n      - run: echo hi\n",
			0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsrv := &fakeRunnerServer{}
			ts := httptest.NewServer(fsrv.handler())
			defer ts.Close()
			r := testRunnerFor(t, ts, Config{})
			// No docker on PATH: the container job must not reach a real
			// daemon. The asserted options are captured before execution.
			t.Setenv("PATH", t.TempDir())
			gotOptions := captureExecutorOptions(t)
			r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
				return os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644)
			}
			r.execute(context.Background(), basicTask(tc.text))
			got, ok := gotOptions()
			if !ok {
				t.Fatal("executor options seam never fired")
			}
			if got.WorkspaceMaxBytes != tc.want {
				t.Fatalf("WorkspaceMaxBytes = %d, want %d", got.WorkspaceMaxBytes, tc.want)
			}
		})
	}
}

// TestWorkspaceMaxBytesForResourcesUnits pins the unit conversion: the
// pipeline decoder already produced bytes, zero/negative values mean
// "undeclared" (bound unset), and no re-parsing can change the value.
func TestWorkspaceMaxBytesForResourcesUnits(t *testing.T) {
	if got := workspaceMaxBytesForResources(pipeline.Resources{Disk: 2 << 30}); got != 2<<30 {
		t.Fatalf("2Gi = %d, want %d", got, 2<<30)
	}
	if got := workspaceMaxBytesForResources(pipeline.Resources{Disk: 512}); got != 512 {
		t.Fatalf("plain bytes = %d, want 512", got)
	}
	if got := workspaceMaxBytesForResources(pipeline.Resources{Disk: 0}); got != 0 {
		t.Fatalf("undeclared disk = %d, want 0", got)
	}
	if got := workspaceMaxBytesForResources(pipeline.Resources{Disk: -1}); got != 0 {
		t.Fatalf("negative disk = %d, want 0", got)
	}
}

// TestSnapshotArchiveMaxBytesDerivation pins the archive cap derivation: a
// declared bound scales by the documented framing factor and an undeclared
// bound falls back to the runner default, which unifies with the control
// plane's hard upload ceiling.
func TestSnapshotArchiveMaxBytesDerivation(t *testing.T) {
	if DefaultSnapshotArchiveMaxBytes != 8<<30 {
		t.Fatalf("default snapshot archive cap = %d, want 8 GiB", DefaultSnapshotArchiveMaxBytes)
	}
	if got := snapshotArchiveMaxBytes(0); got != DefaultSnapshotArchiveMaxBytes {
		t.Fatalf("undeclared bound cap = %d, want %d", got, DefaultSnapshotArchiveMaxBytes)
	}
	if got := snapshotArchiveMaxBytes(64 << 10); got != 128<<10 {
		t.Fatalf("declared bound cap = %d, want %d", got, 128<<10)
	}
	if got := snapshotArchiveMaxBytes(1 << 50); got != 2<<50 {
		t.Fatalf("1 PiB bound cap = %d, want %d", got, 2<<50)
	}
}

// TestUploadJobSnapshotOverCapAbortsAndRemovesTemp proves an archive over the
// derived cap aborts with a clear error while streaming, sends no upload and
// leaves no partial temporary file behind.
func TestUploadJobSnapshotOverCapAbortsAndRemovesTemp(t *testing.T) {
	tmpRoot := t.TempDir()
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	r := testRunnerFor(t, ts, Config{})
	t.Setenv("TMPDIR", tmpRoot)

	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "data.bin"), incompressible(t, 256<<10), 0o644); err != nil {
		t.Fatal(err)
	}
	declared := int64(64 << 10) // archive cap = 128 KiB, workspace = 256 KiB
	err := r.uploadJobSnapshot(context.Background(), basicTask(payloadPipeline), ws, declared)
	if err == nil {
		t.Fatal("over-cap snapshot archive was accepted")
	}
	if !errors.Is(err, safefs.ErrCapExceeded) {
		t.Fatalf("error = %v, want ErrCapExceeded", err)
	}
	if !strings.Contains(err.Error(), "snapshot archive exceeds the runner limit of 131072 bytes") {
		t.Fatalf("error does not name the cap: %v", err)
	}
	if paths := fsrv.pathsFor(""); len(paths) != 0 {
		t.Fatalf("oversized snapshot reached the control plane: %v", paths)
	}
	entries, rerr := os.ReadDir(tmpRoot)
	if rerr != nil {
		t.Fatal(rerr)
	}
	var leftover []string
	for _, e := range entries {
		leftover = append(leftover, e.Name())
	}
	if len(leftover) != 0 {
		t.Fatalf("aborted capture left temp files behind: %v", leftover)
	}
}

// TestUploadJobSnapshotUnderCapUploads proves the cap does not reject a
// workspace within its declared bound: the archive is uploaded as a gzip
// stream.
func TestUploadJobSnapshotUnderCapUploads(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	r := testRunnerFor(t, ts, Config{})
	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "data.txt"), bytes.Repeat([]byte("x"), 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.uploadJobSnapshot(context.Background(), basicTask(payloadPipeline), ws, 64<<10); err != nil {
		t.Fatalf("upload within cap: %v", err)
	}
	if len(fsrv.snapshotBodies) != 1 {
		t.Fatalf("snapshot uploads = %d, want 1", len(fsrv.snapshotBodies))
	}
	if !bytes.HasPrefix(fsrv.snapshotBodies[0], []byte{0x1f, 0x8b}) {
		t.Fatalf("uploaded body is not a gzip stream: %d bytes", len(fsrv.snapshotBodies[0]))
	}
}

// TestPostMarshalErrorIsSurfaced proves a non-marshallable payload (NaN) is a
// real error before any request is created, instead of a silently malformed
// request body.
func TestPostMarshalErrorIsSurfaced(t *testing.T) {
	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()
	r := testRunnerFor(t, ts, Config{})
	err := r.post(context.Background(), "/api/v1/jobs/job-1/tests", map[string]any{
		"report": map[string]any{"score": math.NaN()},
	}, nil)
	if err == nil {
		t.Fatal("NaN payload was accepted")
	}
	if !strings.Contains(err.Error(), "encode request body for /api/v1/jobs/job-1/tests") {
		t.Fatalf("error lacks endpoint context: %v", err)
	}
	if !strings.Contains(err.Error(), "NaN") {
		t.Fatalf("error does not surface the encoder failure: %v", err)
	}
	if paths := fsrv.pathsFor(""); len(paths) != 0 {
		t.Fatalf("request was sent despite the encode failure: %v", paths)
	}
}

// TestExecuteDiskBoundAndSnapshotCapEndToEnd proves the two bounds cooperate
// on the live execute path: an oversized checkout fails the job through the
// container backend's disk bound, and the failure snapshot capture then
// aborts locally on the derived archive cap (no upload, warning logged, no
// leftover temp file).
func TestExecuteDiskBoundAndSnapshotCapEndToEnd(t *testing.T) {
	rsrv := &reportServer{}
	ts := httptest.NewServer(rsrv.handler())
	defer ts.Close()
	r := testRunnerFor(t, ts, Config{CaptureSnapshots: true})
	tmpRoot := t.TempDir()
	t.Setenv("TMPDIR", tmpRoot)
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		return os.WriteFile(filepath.Join(dir, "checkout.bin"), incompressible(t, 256<<10), 0o644)
	}
	text := "version: 1\njobs:\n  build:\n    runtime: container\n    image: alpine:3.19\n    resources:\n      disk: 64Ki\n    snapshot: {}\n    steps:\n      - run: echo hi\n"
	r.execute(context.Background(), basicTask(text))

	rsrv.mu.Lock()
	snapshots := rsrv.snapshots
	logs := strings.Join(rsrv.logs, "\n")
	var complete []server.Complete
	complete = append(complete, rsrv.complete...)
	rsrv.mu.Unlock()

	if len(complete) == 0 {
		t.Fatal("no completion recorded")
	}
	c := complete[len(complete)-1]
	if c.Status != model.StatusFailure {
		t.Fatalf("status = %s, want failure", c.Status)
	}
	if !strings.Contains(c.Error, "resources.disk") {
		t.Fatalf("job error does not name the disk bound: %q", c.Error)
	}
	if !strings.Contains(logs, "snapshot archive exceeds the runner limit of 131072 bytes") {
		t.Fatalf("snapshot cap warning missing: %q", logs)
	}
	if snapshots != 0 {
		t.Fatalf("over-cap snapshot uploads = %d, want 0", snapshots)
	}
	entries, rerr := os.ReadDir(tmpRoot)
	if rerr != nil {
		t.Fatal(rerr)
	}
	var leftover []string
	for _, e := range entries {
		leftover = append(leftover, e.Name())
	}
	if len(leftover) != 0 {
		t.Fatalf("execute left temp files behind: %v", leftover)
	}
}
