package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// writeSizedFile writes n bytes (a repeating pattern so the test stays fast
// without depending on entropy) to name under dir.
func writeSizedFile(t *testing.T, dir, name string, n int) string {
	t.Helper()
	pattern := make([]byte, 4096)
	for i := range pattern {
		pattern[i] = byte(i)
	}
	out := make([]byte, n)
	for i := range out {
		out[i] = pattern[i%len(pattern)]
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func runErrorKind(t *testing.T, err error) string {
	t.Helper()
	var re *RunError
	if !errors.As(err, &re) {
		t.Fatalf("error %v is not a *RunError", err)
	}
	return re.Kind
}

// TestContainerDiskBoundRejectsOversizedCheckoutBeforeDocker proves a
// checkout larger than the declared resources.disk is refused by StartJob
// before any docker lookup or invocation: the error names the disk bound and
// never mentions the missing daemon, so the enforcement does not depend on
// the host's docker installation.
func TestContainerDiskBoundRejectsOversizedCheckoutBeforeDocker(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	ws := t.TempDir()
	writeSizedFile(t, ws, "big.bin", 4096)
	b := &ContainerBackend{Image: "alpine:3.19", Resources: pipeline.Resources{Disk: 1024}}
	err := b.StartJob(context.Background(), ws, func(string) {})
	if err == nil {
		t.Fatal("oversized workspace accepted")
	}
	if !strings.Contains(err.Error(), "resources.disk") || !strings.Contains(err.Error(), "4096 bytes used") {
		t.Fatalf("error does not explain the disk bound: %v", err)
	}
	if strings.Contains(err.Error(), "docker") {
		t.Fatalf("disk bound check ran after the docker lookup: %v", err)
	}
	if kind := runErrorKind(t, err); kind != ErrorFailure {
		t.Fatalf("kind = %q, want %q", kind, ErrorFailure)
	}
}

// TestContainerDiskBoundRejectsOversizedWorkspaceBeforeStep proves Run
// refuses to start a step on an already over-bound workspace without
// executing anything: the configured docker binary is deliberately
// nonexistent, so any docker invocation would surface a different error.
func TestContainerDiskBoundRejectsOversizedWorkspaceBeforeStep(t *testing.T) {
	ws := t.TempDir()
	writeSizedFile(t, ws, "big.bin", 2048)
	b := &ContainerBackend{
		Image:     "alpine:3.19",
		Resources: pipeline.Resources{Disk: 1024},
		docker:    filepath.Join(t.TempDir(), "no-such-docker"),
		container: "kiwi-job-test",
		workspace: ws,
	}
	var emitted []string
	err := b.Run(context.Background(), Command{Shell: "sh", Script: "echo ran", Dir: ws}, func(s string) { emitted = append(emitted, s) })
	if err == nil {
		t.Fatal("over-bound step accepted")
	}
	if !strings.Contains(err.Error(), "resources.disk") {
		t.Fatalf("error does not explain the disk bound: %v", err)
	}
	if len(emitted) != 0 {
		t.Fatalf("over-bound workspace still ran a command: %v", emitted)
	}
	if kind := runErrorKind(t, err); kind != ErrorFailure {
		t.Fatalf("kind = %q, want %q", kind, ErrorFailure)
	}
}

// TestContainerDiskBoundFailsStepThatGrowsWorkspace proves the step boundary
// check catches growth caused by the step itself: the step command succeeds,
// the workspace is then over the declared bound, and the step fails with the
// disk-bound error instead of the growth passing silently.
func TestContainerDiskBoundFailsStepThatGrowsWorkspace(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	b := &ContainerBackend{Image: "alpine:3.19", Resources: pipeline.Resources{Disk: 4096}, RunID: "r", JobID: "j"}
	if err := b.StartJob(context.Background(), ws, func(string) {}); err != nil {
		t.Fatalf("StartJob: %v", err)
	}
	err := b.Run(context.Background(), Command{Shell: "sh", Script: "head -c 8192 /dev/zero > grown.bin", Dir: ws, Env: os.Environ()}, func(string) {})
	if err == nil {
		t.Fatal("step that grew the workspace past the bound succeeded")
	}
	if !strings.Contains(err.Error(), "exceeds the declared resources.disk bound") {
		t.Fatalf("error does not explain the growth: %v", err)
	}
	if kind := runErrorKind(t, err); kind != ErrorFailure {
		t.Fatalf("kind = %q, want %q", kind, ErrorFailure)
	}
}

// TestContainerDiskBoundAllowsWorkspaceWithinBound proves a workspace within
// the declared bound keeps running normally (the bound is not a false
// positive).
func TestContainerDiskBoundAllowsWorkspaceWithinBound(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	writeSizedFile(t, ws, "payload.bin", 8192)
	b := &ContainerBackend{Image: "alpine:3.19", Resources: pipeline.Resources{Disk: 1 << 20}, RunID: "r", JobID: "j"}
	if err := b.StartJob(context.Background(), ws, func(string) {}); err != nil {
		t.Fatalf("StartJob: %v", err)
	}
	var emitted []string
	if err := b.Run(context.Background(), Command{Shell: "sh", Script: "echo within-bound", Dir: ws, Env: os.Environ()}, func(s string) { emitted = append(emitted, s) }); err != nil {
		t.Fatalf("Run within bound: %v", err)
	}
	if !containsLine(emitted, "within-bound") {
		t.Fatalf("emitted = %v", emitted)
	}
}

// TestContainerDiskUnsetKeepsPreviousBehavior pins the documented default: a
// job without resources.disk has an unbounded workspace, exactly as before
// the disk bound was enforced.
func TestContainerDiskUnsetKeepsPreviousBehavior(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	writeSizedFile(t, ws, "huge.bin", 1<<20)
	b := &ContainerBackend{Image: "alpine:3.19", RunID: "r", JobID: "j"}
	if b.workspaceMaxBytes() != 0 {
		t.Fatalf("undeclared disk bound = %d, want 0", b.workspaceMaxBytes())
	}
	if err := b.StartJob(context.Background(), ws, func(string) {}); err != nil {
		t.Fatalf("unbounded StartJob: %v", err)
	}
	if err := b.Run(context.Background(), Command{Shell: "sh", Script: "echo unbounded", Dir: ws, Env: os.Environ()}, func(string) {}); err != nil {
		t.Fatalf("unbounded Run: %v", err)
	}
}

// TestContainerDiskBoundUnmeasurableWorkspaceFailsClosed proves a workspace
// that cannot be measured fails as infra instead of silently skipping the
// bound.
func TestContainerDiskBoundUnmeasurableWorkspaceFailsClosed(t *testing.T) {
	b := &ContainerBackend{
		Image:     "alpine:3.19",
		Resources: pipeline.Resources{Disk: 1 << 20},
		docker:    filepath.Join(t.TempDir(), "no-such-docker"),
		container: "kiwi-job-test",
		workspace: filepath.Join(t.TempDir(), "missing"),
	}
	err := b.Run(context.Background(), Command{Shell: "sh", Script: "true", Dir: b.workspace}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "measure workspace usage") {
		t.Fatalf("unmeasurable workspace = %v", err)
	}
	if kind := runErrorKind(t, err); kind != ErrorInfra {
		t.Fatalf("kind = %q, want %q", kind, ErrorInfra)
	}
}

// TestWorkspaceUsageBytesSumsRegularFilesOnly proves the measurement is
// stat-only, never follows symlinks out of the tree, and sums nested regular
// files.
func TestWorkspaceUsageBytesSumsRegularFilesOnly(t *testing.T) {
	ws := t.TempDir()
	writeSizedFile(t, ws, "a.bin", 1000)
	if err := os.MkdirAll(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeSizedFile(t, filepath.Join(ws, "sub"), "b.bin", 2000)
	outside := t.TempDir()
	big := writeSizedFile(t, outside, "big.bin", 1<<20)
	if err := os.Symlink(big, filepath.Join(ws, "link.bin")); err != nil {
		t.Fatal(err)
	}
	got, err := workspaceUsageBytes(ws)
	if err != nil {
		t.Fatalf("workspaceUsageBytes: %v", err)
	}
	if got != 3000 {
		t.Fatalf("usage = %d, want 3000 (symlinked target must not count)", got)
	}
	if _, err := workspaceUsageBytes(filepath.Join(ws, "missing")); err == nil {
		t.Fatal("missing workspace measured successfully")
	}
	if _, err := workspaceUsageBytes(""); err == nil {
		t.Fatal("empty workspace path measured successfully")
	}
}
