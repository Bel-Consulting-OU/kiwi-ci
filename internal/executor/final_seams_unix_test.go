//go:build !windows

package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/logging"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/safefs"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

func TestFinalBackendForUnknownKind(t *testing.T) {
	if _, err := BackendFor("bogus", "", ""); err == nil {
		t.Fatal("unknown backend accepted")
	}
}

// TestFinalSeamAbsWorkspaceFailures forces filepath.Abs to fail (the real
// getcwd-ENOENT case on Linux) so the workspace-canonicalization error
// branches of both lifecycle backends and secureWorkingDir run.
func TestFinalSeamAbsWorkspaceFailures(t *testing.T) {
	installFakeBins(t)
	orig := absWorkspacePath
	absWorkspacePath = func(string) (string, error) { return "", fmt.Errorf("getwd refused") }
	t.Cleanup(func() { absWorkspacePath = orig })

	if err := (&ContainerBackend{Image: "alpine:3.19"}).StartJob(context.Background(), ".", func(string) {}); err == nil {
		t.Fatal("container StartJob with an unresolvable workspace accepted")
	}
	if err := (&TartBackend{VM: "vm"}).StartJob(context.Background(), ".", func(string) {}); err == nil {
		t.Fatal("tart StartJob with an unresolvable workspace accepted")
	}
	if _, err := secureWorkingDir(".", ""); err == nil {
		t.Fatal("secureWorkingDir with an unresolvable workspace accepted")
	}
}

func TestFinalContainerReadFileStartError(t *testing.T) {
	ws := t.TempDir()
	b := &ContainerBackend{docker: filepath.Join(t.TempDir(), "missing-docker"), container: "cid", workspace: ws}
	if _, err := b.ReadFile(context.Background(), filepath.Join(ws, "out.txt"), 1024); err == nil {
		t.Fatal("missing docker binary accepted")
	}
}

func TestFinalStreamCommandPipeAndStartErrors(t *testing.T) {
	ctx := context.Background()
	emit := func(string) {}

	var buf bytes.Buffer
	cmd := exec.Command("true")
	cmd.Stdout = &buf
	if err := streamCommand(ctx, cmd, emit); err == nil {
		t.Fatal("preset stdout accepted")
	}

	cmd = exec.Command("true")
	cmd.Stderr = &buf
	if err := streamCommand(ctx, cmd, emit); err == nil {
		t.Fatal("preset stderr accepted")
	}

	cmd = exec.Command(filepath.Join(t.TempDir(), "missing-binary"))
	err := streamCommand(ctx, cmd, emit)
	var runErr *RunError
	if err == nil || !errors.As(err, &runErr) || runErr.Kind != ErrorInfra {
		t.Fatalf("missing binary = %v", err)
	}
}

func TestFinalGCNilContext(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	// The nil context is the condition under test: GC documents that it falls
	// back to context.Background.
	var nilCtx context.Context
	rep := GC(nilCtx, t.TempDir(), time.Hour)
	if rep != (GCReport{}) {
		t.Fatalf("GC with a nil context = %+v", rep)
	}
}

func TestFinalServicesHealthcheckCancelled(t *testing.T) {
	installFakeBins(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	services := []pipeline.Service{{
		Name: "db", Image: "postgres:16", Healthcheck: "true", Retries: 3,
		Interval: pipeline.Duration{Duration: time.Hour},
	}}
	// The emit callback fires after the container started and before the
	// healthcheck loop runs: cancelling there deterministically lands the
	// retry select on the ctx.Done branch.
	_, _, err := startContainerServices(ctx, "r", "j", services, false, false, func(line string) {
		if strings.Contains(line, "started") {
			cancel()
		}
	})
	if err == nil {
		t.Fatal("cancelled healthcheck accepted")
	}
	var runErr *RunError
	if !errors.As(err, &runErr) || runErr.Kind != ErrorCancelled {
		t.Fatalf("error = %v, want an ErrorCancelled RunError", err)
	}
}

func TestFinalRelWithinRootCanonicalSpelling(t *testing.T) {
	ws := t.TempDir()
	root, err := safefs.OpenWorkspaceRoot(ws)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	child := filepath.Join(root.Canonical, "out", "report.txt")
	rel, ok := relWithinRoot(root, ws, child)
	if !ok || rel != filepath.Join("out", "report.txt") {
		t.Fatalf("relWithinRoot = %q, %v", rel, ok)
	}
	if _, ok := relWithinRoot(root, ws, filepath.Join(root.Canonical, "..", "escape.txt")); ok {
		t.Fatal("escaping path accepted")
	}
}

func TestFinalSeamSnapshotCloseFailure(t *testing.T) {
	orig := closeSnapshotFile
	closeSnapshotFile = func(*os.File) error { return fmt.Errorf("snapshot close refused") }
	t.Cleanup(func() { closeSnapshotFile = orig })

	var lines []string
	e := &Executor{Opt: Options{RunID: "run-1", Logs: logging.Func(func(job, step, line string) {
		lines = append(lines, job+"/"+step+": "+line)
	})}, Masker: &secrets.Masker{}}
	e.captureSnapshot("job-1", t.TempDir())
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "snapshot close refused") {
		t.Fatalf("close failure not logged: %s", joined)
	}
	if strings.Contains(joined, "saved ") {
		t.Fatalf("snapshot reported saved despite the close failure: %s", joined)
	}
}

func TestFinalSeamAttachChildSupervisionFailure(t *testing.T) {
	orig := attachChildSupervision
	attachChildSupervision = func(*exec.Cmd, *[]string) (func(), error) {
		return nil, fmt.Errorf("job object refused")
	}
	t.Cleanup(func() { attachChildSupervision = orig })

	err := (&NativeBackend{}).Run(context.Background(), Command{Script: "true", Shell: "sh"}, func(string) {})
	if err == nil {
		t.Fatal("supervision failure accepted")
	}
	if !strings.Contains(err.Error(), "attach child process supervision") {
		t.Fatalf("error = %v", err)
	}
	var runErr *RunError
	if !errors.As(err, &runErr) || runErr.Kind != ErrorInfra {
		t.Fatalf("kind = %v, want ErrorInfra", err)
	}
}

func TestFinalSeamTartIPWaitExpiry(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_TART_NO_IP", "1")
	orig := tartIPWait
	tartIPWait = 20 * time.Millisecond
	t.Cleanup(func() { tartIPWait = orig })

	b := &TartBackend{VM: "vm"}
	err := b.StartJob(context.Background(), t.TempDir(), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "did not obtain an IP") {
		t.Fatalf("tart StartJob without an IP = %v", err)
	}
}

func TestFinalSeamGenerateSSHKeyFailure(t *testing.T) {
	orig := generateSSHKey
	generateSSHKey = func(string) error { return fmt.Errorf("keygen refused") }
	t.Cleanup(func() { generateSSHKey = orig })

	b := &TartBackend{}
	if err := b.setupSSHDir(); err == nil || !strings.Contains(err.Error(), "generate ephemeral SSH key") {
		t.Fatalf("setupSSHDir = %v", err)
	}
	if b.sshDir != "" {
		t.Fatalf("failed setup left sshDir = %q", b.sshDir)
	}
}

func TestFinalSeamKeyFileCreateBranches(t *testing.T) {
	orig := keyFileCreate
	t.Cleanup(func() { keyFileCreate = orig })

	// A closed descriptor fails the chmod step; the file is removed.
	dir := t.TempDir()
	path := filepath.Join(dir, "closed")
	keyFileCreate = func(p string, _ int, _ os.FileMode) (*os.File, error) {
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		_ = f.Close()
		return f, nil
	}
	if err := WriteOwnerOnly(path, []byte("secret")); err == nil {
		t.Fatal("closed descriptor accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("failed chmod left the key file behind: %v", err)
	}

	// A read-only descriptor fails the write step; the file is removed.
	path = filepath.Join(dir, "readonly")
	keyFileCreate = func(p string, _ int, _ os.FileMode) (*os.File, error) {
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		_ = f.Close()
		return os.Open(p)
	}
	if err := WriteOwnerOnly(path, []byte("secret")); err == nil {
		t.Fatal("read-only descriptor accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("failed write left the key file behind: %v", err)
	}

	// An endlessly recreated path exhausts the exclusive-create attempts.
	path = filepath.Join(dir, "exhaust")
	keyFileCreate = func(p string, _ int, _ os.FileMode) (*os.File, error) {
		_ = os.WriteFile(p, []byte("x"), 0o600)
		return nil, &os.PathError{Op: "open", Path: p, Err: syscall.EEXIST}
	}
	err := WriteOwnerOnly(path, []byte("secret"))
	if err == nil || !strings.Contains(err.Error(), "could not be created exclusively") {
		t.Fatalf("exhaustion = %v", err)
	}
}
