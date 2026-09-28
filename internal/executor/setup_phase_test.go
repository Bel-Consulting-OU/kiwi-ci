package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
)

// TestPhaseCommandHangingBoundedTypedTimeout is the shared phase helper
// contract: a wedged setup command returns within its phase ceiling with the
// typed timeout error and a diagnostic that names the command.
func TestPhaseCommandHangingBoundedTypedTimeout(t *testing.T) {
	testutil.UnixShell(t)
	fake := writeCleanupScript(t, "tool", "#!/bin/sh\nexec sleep 300\n")
	start := time.Now()
	out, err := phaseCommand(context.Background(), 150*time.Millisecond, fake, "info", "--format")
	elapsed := time.Since(start)
	if !errors.Is(err, ErrExternalCommandTimeout) {
		t.Fatalf("hanging phase command = %v, want ErrExternalCommandTimeout", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("phase timeout error does not wrap context.DeadlineExceeded: %v", err)
	}
	if !strings.Contains(err.Error(), "info --format") {
		t.Fatalf("phase timeout error does not name the command: %v", err)
	}
	_ = out
	if elapsed > 5*time.Second {
		t.Fatalf("phase command took %v; the caller was stranded", elapsed)
	}
}

// TestPhaseCommandHonorsParentDeadlineFirst proves the ceiling is
// min(parent deadline, phase deadline): when the job context expires first,
// the raw command error is returned and is NOT mislabeled as a phase
// timeout, so the caller keeps its own cancellation/timeout classification.
func TestPhaseCommandHonorsParentDeadlineFirst(t *testing.T) {
	testutil.UnixShell(t)
	fake := writeCleanupScript(t, "tool", "#!/bin/sh\nexec sleep 300\n")
	parent, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := phaseCommand(parent, time.Hour, fake, "info")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expired parent was ignored")
	}
	if errors.Is(err, ErrExternalCommandTimeout) {
		t.Fatalf("parent-side deadline was mislabeled as a phase timeout: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("parent-bounded phase command took %v", elapsed)
	}
}

// TestRequireRootlessDaemonHangingProbeBounded proves the docker rootless
// probe (`docker info`) is bounded by the probe ceiling even when the job
// carries no timeout at all.
func TestRequireRootlessDaemonHangingProbeBounded(t *testing.T) {
	testutil.UnixShell(t)
	origProbe := runtimeProbeTimeout
	runtimeProbeTimeout = 150 * time.Millisecond
	t.Cleanup(func() { runtimeProbeTimeout = origProbe })

	fake := writeCleanupScript(t, "docker", "#!/bin/sh\nexec sleep 300\n")
	start := time.Now()
	err := requireRootlessDaemon(context.Background(), fake)
	elapsed := time.Since(start)
	if err == nil || errorKind(err) != ErrorInfra {
		t.Fatalf("hanging docker info = %v, want an ErrorInfra failure", err)
	}
	if !errors.Is(err, ErrExternalCommandTimeout) {
		t.Fatalf("hanging docker info error does not wrap ErrExternalCommandTimeout: %v", err)
	}
	if !strings.Contains(err.Error(), "inspect docker daemon") {
		t.Fatalf("error does not name the probe: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("docker info probe took %v; the no-job-timeout case was not bounded", elapsed)
	}
}

// TestStartContainerServicesHangingNetworkCreateBounded proves the service
// network create is bounded by the control ceiling.
func TestStartContainerServicesHangingNetworkCreateBounded(t *testing.T) {
	testutil.UnixShell(t)
	origControl := runtimeControlTimeout
	runtimeControlTimeout = 150 * time.Millisecond
	t.Cleanup(func() { runtimeControlTimeout = origControl })

	dir := t.TempDir()
	script := "#!/bin/sh\ncase \"$1\" in\n  network) exec sleep 300;;\nesac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	start := time.Now()
	_, _, err := startContainerServices(context.Background(), "r", "j",
		[]pipeline.Service{{Name: "db", Image: "postgres:16"}},
		pipeline.Resources{}, false, false, "", func(string) {})
	elapsed := time.Since(start)
	if err == nil || errorKind(err) != ErrorInfra {
		t.Fatalf("hanging network create = %v, want an ErrorInfra failure", err)
	}
	if !errors.Is(err, ErrExternalCommandTimeout) {
		t.Fatalf("hanging network create error does not wrap ErrExternalCommandTimeout: %v", err)
	}
	if !strings.Contains(err.Error(), "create services network") {
		t.Fatalf("error does not name the network create: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("network create took %v; the control ceiling did not bound it", elapsed)
	}
}

// TestStartContainerServicesHangingServiceRunBounded proves a service
// `docker run` (which pulls an image and is legitimately slow) is bounded by
// the setup ceiling, and the failure still runs the bounded cleanup.
func TestStartContainerServicesHangingServiceRunBounded(t *testing.T) {
	testutil.UnixShell(t)
	origSetup, origCleanup := runtimeSetupTimeout, dockerCleanupTimeout
	runtimeSetupTimeout = 150 * time.Millisecond
	dockerCleanupTimeout = 150 * time.Millisecond
	t.Cleanup(func() { runtimeSetupTimeout, dockerCleanupTimeout = origSetup, origCleanup })

	dir := t.TempDir()
	logPath := filepath.Join(dir, "docker.log")
	script := `#!/bin/sh
echo "$@" >> "` + logPath + `"
sub="$1"; shift
case "$sub" in
  network) echo netid; exit 0;;
  run) exec sleep 300;;
  rm) exit 0;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	var lines []string
	start := time.Now()
	_, _, err := startContainerServices(context.Background(), "r", "j",
		[]pipeline.Service{{Name: "db", Image: "postgres:16"}},
		pipeline.Resources{}, false, false, "", func(line string) { lines = append(lines, line) })
	elapsed := time.Since(start)
	if err == nil || errorKind(err) != ErrorInfra {
		t.Fatalf("hanging service run = %v, want an ErrorInfra failure", err)
	}
	if !errors.Is(err, ErrExternalCommandTimeout) {
		t.Fatalf("hanging service run error does not wrap ErrExternalCommandTimeout: %v", err)
	}
	if !strings.Contains(err.Error(), "start service") {
		t.Fatalf("error does not name the service start: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("service run took %v; the setup ceiling did not bound it", elapsed)
	}
	data, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatalf("fake docker did not run: %v", readErr)
	}
	if !strings.Contains(string(data), "network rm "+serviceNetworkName("r", "j")) {
		t.Fatalf("failed service start did not run the bounded network cleanup:\n%s", data)
	}
}

// TestContainerBackendStartJobHangingRunBounded proves the job container
// `docker run` is bounded by the setup ceiling even with no job timeout.
func TestContainerBackendStartJobHangingRunBounded(t *testing.T) {
	testutil.UnixShell(t)
	origSetup := runtimeSetupTimeout
	runtimeSetupTimeout = 150 * time.Millisecond
	t.Cleanup(func() { runtimeSetupTimeout = origSetup })

	fake := writeCleanupScript(t, "docker", "#!/bin/sh\nexec sleep 300\n")
	t.Setenv("PATH", filepath.Dir(fake)+string(os.PathListSeparator)+os.Getenv("PATH"))

	b := &ContainerBackend{Image: "alpine:3.19", RunID: "r", JobID: "j"}
	start := time.Now()
	err := b.StartJob(context.Background(), t.TempDir(), func(string) {})
	elapsed := time.Since(start)
	if err == nil || errorKind(err) != ErrorInfra {
		t.Fatalf("hanging docker run = %v, want an ErrorInfra failure", err)
	}
	if !errors.Is(err, ErrExternalCommandTimeout) {
		t.Fatalf("hanging docker run error does not wrap ErrExternalCommandTimeout: %v", err)
	}
	if !strings.Contains(err.Error(), "start job container") {
		t.Fatalf("error does not name the job container start: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("job docker run took %v; the setup ceiling did not bound it", elapsed)
	}
}

// TestTartStartJobHangingCloneBounded proves `tart clone` (which pulls the
// base image and is legitimately slow) is bounded by the setup ceiling even
// when the job carries no timeout.
func TestTartStartJobHangingCloneBounded(t *testing.T) {
	testutil.UnixShell(t)
	origSetup := runtimeSetupTimeout
	runtimeSetupTimeout = 150 * time.Millisecond
	t.Cleanup(func() { runtimeSetupTimeout = origSetup })

	dir := t.TempDir()
	tart := "#!/bin/sh\ncase \"$1\" in\n  clone) exec sleep 300;;\n  delete) exit 0;;\nesac\nexit 0\n"
	ssh := "#!/bin/sh\nexit 0\n"
	for name, body := range map[string]string{"tart": tart, "ssh": ssh} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	b := &TartBackend{VM: "vm"}
	start := time.Now()
	err := b.StartJob(context.Background(), t.TempDir(), func(string) {})
	elapsed := time.Since(start)
	if err == nil || errorKind(err) != ErrorInfra {
		t.Fatalf("hanging tart clone = %v, want an ErrorInfra failure", err)
	}
	if !errors.Is(err, ErrExternalCommandTimeout) {
		t.Fatalf("hanging tart clone error does not wrap ErrExternalCommandTimeout: %v", err)
	}
	if !strings.Contains(err.Error(), "tart clone") {
		t.Fatalf("error does not name the clone: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("tart clone took %v; the setup ceiling did not bound it", elapsed)
	}
}

// TestTartVerifyBootstrapGetHangingProbeBounded proves the tart get label
// query is bounded by the probe ceiling.
func TestTartVerifyBootstrapGetHangingProbeBounded(t *testing.T) {
	testutil.UnixShell(t)
	origProbe := runtimeProbeTimeout
	runtimeProbeTimeout = 150 * time.Millisecond
	t.Cleanup(func() { runtimeProbeTimeout = origProbe })

	fake := writeCleanupScript(t, "tart", "#!/bin/sh\nexec sleep 300\n")
	b := &TartBackend{clone: "kiwi-1"}
	start := time.Now()
	err := b.verifyBootstrapContract(context.Background(), fake)
	elapsed := time.Since(start)
	if err == nil || errorKind(err) != ErrorInfra {
		t.Fatalf("hanging tart get = %v, want an ErrorInfra failure", err)
	}
	if !errors.Is(err, ErrExternalCommandTimeout) {
		t.Fatalf("hanging tart get error does not wrap ErrExternalCommandTimeout: %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("tart get took %v; the probe ceiling did not bound it", elapsed)
	}
}

// TestTartIPProbeHangingPhaseCeiling proves each `tart ip` attempt is bounded
// by the probe ceiling even when the enclosing IP-wait window is far away.
func TestTartIPProbeHangingPhaseCeiling(t *testing.T) {
	testutil.UnixShell(t)
	origProbe := runtimeProbeTimeout
	runtimeProbeTimeout = 150 * time.Millisecond
	t.Cleanup(func() { runtimeProbeTimeout = origProbe })

	fake := writeCleanupScript(t, "tart", "#!/bin/sh\nexec sleep 300\n")
	start := time.Now()
	ip := tartIPProbe(context.Background(), time.Now().Add(time.Hour), fake, "kiwi-1")
	elapsed := time.Since(start)
	if ip != "" {
		t.Fatalf("hanging tart ip returned %q, want empty", ip)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("tart ip probe took %v; the probe ceiling did not bound it", elapsed)
	}
}

// TestSetupPhaseLongButSuccessfulWithinCeiling proves a setup that is slow
// but healthy (pulls take time) still succeeds when it finishes inside its
// phase ceiling: the ceiling bounds the phase, it does not forbid slowness.
func TestSetupPhaseLongButSuccessfulWithinCeiling(t *testing.T) {
	testutil.UnixShell(t)
	origProbe, origControl, origSetup := runtimeProbeTimeout, runtimeControlTimeout, runtimeSetupTimeout
	// The fake subcommands take 0.2s each; a 20s ceiling leaves a 100x
	// margin so a heavily loaded host cannot turn a healthy-but-slow setup
	// into a spurious timeout (the macOS lane hit exactly that at 5s while
	// the integration lane was compiling).
	runtimeProbeTimeout, runtimeControlTimeout, runtimeSetupTimeout = 20*time.Second, 20*time.Second, 20*time.Second
	t.Cleanup(func() {
		runtimeProbeTimeout, runtimeControlTimeout, runtimeSetupTimeout = origProbe, origControl, origSetup
	})

	dir := t.TempDir()
	script := `#!/bin/sh
sub="$1"; shift
case "$sub" in
  info) sleep 0.2; echo "[name=seccomp,profile=builtin name=rootless]"; exit 0;;
  network) sleep 0.2; echo netid; exit 0;;
  run) sleep 0.2; echo fake-container; exit 0;;
esac
exit 0
`
	fake := filepath.Join(dir, "docker")
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := requireRootlessDaemon(context.Background(), fake); err != nil {
		t.Fatalf("slow but healthy docker info = %v", err)
	}
	_, cleanup, err := startContainerServices(context.Background(), "r", "j",
		[]pipeline.Service{{Name: "db", Image: "postgres:16"}},
		pipeline.Resources{}, false, false, "", func(string) {})
	if err != nil {
		t.Fatalf("slow but healthy services = %v", err)
	}
	cleanup()

	b := &ContainerBackend{Image: "alpine:3.19", RunID: "r", JobID: "j"}
	if err := b.StartJob(context.Background(), t.TempDir(), func(string) {}); err != nil {
		t.Fatalf("slow but healthy job docker run = %v", err)
	}
	if err := b.CloseJob(); err != nil {
		t.Fatalf("CloseJob: %v", err)
	}
}
