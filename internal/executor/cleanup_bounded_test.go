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
)

// writeCleanupScript writes one executable fake binary and returns its path.
func writeCleanupScript(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestDockerCleanupCommandHangingDockerTimesOut is the Y2-B core: a fake
// docker that sleeps forever must not strand the caller; cleanup returns
// within the bound with the typed timeout error.
func TestDockerCleanupCommandHangingDockerTimesOut(t *testing.T) {
	orig := dockerCleanupTimeout
	dockerCleanupTimeout = 150 * time.Millisecond
	t.Cleanup(func() { dockerCleanupTimeout = orig })

	fake := writeCleanupScript(t, "docker", "#!/bin/sh\nexec sleep 300\n")
	start := time.Now()
	err := dockerCleanupCommand(context.Background(), fake, "rm", "-f", "stuck-container")
	elapsed := time.Since(start)
	if !errors.Is(err, ErrDockerCleanupTimeout) {
		t.Fatalf("hanging docker cleanup error = %v, want ErrDockerCleanupTimeout", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error does not wrap context.DeadlineExceeded: %v", err)
	}
	if !strings.Contains(err.Error(), "rm -f stuck-container") {
		t.Fatalf("timeout error does not name the command: %v", err)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("bounded cleanup took %v; the caller was stranded", elapsed)
	}
}

// TestDockerCleanupCommandRunsDespiteCancelledParent proves cleanup is
// detached from the (already dead) job context: it must still execute and
// succeed instead of failing instantly on a canceled parent.
func TestDockerCleanupCommandRunsDespiteCancelledParent(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "docker.log")
	fake := writeCleanupScript(t, "docker", "#!/bin/sh\necho \"$@\" >> \""+logPath+"\"\nexit 0\n")
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	if err := dockerCleanupCommand(parent, fake, "network", "rm", "net-1"); err != nil {
		t.Fatalf("cleanup with a cancelled parent = %v, want success", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("fake docker did not run: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "network rm net-1" {
		t.Fatalf("cleanup ran %q, want the network rm", got)
	}
}

// TestDockerCleanupCommandReportsFailureOutput proves failures are surfaced
// with trimmed output instead of being silently discarded.
func TestDockerCleanupCommandReportsFailureOutput(t *testing.T) {
	fake := writeCleanupScript(t, "docker", "#!/bin/sh\necho 'daemon exploded' >&2\nexit 3\n")
	err := dockerCleanupCommand(context.Background(), fake, "network", "rm", "net-1")
	if err == nil {
		t.Fatal("failing cleanup reported success")
	}
	if errors.Is(err, ErrDockerCleanupTimeout) {
		t.Fatalf("exit-3 cleanup reported a timeout: %v", err)
	}
	for _, want := range []string{"daemon exploded", "network rm net-1"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("cleanup error %q missing %q", err, want)
		}
	}
}

// TestStartContainerServicesCleanupBoundedAndSignals drives the real service
// cleanup closure with a fake docker that hangs on `rm -f` and `network rm`:
// cleanup returns within the bound and the failures are surfaced through the
// existing per-service emit sink as "cleanup required" diagnostics.
func TestStartContainerServicesCleanupBoundedAndSignals(t *testing.T) {
	orig := dockerCleanupTimeout
	dockerCleanupTimeout = 120 * time.Millisecond
	t.Cleanup(func() { dockerCleanupTimeout = orig })

	dir := t.TempDir()
	logPath := filepath.Join(dir, "docker.log")
	script := `#!/bin/sh
echo "$@" >> "` + logPath + `"
sub="$1"; shift
case "$sub" in
  network)
    case "$1" in
      create) echo netid; exit 0;;
      rm) exec sleep 300;;
    esac;;
  run) echo fake-container; exit 0;;
  rm) exec sleep 300;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	var lines []string
	_, cleanup, err := startContainerServices(context.Background(), "r", "j",
		[]pipeline.Service{{Name: "db", Image: "postgres:16"}},
		pipeline.Resources{}, false, false, "", func(line string) { lines = append(lines, line) })
	if err != nil {
		t.Fatalf("startContainerServices: %v", err)
	}
	start := time.Now()
	cleanup()
	elapsed := time.Since(start)
	if elapsed > 10*time.Second {
		t.Fatalf("bounded service cleanup took %v; the runner goroutine was stranded", elapsed)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "cleanup required") || !strings.Contains(joined, "timed out") {
		t.Fatalf("cleanup failures were not surfaced through emit:\n%s", joined)
	}
	data, readErr := os.ReadFile(logPath)
	if readErr != nil {
		t.Fatalf("fake docker did not run: %v", readErr)
	}
	if !strings.Contains(string(data), "rm -f "+serviceContainerName("r", "j", 0)) {
		t.Fatalf("service container removal was not attempted:\n%s", data)
	}
	if !strings.Contains(string(data), "network rm "+serviceNetworkName("r", "j")) {
		t.Fatalf("network removal was not attempted:\n%s", data)
	}
}

// TestContainerCloseJobHangingDockerBounded proves the job-container removal
// path is bounded and surfaces the typed timeout instead of blocking forever.
func TestContainerCloseJobHangingDockerBounded(t *testing.T) {
	orig := dockerCleanupTimeout
	dockerCleanupTimeout = 120 * time.Millisecond
	t.Cleanup(func() { dockerCleanupTimeout = orig })

	fake := writeCleanupScript(t, "docker", "#!/bin/sh\nexec sleep 300\n")
	b := &ContainerBackend{docker: fake, container: "kiwi-job-test"}
	start := time.Now()
	err := b.CloseJob()
	elapsed := time.Since(start)
	if err == nil || !errors.Is(err, ErrDockerCleanupTimeout) {
		t.Fatalf("hanging CloseJob = %v, want ErrDockerCleanupTimeout", err)
	}
	if !strings.Contains(err.Error(), "remove job container") {
		t.Fatalf("CloseJob error does not name the container removal: %v", err)
	}
	if b.container != "" {
		t.Fatalf("CloseJob left container state %q", b.container)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("bounded CloseJob took %v", elapsed)
	}
}

// TestContainerCloseJobSuccessUnchanged proves successful cleanup still
// reports no error and clears the session state.
func TestContainerCloseJobSuccessUnchanged(t *testing.T) {
	fake := writeCleanupScript(t, "docker", "#!/bin/sh\nexit 0\n")
	b := &ContainerBackend{docker: fake, container: "kiwi-job-test"}
	if err := b.CloseJob(); err != nil {
		t.Fatalf("successful CloseJob = %v", err)
	}
	if b.container != "" {
		t.Fatalf("CloseJob left container state %q", b.container)
	}
}
