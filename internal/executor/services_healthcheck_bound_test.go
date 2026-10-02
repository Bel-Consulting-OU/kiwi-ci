package executor

// Healthcheck output-bound regressions: the healthcheck command is
// pipeline-controlled, so its stdout/stderr must never be buffered unbounded
// in the RUNNER process. The capture retains a small diagnostic prefix,
// discards (but keeps draining) the rest, and reports truncation.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executil"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func runHugeHealthcheck(t *testing.T, spamBytes string, fd string) (time.Duration, error) {
	t.Helper()
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_EXEC_SPAM", spamBytes)
	t.Setenv("FAKE_DOCKER_EXEC_SPAM_FD", fd)
	hc := []pipeline.Service{{
		Name: "evil", Image: "postgres:16", Healthcheck: "while true; do head -c 1048576 /dev/zero; done",
		Retries: 1, Interval: pipeline.Duration{Duration: time.Millisecond},
		Timeout: pipeline.Duration{Duration: 5 * time.Second},
	}}
	start := time.Now()
	_, _, err := startContainerServices(context.Background(), "r", "j", hc, pipeline.Resources{}, true, false, "", func(string) {})
	return time.Since(start), err
}

func TestServiceHealthcheckOutputIsBounded(t *testing.T) {
	elapsed, err := runHugeHealthcheck(t, "8388608", "1") // 8 MiB stdout
	if err == nil {
		t.Fatal("spamming healthcheck reported healthy")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("healthcheck with huge output took %s: the capture likely stopped draining", elapsed)
	}
	if len(err.Error()) > maxHealthcheckOutputBytes+4096 {
		t.Fatalf("retained healthcheck diagnostic = %d bytes, want <= %d", len(err.Error()), maxHealthcheckOutputBytes+4096)
	}
	if !strings.Contains(err.Error(), "[output truncated]") {
		t.Fatalf("truncation not reported: %q", err.Error())
	}
}

func TestServiceHealthcheckHugeStderrIsBounded(t *testing.T) {
	elapsed, err := runHugeHealthcheck(t, "8388608", "2") // 8 MiB stderr
	if err == nil {
		t.Fatal("spamming healthcheck reported healthy")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("stderr-spamming healthcheck took %s", elapsed)
	}
	if len(err.Error()) > maxHealthcheckOutputBytes+4096 || !strings.Contains(err.Error(), "[output truncated]") {
		t.Fatalf("stderr capture not bounded/truncated: %d bytes", len(err.Error()))
	}
}

func TestEightUntrustedServicesCannotMultiplyHostOutputBufferWithoutBound(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_EXEC_SPAM", "4194304") // 4 MiB per attempt
	services := make([]pipeline.Service, 0, 8)
	for i := 0; i < 8; i++ {
		services = append(services, pipeline.Service{
			Name: "evil", Image: "postgres:16", Healthcheck: "while true; do head -c 1048576 /dev/zero; done",
			Retries: 1, Interval: pipeline.Duration{Duration: time.Millisecond},
			Timeout: pipeline.Duration{Duration: 5 * time.Second},
		})
	}
	start := time.Now()
	_, _, err := startContainerServices(context.Background(), "r", "j", services, pipeline.Resources{}, true, false, "", func(string) {})
	if err == nil {
		t.Fatal("eight spamming services reported healthy")
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("eight spamming services took %s: host capture is not bounded/draining", elapsed)
	}
}

// TestHealthcheckCollectorDrainsAfterCaptureLimit pins the collector itself:
// it retains at most the cap, reports truncation, and consumes every byte the
// child writes (so a full pipe can never block the child).
func TestHealthcheckCollectorDrainsAfterCaptureLimit(t *testing.T) {
	collector := executil.NewBoundedBuffer(maxHealthcheckOutputBytes)
	total := 0
	chunk := make([]byte, 64<<10)
	for i := 0; i < 512; i++ { // 32 MiB
		n, err := collector.Write(chunk)
		if err != nil || n != len(chunk) {
			t.Fatalf("write %d = (%d, %v), want full consumption", i, n, err)
		}
		total += n
	}
	if total != 32<<20 {
		t.Fatalf("consumed %d bytes, want %d", total, 32<<20)
	}
	if got := len(collector.Bytes()); got != maxHealthcheckOutputBytes {
		t.Fatalf("retained %d bytes, want the %d-byte cap", got, maxHealthcheckOutputBytes)
	}
	if !collector.Truncated() {
		t.Fatal("truncation not reported")
	}

	// A real child that streams far past the cap is fully drained: the
	// command finishes promptly instead of blocking on a full pipe.
	cmd := exec.Command("sh", "-c", "head -c 33554432 /dev/zero")
	out, truncated, err := executil.CaptureBounded(cmd, maxHealthcheckOutputBytes)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(out) != maxHealthcheckOutputBytes || !truncated {
		t.Fatalf("capture = %d bytes truncated=%t, want cap/true", len(out), truncated)
	}
}

// TestContainerReadFileBoundsStderr pins the remaining unbounded stderr path:
// `docker exec cat` normal stderr is tiny, but a hostile daemon/adapter must
// not be able to flood the runner through it.
func TestContainerReadFileBoundsStderr(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\nif [ \"$1\" = \"exec\" ]; then head -c 8388608 /dev/zero >&2; exit 1; fi\nexit 0\n"
	docker := filepath.Join(dir, "docker")
	if err := os.WriteFile(docker, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	b := &ContainerBackend{docker: docker, container: "c1", workspace: t.TempDir()}
	_, err := b.ReadFile(context.Background(), filepath.Join(b.workspace, "out.txt"), 1<<20)
	if err == nil {
		t.Fatal("spamming stderr read reported success")
	}
	if len(err.Error()) > maxCommandStderrBytes+4096 {
		t.Fatalf("container stderr capture unbounded: %d bytes", len(err.Error()))
	}
}
