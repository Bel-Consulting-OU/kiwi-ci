package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestServiceRunArgsNeverMountDockerSock pins the SM14-F5 contract: service
// containers are started by the HOST daemon with no docker-socket mount and
// no --privileged flag. A DB-gated suite reaches them only via the job
// network alias — the executor image can stay docker-free.
func TestServiceRunArgsNeverMountDockerSock(t *testing.T) {
	installFakeBins(t)
	services := []pipeline.Service{
		{Name: "postgres", Image: "postgres:16-alpine"},
		{Name: "redis", Image: "redis:7-alpine"},
	}
	_, cleanup, err := startContainerServices(t.Context(), "run1", "job1", services, pipeline.Resources{}, false, false, "", func(string) {})
	if cleanup != nil {
		_ = cleanup()
	}
	_ = err // the fake daemon may fail later phases; the argv is what we pin

	logPath := os.Getenv("FAKE_DOCKER_LOG")
	outBytes, _ := os.ReadFile(logPath)
	out := string(outBytes)
	if strings.Contains(out, "docker.sock") {
		t.Fatalf("service run must not mount docker.sock:\n%s", out)
	}
	if strings.Contains(out, "--privileged") {
		t.Fatalf("service run must not use --privileged:\n%s", out)
	}
	if !strings.Contains(out, "--network-alias postgres") {
		t.Fatalf("postgres alias missing:\n%s", out)
	}
	if !strings.Contains(out, "--network-alias redis") {
		t.Fatalf("redis alias missing:\n%s", out)
	}
	if !strings.Contains(out, "--cap-drop=ALL") {
		t.Fatalf("service run must drop all caps:\n%s", out)
	}
}

// TestServiceCommandAppendedAfterImage: custom entrypoints (Woodpecker
// service commands) land after the image, never as docker flags.
func TestServiceCommandAppendedAfterImage(t *testing.T) {
	installFakeBins(t)
	services := []pipeline.Service{
		{Name: "cache", Image: "redis:7", Command: []string{"redis-server", "--save", ""}},
	}
	_, cleanup, err := startContainerServices(t.Context(), "run1", "job1", services, pipeline.Resources{}, false, false, "", func(string) {})
	if cleanup != nil {
		_ = cleanup()
	}
	_ = err
	logPath := os.Getenv("FAKE_DOCKER_LOG")
	outBytes, _ := os.ReadFile(logPath)
	out := string(outBytes)
	idx := strings.Index(out, "redis:7")
	if idx < 0 {
		t.Fatalf("image not in argv:\n%s", out)
	}
	rest := out[idx:]
	if !strings.Contains(rest, "redis-server") || !strings.Contains(rest, "--save") {
		t.Fatalf("command not appended after image:\n%s", out)
	}
	// The first token after the image is the entrypoint, not a docker flag.
	line := out
	for _, l := range strings.Split(line, "\n") {
		if strings.Contains(l, "redis:7") && strings.Contains(l, "redis-server") {
			parts := strings.Fields(l)
			for i, p := range parts {
				if p == "redis:7" && i+1 < len(parts) {
					if strings.HasPrefix(parts[i+1], "-") && parts[i+1] != "--save" {
						t.Fatalf("token after image looks like a docker flag: %q\n%s", parts[i+1], l)
					}
				}
			}
		}
	}
	_ = filepath.Separator
}
