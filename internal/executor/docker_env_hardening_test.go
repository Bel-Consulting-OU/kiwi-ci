package executor

// Docker CLI environment hardening: pipeline-controlled env must never
// redirect the docker client (DOCKER_HOST/context/TLS/config/proxy/HOME).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerClientEnvReplacesClientControlVars(t *testing.T) {
	job := []string{
		"DOCKER_HOST=tcp://attacker:2375",
		"docker_context=evil", // case-insensitive
		"HTTP_PROXY=http://attacker:8080",
		"HOME=/tmp/attacker-home",
		"SSL_CERT_FILE=/tmp/attacker.pem",
		"SECRET_TOKEN=shh",
		"FOO=bar",
	}
	runner := []string{
		"DOCKER_HOST=unix:///run/docker.sock",
		"HOME=/root",
		"HTTP_PROXY=",
	}
	got := dockerClientEnv(job, runner)
	joined := strings.Join(got, "\n")
	for _, must := range []string{"SECRET_TOKEN=shh", "FOO=bar", "DOCKER_HOST=unix:///run/docker.sock", "HOME=/root"} {
		if !strings.Contains(joined, must) {
			t.Fatalf("client env missing %q:\n%s", must, joined)
		}
	}
	for _, forbidden := range []string{"attacker", "/tmp/attacker"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("client env leaked job-controlled %q:\n%s", forbidden, joined)
		}
	}
}

func TestRunForwardsClientControlVarsByValueNotToCLI(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "docker.log")
	script := filepath.Join(dir, "docker")
	body := "#!/bin/sh\necho \"ARGS:$* ENVDOCKER:${DOCKER_HOST:-unset}\" >> \"$FAKE_LOG\"\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_HOST", "unix:///runner-real.sock")

	b := &ContainerBackend{docker: script, container: "c1", workspace: t.TempDir()}
	b.runnerClientEnv = runnerClientEnv()
	err := b.Run(context.Background(), Command{
		Dir:    b.workspace,
		Script: "true",
		Env:    []string{"DOCKER_HOST=tcp://attacker:2375", "KIWI_SECRET_X=s3cr3t", "FAKE_LOG=" + logPath},
	}, func(string) {})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	line := string(logged)
	if !strings.Contains(line, "-e DOCKER_HOST=tcp://attacker:2375") {
		t.Fatalf("job DOCKER_HOST not forwarded to the container by value: %s", line)
	}
	if strings.Contains(line, "ARGS:exec -w /workspace -e DOCKER_HOST -e KIWI_SECRET_X") {
		t.Fatalf("job DOCKER_HOST forwarded as a CLI-resolved name: %s", line)
	}
	if !strings.Contains(line, "ENVDOCKER:unix:///runner-real.sock") {
		t.Fatalf("docker CLI did not see the RUNNER's DOCKER_HOST: %s", line)
	}
	if !strings.Contains(line, "-e KIWI_SECRET_X") || strings.Contains(line, "s3cr3t") {
		t.Fatalf("secret handling regressed: %s", line)
	}
}

func TestContainerReadFileOversizeDoesNotHang(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "docker")
	body := "#!/bin/sh\nif [ \"$1\" = \"exec\" ]; then head -c 8388608 /dev/zero; exit 0; fi\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	b := &ContainerBackend{docker: script, container: "c1", workspace: t.TempDir()}
	out, err := b.ReadFile(context.Background(), filepath.Join(b.workspace, "f"), 1024)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize ReadFile = (%d bytes, %v), want a limit error", len(out), err)
	}
}
