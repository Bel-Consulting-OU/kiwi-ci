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

func TestContainerInitEPERMDetection(t *testing.T) {
	if !containerInitEPERM("docker: Error response from daemon: failed to create task: exec /sbin/docker-init: operation not permitted") {
		t.Fatal("docker-init EPERM signature not detected")
	}
	if containerInitEPERM("docker: image pull failed: manifest unknown") {
		t.Fatal("unrelated failure misclassified as init EPERM")
	}
	got := withoutFlag([]string{"run", "--init", "-d", "--init", "x"}, "--init")
	if strings.Join(got, " ") != "run -d x" {
		t.Fatalf("withoutFlag = %v", got)
	}
}

// TestStartJobRetriesWithoutInitOnEPERM: when the daemon refuses docker-init
// under no-new-privileges, StartJob retries once without --init and still
// starts the hold container; any other run failure keeps failing.
func TestStartJobRetriesWithoutInitOnEPERM(t *testing.T) {
	dir := t.TempDir()
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_RUN_INIT_EPERM", "1")
	t.Setenv("FAKE_DOCKER_RUN_INIT_EPERM_MARKER", filepath.Join(dir, "init-eperm-marker"))
	b := &ContainerBackend{
		RunID:    "run-init-retry",
		JobID:    "job",
		Image:    "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
		Rootless: true,
	}
	var lines []string
	if err := b.StartJob(context.Background(), dir, func(s string) { lines = append(lines, s) }); err != nil {
		t.Fatalf("StartJob with init EPERM retry: %v", err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "retrying without --init") {
		t.Fatalf("retry warning missing: %s", joined)
	}
	if !strings.Contains(joined, "job container started") {
		t.Fatalf("container did not start after retry: %s", joined)
	}
}

func initEPERMBackend(t *testing.T) (*ContainerBackend, string) {
	t.Helper()
	installFakeBins(t)
	state := t.TempDir()
	t.Setenv("FAKE_DOCKER_STATE", state)
	t.Setenv("FAKE_DOCKER_RUN_INIT_EPERM", "1")
	t.Setenv("FAKE_DOCKER_RUN_INIT_EPERM_MARKER", filepath.Join(t.TempDir(), "init-eperm-marker"))
	t.Setenv("FAKE_DOCKER_RUN_INIT_EPERM_CREATE", "1")
	b := &ContainerBackend{
		RunID:    "run-init-create",
		JobID:    "job",
		Image:    "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
		Rootless: true,
	}
	return b, state
}

// TestStartJobInitEPERMAfterCreateRemovesBeforeRetry: the docker-init EPERM
// can arrive AFTER the daemon created the container. Retrying with the SAME
// name without proving absence would then fail with "container already
// exists"; the fixed path removes the possibly-created container first and
// only then retries without --init.
func TestStartJobInitEPERMAfterCreateRemovesBeforeRetry(t *testing.T) {
	b, _ := initEPERMBackend(t)
	var lines []string
	if err := b.StartJob(context.Background(), t.TempDir(), func(s string) { lines = append(lines, s) }); err != nil {
		t.Fatalf("StartJob with init EPERM after create: %v", err)
	}
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	runs := runLines(log)
	if len(runs) != 2 {
		t.Fatalf("docker run lines = %d, want 2 (EPERM attempt + retry):\n%s", len(runs), log)
	}
	if !strings.Contains(runs[0], "--init") || strings.Contains(runs[1], "--init") {
		t.Fatalf("init profile changed across attempts: %v", runs)
	}
	rmIdx := strings.Index(log, "rm -f "+b.container)
	retryIdx := strings.LastIndex(log, "run -d ")
	if rmIdx < 0 || retryIdx < 0 || rmIdx > retryIdx {
		t.Fatalf("remove-by-name must precede the retry (rm@%d, retry@%d):\n%s", rmIdx, retryIdx, log)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "retrying without --init") || !strings.Contains(joined, "job container started") {
		t.Fatalf("emitted = %s", joined)
	}
	if b.container == "" || b.docker == "" {
		t.Fatal("session state not set after retry")
	}
}

// TestStartJobInitEPERMAfterCreateRemovalFailureReportsDebt: when the
// post-EPERM remove cannot prove absence, the init fallback must NOT be
// attempted (a retry would collide with the possibly-created container and
// hide it). The identity stays, cleanup debt is reported, and StartJob fails
// with a "may exist" error.
func TestStartJobInitEPERMAfterCreateRemovalFailureReportsDebt(t *testing.T) {
	b, state := initEPERMBackend(t)
	t.Setenv("FAKE_DOCKER_RM_EXIT", "1")
	var debts []CleanupDebt
	b.ReportCleanupDebt = backendDebtCollector(&debts)
	var lines []string
	err := b.StartJob(context.Background(), t.TempDir(), func(s string) { lines = append(lines, s) })
	if err == nil || !strings.Contains(err.Error(), "may exist") || !strings.Contains(err.Error(), "init fallback not attempted") {
		t.Fatalf("unproven absence after init EPERM = %v, want a may-exist error", err)
	}
	if kind := errorKind(err); kind != ErrorInfra {
		t.Fatalf("kind = %q, want %q", kind, ErrorInfra)
	}
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	if got := len(runLines(log)); got != 1 {
		t.Fatalf("docker run lines = %d, want exactly 1 (no retry):\n%s", got, log)
	}
	if len(debts) != 1 || debts[0].Kind != CleanupMainRuntime || debts[0].Resource != b.container || debts[0].Err == nil {
		t.Fatalf("debts = %+v, want one %s debt for %q", debts, CleanupMainRuntime, b.container)
	}
	if strings.Contains(strings.Join(lines, "\n"), "retrying without --init") {
		t.Fatalf("init fallback was retried despite unproven absence: %v", lines)
	}
	if _, statErr := os.Stat(filepath.Join(state, b.container)); statErr != nil {
		t.Fatalf("container may exist, but its fake state is gone: %v", statErr)
	}
}
