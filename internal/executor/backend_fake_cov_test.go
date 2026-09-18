package executor

import (
	"context"
	"errors"
	"fmt"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/secrets"
)

const fakeDockerScript = `#!/bin/sh
echo "$@" >> "${FAKE_DOCKER_LOG:-/dev/null}"
sub="$1"; shift
case "$sub" in
  info)
    if [ -n "$FAKE_DOCKER_INFO" ]; then printf '%s\n' "$FAKE_DOCKER_INFO"; else echo "[name=seccomp,profile=builtin name=rootless]"; fi
    exit "${FAKE_DOCKER_INFO_EXIT:-0}";;
  run)
    if [ -n "$FAKE_DOCKER_RUN_FAIL" ]; then echo "run failed"; exit 1; fi
    echo "fake-container-$$"
    exit 0;;
  exec)
    ws="${FAKE_WS:-}"
    if [ -z "$ws" ]; then ws=$(cat "$(dirname "$0")/fake-ws" 2>/dev/null); fi
    while [ $# -gt 0 ]; do
      case "$1" in
        -w) shift;;
        -e) shift;;
        *) break;;
      esac
      shift
    done
    shift
    cmd="$1"; shift
    if [ "$cmd" = "cat" ]; then
      p="$1"
      case "$p" in
        /workspace*) p="$ws${p#/workspace}";;
      esac
      if [ "${FAKE_DOCKER_CAT_MISSING:-0}" = "1" ]; then echo "cat: $p: No such file or directory" >&2; exit 1; fi
      if [ -n "$FAKE_DOCKER_CAT_ERR" ]; then echo "$FAKE_DOCKER_CAT_ERR" >&2; exit 1; fi
      if [ -n "$FAKE_DOCKER_OVERSIZE" ]; then head -c "$FAKE_DOCKER_OVERSIZE" /dev/zero | tr '\0' 'x'; exit 0; fi
      exec cat "$p"
    fi
    if [ "${FAKE_DOCKER_EXEC_FAIL:-0}" = "1" ]; then echo "step failed" >&2; exit 3; fi
    if [ "$cmd" = "sh" ] && [ "$1" = "-lc" ]; then
      shift
      script="$1"
      tmp=$(mktemp)
      printf '%s\n' "$script" > "$tmp"
      ( cd "$ws" && sh "$tmp" )
      rc=$?
      rm -f "$tmp"
      exit $rc
    fi
    exec "$cmd" "$@";;
  ps)
    if [ "${FAKE_DOCKER_PS_EXIT:-0}" != "0" ]; then exit "$FAKE_DOCKER_PS_EXIT"; fi
    printf '%s\n' "$FAKE_DOCKER_PS";;
  network)
    case "$1" in
      create) if [ -n "$FAKE_DOCKER_NET_FAIL" ]; then echo "net fail"; exit 1; fi; echo "netid";;
      ls) printf '%s\n' "$FAKE_DOCKER_NET_LS";;
      rm) exit "${FAKE_DOCKER_NET_RM_EXIT:-0}";;
    esac;;
  rm) exit "${FAKE_DOCKER_RM_EXIT:-0}";;
esac
exit 0
`

const fakeTartScript = `#!/bin/sh
echo "$@" >> "${FAKE_TART_LOG:-/dev/null}"
sub="$1"
case "$sub" in
  run)
    if [ "$2" = "--help" ]; then
      if [ "${FAKE_TART_SELF_DESTRUCT:-0}" = "1" ]; then rm -f "$0"; exit 0; fi
      echo "--cpu"; echo "--memory"; exit 0
    fi
    if [ "${FAKE_TART_RUN_SLEEP:-0}" = "1" ]; then exec sleep 300; fi
    exit 0;;
  clone) exit "${FAKE_TART_CLONE_EXIT:-0}";;
  ip)
    if [ "${FAKE_TART_NO_IP:-0}" = "1" ]; then exit 0; fi
    if [ "${FAKE_TART_IP_EXIT:-0}" != "0" ]; then exit "$FAKE_TART_IP_EXIT"; fi
    echo "${FAKE_TART_IP:-127.0.0.1}";;
  get)
    if [ "${FAKE_TART_GET_FAIL:-0}" = "1" ]; then echo "get failed" >&2; exit 1; fi
    if [ -n "$FAKE_TART_GET_JSON" ]; then printf '%s\n' "$FAKE_TART_GET_JSON"; else printf '%s\n' '{"name":"vm","labels":{"kiwi.ssh.bootstrap":"true"}}'; fi;;
  delete) exit "${FAKE_TART_DELETE_EXIT:-0}";;
  list) printf '%s\n' "$FAKE_TART_LIST";;
esac
exit 0
`

const fakePwshScript = `#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    -NoProfile) shift;;
    -Command) shift; break;;
    *) break;;
  esac
done
if [ "$1" = "-" ]; then exec sh -s; fi
exec sh -c "$1"
`

const fakeSSHScript = `#!/bin/sh
echo "$@" >> "${FAKE_SSH_LOG:-/dev/null}"
last=""
for a in "$@"; do last="$a"; done
if [ "${FAKE_SSH_EXIT:-0}" != "0" ]; then echo "${FAKE_SSH_STDERR:-ssh error}" >&2; exit "$FAKE_SSH_EXIT"; fi
cmd=$(printf '%s' "$last" | sed "s#/Volumes/My Shared Files/workspace#${FAKE_WS}#g")
eval "$cmd"
`

// installFakeBins writes the fake bin scripts and prepends them to PATH.
func installFakeBins(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{"docker": fakeDockerScript, "tart": fakeTartScript, "ssh": fakeSSHScript, "pwsh": fakePwshScript} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	logDir := t.TempDir()
	t.Setenv("FAKE_DOCKER_LOG", filepath.Join(logDir, "docker.log"))
	t.Setenv("FAKE_TART_LOG", filepath.Join(logDir, "tart.log"))
	t.Setenv("FAKE_SSH_LOG", filepath.Join(logDir, "ssh.log"))
	// The fakes call regular shell utilities (cat, sed, mktemp): keep the
	// system PATH behind the fake directory.
	t.Setenv("FAKE_BIN_DIR", dir)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return dir
}

// fakeBinDir returns the fake binary directory installed by installFakeBins.
func fakeBinDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("FAKE_BIN_DIR")
	if dir == "" {
		t.Fatal("fake binaries not installed")
	}
	return dir
}

// setFakeWS points the fake docker workspace mapping at ws. The docker CLI
// env is replaced by the job env at exec time, so the workspace travels via
// a sidecar file in the fake bin directory instead of an env var.
func setFakeWS(t *testing.T, ws string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(fakeBinDir(t), "fake-ws"), []byte(ws), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestContainerBackendStartJobFakeDocker(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	b := &ContainerBackend{Image: "alpine:3.19", RunID: "run1", JobID: "job1",
		Resources: pipeline.Resources{CPU: 1.5, Memory: 1 << 30, PIDs: 128}}
	var lines []string
	if err := b.StartJob(context.Background(), ws, func(s string) { lines = append(lines, s) }); err != nil {
		t.Fatalf("StartJob: %v", err)
	}
	if b.container == "" || b.docker == "" {
		t.Fatal("session state not set")
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "job container started") {
		t.Fatalf("emit = %v", lines)
	}
	// Read-only + rootless + explicit network produce the hardened flags. A
	// rootless daemon runs the workload as namespace root: container root maps
	// to the host runner uid, so the bind mount stays accessible without any
	// host-side chown (see TestContainerBackendStartJobHardenedRootful…).
	b2 := &ContainerBackend{Image: "alpine:3.19", Network: "kiwi-net", Rootless: true, ReadOnlyRootFS: true, RunID: "r", JobID: "j"}
	if err := b2.StartJob(context.Background(), ws, func(string) {}); err != nil {
		t.Fatalf("hardened StartJob: %v", err)
	}
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	if !strings.Contains(log, "--read-only") || !strings.Contains(log, "--user=0:0") || !strings.Contains(log, "--network=kiwi-net") {
		t.Fatalf("hardened args missing: %s", log)
	}
}

func TestContainerBackendStartJobErrors(t *testing.T) {
	ws := t.TempDir()
	// Missing image.
	b := &ContainerBackend{}
	if err := b.StartJob(context.Background(), ws, func(string) {}); err == nil {
		t.Fatal("missing image accepted")
	}
	// Unpinned image under the immutability requirement.
	b = &ContainerBackend{Image: "alpine:latest", RequireImmutableImages: true}
	err := b.StartJob(context.Background(), ws, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("unpinned image = %v", err)
	}
	// Docker missing from PATH.
	t.Setenv("PATH", t.TempDir())
	b = &ContainerBackend{Image: "alpine:3.19"}
	if err := b.StartJob(context.Background(), ws, func(string) {}); err == nil {
		t.Fatal("docker-less StartJob succeeded")
	}
	// Rootless verification fails on a rootful daemon.
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_INFO", "[name=seccomp,profile=builtin]")
	b = &ContainerBackend{Image: "alpine:3.19", Rootless: true}
	err = b.StartJob(context.Background(), ws, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "not rootless") {
		t.Fatalf("rootful daemon = %v", err)
	}
	// The docker run invocation itself fails.
	t.Setenv("FAKE_DOCKER_INFO", "")
	t.Setenv("FAKE_DOCKER_RUN_FAIL", "1")
	b = &ContainerBackend{Image: "alpine:3.19"}
	err = b.StartJob(context.Background(), ws, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "start job container") {
		t.Fatalf("docker run failure = %v", err)
	}
	// The docker info probe itself fails.
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_INFO_EXIT", "1")
	b = &ContainerBackend{Image: "alpine:3.19", Rootless: true}
	if err := b.StartJob(context.Background(), ws, func(string) {}); err == nil {
		t.Fatal("failing docker info accepted")
	}
}

func TestContainerBackendRunFakeDocker(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	if err := os.MkdirAll(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	b := &ContainerBackend{}
	// Not started.
	if err := b.Run(context.Background(), Command{Script: "true"}, func(string) {}); err == nil {
		t.Fatal("unstarted Run succeeded")
	}
	if _, err := b.ReadFile(context.Background(), filepath.Join(ws, "f"), 10); err == nil {
		t.Fatal("unstarted ReadFile succeeded")
	}
	b.docker, b.container, b.workspace = "docker", "cid", ws
	var emitted []string
	err := b.Run(context.Background(), Command{Shell: "sh", Script: "echo container-ok", Dir: filepath.Join(ws, "sub"), Env: []string{"A=1", "BAD"}}, func(s string) { emitted = append(emitted, s) })
	if err != nil {
		t.Fatalf("container Run: %v", err)
	}
	if !containsLine(emitted, "container-ok") {
		t.Fatalf("emitted = %v", emitted)
	}
	// pwsh scripts take the -Command path.
	if err := b.Run(context.Background(), Command{Shell: "pwsh", Script: "echo pwsh", Dir: ws}, func(string) {}); err != nil {
		t.Fatalf("pwsh Run: %v", err)
	}
	// A step directory outside the workspace is rejected.
	err = b.Run(context.Background(), Command{Script: "true", Dir: filepath.Join(ws, "..", "elsewhere")}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "outside mounted workspace") {
		t.Fatalf("outside dir = %v", err)
	}
	// A failing script classifies as a command failure.
	err = b.Run(context.Background(), Command{Shell: "sh", Script: "exit 7", Dir: ws}, func(string) {})
	if err == nil || errorKind(err) != ErrorFailure {
		t.Fatalf("failing script = %v", err)
	}
	// A timeout classifies as a timeout.
	err = b.Run(context.Background(), Command{Shell: "sh", Script: "sleep 5", Dir: ws, TimeoutSeconds: 1}, func(string) {})
	if err == nil || errorKind(err) != ErrorTimeout {
		t.Fatalf("timeout run = %v", err)
	}
}

func TestContainerBackendReadFileFakeDocker(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	setFakeWS(t, ws)
	file := filepath.Join(ws, "out.txt")
	if err := os.WriteFile(file, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := &ContainerBackend{docker: "docker", container: "cid", workspace: ws}
	got, err := b.ReadFile(context.Background(), file, 100)
	if err != nil || string(got) != "payload" {
		t.Fatalf("ReadFile = %q, %v", got, err)
	}
	// A path outside the mounted workspace is rejected.
	if _, err := b.ReadFile(context.Background(), filepath.Join(ws, "..", "host.txt"), 100); err == nil {
		t.Fatal("outside path accepted")
	}
	// A missing file maps to os.ErrNotExist.
	t.Setenv("FAKE_DOCKER_CAT_MISSING", "1")
	if _, err := b.ReadFile(context.Background(), file, 100); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file = %v", err)
	}
	// Any other cat failure is surfaced.
	t.Setenv("FAKE_DOCKER_CAT_MISSING", "")
	t.Setenv("FAKE_DOCKER_CAT_ERR", "cat exploded")
	if _, err := b.ReadFile(context.Background(), file, 100); err == nil || !strings.Contains(err.Error(), "cat exploded") {
		t.Fatalf("cat failure = %v", err)
	}
	// Oversized files are rejected by the cap.
	t.Setenv("FAKE_DOCKER_CAT_ERR", "")
	t.Setenv("FAKE_DOCKER_OVERSIZE", "64")
	if _, err := b.ReadFile(context.Background(), file, 8); err == nil {
		t.Fatal("oversized file accepted")
	}
}

func TestContainerBackendCloseJob(t *testing.T) {
	installFakeBins(t)
	if err := (&ContainerBackend{}).CloseJob(); err != nil {
		t.Fatalf("no session CloseJob = %v", err)
	}
	b := &ContainerBackend{docker: "docker", container: "cid"}
	if err := b.CloseJob(); err != nil {
		t.Fatalf("CloseJob: %v", err)
	}
	if b.container != "" {
		t.Fatal("container name retained")
	}
	// A failing rm surfaces an error.
	t.Setenv("FAKE_DOCKER_RM_EXIT", "1")
	b = &ContainerBackend{docker: "docker", container: "cid"}
	if err := b.CloseJob(); err == nil {
		t.Fatal("failing rm accepted")
	}
	// "No such container" is tolerated.
	installFakeBins(t)
	script := filepath.Join(fakeBinDir(t), "docker")
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte(strings.Replace(string(body), `rm) exit "${FAKE_DOCKER_RM_EXIT:-0}";;`, `rm) echo "Error: No such container: cid" >&2; exit 1;;`, 1)), 0o755); err != nil {
		t.Fatal(err)
	}
	b = &ContainerBackend{docker: "docker", container: "cid"}
	if err := b.CloseJob(); err != nil {
		t.Fatalf("No such container must be tolerated: %v", err)
	}
}

func TestFindPortAndRootlessHelpers(t *testing.T) {
	if !securityOptionsRootless("[name=seccomp,profile=builtin name=ROOTLESS]") {
		t.Fatal("case-insensitive rootless detection failed")
	}
	if securityOptionsRootless("[]") {
		t.Fatal("rootful report detected as rootless")
	}
	installFakeBins(t)
	if err := requireRootlessDaemon(context.Background(), "docker"); err != nil {
		t.Fatalf("fake rootless daemon: %v", err)
	}
	t.Setenv("FAKE_DOCKER_INFO", "[]")
	if err := requireRootlessDaemon(context.Background(), "docker"); err == nil {
		t.Fatal("rootful daemon accepted")
	}
	if err := (&ContainerBackend{}).verifyRootlessDaemon(context.Background(), "docker"); err == nil {
		t.Fatal("verifyRootlessDaemon with rootful daemon succeeded")
	}
}

func TestStartContainerServicesFakeDocker(t *testing.T) {
	installFakeBins(t)
	ctx := context.Background()
	services := []pipeline.Service{{Name: "db", Image: "postgres:16", Env: map[string]string{"POSTGRES_PASSWORD": "x"}}}
	network, cleanup, err := startContainerServices(ctx, "run1", "job1", services, true, false, func(string) {})
	if err != nil {
		t.Fatalf("startContainerServices: %v", err)
	}
	if network == "" || cleanup == nil {
		t.Fatal("network/cleanup missing")
	}
	cleanup()
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	if !strings.Contains(log, "network create --driver bridge --internal") {
		t.Fatalf("isolated network args missing: %s", log)
	}
	// A long name is truncated to 60 characters.
	long := strings.Repeat("a", 80)
	network, cleanup, err = startContainerServices(ctx, long, long, services, false, false, func(string) {})
	if err != nil {
		t.Fatalf("long-name services: %v", err)
	}
	if len(network) > 60 {
		t.Fatalf("network name not truncated: %d", len(network))
	}
	cleanup()
	// Healthcheck success path (immediate, with the default interval and
	// retry budget).
	hc := []pipeline.Service{{Name: "db", Image: "postgres:16", Healthcheck: "true"}}
	if _, cleanup, err = startContainerServices(ctx, "r", "j", hc, false, false, func(string) {}); err != nil {
		t.Fatalf("healthcheck success: %v", err)
	}
	cleanup()
	// Healthcheck success after one retry uses an explicit interval.
	hc = []pipeline.Service{{Name: "db", Image: "postgres:16", Healthcheck: "true", Retries: 2, Interval: pipeline.Duration{Duration: 10 * time.Millisecond}}}
	if _, cleanup, err = startContainerServices(ctx, "r", "j", hc, false, false, func(string) {}); err != nil {
		t.Fatalf("healthcheck retry: %v", err)
	}
	cleanup()
}

func TestStartContainerServicesErrors(t *testing.T) {
	ctx := context.Background()
	// Missing image.
	if _, _, err := startContainerServices(ctx, "r", "j", []pipeline.Service{{}}, false, false, func(string) {}); err == nil {
		t.Fatal("missing service image accepted")
	}
	// Unpinned image under the immutability requirement.
	if _, _, err := startContainerServices(ctx, "r", "j", []pipeline.Service{{Image: "postgres:16"}}, false, true, func(string) {}); err == nil {
		t.Fatal("unpinned service image accepted")
	}
	// Docker missing.
	t.Setenv("PATH", t.TempDir())
	if _, _, err := startContainerServices(ctx, "r", "j", []pipeline.Service{{Image: "postgres:16"}}, false, false, func(string) {}); err == nil {
		t.Fatal("docker-less services succeeded")
	}
	installFakeBins(t)
	svc := []pipeline.Service{{Image: "postgres:16"}}
	// Network creation fails.
	t.Setenv("FAKE_DOCKER_NET_FAIL", "1")
	if _, _, err := startContainerServices(ctx, "r", "j", svc, false, false, func(string) {}); err == nil {
		t.Fatal("network failure accepted")
	}
	// Service start fails (cleanup runs).
	t.Setenv("FAKE_DOCKER_NET_FAIL", "")
	t.Setenv("FAKE_DOCKER_RUN_FAIL", "1")
	if _, _, err := startContainerServices(ctx, "r", "j", svc, false, false, func(string) {}); err == nil {
		t.Fatal("service start failure accepted")
	}
	// Healthcheck exhausts its retries and fails (cleanup runs).
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_RUN_FAIL", "")
	t.Setenv("FAKE_DOCKER_EXEC_FAIL", "1")
	hc := []pipeline.Service{{Name: "db", Image: "postgres:16", Healthcheck: "false", Retries: 1, Interval: pipeline.Duration{Duration: time.Millisecond}}}
	if _, _, err := startContainerServices(ctx, "r", "j", hc, false, false, func(string) {}); err == nil {
		t.Fatal("unhealthy service accepted")
	}
	// A context cancelled during the healthcheck wait aborts it: a long
	// interval keeps the retry asleep until the cancel lands.
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_EXEC_FAIL", "1")
	slowHC := []pipeline.Service{{Name: "db", Image: "postgres:16", Healthcheck: "false", Retries: 3, Interval: pipeline.Duration{Duration: 5 * time.Second}}}
	cctx, cancel := context.WithCancel(ctx)
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	if _, _, err := startContainerServices(cctx, "r", "j", slowHC, false, false, func(string) {}); err == nil {
		t.Fatal("cancelled service wait accepted")
	}
	// A pre-cancelled context aborts immediately.
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_EXEC_FAIL", "1")
	cctx2, cancel2 := context.WithCancel(ctx)
	cancel2()
	if _, _, err := startContainerServices(cctx2, "r", "j", hc, false, false, func(string) {}); err == nil {
		t.Fatal("pre-cancelled service wait accepted")
	}
}

func TestServiceNetworkAndNameHelpers(t *testing.T) {
	if got := serviceNetworkArgs(false); len(got) != 3 {
		t.Fatalf("non-isolated args = %v", got)
	}
	if got := serviceNetworkArgs(true); got[len(got)-1] != "--internal" {
		t.Fatalf("isolated args = %v", got)
	}
	if got := serviceContainerName("r", "j", 0, pipeline.Service{}); !strings.HasPrefix(got, "kiwi-svc-r-j-1") {
		t.Fatalf("default name = %q", got)
	}
	got := serviceContainerName("r", "j", 0, pipeline.Service{Name: "My DB!"})
	if got != "my-db-" {
		t.Fatalf("custom name = %q", got)
	}
	if got := serviceContainerName("r", "j", 0, pipeline.Service{Name: "!!!"}); got != "---" {
		t.Fatalf("sanitized name = %q", got)
	}
}

func TestGCFakeBinaries(t *testing.T) {
	installFakeBins(t)
	root := t.TempDir()
	old := time.Now().Add(-48 * time.Hour).Format("2006-01-02 15:04:05 -0700 MST")
	t.Setenv("FAKE_DOCKER_PS", "cid1 "+old+"\ncid2 not-a-time")
	t.Setenv("FAKE_DOCKER_NET_LS", "net1 "+old)
	t.Setenv("FAKE_TART_LIST", fmt.Sprintf("kiwi-%d running", time.Now().Add(-48*time.Hour).UnixNano()))
	rep := GC(context.Background(), root, time.Hour)
	if rep.Containers != 1 || rep.Networks != 1 || rep.VMs != 1 {
		t.Fatalf("GC report = %+v", rep)
	}
	// Failing removals are not counted.
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_PS", "cid1 "+old)
	t.Setenv("FAKE_DOCKER_RM_EXIT", "1")
	t.Setenv("FAKE_DOCKER_NET_LS", "net1 "+old)
	t.Setenv("FAKE_DOCKER_NET_RM_EXIT", "1")
	t.Setenv("FAKE_TART_LIST", fmt.Sprintf("kiwi-%d", time.Now().Add(-48*time.Hour).UnixNano()))
	t.Setenv("FAKE_TART_DELETE_EXIT", "1")
	rep = GC(context.Background(), root, time.Hour)
	if rep != (GCReport{}) {
		t.Fatalf("failing GC report = %+v", rep)
	}
	// A failing docker ps output helper returns nothing.
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_PS", "")
	if rep := GC(context.Background(), root, time.Hour); rep.Containers != 0 {
		t.Fatalf("empty ps report = %+v", rep)
	}
}

func TestTartBackendPureStartErrors(t *testing.T) {
	testutil.UnixShell(t)
	ctx := context.Background()
	ws := t.TempDir()
	// Missing VM.
	if err := (&TartBackend{}).StartJob(ctx, ws, func(string) {}); err == nil {
		t.Fatal("missing VM accepted")
	}
	// Network isolation is refused before any tart invocation.
	for _, net := range []string{"none", "services-only"} {
		b := &TartBackend{VM: "vm", Network: net}
		if err := b.StartJob(ctx, ws, func(string) {}); err == nil {
			t.Fatalf("network %q accepted", net)
		}
	}
	b := &TartBackend{VM: "vm", Network: "weird"}
	if err := b.StartJob(ctx, ws, func(string) {}); err == nil {
		t.Fatal("unknown network accepted")
	}
	// Legacy network values pass that check.
	if err := (&TartBackend{VM: "vm", Network: "host"}).StartJob(ctx, ws, func(string) {}); err == nil {
		t.Fatal("expected tart-not-found")
	}
	// Unpinned VM under the immutability requirement.
	b = &TartBackend{VM: "vm", RequireImmutableImages: true}
	if err := b.StartJob(ctx, ws, func(string) {}); err == nil {
		t.Fatal("unpinned VM accepted")
	}
	// Tart and ssh lookups.
	installFakeBins(t)
	if err := (&TartBackend{VM: "vm"}).StartJob(ctx, ws, func(string) {}); err != nil {
		// Without the local kiwi-agent this is the expected error; any
		// other outcome means the fake contract drifted.
		if !strings.Contains(err.Error(), "kiwi-agent key injection failed") {
			t.Fatalf("tart StartJob = %v", err)
		}
	}
}

func TestTartBackendStartJobViaFakes(t *testing.T) {
	testutil.UnixShell(t)
	installFakeBins(t)
	ws := t.TempDir()
	// A local kiwi-agent on the fixed bootstrap port accepts the key.
	ln, err := net.Listen("tcp", "127.0.0.1:4545")
	if err != nil {
		t.Skipf("port 4545 unavailable: %v", err)
	}
	agent := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != tartAgentKeyPath || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = agent.Serve(ln) }()
	t.Cleanup(func() { _ = agent.Close() })
	t.Setenv("FAKE_TART_RUN_SLEEP", "1")
	b := &TartBackend{VM: "ghcr.io/x/vm:latest", Resources: pipeline.Resources{CPU: 2, Memory: 1 << 30, Disk: 1 << 20}}
	var emitted []string
	if err := b.StartJob(context.Background(), ws, func(s string) { emitted = append(emitted, s) }); err != nil {
		t.Fatalf("tart StartJob: %v", err)
	}
	if b.clone == "" || b.ip != "127.0.0.1" {
		t.Fatalf("session state: clone=%q ip=%q", b.clone, b.ip)
	}
	if !containsLine(emitted, "Tart VM ready") {
		t.Fatalf("emitted = %v", emitted)
	}
	if err := b.CloseJob(); err != nil {
		t.Fatalf("CloseJob: %v", err)
	}
	if b.clone != "" || b.sshDir != "" {
		t.Fatal("CloseJob did not clear session state")
	}
}

func TestTartBackendStartJobErrorBranches(t *testing.T) {
	testutil.UnixShell(t)
	ctx := context.Background()
	ws := t.TempDir()
	// Clone failure.
	installFakeBins(t)
	t.Setenv("FAKE_TART_CLONE_EXIT", "1")
	if err := (&TartBackend{VM: "vm"}).StartJob(ctx, ws, func(string) {}); err == nil {
		t.Fatal("clone failure accepted")
	}
	t.Setenv("FAKE_TART_CLONE_EXIT", "0")
	// No IP within the loop's first iteration (the fake never reports one;
	// the loop would sleep a second per attempt, so cancel instead).
	installFakeBins(t)
	t.Setenv("FAKE_TART_NO_IP", "1")
	cctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	if err := (&TartBackend{VM: "vm"}).StartJob(cctx, ws, func(string) {}); err == nil {
		t.Fatal("IP-less tart run accepted")
	}
	t.Setenv("FAKE_TART_NO_IP", "0")
	// Bootstrap label missing.
	installFakeBins(t)
	t.Setenv("FAKE_TART_CLONE_EXIT", "0")
	t.Setenv("FAKE_TART_GET_JSON", `{"name":"vm","labels":{}}`)
	b := &TartBackend{VM: "vm"}
	err := b.StartJob(ctx, ws, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "bootstrap contract") {
		t.Fatalf("missing bootstrap label = %v", err)
	}
	// Malformed tart get JSON.
	installFakeBins(t)
	t.Setenv("FAKE_TART_CLONE_EXIT", "0")
	t.Setenv("FAKE_TART_GET_JSON", "{")
	if err := (&TartBackend{VM: "vm"}).StartJob(ctx, ws, func(string) {}); err == nil {
		t.Fatal("malformed tart get JSON accepted")
	}
	// tart get itself fails.
	installFakeBins(t)
	t.Setenv("FAKE_TART_CLONE_EXIT", "0")
	t.Setenv("FAKE_TART_GET_FAIL", "1")
	if err := (&TartBackend{VM: "vm"}).StartJob(ctx, ws, func(string) {}); err == nil {
		t.Fatal("failing tart get accepted")
	}
	// The ssh binary is missing.
	dir := t.TempDir()
	for name, body := range map[string]string{"tart": fakeTartScript} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	if err := (&TartBackend{VM: "vm"}).StartJob(ctx, ws, func(string) {}); err == nil {
		t.Fatal("ssh-less StartJob accepted")
	}
}

func TestTartBackendRunAndReadFileViaFakeSSH(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	if err := os.MkdirAll(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	b := &TartBackend{}
	// Not started.
	if err := b.Run(context.Background(), Command{Script: "true"}, func(string) {}); err == nil {
		t.Fatal("unstarted tart Run succeeded")
	}
	if _, err := b.ReadFile(context.Background(), filepath.Join(ws, "f"), 10); err == nil {
		t.Fatal("unstarted tart ReadFile succeeded")
	}
	b.ssh, b.ip, b.workspace = "ssh", "127.0.0.1", ws
	var emitted []string
	err := b.Run(context.Background(), Command{Shell: "bash", Script: "echo tart-ok", Dir: filepath.Join(ws, "sub"), Env: []string{"A=1", "BAD"}}, func(s string) { emitted = append(emitted, s) })
	if err != nil {
		t.Fatalf("tart Run: %v", err)
	}
	if !containsLine(emitted, "tart-ok") {
		t.Fatalf("emitted = %v", emitted)
	}
	// pwsh takes the -Command - path.
	if err := b.Run(context.Background(), Command{Shell: "pwsh", Script: "echo pwsh", Dir: ws}, func(string) {}); err != nil {
		t.Fatalf("pwsh tart Run: %v", err)
	}
	// A step directory outside the workspace is rejected.
	if err := b.Run(context.Background(), Command{Script: "true", Dir: filepath.Join(ws, "..", "x")}, func(string) {}); err == nil {
		t.Fatal("outside dir accepted")
	}
	// A failing remote command surfaces a failure.
	t.Setenv("FAKE_SSH_EXIT", "7")
	if err := b.Run(context.Background(), Command{Shell: "bash", Script: "true", Dir: ws}, func(string) {}); err == nil {
		t.Fatal("failing ssh accepted")
	}
	t.Setenv("FAKE_SSH_EXIT", "")
	// ReadFile round trip.
	file := filepath.Join(ws, "out.txt")
	if err := os.WriteFile(file, []byte("vm-payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := b.ReadFile(context.Background(), file, 100)
	if err != nil || string(got) != "vm-payload" {
		t.Fatalf("tart ReadFile = %q, %v", got, err)
	}
	// Outside path.
	if _, err := b.ReadFile(context.Background(), filepath.Join(ws, "..", "x"), 10); err == nil {
		t.Fatal("outside read accepted")
	}
	// Missing file maps to ErrNotExist.
	t.Setenv("FAKE_SSH_EXIT", "1")
	t.Setenv("FAKE_SSH_STDERR", "cat: no such file")
	if _, err := b.ReadFile(context.Background(), file, 100); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing VM file = %v", err)
	}
	// Other ssh failures surface.
	t.Setenv("FAKE_SSH_STDERR", "boom")
	if _, err := b.ReadFile(context.Background(), file, 100); err == nil {
		t.Fatal("ssh failure accepted")
	}
	t.Setenv("FAKE_SSH_EXIT", "")
	// Oversized file.
	if _, err := b.ReadFile(context.Background(), file, 4); err == nil {
		t.Fatal("oversized VM file accepted")
	}
}

func TestSshRunOnceAndRunExitCodes(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	b := &TartBackend{ssh: "ssh", ip: "127.0.0.1", workspace: ws}
	// Exit 255 becomes an infrastructure error.
	t.Setenv("FAKE_SSH_EXIT", "255")
	args := b.hardenedSSHArgs("admin@127.0.0.1", "true")
	code, err := b.sshRunOnce(context.Background(), args, nil, func(r io.Reader) error { return streamDrain(r) }, func(r io.Reader) error { return streamDrain(r) })
	if code != 255 || err == nil {
		t.Fatalf("sshRunOnce exit 255 = %d, %v", code, err)
	}
	if err := b.sshRun(context.Background(), nil, "true", func(r io.Reader) error { return streamDrain(r) }, func(r io.Reader) error { return streamDrain(r) }); err == nil || !strings.Contains(err.Error(), "no insecure fallback") {
		t.Fatalf("sshRun 255 = %v", err)
	}
	// Success path.
	t.Setenv("FAKE_SSH_EXIT", "0")
	if err := b.sshRun(context.Background(), nil, "echo hi", func(r io.Reader) error { return streamDrain(r) }, func(r io.Reader) error { return streamDrain(r) }); err != nil {
		t.Fatalf("sshRun success: %v", err)
	}
	// A consumer failure is surfaced.
	t.Setenv("FAKE_SSH_EXIT", "0")
	boom := errors.New("consume boom")
	if _, err := b.sshRunOnce(context.Background(), args, nil, func(io.Reader) error { return boom }, func(r io.Reader) error { return streamDrain(r) }); !errors.Is(err, boom) {
		t.Fatalf("consume failure = %v", err)
	}
	// A context deadline classifies as a timeout.
	t.Setenv("FAKE_SSH_EXIT", "")
	slow := filepath.Join(fakeBinDir(t), "ssh")
	if err := os.WriteFile(slow, []byte("#!/bin/sh\nsleep 5\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	dctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := b.sshRunOnce(dctx, args, nil, func(r io.Reader) error { return streamDrain(r) }, func(r io.Reader) error { return streamDrain(r) }); err == nil {
		t.Fatal("deadline ssh accepted")
	}
	if err := os.WriteFile(slow, []byte(fakeSSHScript), 0o755); err != nil {
		t.Fatal(err)
	}
}

func streamDrain(r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}

func TestTartCloseJobErrorsAndKeyFiles(t *testing.T) {
	installFakeBins(t)
	// Delete failure surfaces.
	t.Setenv("FAKE_TART_DELETE_EXIT", "1")
	b := &TartBackend{tart: "tart", clone: "kiwi-1", sshDir: t.TempDir()}
	if err := b.CloseJob(); err == nil {
		t.Fatal("delete failure accepted")
	}
	// "does not exist" is tolerated.
	installFakeBins(t)
	t.Setenv("FAKE_TART_DELETE_EXIT", "1")
	script := filepath.Join(fakeBinDir(t), "tart")
	body, _ := os.ReadFile(script)
	if err := os.WriteFile(script, []byte(strings.Replace(string(body), "sub=\"$1\"", "sub=\"$1\"\nif [ \"$sub\" = \"delete\" ]; then echo \"does not exist\" >&2; exit 1; fi", 1)), 0o755); err != nil {
		t.Fatal(err)
	}
	b = &TartBackend{tart: "tart", clone: "kiwi-1"}
	if err := b.CloseJob(); err != nil {
		t.Fatalf("missing VM must be tolerated: %v", err)
	}
	if b.clone != "" {
		t.Fatal("clone retained")
	}
	if (&TartBackend{}).CloseJob() != nil {
		t.Fatal("empty CloseJob must be nil")
	}
	// Key path helpers.
	sshDir := t.TempDir()
	b = &TartBackend{sshDir: sshDir}
	if !strings.HasSuffix(b.keyFile(), "id_ed25519") || !strings.HasSuffix(b.knownHostsFile(), "known_hosts") {
		t.Fatal("key path helpers wrong")
	}
	// setupSSHDir creates a keypair.
	if err := b.setupSSHDir(); err != nil {
		t.Fatalf("setupSSHDir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(b.sshDir, "id_ed25519")); err != nil {
		t.Fatalf("key missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(b.sshDir, "id_ed25519.pub")); err != nil {
		t.Fatalf("public key missing: %v", err)
	}
	_ = os.RemoveAll(b.sshDir)
	// setupSSHDir fails when the temp root is unusable.
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing-root"))
	if err := (&TartBackend{}).setupSSHDir(); err == nil {
		t.Fatal("unusable TMPDIR accepted")
	}
	// The Go-generated key is the fallback when ssh-keygen is absent.
	t.Setenv("TMPDIR", "")
	t.Setenv("PATH", t.TempDir())
	path := filepath.Join(t.TempDir(), "fallback-key")
	if err := generateEphemeralSSHKey(path); err != nil {
		t.Fatalf("fallback key generation: %v", err)
	}
	if _, err := os.Stat(path + ".pub"); err != nil {
		t.Fatalf("fallback public key missing: %v", err)
	}
}

func containsLine(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func readFakeLog(t *testing.T, env string) string {
	t.Helper()
	path := os.Getenv(env)
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func TestBackendNames(t *testing.T) {
	if (&ContainerBackend{}).Name() != "container" {
		t.Fatal("container name")
	}
	if (&TartBackend{}).Name() != "tart" {
		t.Fatal("tart name")
	}
}

func TestContainerRunCancelledKind(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	b := &ContainerBackend{docker: "docker", container: "cid", workspace: ws}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	err := b.Run(ctx, Command{Shell: "sh", Script: "sleep 5", Dir: ws}, func(string) {})
	if err == nil || errorKind(err) != ErrorCancelled {
		t.Fatalf("cancelled container run = %v", err)
	}
}

func TestNativeRunDirectBranches(t *testing.T) {
	nb := &NativeBackend{}
	ws := t.TempDir()
	// The default shell is bash when empty.
	if err := nb.Run(context.Background(), Command{Script: "echo default-shell", Dir: ws}, func(string) {}); err != nil {
		t.Fatalf("default shell: %v", err)
	}
	// pwsh takes the -Command path (a fake pwsh is installed).
	installFakeBins(t)
	if err := nb.Run(context.Background(), Command{Shell: "pwsh", Script: "echo pwsh-ok", Dir: ws}, func(string) {}); err != nil {
		t.Fatalf("pwsh: %v", err)
	}
	// A per-command timeout classifies as a timeout.
	err := nb.Run(context.Background(), Command{Shell: "bash", Script: "sleep 5", Dir: ws, TimeoutSeconds: 1}, func(string) {})
	if err == nil || errorKind(err) != ErrorTimeout {
		t.Fatalf("native timeout = %v", err)
	}
	// A missing shell is an infrastructure error.
	err = nb.Run(context.Background(), Command{Shell: filepath.Join(t.TempDir(), "no-shell"), Script: "true", Dir: ws}, func(string) {})
	if err == nil || errorKind(err) != ErrorInfra {
		t.Fatalf("missing shell = %v", err)
	}
}

func TestQuotaSinkForwardsWithinQuota(t *testing.T) {
	sink := &covSink{}
	l := limitedSink(sink, 100)
	l.WriteLine("j", "s", "fits")
	if !sink.has("fits") {
		t.Fatal("line within quota dropped")
	}
}

func TestGCFailingPSOutput(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_PS_EXIT", "1")
	t.Setenv("FAKE_TART_LIST", "")
	if rep := GC(context.Background(), t.TempDir(), time.Hour); rep.Containers != 0 {
		t.Fatalf("failing ps report = %+v", rep)
	}
}

func TestTartDirectErrorBranches(t *testing.T) {
	ctx := context.Background()
	// setupSSHDir failure inside StartJob (unusable TMPDIR).
	installFakeBins(t)
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing-root"))
	if err := (&TartBackend{VM: "vm"}).StartJob(ctx, t.TempDir(), func(string) {}); err == nil {
		t.Fatal("unusable TMPDIR accepted")
	}
	t.Setenv("TMPDIR", "")
	// injectBootstrapKey fails without the ephemeral public key.
	b := &TartBackend{ip: "127.0.0.1", sshDir: t.TempDir()}
	if err := b.injectBootstrapKey(ctx); err == nil {
		t.Fatal("missing public key accepted")
	}
	// postAuthorizedKey rejects a malformed endpoint.
	if err := postAuthorizedKey(ctx, "http://[::1", "key", tartBootstrapHTTPClient()); err == nil {
		t.Fatal("malformed endpoint accepted")
	}
	// sshRunOnce fails when the ssh binary cannot start.
	b2 := &TartBackend{ssh: t.TempDir(), ip: "127.0.0.1", workspace: t.TempDir()}
	if _, err := b2.sshRunOnce(ctx, []string{"true"}, nil, streamDrain, streamDrain); err == nil {
		t.Fatal("non-executable ssh accepted")
	}
}

func TestTartRunTimeoutKind(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	t.Setenv("FAKE_WS", ws)
	slow := filepath.Join(fakeBinDir(t), "ssh")
	if err := os.WriteFile(slow, []byte("#!/bin/sh\nsleep 5\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	b := &TartBackend{ssh: "ssh", ip: "127.0.0.1", workspace: ws}
	err := b.Run(context.Background(), Command{Shell: "bash", Script: "true", Dir: ws, TimeoutSeconds: 1}, func(string) {})
	if err == nil || errorKind(err) != ErrorTimeout {
		t.Fatalf("tart run timeout = %v", err)
	}
	if err := os.WriteFile(slow, []byte(fakeSSHScript), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestQuotaSinkZeroMaxForwards(t *testing.T) {
	sink := &covSink{}
	q := &quotaSink{inner: sink, max: 0}
	q.WriteLine("j", "s", "forwarded")
	if !sink.has("forwarded") {
		t.Fatal("zero-max quota sink did not forward")
	}
}

func TestStreamLinesInvalidUTF8Truncation(t *testing.T) {
	var got []string
	streamLines(strings.NewReader("é\n"), 1, func(s string) { got = append(got, s) })
	if len(got) != 1 || !strings.Contains(got[0], "line truncated") {
		t.Fatalf("invalid utf8 truncation = %q", got)
	}
}

func TestBackoffFloor(t *testing.T) {
	// A sub-nanosecond jittered backoff is clamped to 1ns.
	floored := false
	for seed := uint64(0); seed < 64; seed++ {
		d := backoffFor(1, time.Nanosecond, time.Nanosecond, seed)
		if d < 1 {
			t.Fatalf("backoff floor violated for seed %d: %v", seed, d)
		}
		if d == 1 {
			floored = true
		}
	}
	if !floored {
		t.Fatal("no seed exercised the 1ns floor")
	}
}

func TestNativeRunKillAfterTerminateTimeout(t *testing.T) {
	// The child ignores SIGTERM: the native backend falls back to SIGKILL
	// after its 2s grace period. This is the production grace window, not a
	// test sleep.
	ws := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	nb := &NativeBackend{}
	err := nb.Run(ctx, Command{Shell: "bash", Script: "trap '' TERM; sleep 30", Dir: ws}, func(string) {})
	if err == nil {
		t.Fatal("SIGTERM-ignoring child reported success")
	}
}

func TestTartBackendRunStartFailure(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_TART_SELF_DESTRUCT", "1")
	err := (&TartBackend{VM: "vm"}).StartJob(context.Background(), t.TempDir(), func(string) {})
	if err == nil {
		t.Fatal("vanishing tart binary accepted")
	}
}

func TestSshRunOnceCancelledKind(t *testing.T) {
	installFakeBins(t)
	// The fake ssh signals that it started before sleeping, so the
	// cancellation can never race the exec.Cmd.Start (which would surface
	// as an infra error instead of the cancelled kind).
	started := filepath.Join(t.TempDir(), "ssh-started")
	slow := filepath.Join(fakeBinDir(t), "ssh")
	if err := os.WriteFile(slow, []byte("#!/bin/sh\ntouch "+started+"\nsleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	b := &TartBackend{ssh: "ssh", ip: "127.0.0.1", workspace: t.TempDir()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(started); err == nil {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		cancel()
	}()
	// The drain tolerates the os/exec documented race between Wait closing
	// the pipes and an in-flight pipe read: that artifact must not mask the
	// cancelled-kind mapping under test.
	drain := func(r io.Reader) error {
		_, err := io.Copy(io.Discard, r)
		if err != nil && strings.Contains(err.Error(), "file already closed") {
			return nil
		}
		return err
	}
	_, err := b.sshRunOnce(ctx, b.hardenedSSHArgs("admin@127.0.0.1", "true"), nil, drain, drain)
	if err == nil || errorKind(err) != ErrorCancelled {
		t.Fatalf("cancelled ssh = %v", err)
	}
}

func TestSnapshotMkdirFailure(t *testing.T) {
	// TMPDIR points at a regular file: MkdirAll cannot create the snapshot
	// directory.
	ws := t.TempDir()
	sink := &covSink{}
	fileAsTmp := filepath.Join(t.TempDir(), "tmp-file")
	if err := os.WriteFile(fileAsTmp, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", fileAsTmp)
	ex := &Executor{Opt: Options{Workspace: ws, Logs: sink, RunID: "snap9", CaptureSnapshot: true}, Masker: &secrets.Masker{}}
	res := ex.runJob(context.Background(), &pipeline.Spec{}, pipeline.CompiledJob{
		ID: "j", Job: pipeline.Job{Steps: []pipeline.Step{{Run: "true"}}},
	}, model.StatusSuccess, nil)
	if res.Status != model.StatusSuccess || !sink.has("snapshot") {
		t.Fatalf("snapshot mkdir failure = %+v", res)
	}
}
