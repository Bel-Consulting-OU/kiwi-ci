//go:build !windows

package runner

import (
	"bytes"
	"context"
	"fmt"
	testutil "github.com/Bel-Consulting-OU/kiwi-ci/internal/testutil"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/snapshot"
)

// TestRootlessHardenedContainerWorkspaceIntegration is the end-to-end proof
// of the hardened-container workspace contract. It is gated behind
// KIWI_TEST_DOCKER=1 (the Woodpecker step only exports it when the agent's
// docker socket is usable) and drives a real container job through the
// runner:
//
//   - rootless daemon: the job declares sandbox.rootless and must run as
//     namespace root (id -u == 0) so the container root maps to the runner
//     uid on the host; the 0700 runner-owned checkout stays untouched
//     (mode 700) and the workload appends to a host-created 0600 file.
//   - rootful daemon: the job declares sandbox.read_only_rootfs and must run
//     as 65534:65534 with the workspace root traverse-only (mode 711) and the
//     tree chowned to the workload for the container lifetime.
//
// In both cases the job writes a file inside the bind-mounted workspace,
// captures it as an artifact, and the test asserts the file is visible on the
// host, the artifact uploads (through the runner's real HTTP path), the host
// tree is fully restored to the runner's ownership and 0700 mode afterwards,
// and the container identity is the expected one. On a rootful daemon as a
// non-root runner, provisioning cannot chown the tree and the job must fail
// with the explicit provisioning refusal instead of starting a broken
// container.
func TestRootlessHardenedContainerWorkspaceIntegration(t *testing.T) {
	testutil.UnixChmod(t)
	if os.Getenv("KIWI_TEST_DOCKER") != "1" {
		t.Skip("set KIWI_TEST_DOCKER=1 on a host with a Docker daemon to run the workspace integration test")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skipf("docker CLI not available: %v", err)
	}
	securityOptions, infoErr := exec.Command(docker, "info", "--format", "{{.SecurityOptions}}").CombinedOutput()
	if infoErr != nil {
		t.Skipf("docker daemon not available: %v: %s", infoErr, strings.TrimSpace(string(securityOptions)))
	}
	rootless := strings.Contains(strings.ToLower(string(securityOptions)), "rootless")
	rootfulNonRoot := !rootless && os.Geteuid() != 0

	image := os.Getenv("KIWI_TEST_DOCKER_IMAGE")
	if image == "" {
		image = "alpine:3.20"
	}
	sandbox := "read_only_rootfs: true"
	if rootless {
		sandbox = "rootless: true"
	}
	// checkout.txt is created by CheckoutFn with mode 0600 on the host. The
	// container append only succeeds when the workload really has access:
	// namespace root mapped to the runner uid (rootless) or the chowned tree
	// (rootful).
	pipelineText := fmt.Sprintf(`version: 1
jobs:
  build:
    runtime: container
    image: %s
    sandbox:
      %s
    steps:
      - name: cid
        run: id -u
      - name: rootmode
        run: stat -c %%a /workspace
      - name: write
        run: mkdir -p out && echo hello > out/app.txt && echo appended >> checkout.txt
      - name: fileowner
        run: stat -c %%u:%%g out/app.txt
    artifacts:
      - name: app
        paths: [out]
`, image, sandbox)

	fsrv := &fakeRunnerServer{}
	ts := httptest.NewServer(fsrv.handler())
	defer ts.Close()

	workspace := ""
	r := testRunnerFor(t, ts, Config{CaptureSnapshots: true})
	r.Cfg.CheckoutFn = func(_ context.Context, _ model.Job, dir string) error {
		workspace = dir
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		if err := os.WriteFile(filepath.Join(dir, "checkout.txt"), []byte("host-checkout\n"), 0o600); err != nil {
			return err
		}
		return os.Chmod(dir, 0o700)
	}
	// Keep the workspace after execute so the test can assert the host-side
	// state (ownership and mode) that the restore path produced.
	restoreRemove := removeJobWorkspace
	t.Cleanup(func() { removeJobWorkspace = restoreRemove })
	removeJobWorkspace = func(string) error { return nil }

	r.execute(context.Background(), basicTask(pipelineText))

	complete, ok := fsrv.lastComplete()
	if !ok {
		t.Fatal("no completion recorded")
	}
	if rootfulNonRoot {
		if complete.Status != model.StatusFailure {
			t.Fatalf("rootful daemon as non-root: status = %s (%s), want refusal", complete.Status, complete.Error)
		}
		if !strings.Contains(complete.Error, "provision container workspace") {
			t.Fatalf("refusal = %q, want workspace provisioning error", complete.Error)
		}
		return
	}
	if complete.Status != model.StatusSuccess {
		t.Fatalf("job status = %s: %s", complete.Status, complete.Error)
	}

	// (a) The container identity and the container-visible workspace mode are
	// exactly the decision-table values. Mode/ownership views are only
	// asserted on Linux: Docker Desktop synthesizes bind-mount metadata.
	wantUID := "65534"
	if rootless {
		wantUID = "0"
	}
	fsrv.mu.Lock()
	logs := append([]string{}, fsrv.logLines...)
	fsrv.mu.Unlock()
	if !containsString(logs, "cid: "+wantUID) {
		t.Fatalf("container uid logs = %v, want id -u == %s", logs, wantUID)
	}
	if runtime.GOOS == "linux" {
		wantMode, wantOwner := "711", "65534:65534"
		if rootless {
			wantMode, wantOwner = "700", "0:0"
		}
		if !containsString(logs, "rootmode: "+wantMode) {
			t.Fatalf("workspace mode logs = %v, want %s", logs, wantMode)
		}
		if !containsString(logs, "fileowner: "+wantOwner) {
			t.Fatalf("file owner logs = %v, want %s", logs, wantOwner)
		}
	}

	// (a, host side) The workload wrote through the bind mount; the runner
	// must see the file with its own ownership and the original 0700 root
	// mode after the restore.
	if workspace == "" {
		t.Fatal("checkout never ran")
	}
	hostFile := filepath.Join(workspace, "out", "app.txt")
	data, err := os.ReadFile(hostFile)
	if err != nil {
		t.Fatalf("container-written file not visible on the host: %v", err)
	}
	if string(data) != "hello\n" {
		t.Fatalf("host file content = %q, want %q", data, "hello\n")
	}
	info, err := os.Stat(hostFile)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no unix stat data for %s", hostFile)
	}
	if int(st.Uid) != os.Getuid() {
		t.Fatalf("host owner uid = %d, want runner uid %d (restore must chown the tree back)", st.Uid, os.Getuid())
	}
	rootInfo, err := os.Stat(workspace)
	if err != nil {
		t.Fatal(err)
	}
	if rootInfo.Mode().Perm() != 0o700 {
		t.Fatalf("workspace root mode = %#o, want 0700 after restore", rootInfo.Mode().Perm())
	}
	// The 0600 host-created file was appended by the workload; its content is
	// the host-side proof that the container identity had real access.
	appended, err := os.ReadFile(filepath.Join(workspace, "checkout.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(appended) != "host-checkout\nappended\n" {
		t.Fatalf("checkout.txt = %q, want the container append visible on the host", appended)
	}

	// (b) The artifact captured host-side from the container-written tree
	// uploaded through the runner's real HTTP path.
	if !containsString(fsrv.pathsFor("/api/v1/jobs/job-1/artifacts/"), "app") {
		t.Fatalf("artifact uploads = %v, want app", fsrv.pathsFor("/api/v1/jobs/job-1/artifacts/"))
	}
	// (b, host side) The snapshot archive (created host-side) contains the
	// container-written file.
	fsrv.mu.Lock()
	bodies := append([][]byte{}, fsrv.snapshotBodies...)
	fsrv.mu.Unlock()
	if len(bodies) == 0 {
		t.Fatal("no snapshot uploaded: the runner could not read the workspace host-side")
	}
	man, err := snapshot.Parse(bytes.NewReader(bodies[len(bodies)-1]))
	if err != nil {
		t.Fatalf("snapshot parse: %v", err)
	}
	found := false
	for _, e := range man.Entries {
		if e.Path == "out/app.txt" {
			found = true
		}
	}
	if !found {
		paths := make([]string, 0, len(man.Entries))
		for _, e := range man.Entries {
			paths = append(paths, e.Path)
		}
		t.Fatalf("snapshot entries %v missing out/app.txt", paths)
	}
}
