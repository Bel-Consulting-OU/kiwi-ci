//go:build !windows

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPlanHardenedContainer pins the rootless/rootful decision table: the
// rootless daemon runs the workload as namespace root and never provisions
// the host tree, the rootful daemon drops to nobody and requires the
// 0711 + chown workspace provisioning.
func TestPlanHardenedContainer(t *testing.T) {
	rootless := planHardenedContainer(true)
	if rootless.User != "0:0" {
		t.Fatalf("rootless user = %q, want 0:0 (container root maps to the runner uid)", rootless.User)
	}
	if rootless.ProvisionWorkspace {
		t.Fatal("rootless daemon must not chown the runner workspace")
	}
	rootful := planHardenedContainer(false)
	if rootful.User != "65534:65534" {
		t.Fatalf("rootful user = %q, want 65534:65534", rootful.User)
	}
	if !rootful.ProvisionWorkspace || rootful.WorkspaceDirMode != workspaceTraverseMode {
		t.Fatalf("rootful plan = %+v, want provisioning with %#o", rootful, workspaceTraverseMode)
	}
	if rootful.UID != containerWorkloadUID || rootful.GID != containerWorkloadGID {
		t.Fatalf("rootful workload ids = %d/%d, want %d/%d", rootful.UID, rootful.GID, containerWorkloadUID, containerWorkloadGID)
	}
}

// TestProvisionContainerWorkspaceRootlessNoop asserts the rootless contract:
// no ownership or mode mutation, and an idempotent no-op restore.
func TestProvisionContainerWorkspaceRootlessNoop(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "checkout.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	restore, err := provisionContainerWorkspace(dir, containerWorkloadUID, containerWorkloadGID, true)
	if err != nil {
		t.Fatalf("rootless provision: %v", err)
	}
	if restore == nil {
		t.Fatal("rootless provision returned no restore function")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("rootless workspace mode = %#o, want 0700 (files stay runner-owned)", info.Mode().Perm())
	}
	owner, _, err := lstatOwner(file)
	if err != nil {
		t.Fatal(err)
	}
	if owner != os.Getuid() {
		t.Fatalf("rootless provisioning changed ownership: uid %d, want %d", owner, os.Getuid())
	}
	if err := restore(); err != nil {
		t.Fatalf("rootless restore: %v", err)
	}
}

// TestProvisionContainerWorkspaceChownsTreeAndRestores drives the full
// provision/restore lifecycle. Without root the chown target is the runner's
// own uid/gid (the ownership mutation itself is exercised only under root, on
// the platforms where the hardening applies).
func TestProvisionContainerWorkspaceChownsTreeAndRestores(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "repo")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(sub, "file.txt")
	if err := os.WriteFile(file, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	originalMode := info.Mode().Perm()

	runnerUID := os.Getuid()
	targetUID, targetGID := runnerUID, os.Getgid()
	if os.Geteuid() == 0 {
		targetUID, targetGID = containerWorkloadUID, containerWorkloadGID
	}
	restore, err := provisionContainerWorkspace(dir, targetUID, targetGID, false)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	info, err = os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o711 {
		t.Fatalf("workspace mode after provision = %#o, want 0711 (traverse-only)", info.Mode().Perm())
	}
	for _, path := range []string{dir, sub, file} {
		owner, _, oerr := lstatOwner(path)
		if oerr != nil {
			t.Fatal(oerr)
		}
		if owner != targetUID {
			t.Fatalf("%s owner uid = %d, want %d", path, owner, targetUID)
		}
	}
	if err := restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	info, err = os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != originalMode {
		t.Fatalf("workspace mode after restore = %#o, want %#o", info.Mode().Perm(), originalMode)
	}
	for _, path := range []string{dir, sub, file} {
		owner, _, oerr := lstatOwner(path)
		if oerr != nil {
			t.Fatal(oerr)
		}
		if owner != runnerUID {
			t.Fatalf("%s owner uid after restore = %d, want runner uid %d", path, owner, runnerUID)
		}
	}
}

// TestProvisionContainerWorkspaceRefusesForeignOwner verifies the refusal:
// a tree the runner does not own is rejected before any mutation. As root the
// fixture is really chowned to a foreign uid; otherwise the runner identity
// seam simulates it.
func TestProvisionContainerWorkspaceRefusesForeignOwner(t *testing.T) {
	dir := t.TempDir()
	foreign := os.Getuid() + 4242
	if os.Geteuid() == 0 {
		if err := os.Chown(dir, foreign, os.Getegid()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chown(dir, os.Getuid(), os.Getgid()) })
	} else {
		orig := runnerWorkspaceOwner
		runnerWorkspaceOwner = func() (int, int) { return foreign, os.Getegid() }
		t.Cleanup(func() { runnerWorkspaceOwner = orig })
	}
	before, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	restore, err := provisionContainerWorkspace(dir, containerWorkloadUID, containerWorkloadGID, false)
	if err == nil {
		t.Fatal("foreign-owned workspace accepted")
	}
	if !errors.Is(err, errWorkspaceNotOwned) {
		t.Fatalf("refusal = %v, want errWorkspaceNotOwned", err)
	}
	if restore != nil {
		t.Fatal("refusal returned a restore function")
	}
	after, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("refusal mutated the workspace mode: %#o -> %#o", before.Mode().Perm(), after.Mode().Perm())
	}
}

// TestProvisionWorkspaceTreeChownFailureRollsBack asserts a mid-tree chown
// failure leaves the workspace root mode restored instead of half-provisioned.
func TestProvisionWorkspaceTreeChownFailureRollsBack(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(dir, "entry")
	if err := os.WriteFile(inner, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := lchownWorkspaceEntry
	lchownWorkspaceEntry = func(path string, uid, gid int) error {
		// The workspace root is EvalSymlinks-resolved before walking (macOS
		// /var is a symlink to /private/var), so match on the base name.
		if filepath.Base(path) == "entry" {
			return errors.New("injected chown failure")
		}
		return os.Lchown(path, uid, gid)
	}
	t.Cleanup(func() { lchownWorkspaceEntry = orig })

	restore, err := provisionContainerWorkspace(dir, os.Getuid(), os.Getgid(), false)
	if err == nil || !strings.Contains(err.Error(), "injected chown failure") {
		t.Fatalf("chown failure = %v, want injected failure surfaced", err)
	}
	if restore != nil {
		t.Fatal("failed provision returned a restore function")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("failed provision left mode %#o, want 0750", info.Mode().Perm())
	}
}

// TestProvisionWorkspaceTreeRestoreFailureSurfaced asserts restore errors are
// returned (never swallowed), because a silent failure would leave the
// checkout under the workload uid.
func TestProvisionWorkspaceTreeRestoreFailureSurfaced(t *testing.T) {
	dir := t.TempDir()
	restore, err := provisionContainerWorkspace(dir, os.Getuid(), os.Getgid(), false)
	if err != nil {
		t.Fatal(err)
	}
	orig := lchownWorkspaceEntry
	lchownWorkspaceEntry = func(string, int, int) error { return errors.New("injected restore failure") }
	t.Cleanup(func() { lchownWorkspaceEntry = orig })
	if err := restore(); err == nil || !strings.Contains(err.Error(), "injected restore failure") {
		t.Fatalf("restore failure = %v, want injected failure surfaced", err)
	}
}

// TestProvisionWorkspaceTreeSymlinkedRoot asserts the workspace root is
// resolved before walking: an unresolved symlink would make WalkDir skip the
// whole tree (and the runner integration test relies on exactly this shape).
func TestProvisionWorkspaceTreeSymlinkedRoot(t *testing.T) {
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	restore, err := provisionContainerWorkspace(link, os.Getuid(), os.Getgid(), false)
	if err != nil {
		t.Fatalf("symlinked provision: %v", err)
	}
	info, err := os.Stat(real)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o711 {
		t.Fatalf("symlink target mode = %#o, want 0711 (tree was provisioned)", info.Mode().Perm())
	}
	if err := restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
}

// TestContainerBackendStartJobHardenedRootfulProvisionsWorkspace drives
// StartJob/CloseJob through the fake docker binary with the provisioning seam:
// rootful hardened containers get --user=65534:65534 and exactly one
// provision/restore cycle around the container lifetime.
func TestContainerBackendStartJobHardenedRootfulProvisionsWorkspace(t *testing.T) {
	installFakeBins(t)
	ws := t.TempDir()
	type provisionCall struct {
		workspace string
		uid, gid  int
		rootless  bool
	}
	var calls []provisionCall
	restores := 0
	orig := provisionWorkspace
	provisionWorkspace = func(workspace string, uid, gid int, rootless bool) (func() error, error) {
		calls = append(calls, provisionCall{workspace, uid, gid, rootless})
		return func() error { restores++; return nil }, nil
	}
	t.Cleanup(func() { provisionWorkspace = orig })

	b := &ContainerBackend{Image: "alpine:3.19", ReadOnlyRootFS: true}
	if err := b.StartJob(context.Background(), ws, func(string) {}); err != nil {
		t.Fatalf("hardened rootful StartJob: %v", err)
	}
	log := readFakeLog(t, "FAKE_DOCKER_LOG")
	if !strings.Contains(log, "--read-only") || !strings.Contains(log, "--user=65534:65534") {
		t.Fatalf("hardened rootful args missing: %s", log)
	}
	abs, err := filepath.Abs(ws)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0].workspace != abs || calls[0].uid != containerWorkloadUID || calls[0].gid != containerWorkloadGID || calls[0].rootless {
		t.Fatalf("provision calls = %+v, want one rootful %d:%d call for %s", calls, containerWorkloadUID, containerWorkloadGID, abs)
	}
	if restores != 0 {
		t.Fatalf("restore ran before CloseJob (%d times)", restores)
	}
	if err := b.CloseJob(); err != nil {
		t.Fatalf("CloseJob: %v", err)
	}
	if restores != 1 {
		t.Fatalf("restores after CloseJob = %d, want 1", restores)
	}
	// CloseJob is idempotent: the restore must not run twice.
	if err := b.CloseJob(); err != nil {
		t.Fatalf("second CloseJob: %v", err)
	}
	if restores != 1 {
		t.Fatalf("restores after second CloseJob = %d, want 1", restores)
	}
}

// TestContainerBackendStartJobRestoresWhenDockerRunFails asserts a failed
// container start cannot leave the checkout chowned to the workload.
func TestContainerBackendStartJobRestoresWhenDockerRunFails(t *testing.T) {
	installFakeBins(t)
	t.Setenv("FAKE_DOCKER_RUN_FAIL", "1")
	restores := 0
	orig := provisionWorkspace
	provisionWorkspace = func(string, int, int, bool) (func() error, error) {
		return func() error { restores++; return nil }, nil
	}
	t.Cleanup(func() { provisionWorkspace = orig })

	b := &ContainerBackend{Image: "alpine:3.19", ReadOnlyRootFS: true}
	err := b.StartJob(context.Background(), t.TempDir(), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "start job container") {
		t.Fatalf("docker run failure = %v, want start job container error", err)
	}
	if restores != 1 {
		t.Fatalf("restores after failed start = %d, want 1", restores)
	}
}

// TestContainerBackendStartJobProvisionFailureRefuses asserts a workspace
// that cannot be provisioned fails the StartJob before docker ever runs.
func TestContainerBackendStartJobProvisionFailureRefuses(t *testing.T) {
	installFakeBins(t)
	orig := provisionWorkspace
	provisionWorkspace = func(string, int, int, bool) (func() error, error) {
		return nil, errors.New("injected provision failure")
	}
	t.Cleanup(func() { provisionWorkspace = orig })

	b := &ContainerBackend{Image: "alpine:3.19", ReadOnlyRootFS: true}
	err := b.StartJob(context.Background(), t.TempDir(), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "injected provision failure") {
		t.Fatalf("provision failure = %v, want refusal", err)
	}
	if log := readFakeLog(t, "FAKE_DOCKER_LOG"); strings.Contains(log, "run -d") {
		t.Fatalf("docker run ran despite the provision refusal: %s", log)
	}
}
