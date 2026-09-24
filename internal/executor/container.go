package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

var dockerNameClean = regexp.MustCompile(`[^a-zA-Z0-9_.-]`)

type ContainerBackend struct {
	Image     string
	Network   string
	docker    string
	container string
	workspace string
	// RunID and JobID identify the owning run/job for the kiwi.run/kiwi.job
	// labels applied to the job container so GC can find stale ones.
	RunID string
	JobID string
	// RequireImmutableImages rejects images that are not pinned by an
	// @sha256: digest. Set by the executor from Options for untrusted jobs.
	RequireImmutableImages bool
	// Rootless demands a rootless Docker daemon (verified via
	// `docker info --format {{.SecurityOptions}}`).
	Rootless bool
	// ReadOnlyRootFS mounts the job container root filesystem read-only.
	ReadOnlyRootFS bool
	// Resources carries the job's resource requests, rendered into docker
	// run flags by StartJob. Values are already admission-checked by
	// pipeline validation; zero requests produce no flags. resources.disk
	// has no docker run flag (a bind-mounted workspace has no per-mount
	// quota): it is enforced as the workspace content bound instead, see
	// workspaceMaxBytes/enforceWorkspaceBound.
	Resources pipeline.Resources
	// Untrusted marks the job as untrusted. Untrusted jobs always get a
	// workspace disk budget: the declared resources.disk when set, otherwise
	// UntrustedDiskMaxBytes (or DefaultUntrustedWorkspaceMaxBytes). Trusted
	// jobs without a disk declaration keep the historical unbounded
	// behavior.
	Untrusted bool
	// UntrustedDiskMaxBytes overrides DefaultUntrustedWorkspaceMaxBytes for
	// untrusted jobs without a resources.disk declaration. Zero selects the
	// package default; negative is treated as zero.
	UntrustedDiskMaxBytes int64
	// RequireDiskQuota fails StartJob closed when the job is untrusted and no
	// OS-level hard bound (project quota) can be established for the
	// workspace. Production runners set this for untrusted jobs; the
	// step-boundary resources.disk check alone is not a security boundary,
	// so advertising it as enforced without this gate would be dishonest. The
	// operator escape hatch for trusted-only/self-hosted runners lives in
	// Options/KIWI_ALLOW_UNQUOTAED_UNTRUSTED_DISK.
	RequireDiskQuota bool
	// WorkspaceQuota, when non-nil, is the outcome of a hard workspace
	// quota attempt the CALLER already performed before the workspace was
	// populated (the distributed runner installs it before checkout, see
	// runner.execute). A Hard outcome satisfies RequireDiskQuota without a
	// second probe; a non-Hard outcome fails the gate closed with the
	// caller's reason. Nil (direct backend users) keeps the historical
	// probe-at-StartJob behavior.
	WorkspaceQuota *DiskQuotaStatus
	// CgroupParent, when non-empty, is the job's scoped parent cgroup (see
	// jobcgroup.go): the container is placed in it with --cgroup-parent so
	// the main container and the job's service containers together can never
	// exceed the job's declared envelope at the kernel.
	CgroupParent string
	// restoreWorkspace undoes the host-side workspace provisioning applied
	// before a hardened rootful container started. It is set by StartJob and
	// run exactly once by CloseJob (or by StartJob itself when the docker run
	// fails after provisioning).
	restoreWorkspace func() error
	// quotaCleanup removes the OS-level workspace project quota applied by
	// the capability probe. Set by StartJob and run exactly once by CloseJob
	// (or by StartJob itself on a failure after the probe succeeded).
	quotaCleanup func() error
}

func (*ContainerBackend) Name() string { return "container" }

// StartJob creates one hardened, long-lived container for the whole CI job.
// Every step is executed with docker exec so package installs and process state
// behave like developers expect from a job while the checkout remains mounted.
func (b *ContainerBackend) StartJob(ctx context.Context, workspace string, emit func(string)) error {
	if b.Image == "" {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("container runtime requires job.image")}
	}
	// Digest pinning is checked before any docker invocation so a missing
	// daemon can never mask an unpinned image. Production policy should
	// always require digests for untrusted jobs (see RequireImmutableImages).
	if b.RequireImmutableImages && !digestPinned(b.Image) {
		return unpinnedImageError("container image", b.Image)
	}
	abs, err := absWorkspacePath(workspace)
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: err}
	}
	b.workspace = abs
	// The declared resources.disk request is a hard workspace bound: a
	// checkout that already exceeds it is refused before any container is
	// created, so an over-quota workspace can never half-run. The check is
	// host-side and does not depend on the daemon, so it deliberately runs
	// before the docker lookup. Untrusted jobs without a declaration measure
	// against the mandatory default budget (workspaceMaxBytes).
	if err := b.enforceWorkspaceBound(); err != nil {
		return err
	}
	// Untrusted jobs must not advertise a disk bound that exists only at step
	// boundaries. When the caller demands a hard bound, either the caller
	// already installed one before the workspace was populated (runner
	// lifecycle, WorkspaceQuota) or the capability probe must establish one
	// (XFS project quota); otherwise the job fails closed before docker is
	// even looked up, with a message that names the escape hatch instead of
	// silently running unbounded. The runner-side gate is the primary check
	// (it runs before checkout); this is defense in depth for direct backend
	// users and for callers that pass a preinstalled non-hard status.
	if b.Untrusted && b.RequireDiskQuota {
		switch {
		case b.WorkspaceQuota != nil && b.WorkspaceQuota.Hard:
			// Already bounded by the caller, before any workspace content
			// existed.
		case b.WorkspaceQuota != nil:
			return UntrustedDiskQuotaGateError(b.WorkspaceQuota.Detail)
		default:
			status, cleanup := workspaceDiskQuotaSetup(abs, b.workspaceMaxBytes())
			if !status.Hard {
				return UntrustedDiskQuotaGateError(status.Detail)
			}
			b.quotaCleanup = cleanup
		}
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		_ = b.cleanupWorkspaceQuota()
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("docker not found: %w", err)}
	}
	if b.Rootless {
		if err := b.verifyRootlessDaemon(ctx, docker); err != nil {
			_ = b.cleanupWorkspaceQuota()
			return err
		}
	}
	b.docker = docker
	b.container = dockerNameClean.ReplaceAllString(fmt.Sprintf("kiwi-job-%d", time.Now().UnixNano()), "-")
	network := b.Network
	if network == "" {
		network = "bridge"
	}
	args := []string{
		"run", "-d", "--rm", "--init", "--network=" + network,
		"--cap-drop=ALL", "--security-opt=no-new-privileges",
		"-v", abs + ":/workspace", "-w", "/workspace", "--name", b.container,
	}
	if b.CgroupParent != "" {
		args = append(args, "--cgroup-parent="+b.CgroupParent)
	}
	args = append(args, resourceArgsFor(b.Resources)...)
	args = append(args, containerLabels(b.RunID, b.JobID)...)
	if b.Rootless || b.ReadOnlyRootFS {
		plan := planHardenedContainer(b.Rootless)
		args = append(args,
			"--read-only",
			"--tmpfs", "/tmp:rw,nosuid,nodev",
			"--tmpfs", "/run:rw,nosuid,nodev",
			"--user="+plan.User,
		)
		if plan.ProvisionWorkspace {
			restore, perr := provisionWorkspace(abs, plan.UID, plan.GID, false)
			if perr != nil {
				_ = b.cleanupWorkspaceQuota()
				return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("provision container workspace: %w", perr)}
			}
			b.restoreWorkspace = restore
		}
	}
	// "--" terminates docker's own flag parsing, so a hostile or malformed
	// image reference can never be reinterpreted as an option (the digest
	// grammar also rejects flag-shaped refs for untrusted jobs, but the argv
	// boundary is defense in depth for trusted jobs and future grammars).
	args = append(args, "--", b.Image, "sh", "-c", "while :; do sleep 3600; done")
	out, err := exec.CommandContext(ctx, docker, args...).CombinedOutput()
	if err != nil {
		restoreErr := errors.Join(b.restoreProvisionedWorkspace(), b.cleanupWorkspaceQuota())
		if restoreErr != nil {
			return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("start job container: %v: %s (workspace restore also failed: %v)", err, strings.TrimSpace(string(out)), restoreErr)}
		}
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("start job container: %v: %s", err, strings.TrimSpace(string(out)))}
	}
	emit("job container started " + b.container)
	return nil
}

// containerResourceArgs renders the docker run flags enforcing a job's
// resource requests: resources.cpu -> --cpus, resources.memory -> --memory,
// resources.pids -> --pids-limit. Zero/absent requests produce no flags; the
// values themselves are already range-checked by pipeline admission. The
// disk request has no docker run equivalent and is not rendered as a flag:
// it bounds the workspace content instead (workspaceMaxBytes /
// enforceWorkspaceBound).
func containerResourceArgs(j pipeline.Job) []string {
	return resourceArgsFor(j.Resources)
}

// workspaceMaxBytes is the workspace content bound for one container job.
// The precedence (declared resources.disk, then an untrusted job's
// UntrustedDiskMaxBytes override or the mandatory default, then zero for
// trusted undeclared jobs) lives in the shared WorkspaceBoundBytes so the
// runner and the backend can never disagree. pipeline.ByteSize is already the
// canonical byte count the pipeline decoder produced (binary suffixes: "2Gi"
// = 2<<30; plain integers are bytes), so no re-parsing is involved.
//
// The untrusted default is the fix for the unbounded-workspace defect: an
// undeclared disk no longer means "unbounded" for jobs the runner does not
// trust. The bound is still measured at step boundaries (a bind mount has no
// per-mount quota); the hard OS-level bound for untrusted jobs comes from the
// RequireDiskQuota capability gate (runner-installed before checkout, or
// probed here when no caller installed one), which fails closed when no
// project quota can be established.
func (b *ContainerBackend) workspaceMaxBytes() int64 {
	return WorkspaceBoundBytes(int64(b.Resources.Disk), b.Untrusted, b.UntrustedDiskMaxBytes)
}

// enforceWorkspaceBound fails with a clear error when the host-side workspace
// already holds more than the job's workspace bound. A bind mount has no
// per-mount quota, so the bound is measured at step boundaries (before a step
// starts and again after it succeeded) and the offending step fails instead
// of the workspace silently growing past its declaration. Nothing is ever
// truncated: an over-bound workspace is reported, never silently trimmed.
//
// The measurement is a stat-only walk (see workspaceUsageBytes); it is not
// part of the security boundary (the daemon has no quota to set), so it is
// deliberately best-effort about concurrent workspace mutations. Untrusted
// jobs get a hard bound from the project-quota capability gate when the
// caller requires one.
func (b *ContainerBackend) enforceWorkspaceBound() error {
	limit := b.workspaceMaxBytes()
	if limit <= 0 {
		return nil
	}
	used, err := workspaceUsageBytes(b.workspace)
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("measure workspace usage: %w", err)}
	}
	if used > limit {
		return &RunError{Kind: ErrorFailure, Err: fmt.Errorf("workspace exceeds the declared resources.disk bound: %d bytes used, %d bytes allowed", used, limit)}
	}
	return nil
}

// workspaceUsageBytes sums the sizes of the regular files in the workspace
// tree rooted at path. Symlinks are never followed (a link out of the tree
// must not be able to inflate or hide the measurement) and non-regular
// entries contribute nothing, matching what a bind-mounted workspace can
// actually hold. The root is resolved through symlinks first, so a symlinked
// workspace root is measured instead of silently reading as empty.
func workspaceUsageBytes(path string) (int64, error) {
	if path == "" {
		return 0, fmt.Errorf("empty workspace path")
	}
	root, err := filepath.EvalSymlinks(path)
	if err != nil {
		return 0, err
	}
	var total int64
	err = filepath.WalkDir(root, func(_ string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return total, nil
}

// resourceArgsFor renders the docker run resource flags for a Resources
// value (shared by containerResourceArgs and the container backend).
func resourceArgsFor(r pipeline.Resources) []string {
	var args []string
	if r.CPU > 0 {
		args = append(args, "--cpus", strconv.FormatFloat(r.CPU, 'f', -1, 64))
	}
	if r.Memory > 0 {
		args = append(args, "--memory", strconv.FormatInt(int64(r.Memory), 10))
	}
	if r.PIDs > 0 {
		args = append(args, "--pids-limit", strconv.Itoa(r.PIDs))
	}
	return args
}

// containerWorkloadUID/GID is the unprivileged identity a hardened container
// drops to on a rootful daemon ("nobody"). A rootful daemon has no user
// namespace mapping, so this uid exists on the host and cannot traverse the
// 0700 runner-owned checkout until the workspace is provisioned.
const (
	containerWorkloadUID = 65534
	containerWorkloadGID = 65534
)

// workspaceTraverseMode is the mode applied to the workspace ROOT while a
// hardened rootful workload owns it: execute-only for the runner and other
// local users (traverse), while the workload, as owner, keeps rwx. Inner
// checkout entries are chowned to the workload rather than opened up.
const workspaceTraverseMode = os.FileMode(0o711)

// hardenedContainerPlan is the pure decision for how a hardened container job
// reaches the bind-mounted workspace:
//
//   - rootless daemon: the daemon is user-namespaced, so container root IS the
//     host runner uid. The workload runs as 0:0 inside the namespace (never
//     65534, which would map to a subordinate UID and lose access to the
//     runner-owned mount). No host-side provisioning is needed: files the
//     workload writes stay runner-owned on the host, and the user namespace is
//     the isolation boundary.
//   - rootful daemon: the workload drops to 65534:65534. The checkout is 0700
//     and runner-owned, so the tree is chowned to the workload and the
//     workspace root is made traverse-only (0711) before the container starts;
//     the executor restores ownership and mode when the job ends.
type hardenedContainerPlan struct {
	User               string
	ProvisionWorkspace bool
	WorkspaceDirMode   os.FileMode
	UID                int
	GID                int
}

func planHardenedContainer(rootless bool) hardenedContainerPlan {
	if rootless {
		return hardenedContainerPlan{User: "0:0"}
	}
	return hardenedContainerPlan{
		User:               "65534:65534",
		ProvisionWorkspace: true,
		WorkspaceDirMode:   workspaceTraverseMode,
		UID:                containerWorkloadUID,
		GID:                containerWorkloadGID,
	}
}

// provisionContainerWorkspace prepares the runner-owned checkout for a
// hardened container workload and returns the restore function that puts the
// tree back under the runner's uid/gid. Rootless daemons need no ownership
// change (see planHardenedContainer); rootful daemons chown the tree to the
// workload uid/gid and leave the workspace root traverse-only (0711), so the
// workload can enter and write the checkout without the checkout ever being
// world-writable.
func provisionContainerWorkspace(workspace string, uid, gid int, rootless bool) (func() error, error) {
	if rootless {
		return func() error { return nil }, nil
	}
	return provisionWorkspaceTree(workspace, uid, gid)
}

// provisionWorkspace is a seam over provisionContainerWorkspace so backend
// tests can exercise a hardened rootful StartJob without a root runner: the
// real chown to 65534 requires CAP_CHOWN.
var provisionWorkspace = provisionContainerWorkspace

// securityOptionsRootless reports whether a `docker info --format
// {{.SecurityOptions}}` report claims a rootless daemon. The daemon emits
// the option list as bracketed entries (e.g. "[name=seccomp,profile=builtin
// name=rootless]"), so a case-insensitive substring match on the whole
// report is the robust check. Pure helper so it can be tested without a
// daemon.
func securityOptionsRootless(report string) bool {
	return strings.Contains(strings.ToLower(report), "rootless")
}

// requireRootlessDaemon requires `docker info --format {{.SecurityOptions}}`
// to report "rootless". sandbox.rootless is an explicit promise to the job
// author; if the daemon is a privileged rootful one we must refuse rather
// than silently run with weaker isolation.
func requireRootlessDaemon(ctx context.Context, docker string) error {
	out, err := exec.CommandContext(ctx, docker, "info", "--format", "{{.SecurityOptions}}").CombinedOutput()
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("inspect docker daemon: %v: %s", err, strings.TrimSpace(string(out)))}
	}
	if !securityOptionsRootless(string(out)) {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("sandbox.rootless requested but the docker daemon is not rootless (security options: %s)", strings.TrimSpace(string(out)))}
	}
	return nil
}

// verifyRootlessDaemon re-checks the daemon from the container backend
// itself (defense in depth: the executor hoists this check before services
// start, and StartJob re-verifies it for direct backend users).
func (b *ContainerBackend) verifyRootlessDaemon(ctx context.Context, docker string) error {
	return requireRootlessDaemon(ctx, docker)
}

func (b *ContainerBackend) CloseJob() error {
	if b.container == "" || b.docker == "" {
		return b.finishJobWorkspace()
	}
	out, err := exec.Command(b.docker, "rm", "-f", b.container).CombinedOutput()
	b.container = ""
	if err != nil && !strings.Contains(string(out), "No such container") {
		if rerr := b.finishJobWorkspace(); rerr != nil {
			return fmt.Errorf("remove job container: %v: %s (workspace restore also failed: %v)", err, strings.TrimSpace(string(out)), rerr)
		}
		return fmt.Errorf("remove job container: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return b.finishJobWorkspace()
}

// finishJobWorkspace runs the pending workspace teardown (ownership restore
// and project-quota removal), joining both errors. Each step is idempotent
// (the function values are cleared before use), so CloseJob and the StartJob
// failure paths can call it unconditionally.
func (b *ContainerBackend) finishJobWorkspace() error {
	return errors.Join(b.restoreProvisionedWorkspace(), b.cleanupWorkspaceQuota())
}

// cleanupWorkspaceQuota removes the OS-level workspace project quota applied
// by the capability probe, exactly once. Errors are returned, never
// swallowed: a failed removal leaves quota state behind and must surface as a
// cleanup warning.
func (b *ContainerBackend) cleanupWorkspaceQuota() error {
	cleanup := b.quotaCleanup
	b.quotaCleanup = nil
	if cleanup == nil {
		return nil
	}
	return cleanup()
}

// restoreProvisionedWorkspace runs the pending ownership restore exactly once.
// Errors are returned, never swallowed: a failed restore leaves the checkout
// under the workload uid and must surface as a cleanup warning.
func (b *ContainerBackend) restoreProvisionedWorkspace() error {
	restore := b.restoreWorkspace
	b.restoreWorkspace = nil
	if restore == nil {
		return nil
	}
	return restore()
}

// ReadFile reads a workspace file from inside the job container via
// `docker exec <container> cat`, capped at maxBytes. Paths are constrained to
// the mounted workspace and resolved against the container's view, so a
// symlink planted in the workspace can only resolve inside the sandbox.
func (b *ContainerBackend) ReadFile(ctx context.Context, path string, maxBytes int64) ([]byte, error) {
	if b.container == "" || b.docker == "" {
		return nil, &RunError{Kind: ErrorInfra, Err: fmt.Errorf("container job session is not started")}
	}
	rel, err := filepath.Rel(b.workspace, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("output path is outside mounted workspace")
	}
	containerPath := "/workspace"
	if rel != "." && rel != "" {
		containerPath += "/" + filepath.ToSlash(rel)
	}
	cmd := exec.CommandContext(ctx, b.docker, "exec", b.container, "cat", containerPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(stdout, maxBytes+1))
	waitErr := cmd.Wait()
	if waitErr != nil {
		msg := strings.ToLower(stderr.String())
		if strings.Contains(msg, "no such file") || strings.Contains(msg, "cannot open") {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("read output file in container: %v: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	if readErr != nil {
		return nil, readErr
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("output file exceeds %d byte limit", maxBytes)
	}
	return data, nil
}

func (b *ContainerBackend) Run(ctx context.Context, c Command, emit func(string)) error {
	if b.container == "" || b.docker == "" {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("container job session is not started")}
	}
	if c.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(c.TimeoutSeconds)*time.Second)
		defer cancel()
	}
	rel, err := filepath.Rel(b.workspace, c.Dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("step directory is outside mounted workspace")}
	}
	containerDir := "/workspace"
	if rel != "." && rel != "" {
		containerDir += "/" + filepath.ToSlash(rel)
	}
	args := []string{"exec", "-w", containerDir}
	for _, e := range c.Env {
		if i := strings.IndexByte(e, '='); i > 0 {
			// Passing only the variable name keeps secret values out of host argv;
			// Docker reads the value from cmd.Env.
			args = append(args, "-e", e[:i])
		}
	}
	// An already over-bound workspace never starts another step: the check
	// fails closed before this step's command is launched.
	if err := b.enforceWorkspaceBound(); err != nil {
		return err
	}
	args = append(args, b.container)
	args = append(args, shellCommand(c.Shell, c.Script)...)
	cmd := exec.CommandContext(ctx, b.docker, args...)
	cmd.Env = c.Env
	err = streamCommand(ctx, cmd, emit)
	if err == nil {
		// Catch growth caused by this step. A bind mount cannot be capped by
		// the daemon, so the step that pushed the workspace past its
		// declared disk bound fails here, deterministically and with a clear
		// error, rather than being silently truncated or left unmeasured.
		if berr := b.enforceWorkspaceBound(); berr != nil {
			return berr
		}
	}
	return err
}

func shellCommand(shell, script string) []string {
	if shell == "pwsh" || shell == "powershell" {
		return []string{shell, "-NoProfile", "-Command", script}
	}
	return []string{shell, "-lc", script}
}

func streamCommand(ctx context.Context, cmd *exec.Cmd, emit func(string)) error {
	// Parent-owned pipes: cmd.StdoutPipe hands pipe closure to Wait, which
	// closes the read ends the moment it sees the child exit and can discard
	// buffered output (race reproduced under single-P load). os.Pipe keeps
	// ownership with us: Wait only reaps; we close the write ends after
	// Start so the drains see EOF when the child exits, then join them.
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: err}
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		stdoutR.Close()
		stdoutW.Close()
		return &RunError{Kind: ErrorInfra, Err: err}
	}
	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW
	if err := cmd.Start(); err != nil {
		stdoutR.Close()
		stdoutW.Close()
		stderrR.Close()
		stderrW.Close()
		return &RunError{Kind: ErrorInfra, Err: err}
	}
	stdoutW.Close()
	stderrW.Close()
	done := make(chan struct{}, 2)
	for _, r := range []io.Reader{stdoutR, stderrR} {
		go func(rd io.Reader) {
			defer func() { done <- struct{}{} }()
			streamLines(rd, defaultMaxLine, emit)
		}(r)
	}
	err = cmd.Wait()
	joinDrains(done, 2*time.Second, stdoutR, stderrR)
	if err != nil {
		kind := ErrorFailure
		if ctx.Err() == context.DeadlineExceeded {
			kind = ErrorTimeout
		} else if ctx.Err() == context.Canceled {
			kind = ErrorCancelled
		}
		return &RunError{Kind: kind, Err: err}
	}
	return nil
}
