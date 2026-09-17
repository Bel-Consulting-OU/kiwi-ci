package executor

import (
	"bytes"
	"context"
	"fmt"
	"io"
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
	// pipeline validation; zero requests produce no flags.
	Resources pipeline.Resources
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
	docker, err := exec.LookPath("docker")
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("docker not found: %w", err)}
	}
	if b.Rootless {
		if err := b.verifyRootlessDaemon(ctx, docker); err != nil {
			return err
		}
	}
	abs, err := absWorkspacePath(workspace)
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: err}
	}
	b.docker, b.workspace = docker, abs
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
	args = append(args, resourceArgsFor(b.Resources)...)
	args = append(args, containerLabels(b.RunID, b.JobID)...)
	if b.Rootless || b.ReadOnlyRootFS {
		args = append(args,
			"--read-only",
			"--tmpfs", "/tmp:rw,nosuid,nodev",
			"--tmpfs", "/run:rw,nosuid,nodev",
			"--user=65534:65534",
		)
	}
	args = append(args, b.Image, "sh", "-c", "while :; do sleep 3600; done")
	out, err := exec.CommandContext(ctx, docker, args...).CombinedOutput()
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("start job container: %v: %s", err, strings.TrimSpace(string(out)))}
	}
	emit("job container started " + b.container)
	return nil
}

// containerResourceArgs renders the docker run flags enforcing a job's
// resource requests: resources.cpu -> --cpus, resources.memory -> --memory,
// resources.pids -> --pids-limit. Zero/absent requests produce no flags; the
// values themselves are already range-checked by pipeline admission. The
// disk request has no docker run equivalent and is not rendered.
func containerResourceArgs(j pipeline.Job) []string {
	return resourceArgsFor(j.Resources)
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
		return nil
	}
	out, err := exec.Command(b.docker, "rm", "-f", b.container).CombinedOutput()
	b.container = ""
	if err != nil && !strings.Contains(string(out), "No such container") {
		return fmt.Errorf("remove job container: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
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
	args = append(args, b.container)
	args = append(args, shellCommand(c.Shell, c.Script)...)
	cmd := exec.CommandContext(ctx, b.docker, args...)
	cmd.Env = c.Env
	return streamCommand(ctx, cmd, emit)
}

func shellCommand(shell, script string) []string {
	if shell == "pwsh" || shell == "powershell" {
		return []string{shell, "-NoProfile", "-Command", script}
	}
	return []string{shell, "-lc", script}
}

func streamCommand(ctx context.Context, cmd *exec.Cmd, emit func(string)) error {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: err}
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: err}
	}
	if err := cmd.Start(); err != nil {
		return &RunError{Kind: ErrorInfra, Err: err}
	}
	done := make(chan struct{}, 2)
	for _, r := range []io.Reader{stdout, stderr} {
		go func(rd io.Reader) {
			defer func() { done <- struct{}{} }()
			streamLines(rd, defaultMaxLine, emit)
		}(r)
	}
	err = cmd.Wait()
	<-done
	<-done
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
