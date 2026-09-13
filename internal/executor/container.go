package executor

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var dockerNameClean = regexp.MustCompile(`[^a-zA-Z0-9_.-]`)

type ContainerBackend struct {
	Image     string
	Network   string
	docker    string
	container string
	workspace string
}

func (*ContainerBackend) Name() string { return "container" }

// StartJob creates one hardened, long-lived container for the whole CI job.
// Every step is executed with docker exec so package installs and process state
// behave like developers expect from a job while the checkout remains mounted.
func (b *ContainerBackend) StartJob(ctx context.Context, workspace string, emit func(string)) error {
	if b.Image == "" {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("container runtime requires job.image")}
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("docker not found: %w", err)}
	}
	abs, err := filepath.Abs(workspace)
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
		b.Image, "sh", "-c", "while :; do sleep 3600; done",
	}
	out, err := exec.CommandContext(ctx, docker, args...).CombinedOutput()
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("start job container: %v: %s", err, strings.TrimSpace(string(out)))}
	}
	emit("job container started " + b.container)
	return nil
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
	for _, r := range []interface{ Read([]byte) (int, error) }{stdout, stderr} {
		go func(rd interface{ Read([]byte) (int, error) }) {
			s := bufio.NewScanner(rd)
			s.Buffer(make([]byte, 64*1024), 1<<20)
			for s.Scan() {
				emit(strings.TrimRight(s.Text(), "\r"))
			}
			done <- struct{}{}
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
