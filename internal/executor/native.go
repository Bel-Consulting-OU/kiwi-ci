package executor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// attachChildSupervision is a test-only seam over superviseChildNow, the
// portable wrapper around the per-platform child supervision. Production
// behavior is unchanged; it lets the post-Start supervision failure branch
// (real on Windows where the Job Object assign can fail) be exercised on
// hosts without the Windows Job Object API.
var attachChildSupervision = superviseChildNow

type NativeBackend struct{}

func (*NativeBackend) Name() string { return "native" }

// nativeResourceAdvisory reports the resource requests the native backend
// cannot enforce. The native runtime has no container boundary to apply
// them to, so the requests are logged as advisory and never change job
// status.
func nativeResourceAdvisory(r pipeline.Resources) []string {
	var lines []string
	if r.CPU > 0 {
		lines = append(lines, fmt.Sprintf("advisory: native backend does not enforce cpu requests (requested %v)", r.CPU))
	}
	if r.Memory > 0 {
		lines = append(lines, fmt.Sprintf("advisory: native backend does not enforce memory requests (requested %d bytes)", int64(r.Memory)))
	}
	if r.Disk > 0 {
		lines = append(lines, fmt.Sprintf("advisory: native backend does not enforce disk requests (requested %d bytes)", int64(r.Disk)))
	}
	if r.PIDs > 0 {
		lines = append(lines, fmt.Sprintf("advisory: native backend does not enforce pids requests (requested %d)", r.PIDs))
	}
	return lines
}

// ReadFile reads a workspace file on the host without following symlinks in
// the final path component, so an attacker-controlled workspace cannot
// redirect step-output reads to arbitrary host files.
func (*NativeBackend) ReadFile(ctx context.Context, path string, maxBytes int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return readFileNoFollow(path, maxBytes)
}

func (*NativeBackend) Run(ctx context.Context, c Command, emit func(string)) error {
	shell := c.Shell
	if shell == "" {
		shell = "bash"
	}
	args := []string{"-lc", c.Script}
	if shell == "powershell" || shell == "pwsh" {
		args = []string{"-NoProfile", "-Command", c.Script}
	}
	if c.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(c.TimeoutSeconds)*time.Second)
		defer cancel()
	}
	cmd := exec.Command(shell, args...)
	cmd.Dir = c.Dir
	cmd.Env = c.Env
	configureProcess(cmd)
	// Parent-owned pipes: cmd.StdoutPipe would make Wait responsible for
	// closing the read ends, and Wait closes them as soon as it observes the
	// child exit — which can discard buffered output when Wait wins the race
	// against the drain goroutines (load-dependent; single-P runs reproduce
	// it). With os.Pipe, Wait only reaps; the parent closes its write-end
	// copies right after Start so the drains see EOF when the child exits.
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
	// superviseChildNow must run synchronously here: after cmd.Start() has
	// materialized cmd.Process and before any supervision goroutine reads it.
	// On Windows it creates the Job Object and assigns the just-started child
	// before returning, so no goroutine can observe an unassigned process.
	cleanup, err := attachChildSupervision(cmd, nil)
	if err != nil {
		_ = stdoutR.Close()
		_ = stderrR.Close()
		_ = terminateProcess(cmd)
		_ = cmd.Wait()
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("attach child process supervision: %w", err)}
	}
	done := make(chan struct{}, 2)
	go func() { defer func() { done <- struct{}{} }(); streamLines(stdoutR, defaultMaxLine, emit) }()
	go func() { defer func() { done <- struct{}{} }(); streamLines(stderrR, defaultMaxLine, emit) }()
	wait := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		cleanup()
		joinDrains(done, 2*time.Second, stdoutR, stderrR)
		wait <- err
	}()
	select {
	case err := <-wait:
		if err != nil {
			return &RunError{Kind: ErrorFailure, Err: err}
		}
		return nil
	case <-ctx.Done():
		_ = terminateProcess(cmd)
		select {
		case <-wait:
		case <-time.After(2 * time.Second):
			_ = killProcess(cmd)
			<-wait
		}
		kind := ErrorCancelled
		if ctx.Err() == context.DeadlineExceeded {
			kind = ErrorTimeout
		}
		return &RunError{Kind: kind, Err: fmt.Errorf("command stopped: %w", ctx.Err())}
	}
}
