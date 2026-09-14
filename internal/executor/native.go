package executor

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

type NativeBackend struct{}

func (*NativeBackend) Name() string { return "native" }

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
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return &RunError{Kind: ErrorInfra, Err: err}
	}
	// superviseChildNow must run synchronously here: after cmd.Start() has
	// materialized cmd.Process and before any supervision goroutine reads it.
	// On Windows it creates the Job Object and assigns the just-started child
	// before returning, so no goroutine can observe an unassigned process.
	cleanup, err := superviseChildNow(cmd, nil)
	if err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		_ = terminateProcess(cmd)
		_ = cmd.Wait()
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("attach child process supervision: %w", err)}
	}
	done := make(chan struct{}, 2)
	go func() { defer func() { done <- struct{}{} }(); streamLines(stdout, defaultMaxLine, emit) }()
	go func() { defer func() { done <- struct{}{} }(); streamLines(stderr, defaultMaxLine, emit) }()
	wait := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		cleanup()
		wait <- err
	}()
	select {
	case err := <-wait:
		<-done
		<-done
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
		<-done
		<-done
		kind := ErrorCancelled
		if ctx.Err() == context.DeadlineExceeded {
			kind = ErrorTimeout
		}
		return &RunError{Kind: kind, Err: fmt.Errorf("command stopped: %w", ctx.Err())}
	}
}
