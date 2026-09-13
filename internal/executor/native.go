package executor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

type NativeBackend struct{}

func (*NativeBackend) Name() string { return "native" }
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
	done := make(chan struct{}, 2)
	go scan(stdout, emit, done)
	go scan(stderr, emit, done)
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
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
func scan(r io.Reader, emit func(string), done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	s := bufio.NewScanner(r)
	buf := make([]byte, 64*1024)
	s.Buffer(buf, 1024*1024)
	for s.Scan() {
		emit(strings.TrimRight(s.Text(), "\r"))
	}
}
