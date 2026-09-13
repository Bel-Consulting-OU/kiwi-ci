package executor

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type TartBackend struct {
	VM        string
	tart      string
	ssh       string
	clone     string
	ip        string
	workspace string
	run       *exec.Cmd
}

func (*TartBackend) Name() string { return "tart" }

// StartJob clones and boots one disposable Tart VM for the entire CI job.
// The VM is deleted by CloseJob; steps share VM state and the mounted checkout.
func (b *TartBackend) StartJob(ctx context.Context, workspace string, emit func(string)) error {
	if b.VM == "" {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("tart runtime requires job.vm")}
	}
	tart, err := exec.LookPath("tart")
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("tart not found: %w", err)}
	}
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("ssh not found: %w", err)}
	}
	abs, err := filepath.Abs(workspace)
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: err}
	}
	b.tart, b.ssh, b.workspace = tart, ssh, abs
	b.clone = fmt.Sprintf("kiwi-%d", time.Now().UnixNano())
	if out, err := exec.CommandContext(ctx, tart, "clone", b.VM, b.clone).CombinedOutput(); err != nil {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("tart clone: %v: %s", err, strings.TrimSpace(string(out)))}
	}
	b.run = exec.CommandContext(ctx, tart, "run", "--dir=workspace:"+abs, "--no-graphics", b.clone)
	if err := b.run.Start(); err != nil {
		_ = exec.Command(tart, "delete", b.clone).Run()
		return &RunError{Kind: ErrorInfra, Err: err}
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			_ = b.CloseJob()
			return &RunError{Kind: ErrorCancelled, Err: ctx.Err()}
		}
		out, er := exec.CommandContext(ctx, tart, "ip", b.clone).Output()
		if er == nil && strings.TrimSpace(string(out)) != "" {
			b.ip = strings.TrimSpace(string(out))
			break
		}
		time.Sleep(time.Second)
	}
	if b.ip == "" {
		_ = b.CloseJob()
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("tart VM did not obtain an IP")}
	}
	emit("Tart VM ready " + b.clone)
	return nil
}

func (b *TartBackend) CloseJob() error {
	if b.run != nil && b.run.Process != nil {
		_ = b.run.Process.Kill()
		_, _ = b.run.Process.Wait()
	}
	if b.clone != "" && b.tart != "" {
		out, err := exec.Command(b.tart, "delete", b.clone).CombinedOutput()
		b.clone = ""
		if err != nil && !strings.Contains(string(out), "does not exist") {
			return fmt.Errorf("delete Tart VM: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func (b *TartBackend) Run(ctx context.Context, c Command, emit func(string)) error {
	if b.ip == "" || b.ssh == "" {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("Tart job session is not started")}
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
	remoteDir := "/Volumes/My Shared Files/workspace"
	if rel != "." && rel != "" {
		remoteDir += "/" + filepath.ToSlash(rel)
	}
	remote := "cd " + shellQuote(remoteDir) + " && " + c.Shell + " -s"
	if c.Shell == "pwsh" || c.Shell == "powershell" {
		remote = "cd " + shellQuote(remoteDir) + " && " + c.Shell + " -NoProfile -Command -"
	}
	args := []string{"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "admin@" + b.ip, remote}
	cmd := exec.CommandContext(ctx, b.ssh, args...)
	var script bytes.Buffer
	for _, e := range c.Env {
		if i := strings.IndexByte(e, '='); i > 0 {
			script.WriteString("export " + e[:i] + "=" + shellQuote(e[i+1:]) + "\n")
		}
	}
	script.WriteString(c.Script)
	script.WriteByte('\n')
	cmd.Stdin = &script
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
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

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
