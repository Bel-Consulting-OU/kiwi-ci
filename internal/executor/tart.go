package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type TartBackend struct {
	VM      string
	Network string
	// RequireImmutableImages rejects VM references that are not pinned by an
	// @sha256: digest. Set by the executor from Options for untrusted jobs.
	RequireImmutableImages bool
	tart                   string
	ssh                    string
	clone                  string
	ip                     string
	workspace              string
	sshDir                 string
	run                    *exec.Cmd
}

func (*TartBackend) Name() string { return "tart" }

// StartJob clones and boots one disposable Tart VM for the entire CI job.
// The VM is deleted by CloseJob; steps share VM state and the mounted checkout.
func (b *TartBackend) StartJob(ctx context.Context, workspace string, emit func(string)) error {
	if b.VM == "" {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("tart runtime requires job.vm")}
	}
	// Network isolation checks run before any tart invocation: tart VMs are
	// always attached to the host's default network and offer no bridge or
	// internal-network option, so a job that requires isolation must be
	// refused rather than silently granted internet access.
	switch b.Network {
	case "", "default", "bridge", "host":
		// No isolation requested (or legacy per-job network strings that the
		// tart runtime has always ignored); proceed as before.
	case "none", "services-only":
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("tart runtime does not support network isolation; refusing to run job with network policy %s", b.Network)}
	default:
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("tart runtime does not support network mode %q; refusing to run job", b.Network)}
	}
	if b.RequireImmutableImages && !strings.Contains(b.VM, "@sha256:") {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("tart VM %q is not pinned by an @sha256: digest (require_immutable_images)", b.VM)}
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
	if err := b.setupSSHDir(); err != nil {
		_ = b.CloseJob()
		return &RunError{Kind: ErrorInfra, Err: err}
	}
	if out, err := exec.CommandContext(ctx, tart, "clone", b.VM, b.clone).CombinedOutput(); err != nil {
		_ = b.CloseJob()
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("tart clone: %v: %s", err, strings.TrimSpace(string(out)))}
	}
	b.run = exec.CommandContext(ctx, tart, "run", "--dir=workspace:"+abs, "--no-graphics", b.clone)
	if err := b.run.Start(); err != nil {
		_ = exec.Command(tart, "delete", b.clone).Run()
		_ = b.CloseJob()
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

// setupSSHDir creates a per-job temp dir holding the job's known_hosts file
// and an ephemeral Ed25519 keypair. Host-key trust is scoped to this job: the
// first connection pins the host key via StrictHostKeyChecking=accept-new, and
// removing the dir in CloseJob discards all trust and key material.
func (b *TartBackend) setupSSHDir() error {
	dir, err := os.MkdirTemp("", "kiwi-ssh-")
	if err != nil {
		return err
	}
	b.sshDir = dir
	if err := generateEphemeralSSHKey(filepath.Join(dir, "id_ed25519")); err != nil {
		_ = os.RemoveAll(dir)
		b.sshDir = ""
		return fmt.Errorf("generate ephemeral SSH key: %w", err)
	}
	return nil
}

// generateEphemeralSSHKey writes a fresh Ed25519 keypair. It prefers
// ssh-keygen (present on every Mac with ssh) and falls back to generating the
// key in Go and encoding it as an OpenSSH PKCS8 PEM file, which ssh accepts
// via -i alongside the written .pub file.
func generateEphemeralSSHKey(path string) error {
	if keygen, err := exec.LookPath("ssh-keygen"); err == nil {
		if _, kerr := exec.Command(keygen, "-t", "ed25519", "-N", "", "-C", "kiwi-job", "-f", path).CombinedOutput(); kerr == nil {
			return nil
		}
	}
	return writeGoGeneratedKey(path)
}

func writeGoGeneratedKey(path string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	privPEM := "-----BEGIN PRIVATE KEY-----\n" + wrapBase64(der) + "\n-----END PRIVATE KEY-----\n"
	if err := os.WriteFile(path, []byte(privPEM), 0o600); err != nil {
		return err
	}
	pubLine := "ssh-ed25519 " + base64.StdEncoding.EncodeToString([]byte(pub)) + " kiwi-job\n"
	return os.WriteFile(path+".pub", []byte(pubLine), 0o644)
}

func wrapBase64(b []byte) string {
	s := base64.StdEncoding.EncodeToString(b)
	var sb strings.Builder
	for len(s) > 64 {
		sb.WriteString(s[:64])
		sb.WriteByte('\n')
		s = s[64:]
	}
	sb.WriteString(s)
	return sb.String()
}

func (b *TartBackend) CloseJob() error {
	if b.run != nil && b.run.Process != nil {
		_ = b.run.Process.Kill()
		_, _ = b.run.Process.Wait()
	}
	var err error
	if b.clone != "" && b.tart != "" {
		out, derr := exec.Command(b.tart, "delete", b.clone).CombinedOutput()
		b.clone = ""
		if derr != nil && !strings.Contains(string(out), "does not exist") {
			err = fmt.Errorf("delete Tart VM: %v: %s", derr, strings.TrimSpace(string(out)))
		}
	}
	if b.sshDir != "" {
		_ = os.RemoveAll(b.sshDir)
		b.sshDir = ""
	}
	return err
}

func (b *TartBackend) keyFile() string        { return filepath.Join(b.sshDir, "id_ed25519") }
func (b *TartBackend) knownHostsFile() string { return filepath.Join(b.sshDir, "known_hosts") }

func (b *TartBackend) hardenedSSHArgs(host, command string) []string {
	return []string{
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=" + b.knownHostsFile(),
		"-o", "IdentitiesOnly=yes",
		"-i", b.keyFile(),
		host, command,
	}
}

// sshRunOnce executes one ssh invocation. stdout and stderr are drained
// through separate consumers (never stopped; consumers must read to EOF).
// It returns the ssh exit code and a *RunError on failure.
func (b *TartBackend) sshRunOnce(ctx context.Context, args []string, stdin io.Reader, consumeOut, consumeErr func(io.Reader) error) (int, error) {
	cmd := exec.CommandContext(ctx, b.ssh, args...)
	cmd.Stdin = stdin
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return -1, &RunError{Kind: ErrorInfra, Err: err}
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return -1, &RunError{Kind: ErrorInfra, Err: err}
	}
	if err := cmd.Start(); err != nil {
		return -1, &RunError{Kind: ErrorInfra, Err: err}
	}
	var mu sync.Mutex
	var consumeFailure error
	done := make(chan struct{}, 2)
	drain := func(rd io.Reader, consume func(io.Reader) error) {
		defer func() { done <- struct{}{} }()
		if err := consume(rd); err != nil {
			mu.Lock()
			if consumeFailure == nil {
				consumeFailure = err
			}
			mu.Unlock()
		}
	}
	go drain(stdout, consumeOut)
	go drain(stderr, consumeErr)
	waitErr := cmd.Wait()
	<-done
	<-done
	exitCode := 0
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			exitCode = ee.ExitCode()
		}
	}
	if consumeFailure != nil {
		return exitCode, consumeFailure
	}
	if waitErr != nil {
		kind := ErrorFailure
		if ctx.Err() == context.DeadlineExceeded {
			kind = ErrorTimeout
		} else if ctx.Err() == context.Canceled {
			kind = ErrorCancelled
		}
		return exitCode, &RunError{Kind: kind, Err: waitErr}
	}
	return exitCode, nil
}

// sshRun executes command on the VM with hardened, job-scoped SSH options and
// nothing else: StrictHostKeyChecking=accept-new pinned to the per-job
// known_hosts file, UserKnownHostsFile scoped to this job, IdentitiesOnly=yes,
// and -i with the ephemeral per-job key. There is deliberately no fallback to
// legacy host-verification options: if the VM image cannot authenticate the
// ephemeral key (or its host key fails verification), the job fails hard
// instead of being retried through an insecure path.
func (b *TartBackend) sshRun(ctx context.Context, stdin io.Reader, command string, consumeOut, consumeErr func(io.Reader) error) error {
	code, err := b.sshRunOnce(ctx, b.hardenedSSHArgs("admin@"+b.ip, command), stdin, consumeOut, consumeErr)
	if err == nil {
		return nil
	}
	if code == 255 && ctx.Err() == nil {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("ssh failed with exit code 255 (authentication or host-key verification failure); the ephemeral per-job key is the only accepted credential and no insecure fallback exists: %w", err)}
	}
	return err
}

func (b *TartBackend) Run(ctx context.Context, c Command, emit func(string)) error {
	if b.ip == "" || b.ssh == "" {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("tart job session is not started")}
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
	var script bytes.Buffer
	for _, e := range c.Env {
		if i := strings.IndexByte(e, '='); i > 0 {
			script.WriteString("export " + e[:i] + "=" + shellQuote(e[i+1:]) + "\n")
		}
	}
	script.WriteString(c.Script)
	script.WriteByte('\n')
	return b.sshRun(ctx, &script, remote, func(r io.Reader) error {
		streamLines(r, defaultMaxLine, emit)
		return nil
	}, func(r io.Reader) error {
		streamLines(r, defaultMaxLine, emit)
		return nil
	})
}

// ReadFile reads a workspace file from inside the VM over the authenticated
// ssh channel, capped at maxBytes. A missing file is reported as
// os.ErrNotExist so callers can treat "step wrote no outputs" uniformly.
func (b *TartBackend) ReadFile(ctx context.Context, path string, maxBytes int64) ([]byte, error) {
	if b.ip == "" || b.ssh == "" {
		return nil, &RunError{Kind: ErrorInfra, Err: fmt.Errorf("tart job session is not started")}
	}
	rel, err := filepath.Rel(b.workspace, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("output path is outside mounted workspace")
	}
	remotePath := "/Volumes/My Shared Files/workspace"
	if rel != "." && rel != "" {
		remotePath += "/" + filepath.ToSlash(rel)
	}
	remote := "cat " + shellQuote(remotePath)
	var mu sync.Mutex
	var data []byte
	var limitExceeded bool
	var stderrBuf bytes.Buffer
	consumeOut := func(r io.Reader) error {
		b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
		if err != nil {
			return err
		}
		mu.Lock()
		data = append(data, b...)
		if int64(len(data)) > maxBytes {
			limitExceeded = true
		}
		mu.Unlock()
		return nil
	}
	consumeErr := func(r io.Reader) error {
		_, err := io.Copy(&stderrBuf, r)
		return err
	}
	if err := b.sshRun(ctx, nil, remote, consumeOut, consumeErr); err != nil {
		if strings.Contains(strings.ToLower(stderrBuf.String()), "no such file") {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("read output file from VM: %w", err)
	}
	if limitExceeded {
		return nil, fmt.Errorf("output file exceeds %d byte limit", maxBytes)
	}
	return data, nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
