package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

type TartBackend struct {
	VM      string
	Network string
	// RunID and JobID identify the owning run/job. The clone name embeds a
	// hash of them, so two runner processes that generate the same nanosecond
	// timestamp still derive distinct VM names. Set by the executor.
	RunID string
	JobID string
	// RequireImmutableImages rejects VM references that are not pinned by an
	// @sha256: digest. Set by the executor from Options for untrusted jobs.
	RequireImmutableImages bool
	// Resources carries the job's resource requests. CPU/memory map onto
	// the tart run flags the installed CLI supports; disk is advisory.
	// PIDs requests never reach here (admission rejects them for tart).
	Resources pipeline.Resources
	// AgentPort overrides the guest kiwi-agent bootstrap port. Zero keeps the
	// production default (tartAgentPort); tests use an ephemeral port so they
	// never collide with an external process.
	AgentPort int
	tart      string
	ssh       string
	clone     string
	ip        string
	workspace string
	sshDir    string
	run       *exec.Cmd
}

func (*TartBackend) Name() string { return "tart" }

// tartIPWait bounds how long StartJob waits for the booted VM to report an
// IP. It is a seam: production uses the fixed 60s bound, tests shorten it to
// exercise the never-got-an-IP failure without waiting a minute.
var tartIPWait = 60 * time.Second

// tartProbeTimeout bounds the quick `tart run --help` capability probe, so a
// wedged tart cannot stall job startup waiting for diagnostic output; a probe
// that times out yields no help text and the unsupported flags are reported
// as advisory.
var tartProbeTimeout = 15 * time.Second

// tartRunHelp runs the bounded `tart run --help` probe and returns its output
// (empty on error or timeout).
func tartRunHelp(ctx context.Context, tart string) string {
	hctx, cancel := context.WithTimeout(ctx, tartProbeTimeout)
	defer cancel()
	out, _ := exec.CommandContext(hctx, tart, "run", "--help").CombinedOutput()
	return string(out)
}

// tartIPProbe asks tart for the clone's IP under a context bounded by the
// remaining IP-wait window (and the job context), so a wedged `tart ip`
// cannot defeat the loop's tartIPWait bound. An error or timeout yields "".
func tartIPProbe(ctx context.Context, deadline time.Time, tart, clone string) string {
	pctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	out, err := exec.CommandContext(pctx, tart, "ip", clone).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// generateSSHKey is a test-only seam over generateEphemeralSSHKey. Production
// behavior is unchanged; it lets the checked SSH key-generation failure branch
// be exercised (key generation can genuinely fail: ssh-keygen errors and the
// Go fallback cannot write).
var generateSSHKey = generateEphemeralSSHKey

// maxTartCloneNameLen bounds the generated tart clone name. Tart stores a VM
// as a directory on the host filesystem, whose component limit is 255 bytes;
// 200 keeps the same headroom as the executor's docker physical names.
const maxTartCloneNameLen = 200

// tartCleanupTimeout bounds every tart delete (job cleanup and the deferred
// delete after a failed run start).
var tartCleanupTimeout = 15 * time.Second

// identityHash16 returns the first 8 bytes (16 hex characters) of the SHA-256
// of an identity. The identity is hashed verbatim; callers choose the field
// separator so distinct identities cannot collide through concatenation
// ambiguity. This is the same construction as the bounding suffix of
// boundedNormalizedName (SHA-256 of the full identity, first 8 bytes as hex).
func identityHash16(identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:8])
}

// tartCloneNameFor is the pure naming rule behind tartCloneName: the physical
// name of a disposable VM clone is kiwi-<unix-nano>-<hash16>, where hash16 is
// the first 8 bytes of the SHA-256 of the full run/job identity. The
// monotonic timestamp keeps two clones from one process distinct even on a
// coarse clock; the identity hash keeps clones from different run/job
// identities distinct even when two processes generate the same nanosecond.
// The name is passed through boundedNormalizedName so it can never exceed the
// executor's tart name budget, and the GC grammar (parseTartVMs) accepts both
// this form and the legacy kiwi-<unix-nano>.
func tartCloneNameFor(runID, jobID string, nano int64) string {
	return boundedNormalizedName(fmt.Sprintf("kiwi-%d-%s", nano, identityHash16(runID+"\x00"+jobID)), maxTartCloneNameLen)
}

// tartCloneName derives the clone name with this process's next monotonic
// timestamp.
func tartCloneName(runID, jobID string) string {
	return tartCloneNameFor(runID, jobID, nextPhysicalNano())
}

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
	if b.RequireImmutableImages && !digestPinned(b.VM) {
		return unpinnedImageError("tart VM", b.VM)
	}
	tart, err := exec.LookPath("tart")
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("tart not found: %w", err)}
	}
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("ssh not found: %w", err)}
	}
	abs, err := absWorkspacePath(workspace)
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: err}
	}
	b.tart, b.ssh, b.workspace = tart, ssh, abs
	b.clone = tartCloneName(b.RunID, b.JobID)
	if err := b.setupSSHDir(); err != nil {
		_ = b.CloseJob()
		return &RunError{Kind: ErrorInfra, Err: err}
	}
	// "--" terminates tart's own flag parsing before the image reference, so
	// a flag-shaped VM reference can never be injected as an option.
	if out, err := exec.CommandContext(ctx, tart, "clone", "--", b.VM, b.clone).CombinedOutput(); err != nil {
		_ = b.CloseJob()
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("tart clone: %v: %s", err, strings.TrimSpace(string(out)))}
	}
	// Resource requests map onto the tart run flags the installed CLI
	// actually supports; unsupported requests are reported as advisory
	// lines (the requests themselves were already admission-checked).
	flags, advisory := tartResourceFlags(b.Resources, tartRunHelp(ctx, tart))
	for _, a := range advisory {
		emit(a)
	}
	runArgs := []string{"run", "--no-graphics"}
	runArgs = append(runArgs, flags...)
	runArgs = append(runArgs, "--dir=workspace:"+abs, b.clone)
	b.run = exec.CommandContext(ctx, tart, runArgs...)
	if err := b.run.Start(); err != nil {
		// The clone was created by the successful clone step even though the
		// run process never started: delete it through the bounded cleanup
		// path (so a wedged tart cannot strand this goroutine) and fold a
		// cleanup failure into the returned error instead of discarding it.
		cerr := b.deleteCloneBounded(ctx)
		_ = b.CloseJob()
		if cerr != nil {
			return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("start tart VM: %w (clone cleanup: %v)", err, cerr)}
		}
		return &RunError{Kind: ErrorInfra, Err: err}
	}
	deadline := time.Now().Add(tartIPWait)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			_ = b.CloseJob()
			return &RunError{Kind: ErrorCancelled, Err: ctx.Err()}
		}
		if ip := tartIPProbe(ctx, deadline, tart, b.clone); ip != "" {
			b.ip = ip
			break
		}
		time.Sleep(time.Second)
	}
	if b.ip == "" {
		_ = b.CloseJob()
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("tart VM did not obtain an IP")}
	}
	// Kiwi ssh bootstrap contract: before the first SSH attempt the image
	// must declare the bootstrap capability and accept the runner-injected
	// ephemeral authorized key. There is no insecure fallback: an image
	// that cannot authenticate the injected key fails the job.
	if err := b.verifyBootstrapContract(ctx, tart); err != nil {
		_ = b.CloseJob()
		return err
	}
	if err := b.injectBootstrapKey(ctx); err != nil {
		_ = b.CloseJob()
		return err
	}
	emit("Tart VM ready " + b.clone)
	return nil
}

// tartBootstrapLabel is the capability label a Tart image must carry to
// declare the kiwi ssh bootstrap contract: the guest installs the
// runner-injected authorized key for the ssh user ("admin") before the
// first ssh attempt. Images without the label are refused.
const tartBootstrapLabel = "kiwi.ssh.bootstrap"

// tartAgentPort is the TCP port the guest's kiwi-agent listens on for key
// injection over the tart NAT; tartAgentKeyPath is the injection route.
const (
	tartAgentPort    = 4545
	tartAgentKeyPath = "/kiwi/v1/bootstrap/authorized-key"
)

// agentPort is the effective guest kiwi-agent bootstrap port.
func (b *TartBackend) agentPort() int {
	if b.AgentPort > 0 {
		return b.AgentPort
	}
	return tartAgentPort
}

// tartGetArgs builds the `tart get --format json <vm>` invocation used to
// query an image's labels. Pure helper so the invocation shape is testable.
func tartGetArgs(vm string) []string {
	return []string{"get", "--format", "json", vm}
}

// tartGetOutput is the minimal JSON shape `tart get --format json` emits:
// the VM name and its label map.
type tartGetOutput struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
}

// parseTartGetJSON decodes `tart get --format json` output.
func parseTartGetJSON(b []byte) (tartGetOutput, error) {
	var out tartGetOutput
	if err := json.Unmarshal(b, &out); err != nil {
		return out, fmt.Errorf("parse tart get output: %w", err)
	}
	return out, nil
}

// bootstrapContractDeclared reports whether the image labels declare the
// kiwi ssh bootstrap contract. The label value is informational: "true",
// "1", "yes", "enabled", or an empty value all declare it; a missing label
// or any other value does not.
func bootstrapContractDeclared(labels map[string]string) bool {
	v, ok := labels[tartBootstrapLabel]
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "true", "1", "yes", "enabled":
		return true
	default:
		return false
	}
}

// tartBootstrapConfigError is the configuration failure for an image that
// does not declare the bootstrap contract. ErrorConfig is deliberately not
// retried: re-running against the same image cannot succeed.
func tartBootstrapConfigError() error {
	return &RunError{Kind: ErrorConfig, Err: fmt.Errorf("image does not declare the kiwi ssh bootstrap contract; pin an image that installs the runner-injected authorized key (tart label %s)", tartBootstrapLabel)}
}

// verifyBootstrapContract queries the cloned VM's labels and refuses the
// job when the bootstrap contract is not declared.
func (b *TartBackend) verifyBootstrapContract(ctx context.Context, tart string) error {
	out, err := exec.CommandContext(ctx, tart, tartGetArgs(b.clone)...).Output()
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("tart get %s: %v: %s", b.clone, err, strings.TrimSpace(string(out)))}
	}
	meta, perr := parseTartGetJSON(out)
	if perr != nil {
		return &RunError{Kind: ErrorInfra, Err: perr}
	}
	if !bootstrapContractDeclared(meta.Labels) {
		return tartBootstrapConfigError()
	}
	return nil
}

// injectBootstrapKey pushes the ephemeral public key to the guest's
// kiwi-agent over the tart NAT. If the agent is unreachable the job fails:
// the contract requires the image to accept the injected key, and there is
// no fallback credential.
func (b *TartBackend) injectBootstrapKey(ctx context.Context) error {
	pub, err := os.ReadFile(b.keyFile() + ".pub")
	if err != nil {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("read ephemeral public key: %w", err)}
	}
	endpoint := fmt.Sprintf("http://%s:%d%s", b.ip, b.agentPort(), tartAgentKeyPath)
	if err := postAuthorizedKey(ctx, endpoint, string(pub), tartBootstrapHTTPClient()); err != nil {
		return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("kiwi-agent key injection failed (image must support the kiwi ssh bootstrap contract): %w", err)}
	}
	return nil
}

// tartBootstrapHTTPClient is the bounded, redirect-refusing client used for
// the kiwi-agent bootstrap call.
func tartBootstrapHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// postAuthorizedKey POSTs one OpenSSH authorized-keys line to the guest's
// kiwi-agent endpoint. The response is bounded and non-2xx responses fail
// the injection. Free function so the wire call is testable.
func postAuthorizedKey(ctx context.Context, endpoint, pubKey string, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(pubKey))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("agent returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

// tartResourceFlags renders the tart run resource flags a job's requests map
// onto, honoring what the installed tart CLI supports (runHelp is the
// `tart run --help` output). Requests whose flags the CLI does not support
// are returned as advisory lines instead of flags; the disk request has no
// tart run equivalent and is always advisory.
func tartResourceFlags(r pipeline.Resources, runHelp string) (flags, advisory []string) {
	cpuOK := strings.Contains(runHelp, "--cpu")
	memOK := strings.Contains(runHelp, "--memory")
	if r.CPU > 0 {
		if cpuOK {
			flags = append(flags, "--cpu", strconv.FormatInt(int64(r.CPU), 10))
		} else {
			advisory = append(advisory, fmt.Sprintf("advisory: tart CLI does not support --cpu; cpu request %v ignored", r.CPU))
		}
	}
	if r.Memory > 0 {
		if memOK {
			flags = append(flags, "--memory", strconv.FormatInt(int64(r.Memory)/(1<<20), 10))
		} else {
			advisory = append(advisory, fmt.Sprintf("advisory: tart CLI does not support --memory; memory request %d bytes ignored", int64(r.Memory)))
		}
	}
	if r.Disk > 0 {
		advisory = append(advisory, fmt.Sprintf("advisory: tart CLI does not support disk requests; disk request %d bytes ignored", int64(r.Disk)))
	}
	return flags, advisory
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
	if err := generateSSHKey(filepath.Join(dir, "id_ed25519")); err != nil {
		_ = os.RemoveAll(dir)
		b.sshDir = ""
		return fmt.Errorf("generate ephemeral SSH key: %w", err)
	}
	return nil
}

// sshKeygenTimeout bounds the ssh-keygen invocation: a wedged keygen must
// fall back to the in-process generator within the bound instead of stranding
// job startup.
var sshKeygenTimeout = 30 * time.Second

// runSSHKeygen runs the bounded ssh-keygen invocation. Split out so the
// typed-timeout contract is directly testable.
func runSSHKeygen(keygen, path string) error {
	_, err := boundedToolCommand(context.Background(), sshKeygenTimeout, keygen, "-t", "ed25519", "-N", "", "-C", "kiwi-job", "-f", path)
	return err
}

// generateEphemeralSSHKey writes a fresh Ed25519 keypair. It prefers
// ssh-keygen (present on every Mac with ssh) and falls back to generating the
// key in Go and encoding it as an OpenSSH PKCS8 PEM file, which ssh accepts
// via -i alongside the written .pub file. The ssh-keygen invocation is
// bounded; any keygen failure (including a timeout) falls back to the Go
// generator, and the keygen failure is preserved and reported if the fallback
// also fails.
func generateEphemeralSSHKey(path string) error {
	var keygenErr error
	if keygen, err := exec.LookPath("ssh-keygen"); err == nil {
		if keygenErr = runSSHKeygen(keygen, path); keygenErr == nil {
			return nil
		}
	}
	if err := writeGoGeneratedKey(path); err != nil {
		if keygenErr != nil {
			return fmt.Errorf("ssh-keygen invocation failed (%v); in-process key generation also failed: %w", keygenErr, err)
		}
		return err
	}
	return nil
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

// deleteCloneBounded removes the job's VM clone through the bounded cleanup
// helper and clears the clone name, so the call is idempotent and safe from
// both CloseJob and the run-start failure path. A clone tart reports as
// missing is not an error; a timeout or any other failure is returned with
// the bounded output, never silently discarded.
func (b *TartBackend) deleteCloneBounded(parent context.Context) error {
	if b.clone == "" || b.tart == "" {
		return nil
	}
	clone := b.clone
	b.clone = ""
	out, err := boundedToolCommand(parent, tartCleanupTimeout, b.tart, "delete", clone)
	if err != nil && !strings.Contains(string(out), "does not exist") {
		return fmt.Errorf("delete Tart VM: %w", err)
	}
	return nil
}

func (b *TartBackend) CloseJob() error {
	if b.run != nil && b.run.Process != nil {
		_ = b.run.Process.Kill()
		_, _ = b.run.Process.Wait()
	}
	err := b.deleteCloneBounded(context.Background())
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
	// Parent-owned pipes (see streamCommand): with StdoutPipe/StderrPipe,
	// Wait closes the read ends as soon as the child exits and can discard
	// buffered output; os.Pipe keeps closure with us.
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return -1, &RunError{Kind: ErrorInfra, Err: err}
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		stdoutR.Close()
		stdoutW.Close()
		return -1, &RunError{Kind: ErrorInfra, Err: err}
	}
	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW
	if err := cmd.Start(); err != nil {
		stdoutR.Close()
		stdoutW.Close()
		stderrR.Close()
		stderrW.Close()
		return -1, &RunError{Kind: ErrorInfra, Err: err}
	}
	stdoutW.Close()
	stderrW.Close()
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
	go drain(stdoutR, consumeOut)
	go drain(stderrR, consumeErr)
	waitErr := cmd.Wait()
	joinDrains(done, 2*time.Second, stdoutR, stderrR)
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
