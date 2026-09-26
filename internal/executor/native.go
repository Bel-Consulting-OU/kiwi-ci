package executor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// attachChildSupervision is a test-only seam over superviseChildNow, the
// portable wrapper around the per-platform child supervision. Production
// behavior is unchanged; it lets the post-Start supervision failure branch
// (real on Windows where the Job Object assign can fail) be exercised on
// hosts without the Windows Job Object API.
var attachChildSupervision = superviseChildNow

// nativeWait is a test-only seam over cmd.Wait in the reaper goroutine.
// Production behavior is unchanged; it lets the un-reapable-after-SIGKILL
// branch be exercised deterministically (a real process stuck in an
// uninterruptible kernel wait cannot be fabricated portably).
var nativeWait = func(cmd *exec.Cmd) error { return cmd.Wait() }

// reapDetached is a test-only seam over the detached drain started when
// SIGKILL could not reap the process: production spawns a goroutine that
// consumes the wait result whenever the process is finally reaped, so the
// reaper goroutine never blocks forever on the channel send and no zombie is
// left behind. Tests substitute a recorder to prove the drain happens.
var reapDetached = func(wait <-chan error) {
	go func() { <-wait }()
}

// nativeTermGrace is the grace period between SIGTERM and SIGKILL for a
// canceled native command. A var so tests can shorten it.
var nativeTermGrace = 2 * time.Second

// killGrace bounds how long the backend waits for the process to be reaped
// after SIGKILL. SIGKILL cannot be caught, but a process wedged in an
// uninterruptible kernel wait can still fail to exit; the backend must not
// block forever on Wait in that case. A var so tests can shorten it.
var killGrace = 2 * time.Second

// nativeCleanupMarker is the durable marker the native backend writes into
// the step directory when a command tree could not be reaped after SIGKILL.
// A workspace carrying it is refused until the existing workspace cleanup
// (Options.WorkspaceFor's cleanup, or workspace.Manager's RemoveAll of the
// job directory) has removed the directory: an un-reapable process may still
// mutate the workspace after the job failed, so the directory must never be
// reused as-is.
const nativeCleanupMarker = ".kiwi-needs-cleanup"

// workspaceCleanupRequired reports whether dir was marked as requiring
// cleanup by a previous un-reapable command.
func workspaceCleanupRequired(dir string) error {
	if dir == "" {
		return nil
	}
	if _, err := os.Stat(filepath.Join(dir, nativeCleanupMarker)); err != nil {
		return nil
	}
	return fmt.Errorf("workspace %q requires cleanup before reuse: an un-reapable command left the %s marker; remove the workspace (or the marker) before running again", dir, nativeCleanupMarker)
}

// markWorkspaceNeedsCleanup writes the durable cleanup marker into dir.
func markWorkspaceNeedsCleanup(dir string) error {
	if dir == "" {
		return fmt.Errorf("no step directory recorded")
	}
	content := fmt.Sprintf("native command could not be reaped after SIGKILL at %s\n", time.Now().UTC().Format(time.RFC3339Nano))
	return os.WriteFile(filepath.Join(dir, nativeCleanupMarker), []byte(content), 0o600)
}

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
	if err := workspaceCleanupRequired(c.Dir); err != nil {
		return &RunError{Kind: ErrorInfra, Err: err}
	}
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
		err := nativeWait(cmd)
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
		kind := ErrorCancelled
		if ctx.Err() == context.DeadlineExceeded {
			kind = ErrorTimeout
		}
		_ = terminateProcess(cmd)
		select {
		case <-wait:
		case <-time.After(nativeTermGrace):
			_ = killProcess(cmd)
			select {
			case <-wait:
			case <-time.After(killGrace):
				// SIGKILL could not reap the process within the bound
				// (for example it is wedged in an uninterruptible kernel
				// wait). Detach a drain so the reaper goroutine's final
				// send never blocks and the process is reaped once it
				// finally exits (no zombie), and fail as infra with the
				// workspace marked as requiring cleanup before reuse.
				reapDetached(wait)
				markErr := markWorkspaceNeedsCleanup(c.Dir)
				reapErr := fmt.Errorf("process could not be reaped after SIGKILL within %s (command stopped: %v)", killGrace, ctx.Err())
				if markErr != nil {
					reapErr = fmt.Errorf("%w; marking workspace %q for cleanup also failed: %v", reapErr, c.Dir, markErr)
				}
				return &RunError{Kind: ErrorInfra, Err: reapErr}
			}
		}
		return &RunError{Kind: kind, Err: fmt.Errorf("command stopped: %w", ctx.Err())}
	}
}
