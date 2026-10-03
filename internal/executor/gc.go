package executor

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/executil"
)

// maxExternalCommandOutputBytes bounds every external-command capture in the
// executor (docker/tart/git helpers). The cap is generous for legitimate
// listings but finite, so a command that streams without end can never grow
// the runner heap without bound; callers that PARSE the output fail closed
// when it is truncated.
const maxExternalCommandOutputBytes = 4 << 20

// maxCommandStderrBytes bounds child STDERR captured for diagnostics whose
// stdout is streamed/limited separately (container/tart ReadFile): normally
// tiny, but a compromised guest can emit arbitrary stderr.
const maxCommandStderrBytes = 64 << 10

// errExternalOutputTooLarge reports that an external command produced more
// than maxExternalCommandOutputBytes; parsed callers must not consume a
// silently truncated prefix.
var errExternalOutputTooLarge = errors.New("external command output exceeded the capture limit")

// GCReport counts the stale resources one GC pass removed.
type GCReport struct {
	Containers int
	Networks   int
	VMs        int
}

// gcCommandTimeout bounds every GC discovery command and gcCleanupTimeout
// every GC removal, so a wedged docker/tart binary can never strand the
// maintenance goroutine that runs GC, even when the caller passed an
// unbounded context.
var (
	gcCommandTimeout = 15 * time.Second
	gcCleanupTimeout = 15 * time.Second
)

// boundedToolWaitDelay bounds the output-pipe drain after an auxiliary
// command is killed, so an orphaned descendant holding the output pipe can
// never extend the command beyond its timeout plus this grace (the same rule
// the docker cleanup path applies).
const boundedToolWaitDelay = 2 * time.Second

// ErrExternalCommandTimeout marks an auxiliary executor command (a tart
// delete, an ssh-keygen invocation, an xfs_quota mutation, a GC removal, a
// setup command that outlived its phase ceiling, a killed process that could
// not be reaped) that did not finish within its per-tool bound. Callers can
// errors.Is it to distinguish a wedged binary or un-reapable process from an
// ordinary command failure.
var ErrExternalCommandTimeout = errors.New("external command timed out")

// Phase-specific ceilings for the executor's normal setup commands. These
// are deliberately separate from the cleanup bounds (boundedToolCommand,
// dockerCleanupCommand): cleanup detaches from the parent with
// context.WithoutCancel, while setup runs under the job context AND the phase
// ceiling, whichever expires first. A job that configures no timeout must
// still not hang forever on a wedged docker daemon or tart CLI, while the
// job's own build commands remain governed by the job timeout alone.
var (
	// runtimeProbeTimeout bounds capability probes: `docker info`, `tart
	// get`, and each `tart ip` attempt.
	runtimeProbeTimeout = 15 * time.Second
	// runtimeControlTimeout bounds quick control-plane mutations: `docker
	// network create`.
	runtimeControlTimeout = 30 * time.Second
	// runtimeSetupTimeout bounds setup commands that legitimately take long
	// because they pull images or clone VM disks: the job `docker run`, each
	// service `docker run`, and `tart clone`. The long-lived `tart run` VM
	// process itself is not a setup wait: it is governed by the job context
	// and bounded on teardown by waitKilledCommand (CloseJob).
	runtimeSetupTimeout = 10 * time.Minute
)

// phaseCommand runs one executor setup command (never a user build command)
// under a context bounded by both the parent (job) context and the phase
// ceiling. context.WithTimeout takes the earlier of the parent deadline and
// now+phase, so a tight job deadline is never extended and a missing job
// deadline is never unlimited. The parent is never detached: cleanup may use
// context.WithoutCancel, but a canceled job must cancel its setup.
//
// On a phase-ceiling expiry with the parent still live the returned error
// wraps ErrExternalCommandTimeout and context.DeadlineExceeded; a parent-side
// cancellation or deadline is returned as the raw command error so callers
// keep their own cancellation/timeout classification.
func phaseCommand(parent context.Context, phase time.Duration, exe string, args ...string) ([]byte, error) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, phase)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	// Bound the output-pipe drain after a kill too, so an orphaned
	// descendant holding the pipe cannot extend a phase beyond its ceiling.
	cmd.WaitDelay = boundedToolWaitDelay
	// Capture with a hard byte cap: an external command's output is never
	// buffered unbounded in the runner process, and a truncated parsed
	// output fails closed instead of silently mis-parsing a prefix.
	out, truncated, err := executil.CaptureBounded(cmd, maxExternalCommandOutputBytes)
	if err == nil && truncated {
		return out, fmt.Errorf("external command %s %s: %w", exe, strings.Join(args, " "), errExternalOutputTooLarge)
	}
	if err == nil {
		return out, nil
	}
	if parent.Err() == nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out, fmt.Errorf("%w after %s: %w: %s %s%s", ErrExternalCommandTimeout, phase, context.DeadlineExceeded, exe, strings.Join(args, " "), boundedCleanupOutput(out))
	}
	return out, err
}

// waitKilledReap is a test-only seam over cmd.Wait inside
// waitKilledCommand. Production behavior is unchanged; it lets a wait that
// cannot complete within the grace be exercised deterministically (a process
// wedged in an uninterruptible kernel wait cannot be fabricated portably).
var waitKilledReap = func(cmd *exec.Cmd) error { return cmd.Wait() }

// reapKilledCommand is a test-only seam over waitKilledCommand. Production
// behavior is unchanged; it lets a bounded-reap failure be injected
// deterministically at the CloseJob and native supervision-failure call
// sites.
var reapKilledCommand = waitKilledCommand

// waitKilledCommand kills cmd's process and reaps it through cmd.Wait —
// never os.Process.Wait, which bypasses exec.Cmd bookkeeping — under a
// bounded grace. Wait runs in a goroutine whose result channel is buffered,
// so a process that outlives the grace can never block the caller: on expiry
// a detached reaper (reapDetached) drains the eventual result, so the reaper
// goroutine never blocks on the send and the process is still reaped once it
// finally exits (no zombie), and a typed ErrExternalCommandTimeout is
// returned. A command reaped within the grace returns nil regardless of the
// wait error: the kill makes a signaled exit the expected outcome.
func waitKilledCommand(cmd *exec.Cmd, grace time.Duration) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	_ = cmd.Process.Kill()
	done := make(chan error, 1)
	go func() { done <- waitKilledReap(cmd) }()
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		reapDetached(done)
		return fmt.Errorf("%w after %s: %w: reaping killed process %q", ErrExternalCommandTimeout, grace, context.DeadlineExceeded, cmd.Path)
	}
}

// boundedToolCommand runs one auxiliary external command (cleanup, delete,
// keygen, quota mutation) under a context detached from parent cancellation:
// cleanup must still run when the job context is already canceled, so the
// parent is detached with context.WithoutCancel and bounded by timeout
// instead. The command output is returned alongside the error (so callers can
// inspect it, for example tart's "does not exist"); the error's diagnostic
// detail is trimmed and length-bounded, and a timeout wraps both
// ErrExternalCommandTimeout and context.DeadlineExceeded.
func boundedToolCommand(parent context.Context, timeout time.Duration, exe string, args ...string) ([]byte, error) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.WaitDelay = boundedToolWaitDelay
	out, truncated, err := executil.CaptureBounded(cmd, maxExternalCommandOutputBytes)
	if err == nil && truncated {
		return out, fmt.Errorf("external command %s %s: %w", exe, strings.Join(args, " "), errExternalOutputTooLarge)
	}
	if err == nil {
		return out, nil
	}
	detail := boundedCleanupOutput(out)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out, fmt.Errorf("%w after %s: %w: %s %s%s", ErrExternalCommandTimeout, timeout, context.DeadlineExceeded, exe, strings.Join(args, " "), detail)
	}
	return out, fmt.Errorf("external command %s %s: %w%s", exe, strings.Join(args, " "), err, detail)
}

// GC removes stale runtime resources older than olderThan: docker
// containers and networks labeled kiwi.run and Tart VM clones named
// kiwi-<unix-nano> or kiwi-<unix-nano>-<hash16>. root is the runner root used
// as the working directory for the discovery subprocesses. If docker or tart
// is not installed the corresponding pass is skipped and the report stays at
// zero for it. Discovery and removals are explicitly bounded (gcCommandTimeout
// / gcCleanupTimeout): a wedged docker or tart binary cannot strand the pass.
// GC is the owner-agnostic legacy sweep: it reaps only resources that carry
// NO runner-ownership label (pre-instance Kiwi) and are older than the
// threshold. Prefer GCScoped from a live runner.
func GC(ctx context.Context, root string, olderThan time.Duration) GCReport {
	return GCScoped(ctx, root, "", "", olderThan)
}

// GCScoped is the age-based backstop with OWNERSHIP SAFETY: a labelled
// resource is reaped only when it belongs to THIS runner's stable ID but a
// previous incarnation (startup reconciliation normally handles those
// immediately) or when it carries no ownership label at all (legacy). Another
// runner's labelled resources are NEVER touched, so a long-running job of a
// sibling runner sharing the daemon cannot be killed by age.
func GCScoped(ctx context.Context, root, runnerID, instanceID string, olderThan time.Duration) GCReport {
	var rep GCReport
	if ctx == nil {
		ctx = context.Background()
	}
	if olderThan <= 0 {
		return rep
	}
	cutoff := time.Now().Add(-olderThan)
	output := func(bin string, args ...string) []byte {
		qctx, cancel := context.WithTimeout(ctx, gcCommandTimeout)
		defer cancel()
		cmd := exec.CommandContext(qctx, bin, args...)
		cmd.Dir = root
		cmd.WaitDelay = boundedToolWaitDelay
		out, truncated, err := executil.CaptureBounded(cmd, maxExternalCommandOutputBytes)
		if err != nil || truncated {
			return nil
		}
		return out
	}
	if docker, err := exec.LookPath("docker"); err == nil {
		out := output(docker, "ps", "-a", "--filter", "label=kiwi.run", "--format", `{{.ID}} {{.CreatedAt}} {{.Label "kiwi.runner"}} {{.Label "kiwi.instance"}}`)
		for _, id := range parseScopedDocker(out, cutoff, runnerID, instanceID) {
			if _, err := boundedToolCommand(ctx, gcCleanupTimeout, docker, "rm", "-f", id); err == nil {
				rep.Containers++
			}
		}
		out = output(docker, "network", "ls", "--filter", "label=kiwi.run", "--format", `{{.ID}} {{.CreatedAt}} {{.Label "kiwi.runner"}} {{.Label "kiwi.instance"}}`)
		for _, id := range parseScopedDocker(out, cutoff, runnerID, instanceID) {
			if _, err := boundedToolCommand(ctx, gcCleanupTimeout, docker, "network", "rm", id); err == nil {
				rep.Networks++
			}
		}
	}
	if tart, err := exec.LookPath("tart"); err == nil {
		out := output(tart, "list")
		for _, name := range parseScopedTartVMs(out, cutoff, runnerID, instanceID) {
			if _, err := boundedToolCommand(ctx, gcCleanupTimeout, tart, "delete", name); err == nil {
				rep.VMs++
			}
		}
	}
	return rep
}

// parseScopedDocker parses "ID CREATED RUNNER INSTANCE" rows and returns IDs
// that are older than the cutoff AND owned by this runner's previous
// incarnation (or unlabelled legacy). Another runner's labelled resources are
// never returned. Docker renders missing labels as empty trailing columns, so
// the label tags are peeled from the END only when the remaining prefix still
// parses as a docker timestamp.
func parseScopedDocker(out []byte, cutoff time.Time, runnerID, instanceID string) []string {
	ownRunner := identityHash8(runnerID)
	ownInstance := identityHash8(instanceID)
	var stale []string
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
		if len(parts) != 2 || parts[0] == "" {
			continue
		}
		id := parts[0]
		rest := strings.Fields(parts[1])
		var (
			created  time.Time
			ok       bool
			owner    string
			instance string
		)
		maxPeel := len(rest) - 4
		if maxPeel > 2 {
			maxPeel = 2
		}
		for peel := maxPeel; peel >= 0; peel-- {
			candidate := strings.Join(rest[:len(rest)-peel], " ")
			if t, err := parseDockerTime(candidate); err == nil {
				created, ok = t, true
				if peel == 2 {
					owner, instance = rest[len(rest)-2], rest[len(rest)-1]
				} else if peel == 1 {
					owner = rest[len(rest)-1]
				}
				break
			}
		}
		if !ok || !created.Before(cutoff) {
			continue
		}
		switch {
		case owner == "":
			stale = append(stale, id) // legacy: no ownership label
		case runnerID != "" && owner == ownRunner && instance != ownInstance:
			stale = append(stale, id)
		}
	}
	return stale
}

// parseScopedTartVMs returns legacy (untagged) clones older than the cutoff
// plus clones of THIS runner's previous incarnation. Other owners' clones are
// never touched.
func parseScopedTartVMs(out []byte, cutoff time.Time, runnerID, instanceID string) []string {
	var stale []string
	legacy := map[string]bool{}
	for _, name := range parseTartVMs(out, cutoff) {
		legacy[name] = true
	}
	ownRunner := identityHash8(runnerID)
	ownInstance := identityHash8(instanceID)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if !strings.HasPrefix(name, "kiwi-") {
			continue
		}
		parts := strings.Split(name, "-")
		if len(parts) < 4 {
			// Legacy name: age-only (parseTartVMs already applied the cutoff).
			if legacy[name] {
				stale = append(stale, name)
			}
			continue
		}
		owner, instance := parts[len(parts)-2], parts[len(parts)-1]
		if runnerID != "" && owner == ownRunner && instance != ownInstance {
			stale = append(stale, name)
		}
	}
	return stale
}

// runtimeOwner identifies one runner process incarnation for runtime
// resource labelling and crash reconciliation.
type runtimeOwner struct {
	RunnerID   string
	InstanceID string
}

// containerLabels returns the docker label flags identifying a job's
// containers and networks so GC can match and reap them. An empty runID
// yields no labels.
func containerLabels(runID, jobID string) []string {
	if runID == "" {
		return nil
	}
	return []string{"--label", "kiwi.run=" + runID, "--label", "kiwi.job=" + jobID}
}

// containerLabelsOwned adds the runner-identity labels. An empty RunnerID
// keeps the legacy unlabelled behavior; an empty InstanceID still labels the
// stable runner so a restart can reap pre-instance resources.
func containerLabelsOwned(runID, jobID string, owner runtimeOwner) []string {
	labels := containerLabels(runID, jobID)
	if owner.RunnerID == "" {
		return labels
	}
	labels = append(labels, "--label", "kiwi.runner="+owner.RunnerID)
	if owner.InstanceID != "" {
		labels = append(labels, "--label", "kiwi.instance="+owner.InstanceID)
	}
	return labels
}

// ReconcileRuntime removes runtime resources that belong to THIS runner's
// stable identity but to a PREVIOUS process incarnation (or a legacy
// unlabelled incarnation). It is the crash-recovery boundary: a SIGKILLed
// runner's detached containers/services/networks must be reaped BEFORE the
// replacement leases new work, not 24 hours later.
//
// Matching only kiwi.runner=<own stable id> makes this safe on a shared
// Docker daemon: another live runner's resources carry a different runner
// label and are never touched. Resources with no instance label (created by a
// pre-instance Kiwi) are treated as previous-incarnation and reaped, because
// one stable runner identity must not have two live processes.
// ReconcileRuntime returns an error when runtime absence CANNOT BE PROVEN or
// when a stale resource cannot be removed: the caller (runner startup) must
// refuse to lease new work rather than treat a discovery/removal failure as
// "nothing stale". A docker binary that is not installed is treated as "this
// host has no Docker subsystem" (nil error); a present-but-failing docker
// (daemon down, timeout, truncated output) is a hard error. Removal failures
// other than a positively reported absence are hard errors too.
func ReconcileRuntime(ctx context.Context, root, runnerID, instanceID string) (GCReport, error) {
	var rep GCReport
	if ctx == nil {
		ctx = context.Background()
	}
	if runnerID == "" {
		return rep, nil
	}
	output := func(bin string, args ...string) ([]byte, error) {
		qctx, cancel := context.WithTimeout(ctx, gcCommandTimeout)
		defer cancel()
		cmd := exec.CommandContext(qctx, bin, args...)
		cmd.Dir = root
		cmd.WaitDelay = boundedToolWaitDelay
		out, truncated, err := executil.CaptureBounded(cmd, maxExternalCommandOutputBytes)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", bin, strings.Join(args, " "), err)
		}
		if truncated {
			return nil, fmt.Errorf("%s %s: output exceeded the discovery bound", bin, strings.Join(args, " "))
		}
		return out, nil
	}
	docker, lookErr := exec.LookPath("docker")
	if lookErr != nil {
		return rep, nil
	}
	filter := "label=kiwi.runner=" + runnerID
	out, err := output(docker, "ps", "-a", "--filter", filter, "--format", `{{.ID}} {{.Label "kiwi.instance"}}`)
	if err != nil {
		return rep, fmt.Errorf("cannot prove prior container absence: %w", err)
	}
	for _, id := range parseForeignInstances(out, instanceID) {
		if _, err := boundedToolCommand(ctx, gcCleanupTimeout, docker, "rm", "-f", id); err != nil && !isContainerAbsentError(err) {
			return rep, fmt.Errorf("cannot remove stale container %s: %w", id, err)
		}
		rep.Containers++
	}
	out, err = output(docker, "network", "ls", "--filter", filter, "--format", `{{.ID}} {{.Label "kiwi.instance"}}`)
	if err != nil {
		return rep, fmt.Errorf("cannot prove prior network absence: %w", err)
	}
	for _, id := range parseForeignInstances(out, instanceID) {
		if _, err := boundedToolCommand(ctx, gcCleanupTimeout, docker, "network", "rm", id); err != nil {
			return rep, fmt.Errorf("cannot remove stale network %s: %w", id, err)
		}
		rep.Networks++
	}
	// Tart: clones encode the runner/instance ownership in their names.
	if tart, terr := exec.LookPath("tart"); terr == nil && instanceID != "" {
		out, err := output(tart, "list")
		if err != nil {
			return rep, fmt.Errorf("cannot prove prior VM absence: %w", err)
		}
		for _, name := range parseForeignTartClones(out, runnerID, instanceID) {
			if _, err := boundedToolCommand(ctx, gcCleanupTimeout, tart, "delete", name); err != nil {
				return rep, fmt.Errorf("cannot remove stale Tart VM %s: %w", name, err)
			}
			rep.VMs++
		}
	}
	return rep, nil
}

// parseForeignTartClones extracts kiwi-owned clone names belonging to the
// SAME stable runner ID but a DIFFERENT (or absent) incarnation. Clone names
// are kiwi-<nano>-<runhash16>-<runnerhash8>-<instancehash8>; only the
// runner-hash verifies ownership, and a different/absent instance hash marks
// a previous incarnation.
func parseForeignTartClones(out []byte, runnerID, instanceID string) []string {
	wantRunner := identityHash8(runnerID)
	wantInstance := identityHash8(instanceID)
	var stale []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if !strings.HasPrefix(name, "kiwi-") {
			continue
		}
		parts := strings.Split(name, "-")
		if len(parts) < 4 {
			continue
		}
		owner := parts[len(parts)-2]
		instance := parts[len(parts)-1]
		if owner == wantRunner && instance != wantInstance {
			stale = append(stale, name)
		}
	}
	return stale
}

// parseForeignInstances parses "ID <instance>" rows from docker ps/network ls
// and returns the IDs whose instance label is missing (legacy) or differs
// from the CURRENT process incarnation.
func parseForeignInstances(out []byte, current string) []string {
	var stale []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 || fields[0] == "" {
			continue
		}
		instance := ""
		if len(fields) > 1 {
			instance = fields[1]
		}
		if instance != current {
			stale = append(stale, fields[0])
		}
	}
	return stale
}

// parseDockerContainers extracts the IDs of docker containers created before
// cutoff from the output of
//
//	docker ps -a --filter label=kiwi.run --format "{{.ID}} {{.CreatedAt}}"
//
// Rows whose timestamps cannot be parsed are ignored rather than deleted.
func parseDockerContainers(out []byte, cutoff time.Time) []string {
	return parseIDCreatedAt(out, cutoff)
}

// parseIDCreatedAt parses "ID <created-at>" rows and returns the IDs whose
// creation time is before cutoff. It backs both container and network
// garbage collection.
func parseIDCreatedAt(out []byte, cutoff time.Time) []string {
	var stale []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), " ", 2)
		if len(fields) != 2 || fields[0] == "" {
			continue
		}
		created, err := parseDockerTime(fields[1])
		if err != nil || !created.Before(cutoff) {
			continue
		}
		stale = append(stale, fields[0])
	}
	return stale
}

// parseDockerTime parses the docker ps/network ls {{.CreatedAt}} rendering
// ("2026-09-14 13:22:32 +0000 UTC") and RFC3339 fallbacks.
func parseDockerTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"2006-01-02 15:04:05 -0700 MST", time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized docker time %q", s)
}

// parseTartVMs extracts the names of stale kiwi-owned Tart clones from the
// output of `tart list`. Both clone grammars are accepted:
//
//	kiwi-<unix-nano>            (legacy)
//	kiwi-<unix-nano>-<hash16>   (identity-hashed, see tartCloneName)
//
// Staleness always comes from the first dash-separated numeric field after
// the prefix; trailing fields (the identity hash) are ignored. A VM not
// created by the executor or one whose first field is not a number is never
// returned for deletion (fail closed).
func parseTartVMs(out []byte, cutoff time.Time) []string {
	var stale []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		nanos, ok := tartCloneTimestamp(name)
		if !ok {
			continue
		}
		if time.Unix(0, nanos).Before(cutoff) {
			stale = append(stale, name)
		}
	}
	return stale
}

// tartCloneTimestamp extracts the creation timestamp embedded in a kiwi tart
// clone name. Only kiwi-prefixed names with a numeric first dash-separated
// field are accepted; everything else (foreign names, kiwi-abc, kiwi-,
// overflow) is rejected so a malformed name is never deleted.
func tartCloneTimestamp(name string) (int64, bool) {
	const prefix = "kiwi-"
	if !strings.HasPrefix(name, prefix) {
		return 0, false
	}
	first, _, _ := strings.Cut(strings.TrimPrefix(name, prefix), "-")
	if first == "" {
		return 0, false
	}
	nanos, err := strconv.ParseInt(first, 10, 64)
	if err != nil {
		return 0, false
	}
	return nanos, true
}
