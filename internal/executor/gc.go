package executor

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

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
// delete, an ssh-keygen invocation, an xfs_quota mutation, a GC removal) that
// did not finish within its per-tool bound. Callers can errors.Is it to
// distinguish a wedged binary from an ordinary command failure.
var ErrExternalCommandTimeout = errors.New("external command timed out")

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
	out, err := cmd.CombinedOutput()
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
func GC(ctx context.Context, root string, olderThan time.Duration) GCReport {
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
		out, err := cmd.Output()
		if err != nil {
			return nil
		}
		return out
	}
	if docker, err := exec.LookPath("docker"); err == nil {
		out := output(docker, "ps", "-a", "--filter", "label=kiwi.run", "--format", "{{.ID}} {{.CreatedAt}}")
		for _, id := range parseDockerContainers(out, cutoff) {
			if _, err := boundedToolCommand(ctx, gcCleanupTimeout, docker, "rm", "-f", id); err == nil {
				rep.Containers++
			}
		}
		out = output(docker, "network", "ls", "--filter", "label=kiwi.run", "--format", "{{.ID}} {{.CreatedAt}}")
		for _, id := range parseIDCreatedAt(out, cutoff) {
			if _, err := boundedToolCommand(ctx, gcCleanupTimeout, docker, "network", "rm", id); err == nil {
				rep.Networks++
			}
		}
	}
	if tart, err := exec.LookPath("tart"); err == nil {
		out := output(tart, "list")
		for _, name := range parseTartVMs(out, cutoff) {
			if _, err := boundedToolCommand(ctx, gcCleanupTimeout, tart, "delete", name); err == nil {
				rep.VMs++
			}
		}
	}
	return rep
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
