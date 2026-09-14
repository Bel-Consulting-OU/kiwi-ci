package executor

import (
	"context"
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

// GC removes stale runtime resources older than olderThan: docker
// containers and networks labeled kiwi.run and Tart VM clones named
// kiwi-<unix-nano>. root is the runner root used as the working directory
// for the cleanup subprocesses. If docker or tart is not installed the
// corresponding pass is skipped and the report stays at zero for it.
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
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir = root
		out, err := cmd.Output()
		if err != nil {
			return nil
		}
		return out
	}
	if docker, err := exec.LookPath("docker"); err == nil {
		out := output(docker, "ps", "-a", "--filter", "label=kiwi.run", "--format", "{{.ID}} {{.CreatedAt}}")
		for _, id := range parseDockerContainers(out, cutoff) {
			if exec.CommandContext(ctx, docker, "rm", "-f", id).Run() == nil {
				rep.Containers++
			}
		}
		out = output(docker, "network", "ls", "--filter", "label=kiwi.run", "--format", "{{.ID}} {{.CreatedAt}}")
		for _, id := range parseIDCreatedAt(out, cutoff) {
			if exec.CommandContext(ctx, docker, "network", "rm", id).Run() == nil {
				rep.Networks++
			}
		}
	}
	if tart, err := exec.LookPath("tart"); err == nil {
		out := output(tart, "list")
		for _, name := range parseTartVMs(out, cutoff) {
			if exec.CommandContext(ctx, tart, "delete", name).Run() == nil {
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
// output of `tart list`. Clones are named kiwi-<unix-nano>; the embedded
// timestamp decides staleness, so a VM not created by the executor (or one
// with an unparsable suffix) is never returned for deletion.
func parseTartVMs(out []byte, cutoff time.Time) []string {
	var stale []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if !strings.HasPrefix(name, "kiwi-") {
			continue
		}
		nanos, err := strconv.ParseInt(strings.TrimPrefix(name, "kiwi-"), 10, 64)
		if err != nil {
			continue
		}
		if time.Unix(0, nanos).Before(cutoff) {
			stale = append(stale, name)
		}
	}
	return stale
}
