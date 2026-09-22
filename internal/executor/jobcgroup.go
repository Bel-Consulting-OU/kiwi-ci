package executor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Job-scoped resource cgroup (E3-A).
//
// The scheduler reserves a job's declared resources ONCE, but before this
// mechanism existed the main container and the aggregated service containers
// were each capped separately against that same envelope, so a 2 CPU /
// 4 GiB / 256 PID reservation could consume up to twice those values on the
// host. The fix is one job-scoped parent cgroup that contains the main
// container and every service container; the declared resources are applied
// to the PARENT, and docker is pointed at it with --cgroup-parent, so the
// kernel enforces the sum regardless of the per-container flags. Service
// children may be narrower (the fair-split service budget) but never widen
// the parent.
//
// The platform entry point is setupJobCgroup (jobcgroup_linux.go). It
// reports a hard reason whenever the parent cgroup cannot be established
// (non-Linux host, cgroup v1, no delegated cgroup-v2 subtree, a docker
// daemon whose systemd cgroup driver rejects raw cgroup paths, ...) so the
// executor can log it and fall back to per-container caps plus the aggregate
// service budget. That fallback is weaker by construction: the main
// container's own cap and the services' aggregate can still add up to two
// envelopes unless the scheduler reserves the service aggregate separately
// (see ServiceEnvelopeRequest).
const (
	jobCgroupNamePrefix = "kiwi-job-"
	// jobCgroupRemoveAttempts/jobCgroupRemoveDelay bound the removal retry:
	// the docker daemon may release a container's child cgroup a moment
	// after the container is gone, so an EBUSY/ENOTEMPTY rmdir is retried a
	// few times before the failure is reported.
	jobCgroupRemoveAttempts = 3
	jobCgroupRemoveDelay    = 100 * time.Millisecond
)

// jobCgroupRequest is the declared job envelope applied to the parent
// cgroup. A zero dimension means "not declared": no cgroup limit is written
// for it, matching a scheduler that reserved nothing on that axis.
type jobCgroupRequest struct {
	JobID  string
	CPU    float64
	Memory int64
	PIDs   int
}

// declared reports whether the job declared at least one enforceable axis.
func (r jobCgroupRequest) declared() bool {
	return r.CPU > 0 || r.Memory > 0 || r.PIDs > 0
}

// JobCgroupStatus is the outcome of one job-scoped parent cgroup attempt.
// Enabled is true only when the cgroup exists and carries the declared
// limits; Parent is then the docker --cgroup-parent value. Detail always
// explains the outcome, including the exact reason when Enabled is false.
type JobCgroupStatus struct {
	Enabled bool
	Parent  string
	Detail  string
}

// jobCgroupSetup is the platform implementation, a package variable so tests
// can substitute a deterministic outcome (mirroring workspaceDiskQuotaSetup).
var jobCgroupSetup func(context.Context, jobCgroupRequest) (JobCgroupStatus, func() error) = setupJobCgroup

// cgroupLimit is one cgroup-v2 control file and the value written to it.
type cgroupLimit struct {
	File  string
	Value string
	// Optional limits (memory.swap.max) are written best-effort: a kernel
	// without the file must not fail the whole job cgroup.
	Optional bool
}

// jobCgroupLimits renders the declared envelope into cgroup v2 limit files:
//
//	resources.cpu    -> cpu.max        ("<quota> 100000", quota in µs)
//	resources.memory -> memory.max     (bytes) and memory.swap.max=0 so the
//	                                   job cannot exceed memory.max via swap
//	resources.pids   -> pids.max       (tasks)
//
// Undeclared axes produce no limit file, never a zero value (0 in pids.max
// and memory.max means "no limit" to the kernel, which would silently
// advertise an unenforced bound).
func jobCgroupLimits(req jobCgroupRequest) []cgroupLimit {
	var out []cgroupLimit
	if req.CPU > 0 {
		quota := int64(req.CPU*100000 + 0.5) // cpu.max's period is 100000µs
		if quota < 1 {
			quota = 1
		}
		out = append(out, cgroupLimit{File: "cpu.max", Value: fmt.Sprintf("%d 100000", quota)})
	}
	if req.Memory > 0 {
		out = append(out, cgroupLimit{File: "memory.max", Value: strconv.FormatInt(req.Memory, 10)})
		out = append(out, cgroupLimit{File: "memory.swap.max", Value: "0", Optional: true})
	}
	if req.PIDs > 0 {
		out = append(out, cgroupLimit{File: "pids.max", Value: strconv.Itoa(req.PIDs)})
	}
	return out
}

// jobCgroupControllers names the controllers the parent cgroup needs for a
// request, in a stable order.
func jobCgroupControllers(req jobCgroupRequest) []string {
	var out []string
	if req.CPU > 0 {
		out = append(out, "cpu")
	}
	if req.Memory > 0 {
		out = append(out, "memory")
	}
	if req.PIDs > 0 {
		out = append(out, "pids")
	}
	return out
}

// jobCgroupEnvelopeSummary renders the declared axes of a request for the
// operator-visible outcome line.
func jobCgroupEnvelopeSummary(req jobCgroupRequest) string {
	var parts []string
	if req.CPU > 0 {
		parts = append(parts, "cpu="+strconv.FormatFloat(req.CPU, 'f', -1, 64))
	}
	if req.Memory > 0 {
		parts = append(parts, "memory="+strconv.FormatInt(req.Memory, 10))
	}
	if req.PIDs > 0 {
		parts = append(parts, "pids="+strconv.Itoa(req.PIDs))
	}
	return strings.Join(parts, " ")
}

// materializeCgroupControls is called right after the job cgroup directory is
// created. A real cgroupfs materializes the controller files (cpu.max,
// memory.max, ...) as soon as the directory exists, so production leaves this
// a no-op; the portable core tests substitute a function that pre-creates the
// control files in a plain temporary directory.
var materializeCgroupControls = func(string) error { return nil }

// createJobCgroupUnder creates the job cgroup directory under base (which the
// caller must have verified is a delegated cgroup directory), enables the
// required controllers for the container child cgroups docker creates
// underneath, writes the limit files, and returns the directory plus a
// cleanup that removes it and any per-container child cgroups docker left
// behind. The cleanup is idempotent and never panics; a failed write removes
// the just-created directory before returning.
//
// Enabling the controllers in the job cgroup's own cgroup.subtree_control is
// what makes docker's per-container cgroups (created below the parent) carry
// cpu/memory/pids control files; the cgroup-v2 rule only forbids enabling a
// controller on a cgroup that has processes of its own, and the just-created
// job cgroup is empty.
func createJobCgroupUnder(base, name string, controllers []string, limits []cgroupLimit) (string, func() error, error) {
	dir := filepath.Join(base, name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		return "", nil, fmt.Errorf("create job cgroup %s: %w", dir, err)
	}
	if err := materializeCgroupControls(dir); err != nil {
		_ = removeJobCgroupDir(dir)
		return "", nil, fmt.Errorf("materialize job cgroup %s: %w", dir, err)
	}
	if len(controllers) > 0 {
		value := "+" + strings.Join(controllers, " +")
		if err := writeCgroupFile(filepath.Join(dir, "cgroup.subtree_control"), value); err != nil {
			_ = removeJobCgroupDir(dir)
			return "", nil, fmt.Errorf("enable controllers %s on job cgroup %s: %w", value, dir, err)
		}
	}
	for _, l := range limits {
		if err := writeCgroupFile(filepath.Join(dir, l.File), l.Value); err != nil {
			if l.Optional {
				continue
			}
			_ = removeJobCgroupDir(dir)
			return "", nil, fmt.Errorf("write %s=%s on job cgroup %s: %w", l.File, l.Value, dir, err)
		}
	}
	cleanup := func() error {
		var err error
		for attempt := 0; attempt < jobCgroupRemoveAttempts; attempt++ {
			if err = removeJobCgroupDir(dir); err == nil {
				return nil
			}
			time.Sleep(jobCgroupRemoveDelay)
		}
		return err
	}
	return dir, cleanup, nil
}

// writeCgroupFile writes one cgroup control value with a plain O_WRONLY open:
// cgroupfs pseudo-files are not regular files, so O_CREATE/O_TRUNC semantics
// do not apply and a single small write is what the kernel expects.
func writeCgroupFile(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(value)
	cerr := f.Close()
	return errors.Join(werr, cerr)
}

// removeJobCgroupDir removes the job cgroup directory, first removing the
// immediate child cgroups docker created for the job's containers. Only
// children of the job's own directory are touched. Kernel-owned control files
// (cpu.max, ...) cannot be unlinked on a real cgroupfs; those unlink attempts
// are expected to fail and are ignored — the final directory removal is the
// real check, and it also succeeds on a plain directory whose control files
// were regular files.
func removeJobCgroupDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var errs []error
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if !e.IsDir() {
			_ = os.Remove(path)
			continue
		}
		if rerr := os.Remove(path); rerr != nil {
			errs = append(errs, fmt.Errorf("remove child cgroup %s: %w", path, rerr))
		}
	}
	if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("remove job cgroup %s: %w", dir, err))
	}
	return errors.Join(errs...)
}

// readCgroupControllerList parses a cgroup.controllers or
// cgroup.subtree_control file into a set. subtree_control entries carry a
// "+"/"-" prefix that is stripped here.
func readCgroupControllerList(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, f := range strings.Fields(string(data)) {
		name := strings.TrimLeft(f, "+-")
		if name != "" {
			out[name] = true
		}
	}
	return out, nil
}

// ensureDelegatedCgroupBase reports whether dir is an existing directory that
// already delegates every required controller to its children (the cgroup-v2
// "no internal processes" rule means the runner cannot enable a controller on
// a directory its own process occupies, so the base must already carry the
// delegation, as systemd's Delegate=yes does).
func ensureDelegatedCgroupBase(dir string, need []string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if len(need) == 0 {
		return nil
	}
	have, err := readCgroupControllerList(filepath.Join(dir, "cgroup.subtree_control"))
	if err != nil {
		return err
	}
	var missing []string
	for _, c := range need {
		if !have[c] {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s does not delegate cgroup controller(s) %s (cgroup.subtree_control is empty or missing them); a runner outside a delegated cgroup-v2 subtree cannot create a job cgroup", dir, strings.Join(missing, ","))
	}
	return nil
}

// jobCgroupDirName derives the job cgroup directory name. The suffix is
// deliberately unique per attempt: the job cgroup must never collide with a
// sibling job's directory, and the job/run IDs are attacker-influenced.
func jobCgroupDirName(jobID, suffix string) string {
	clean := dockerNameClean.ReplaceAllString(jobID, "-")
	if len(clean) > 80 {
		clean = clean[:80]
	}
	return jobCgroupNamePrefix + clean + "-" + suffix
}

// jobCgroupSuffix returns a random 16-hex-character suffix for the job cgroup
// directory, so two jobs with the same ID (or a hostile ID crafted to collide)
// can never share one parent cgroup.
var jobCgroupSuffix = func() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
