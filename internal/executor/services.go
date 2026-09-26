package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// serviceNetworkArgs builds the `docker network create` arguments for the
// job's services network. A plain user-defined bridge HAS a route to the
// outside world by default; the --internal flag removes that route, which is
// what preserves the isolation guarantee when untrusted jobs declare
// services. Extracted as a pure function so it can be unit tested without a
// docker daemon.
func serviceNetworkArgs(isolated bool) []string {
	args := []string{"create", "--driver", "bridge"}
	if isolated {
		args = append(args, "--internal")
	}
	return args
}

// serviceWorkloadUser is the identity every service container runs as: the
// unprivileged "nobody" user. Services never bind-mount the runner checkout,
// so the rootless/rootful workspace mapping (planHardenedContainer) does not
// apply to them; the read-only rootfs, capability drop, no-new-privileges and
// tmpfs keep them restricted on either daemon kind.
const serviceWorkloadUser = "65534:65534"

// boundedNormalizedName renders raw as a deterministic physical docker/VM
// name bounded by limit. The full identity is normalized first
// (dockerNameClean -> "-", then lowercased) and returned unchanged when it
// fits. When it does not fit, the result is a (limit-17)-character prefix of
// the normalized name, a "-", and the first 8 bytes of the SHA-256 of the
// FULL normalized identity as 16 hex characters, sized so the result is
// exactly <= limit. The hash ALWAYS covers the entire identity, never the
// truncated prefix, so two identities that share a long prefix but differ
// later still get distinct physical names. This is the single canonicalizer
// behind every generated docker name in the executor (service containers,
// the services network, the job container).
func boundedNormalizedName(raw string, limit int) string {
	full := strings.ToLower(dockerNameClean.ReplaceAllString(raw, "-"))
	if len(full) <= limit {
		return full
	}
	sum := sha256.Sum256([]byte(full))
	suffix := hex.EncodeToString(sum[:8])
	if limit <= len(suffix) {
		return suffix[:limit]
	}
	return full[:limit-len(suffix)-1] + "-" + suffix
}

// maxServiceContainerNameLen bounds the physical docker container name so a
// pathological run/job ID cannot exceed docker's 255-character name limit.
// The trailing 16-hex SHA-256 prefix of the full untruncated name keeps
// distinct jobs distinct even when their sanitized IDs share a long prefix.
const maxServiceContainerNameLen = 200

// serviceContainerName derives the globally unique physical docker container
// name for one declared service: kiwi-svc-<run>-<job>-<index>. The name is
// ALWAYS physical, never the user-facing alias, because docker container names
// are global to the daemon: two concurrent jobs on one runner may both declare
// a service aliased "postgres", and each must get its own container. The
// user-facing alias is attached separately with --network-alias (see
// serviceAlias), scoped to the job's own network, where uniqueness is
// guaranteed by pipeline validation. Over-long identities are bounded by
// boundedNormalizedName, which hashes the full identity, so two sanitized
// names sharing a long prefix can never collapse onto one container.
func serviceContainerName(runID, jobID string, index int) string {
	return boundedNormalizedName(fmt.Sprintf("kiwi-svc-%s-%s-%d", runID, jobID, index+1), maxServiceContainerNameLen)
}

// maxServiceNetworkNameLen bounds the job's physical docker network name.
// Docker accepts longer names, but the generated name must stay injective
// under bounding: the previous `network[:60]` truncation mapped two distinct
// run/job identities sharing their first 60 normalized characters onto ONE
// physical network, so stale state from one job could be addressed (and
// removed) by another. 60 is the historical physical name budget.
const maxServiceNetworkNameLen = 60

// serviceNetworkName derives the physical docker network name for one job:
// kiwi-net-<run>-<job>, normalized and bounded by boundedNormalizedName. When
// the full normalized identity exceeds 60 characters the name becomes
// full[:60-17] + "-" + the first 16 hex characters of the SHA-256 of the FULL
// identity, so distinct jobs always own distinct networks (isolation and
// cleanup stay injective) and short identities keep their historical name.
func serviceNetworkName(runID, jobID string) string {
	return boundedNormalizedName(fmt.Sprintf("kiwi-net-%s-%s", runID, jobID), maxServiceNetworkNameLen)
}

// serviceAlias derives the user-facing network alias for one service: the
// canonical form of the declared name (lowercased, docker-name-sanitized), or
// "" when the service declares none (or the name sanitizes to nothing). The
// alias is attached with `--network-alias` on the job's dedicated network, so
// the job can reach `postgres` exactly as before while the physical container
// name stays globally unique. Validation uses the SAME canonicalization
// (pipeline.CanonicalServiceAlias) to reject two declarations that would
// collide at runtime.
func serviceAlias(svc pipeline.Service) string {
	if svc.Name == "" {
		return ""
	}
	return pipeline.CanonicalServiceAlias(svc.Name)
}

// serviceDisplayName is the name used in user-facing messages and errors: the
// declared alias when there is one, the physical container name otherwise.
func serviceDisplayName(runID, jobID string, index int, svc pipeline.Service) string {
	if alias := serviceAlias(svc); alias != "" {
		return alias
	}
	return serviceContainerName(runID, jobID, index)
}

// Per-service resource defaults: the limits one service container gets when
// the job's aggregate envelope still has room for them. These are ceilings,
// not grants: a service may only consume its fair share of what is left of
// the job's resources.
const (
	serviceDefaultCPUs   = 2.0
	serviceDefaultMemory = int64(2) << 30
	serviceDefaultPIDs   = 256
)

// Aggregate service-envelope fallbacks, used only when the job declares no
// value for the resource in question. They equal one full per-service default
// (cpu, memory) or two (pids), so a single-service job behaves exactly as
// before while a multi-service job can never multiply the defaults.
const (
	serviceAggregateDefaultCPUs   = 2.0
	serviceAggregateDefaultMemory = int64(2) << 30
	serviceAggregateDefaultPIDs   = 2 * serviceDefaultPIDs
)

// serviceResourceBudget is the aggregate resource envelope all service
// containers of one job share. It is derived from the job's declared
// resources, falling back to the documented defaults above when a resource is
// undeclared:
//
//	total service CPU    <= job resources.cpu    (default: 2)
//	total service memory <= job resources.memory (default: 2 GiB)
//	total service PIDs   <= job resources.pids   (default: 512)
//
// The services are then allocated with a fair split: each of the N services
// gets min(per-service default, remaining / services-not-yet-allocated), so
// the FIRST service can no longer consume the whole envelope and leave the
// remaining ones starved (the E3-B defect: with the untrusted defaults, one
// service used to take min(remaining, 2 CPU / 256 PIDs) and exhaust the
// budget although admission permits up to
// pipeline.MaxUntrustedServicesPerJob = 8 services). The aggregate stays
// <= the envelope by construction, and only a genuinely oversubscribed
// envelope (a share rounding to zero) fails closed with a clear
// "budget exhausted" error.
//
// Kernel-level placement (docker --cgroup-parent onto a job-scoped cgroup
// that contains the main container too) is the stronger mechanism and is
// applied whenever the host supports it (see jobcgroup.go): it bounds the
// main container plus every service by the declared envelope at the kernel,
// which per-container docker flags cannot do. This budget remains in force
// either way, and when no parent cgroup can be established it is the only
// aggregate bound, which is why ServiceEnvelopeRequest exposes the aggregate
// for the scheduler reservation follow-up.
type serviceResourceBudget struct {
	CPU    float64
	Memory int64
	PIDs   int
	// remaining is the number of services still to be allocated. The fair
	// split divides the remaining budget by it.
	remaining int
}

// serviceAllocation is the per-service slice of the budget.
type serviceAllocation struct {
	CPU    float64
	Memory int64
	PIDs   int
}

// serviceBudgetFor derives the aggregate service envelope from a job's
// declared resources (see serviceResourceBudget for the formula) for a plan
// of count services.
func serviceBudgetFor(jobResources pipeline.Resources, count int) serviceResourceBudget {
	b := serviceResourceBudget{
		CPU:       jobResources.CPU,
		Memory:    int64(jobResources.Memory),
		PIDs:      jobResources.PIDs,
		remaining: count,
	}
	if b.CPU <= 0 {
		b.CPU = serviceAggregateDefaultCPUs
	}
	if b.Memory <= 0 {
		b.Memory = serviceAggregateDefaultMemory
	}
	if b.PIDs <= 0 {
		b.PIDs = serviceAggregateDefaultPIDs
	}
	return b
}

// allocate reserves the next service's slice of the budget with the
// documented fair split: min(per-service default, remaining / remaining
// services). Memory and PIDs use integer division, so the last service
// absorbs the floor remainder; CPU divides exactly. A share that rounds to
// zero means the envelope is genuinely too small for the declared service
// count (for example 2 PIDs across 3 services); that fails closed with a
// clear error naming the exhausted resource instead of degrading to an
// unlimited docker flag (which is what a zero value would mean to docker).
func (b *serviceResourceBudget) allocate() (serviceAllocation, error) {
	if b.remaining <= 0 {
		return serviceAllocation{}, fmt.Errorf("service resource budget plan exhausted (no services left to allocate)")
	}
	if b.CPU <= 0 || b.Memory <= 0 || b.PIDs <= 0 {
		return serviceAllocation{}, b.exhaustedError()
	}
	a := serviceAllocation{
		CPU:    min(b.CPU/float64(b.remaining), serviceDefaultCPUs),
		Memory: min(b.Memory/int64(b.remaining), serviceDefaultMemory),
		PIDs:   min(b.PIDs/b.remaining, serviceDefaultPIDs),
	}
	if a.CPU <= 0 || a.Memory <= 0 || a.PIDs <= 0 {
		return serviceAllocation{}, b.exhaustedError()
	}
	b.CPU -= a.CPU
	b.Memory -= a.Memory
	b.PIDs -= a.PIDs
	if b.CPU < 0 {
		b.CPU = 0
	}
	b.remaining--
	return a, nil
}

// exhaustedError renders the fail-closed oversubscription error. It names the
// remaining envelope and the fair-split rule so the job author can either
// declare more resources or declare fewer services.
func (b *serviceResourceBudget) exhaustedError() error {
	return fmt.Errorf("service resource budget exhausted (remaining cpu=%s memory=%d pids=%d across %d remaining services); services share the job's resource envelope, declare resources.cpu/memory/pids or fewer services", strconv.FormatFloat(b.CPU, 'f', -1, 64), b.Memory, b.PIDs, max(b.remaining, 0))
}

// serviceAllocationPlan returns the fair-split allocation for every declared
// service, or the exhaustion error when the envelope cannot host the declared
// count. It is the single planner behind both the executor's start path and
// ServiceEnvelopeRequest, so the reported aggregate and the started limits can
// never disagree.
func serviceAllocationPlan(jobResources pipeline.Resources, services []pipeline.Service) ([]serviceAllocation, error) {
	b := serviceBudgetFor(jobResources, len(services))
	out := make([]serviceAllocation, 0, len(services))
	for range services {
		a, err := b.allocate()
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// RuntimeRunsServices reports whether the executor starts a compiled job's
// declared service containers for the given runtime. Services are
// container-only: the service network, the job-scoped cgroup parent and every
// service container are created solely on the container path (runJob), so a
// native or tart job's declared services never run. The control plane's
// enqueue stamping calls this SAME predicate, so it never reserves the
// aggregate service envelope (model.Job.ServiceEnvelopeRequest) for
// containers that will not be started: an envelope charged for an inert
// service set can make a job permanently un-leasable on a runner whose
// capacity the aggregate alone exceeds.
func RuntimeRunsServices(runtime string) bool {
	return runtime == "container"
}

// ServiceEnvelopeRequest returns the aggregate service resources the
// fair-split plan allocates for a job's declared services. When a job-scoped
// parent cgroup can be established this aggregate is already inside the job's
// declared envelope at the kernel; when it cannot, the services are bounded
// only by per-container docker flags, so the scheduler reservation must
// include this aggregate IN ADDITION to the job's declared envelope to keep
// host usage bounded across replicas. The control plane computes this
// aggregate at enqueue with this same function and persists it as
// model.Job.ServiceEnvelopeRequest; the scheduler charges it (with the job's
// own request) to the runner and the runner logs it when it runs services
// without a parent cgroup.
func ServiceEnvelopeRequest(jobResources pipeline.Resources, services []pipeline.Service) (pipeline.Resources, error) {
	plan, err := serviceAllocationPlan(jobResources, services)
	if err != nil {
		return pipeline.Resources{}, err
	}
	var out pipeline.Resources
	for _, a := range plan {
		out.CPU += a.CPU
		out.Memory += pipeline.ByteSize(a.Memory)
		out.PIDs += a.PIDs
	}
	return out, nil
}

// serviceResourceArgs renders the docker run flags for one service's
// allocation. Values are exact byte/int forms, never the zero value (see
// allocate).
func serviceResourceArgs(a serviceAllocation) []string {
	return []string{
		"--pids-limit=" + strconv.Itoa(a.PIDs),
		"--memory=" + strconv.FormatInt(a.Memory, 10),
		"--cpus=" + strconv.FormatFloat(a.CPU, 'f', -1, 64),
	}
}

// serviceEnvelopeSummary renders the fair-split aggregate service request for
// log lines (see ServiceEnvelopeRequest). An oversubscribed plan is reported
// as such instead of a misleading partial sum.
func serviceEnvelopeSummary(jobResources pipeline.Resources, services []pipeline.Service) string {
	req, err := ServiceEnvelopeRequest(jobResources, services)
	if err != nil {
		return "oversubscribed: " + err.Error()
	}
	return fmt.Sprintf("cpu=%s memory=%d pids=%d", strconv.FormatFloat(req.CPU, 'f', -1, 64), int64(req.Memory), req.PIDs)
}

// validateServiceImages pre-checks every declared service before any docker
// invocation: an image must exist and, when the job is untrusted
// (requireImmutable), carry a strict @sha256:<64-hex> digest pin. A missing
// daemon can never mask an unpinned service image.
func validateServiceImages(services []pipeline.Service, runID, jobID string, requireImmutable bool) error {
	for i, svc := range services {
		name := serviceDisplayName(runID, jobID, i, svc)
		if svc.Image == "" {
			return &RunError{Kind: ErrorInfra, Err: fmt.Errorf("service %q has no image", name)}
		}
		if requireImmutable && !digestPinned(svc.Image) {
			return unpinnedImageError("service "+name+" image", svc.Image)
		}
	}
	return nil
}

// startContainerServices creates one dedicated user-defined bridge network for
// the job, starts every declared service container on it, and waits for their
// healthchecks. The job container itself is attached to this same network, so
// services resolve by name. When isolated is true the network is created with
// --internal, giving the job and its services no route to the outside world.
// requireImmutable rejects any service image without a strict digest pin
// before docker is ever invoked. cgroupParent, when non-empty, is the job's
// scoped parent cgroup (see jobcgroup.go): every service is placed in it with
// --cgroup-parent so the main container and the services together can never
// exceed the job's declared envelope at the kernel.
//
// Every service container gets a globally unique physical name
// (serviceContainerName) for docker run/exec/rm, and its declared alias is
// attached with --network-alias on this job's network only. Two concurrent
// jobs declaring the same alias therefore never collide on the daemon, while
// the job still reaches `postgres` by alias. Per-service resource limits use
// the documented fair split of the job's envelope (allocating the remaining
// budget across the remaining services); a job whose service declarations
// genuinely cannot fit its own resource envelope fails closed.
func startContainerServices(ctx context.Context, runID, jobID string, services []pipeline.Service, jobResources pipeline.Resources, isolated, requireImmutable bool, cgroupParent string, emit func(string)) (string, func(), error) {
	if err := validateServiceImages(services, runID, jobID, requireImmutable); err != nil {
		return "", func() {}, err
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		return "", func() {}, &RunError{Kind: ErrorInfra, Err: fmt.Errorf("docker not found: %w", err)}
	}
	network := serviceNetworkName(runID, jobID)
	createArgs := append(serviceNetworkArgs(isolated), "--label", "kiwi.run="+runID, network)
	if out, err := exec.CommandContext(ctx, docker, append([]string{"network"}, createArgs...)...).CombinedOutput(); err != nil {
		return "", func() {}, &RunError{Kind: ErrorInfra, Err: fmt.Errorf("create services network: %v: %s", err, strings.TrimSpace(string(out)))}
	}
	containers := make([]string, 0, len(services))
	cleanup := func() {
		for _, name := range containers {
			if err := dockerCleanupCommand(ctx, docker, "rm", "-f", name); err != nil {
				emit("cleanup required: " + err.Error())
			}
		}
		if err := dockerCleanupCommand(ctx, docker, "network", "rm", network); err != nil {
			emit("cleanup required: " + err.Error())
		}
	}
	cleanupAll := func() { cleanup() }
	plan, planErr := serviceAllocationPlan(jobResources, services)
	if planErr != nil {
		cleanupAll()
		return "", func() {}, &RunError{Kind: ErrorPolicy, Err: planErr}
	}
	for i, svc := range services {
		name := serviceContainerName(runID, jobID, i)
		display := serviceDisplayName(runID, jobID, i, svc)
		alloc := plan[i]
		// Every service runs maximally hardened. The user is hard-coded to
		// 65534:65534 (nobody) rather than omitted: images known to require
		// root are not a reason to weaken isolation for the rest. Services
		// and the job container share one network only; the workspace
		// ownership mapping never applies here.
		args := []string{"run", "-d", "--rm", "--network=" + network, "--name", name,
			"--cap-drop=ALL", "--security-opt=no-new-privileges", "--read-only",
			"--tmpfs", "/tmp:rw,nosuid,nodev",
			"--user=" + serviceWorkloadUser,
		}
		if cgroupParent != "" {
			args = append(args, "--cgroup-parent="+cgroupParent)
		}
		args = append(args, serviceResourceArgs(alloc)...)
		if alias := serviceAlias(svc); alias != "" {
			args = append(args, "--network-alias", alias)
		}
		args = append(args, containerLabels(runID, jobID)...)
		for k, v := range svc.Env {
			args = append(args, "-e", k+"="+v)
		}
		// "--" terminates docker's flag parsing before the image reference,
		// so a flag-shaped reference can never be injected as an option.
		args = append(args, "--", svc.Image)
		if out, err := exec.CommandContext(ctx, docker, args...).CombinedOutput(); err != nil {
			cleanupAll()
			return "", func() {}, &RunError{Kind: ErrorInfra, Err: fmt.Errorf("start service %q: %v: %s", display, err, strings.TrimSpace(string(out)))}
		}
		containers = append(containers, name)
		emit("service " + display + " started (" + svc.Image + ")")
	}
	for i, svc := range services {
		if strings.TrimSpace(svc.Healthcheck) == "" {
			continue
		}
		interval := svc.Interval.Duration
		if interval <= 0 {
			interval = 5 * time.Second
		}
		timeout := svc.Timeout.Duration
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		retries := svc.Retries
		if retries <= 0 {
			retries = 12
		}
		// Healthchecks always target the physical name: it is the container
		// the daemon knows, the alias is network-scoped (DNS) only.
		name := containers[i]
		display := serviceDisplayName(runID, jobID, i, svc)
		for attempt := 0; attempt <= retries; attempt++ {
			hcCtx, cancel := context.WithTimeout(ctx, timeout)
			hcArgs := append([]string{"exec", name}, shellCommand("sh", svc.Healthcheck)...)
			out, hcErr := exec.CommandContext(hcCtx, docker, hcArgs...).CombinedOutput()
			cancel()
			if hcErr == nil {
				emit("service " + display + " healthy")
				break
			}
			if attempt == retries {
				cleanupAll()
				return "", func() {}, &RunError{Kind: ErrorInfra, Err: fmt.Errorf("service %q healthcheck failed: %v: %s", display, hcErr, strings.TrimSpace(string(out)))}
			}
			select {
			case <-ctx.Done():
				cleanupAll()
				return "", func() {}, &RunError{Kind: ErrorCancelled, Err: ctx.Err()}
			case <-time.After(interval):
			}
		}
	}
	return network, cleanup, nil
}
