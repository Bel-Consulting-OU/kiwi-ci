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
// guaranteed by pipeline validation.
func serviceContainerName(runID, jobID string, index int) string {
	name := strings.ToLower(dockerNameClean.ReplaceAllString(fmt.Sprintf("kiwi-svc-%s-%s-%d", runID, jobID, index+1), "-"))
	if len(name) > maxServiceContainerNameLen {
		sum := sha256.Sum256([]byte(name))
		name = name[:maxServiceContainerNameLen-len(hex.EncodeToString(sum[:8]))-1] + "-" + hex.EncodeToString(sum[:8])
	}
	return name
}

// serviceAlias derives the user-facing network alias for one service: the
// sanitized, lowercased declared name, or "" when the service declares none
// (or the name sanitizes to nothing). The alias is attached with
// `--network-alias` on the job's dedicated network, so the job can reach
// `postgres` exactly as before while the physical container name stays
// globally unique.
func serviceAlias(svc pipeline.Service) string {
	if svc.Name == "" {
		return ""
	}
	return strings.ToLower(dockerNameClean.ReplaceAllString(svc.Name, "-"))
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
// not grants: a service may only consume what is left of the job's resources.
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
// Each service then gets min(per-service default, remaining budget), so the
// services are throttled to the job's envelope and a budget that is fully
// consumed fails the job instead of starting another unbounded service.
// cgroup-level placement (docker --cgroup-parent with a job-scoped cgroup)
// would enforce the same envelope at the kernel level, but it requires a
// delegated cgroup-v2 hierarchy on the daemon (systemd user delegation for
// rootless setups) that the runner cannot assume; the aggregate budget is the
// portable mechanism and is applied on every platform.
type serviceResourceBudget struct {
	CPU    float64
	Memory int64
	PIDs   int
}

// serviceAllocation is the per-service slice of the budget.
type serviceAllocation struct {
	CPU    float64
	Memory int64
	PIDs   int
}

// serviceBudgetFor derives the aggregate service envelope from a job's
// declared resources (see serviceResourceBudget for the formula).
func serviceBudgetFor(jobResources pipeline.Resources) serviceResourceBudget {
	b := serviceResourceBudget{
		CPU:    jobResources.CPU,
		Memory: int64(jobResources.Memory),
		PIDs:   jobResources.PIDs,
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

// allocate reserves the next service's slice of the budget: the per-service
// default capped by what remains. A fully consumed resource fails closed with
// a clear error naming the exhausted resource; it never degrades to an
// unlimited docker flag (which is what a zero value would mean to docker).
func (b *serviceResourceBudget) allocate() (serviceAllocation, error) {
	if b.CPU <= 0 || b.Memory <= 0 || b.PIDs <= 0 {
		return serviceAllocation{}, fmt.Errorf("service resource budget exhausted (remaining cpu=%s memory=%d pids=%d); services share the job's resource envelope, declare resources.cpu/memory/pids or fewer services", strconv.FormatFloat(b.CPU, 'f', -1, 64), b.Memory, b.PIDs)
	}
	a := serviceAllocation{
		CPU:    min(b.CPU, serviceDefaultCPUs),
		Memory: min(b.Memory, serviceDefaultMemory),
		PIDs:   min(b.PIDs, serviceDefaultPIDs),
	}
	b.CPU -= a.CPU
	b.Memory -= a.Memory
	b.PIDs -= a.PIDs
	return a, nil
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
// before docker is ever invoked.
//
// Every service container gets a globally unique physical name
// (serviceContainerName) for docker run/exec/rm, and its declared alias is
// attached with --network-alias on this job's network only. Two concurrent
// jobs declaring the same alias therefore never collide on the daemon, while
// the job still reaches `postgres` by alias. Per-service resource limits are
// min(per-service default, remaining job envelope); a job whose service
// declarations exceed its own resource envelope fails closed.
func startContainerServices(ctx context.Context, runID, jobID string, services []pipeline.Service, jobResources pipeline.Resources, isolated, requireImmutable bool, emit func(string)) (string, func(), error) {
	if err := validateServiceImages(services, runID, jobID, requireImmutable); err != nil {
		return "", func() {}, err
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		return "", func() {}, &RunError{Kind: ErrorInfra, Err: fmt.Errorf("docker not found: %w", err)}
	}
	base := dockerNameClean.ReplaceAllString(fmt.Sprintf("kiwi-net-%s-%s", runID, jobID), "-")
	network := strings.ToLower(base)
	if len(network) > 60 {
		network = network[:60]
	}
	createArgs := append(serviceNetworkArgs(isolated), "--label", "kiwi.run="+runID, network)
	if out, err := exec.CommandContext(ctx, docker, append([]string{"network"}, createArgs...)...).CombinedOutput(); err != nil {
		return "", func() {}, &RunError{Kind: ErrorInfra, Err: fmt.Errorf("create services network: %v: %s", err, strings.TrimSpace(string(out)))}
	}
	containers := make([]string, 0, len(services))
	cleanup := func() {
		for _, name := range containers {
			_ = exec.Command(docker, "rm", "-f", name).Run()
		}
		_ = exec.Command(docker, "network", "rm", network).Run()
	}
	cleanupAll := func() { cleanup() }
	budget := serviceBudgetFor(jobResources)
	for i, svc := range services {
		name := serviceContainerName(runID, jobID, i)
		display := serviceDisplayName(runID, jobID, i, svc)
		alloc, aerr := budget.allocate()
		if aerr != nil {
			cleanupAll()
			return "", func() {}, &RunError{Kind: ErrorPolicy, Err: fmt.Errorf("service %q: %w", display, aerr)}
		}
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
		args = append(args, serviceResourceArgs(alloc)...)
		if alias := serviceAlias(svc); alias != "" {
			args = append(args, "--network-alias", alias)
		}
		args = append(args, containerLabels(runID, jobID)...)
		for k, v := range svc.Env {
			args = append(args, "-e", k+"="+v)
		}
		args = append(args, svc.Image)
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
