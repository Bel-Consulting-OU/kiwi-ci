package executor

import (
	"context"
	"fmt"
	"os/exec"
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

// startContainerServices creates one dedicated user-defined bridge network for
// the job, starts every declared service container on it, and waits for their
// healthchecks. The job container itself is attached to this same network, so
// services resolve by name. When isolated is true the network is created with
// --internal, giving the job and its services no route to the outside world.
func startContainerServices(ctx context.Context, runID, jobID string, services []pipeline.Service, isolated bool, emit func(string)) (string, func(), error) {
	docker, err := exec.LookPath("docker")
	if err != nil {
		return "", func() {}, &RunError{Kind: ErrorInfra, Err: fmt.Errorf("docker not found: %w", err)}
	}
	base := dockerNameClean.ReplaceAllString(fmt.Sprintf("kiwi-net-%s-%s", runID, jobID), "-")
	network := strings.ToLower(base)
	if len(network) > 60 {
		network = network[:60]
	}
	createArgs := append(serviceNetworkArgs(isolated), network)
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
	for i, svc := range services {
		name := dockerNameClean.ReplaceAllString(fmt.Sprintf("kiwi-svc-%s-%s-%d", runID, jobID, i+1), "-")
		if svc.Name != "" {
			custom := dockerNameClean.ReplaceAllString(svc.Name, "-")
			if custom != "" {
				name = strings.ToLower(custom)
			}
		}
		if svc.Image == "" {
			cleanupAll()
			return "", func() {}, &RunError{Kind: ErrorInfra, Err: fmt.Errorf("service %q has no image", name)}
		}
		// Every service runs maximally hardened. The user is hard-coded to
		// 65534:65534 (nobody) rather than omitted: images known to require
		// root are not a reason to weaken isolation for the rest.
		args := []string{"run", "-d", "--rm", "--network=" + network, "--name", name,
			"--cap-drop=ALL", "--security-opt=no-new-privileges", "--read-only",
			"--tmpfs", "/tmp:rw,nosuid,nodev",
			"--pids-limit=256", "--memory=2g", "--cpus=2",
			"--user=65534:65534",
		}
		for k, v := range svc.Env {
			args = append(args, "-e", k+"="+v)
		}
		args = append(args, svc.Image)
		if out, err := exec.CommandContext(ctx, docker, args...).CombinedOutput(); err != nil {
			cleanupAll()
			return "", func() {}, &RunError{Kind: ErrorInfra, Err: fmt.Errorf("start service %q: %v: %s", name, err, strings.TrimSpace(string(out)))}
		}
		containers = append(containers, name)
		emit("service " + name + " started (" + svc.Image + ")")
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
		name := containers[i]
		healthy := false
		for attempt := 0; attempt <= retries; attempt++ {
			hcCtx, cancel := context.WithTimeout(ctx, timeout)
			hcArgs := append([]string{"exec", name}, shellCommand("sh", svc.Healthcheck)...)
			out, hcErr := exec.CommandContext(hcCtx, docker, hcArgs...).CombinedOutput()
			cancel()
			if hcErr == nil {
				healthy = true
				emit("service " + name + " healthy")
				break
			}
			if attempt == retries {
				cleanupAll()
				return "", func() {}, &RunError{Kind: ErrorInfra, Err: fmt.Errorf("service %q healthcheck failed: %v: %s", name, hcErr, strings.TrimSpace(string(out)))}
			}
			select {
			case <-ctx.Done():
				cleanupAll()
				return "", func() {}, &RunError{Kind: ErrorCancelled, Err: ctx.Err()}
			case <-time.After(interval):
			}
		}
		if !healthy {
			cleanupAll()
			return "", func() {}, &RunError{Kind: ErrorInfra, Err: fmt.Errorf("service %q never became healthy", name)}
		}
	}
	return network, cleanup, nil
}
