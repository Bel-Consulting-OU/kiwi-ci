package fleet

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// DockerProvider runs fleet capacity as docker containers on one host. It
// is the second real provider: Provision starts containers, Drain stops
// them gracefully, Terminate force-removes them. The docker CLI is the
// seam (no SDK dependency); a missing docker binary is a hard error, never
// a silent no-op.
type DockerProvider struct {
	name  string
	image string

	mu    sync.Mutex
	inUse map[string]bool
}

// NewDockerProvider builds a provider that starts containers from image.
func NewDockerProvider(name, image string) *DockerProvider {
	return &DockerProvider{name: name, image: image, inUse: map[string]bool{}}
}

func (p *DockerProvider) Name() string { return p.name }

func (p *DockerProvider) docker(ctx context.Context, args ...string) (string, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "", fmt.Errorf("fleet/docker: docker CLI not available: %w", err)
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("fleet/docker: docker %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

// Capacity parses `docker ps` for containers labeled with this provider.
func (p *DockerProvider) Capacity(ctx context.Context) (map[string]Capacity, error) {
	out, err := p.docker(ctx, "ps", "-a", "--filter", "label=kiwi.fleet.provider="+p.name, "--format", "{{.Names}} {{.Status}}")
	if err != nil {
		return nil, err
	}
	c := Capacity{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		c.Max++
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		status := strings.Join(parts[1:], " ")
		switch {
		case strings.HasPrefix(status, "Up"):
			c.Ready++
		case strings.HasPrefix(status, "Created") || strings.HasPrefix(status, "Restarting"):
			c.Pending++
		case strings.HasPrefix(status, "Removing"):
			c.Draining++
		}
	}
	return map[string]Capacity{"container": c}, nil
}

// Provision starts want containers from the provider image.
func (p *DockerProvider) Provision(ctx context.Context, profile Profile, want int) ([]Instance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []Instance
	for i := 0; i < want; i++ {
		name := fmt.Sprintf("kiwi-%s-%s-%d", p.name, profile.Name, i)
		if _, err := p.docker(ctx, "run", "-d", "--name", name,
			"--label", "kiwi.fleet.provider="+p.name,
			"--label", "kiwi.fleet.profile="+profile.Name,
			p.image, "sleep", "infinity"); err != nil {
			return out, err
		}
		p.inUse[name] = true
		out = append(out, Instance{ID: name, Profile: profile.Name, State: StateReady, Labels: profile.Labels, Arch: profile.Architecture, Region: profile.Region})
	}
	return out, nil
}

// Drain stops containers gracefully (docker stop).
func (p *DockerProvider) Drain(ctx context.Context, ids []string) error {
	for _, id := range ids {
		if _, err := p.docker(ctx, "stop", id); err != nil {
			return err
		}
		p.mu.Lock()
		delete(p.inUse, id)
		p.mu.Unlock()
	}
	return nil
}

// Terminate force-removes containers.
func (p *DockerProvider) Terminate(ctx context.Context, ids []string) error {
	for _, id := range ids {
		if _, err := p.docker(ctx, "rm", "-f", id); err != nil {
			return err
		}
		p.mu.Lock()
		delete(p.inUse, id)
		p.mu.Unlock()
	}
	return nil
}

// Cost is not reported by docker; returns 0.
func (p *DockerProvider) Cost(context.Context, string) (float64, error) { return 0, nil }

// Capabilities returns the profile labels recorded at provision time.
func (p *DockerProvider) Capabilities(ctx context.Context, id string) ([]string, error) {
	out, err := p.docker(ctx, "inspect", "--format", "{{index .Config.Labels \"kiwi.fleet.profile\"}}", id)
	if err != nil {
		return nil, err
	}
	profile := strings.TrimSpace(out)
	return []string{"runtime:container", "profile:" + profile}, nil
}

// Attestation returns the container's config digest as weak identity
// evidence (a container runtime has no TPM quote).
func (p *DockerProvider) Attestation(ctx context.Context, id string) ([]byte, error) {
	out, err := p.docker(ctx, "inspect", "--format", "{{.Image}}", id)
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimSpace(out)), nil
}

var (
	_ Provisioner   = (*DockerProvider)(nil)
	_ CountDrainer  = (*DockerProvider)(nil)
	_ HealthScanner = (*DockerProvider)(nil)
)

// DrainN stops n containers of the named profile.
func (p *DockerProvider) DrainN(ctx context.Context, profile string, n int) error {
	out, err := p.docker(ctx, "ps", "--filter", "label=kiwi.fleet.provider="+p.name,
		"--filter", "label=kiwi.fleet.profile="+profile,
		"--format", "{{.Names}}")
	if err != nil {
		return err
	}
	stopped := 0
	for _, name := range strings.Fields(out) {
		if stopped >= n {
			break
		}
		if _, err := p.docker(ctx, "stop", name); err != nil {
			return err
		}
		stopped++
	}
	return nil
}

// Unhealthy reports containers that are restarting or exited.
func (p *DockerProvider) Unhealthy(ctx context.Context, profile string) ([]string, error) {
	out, err := p.docker(ctx, "ps", "-a", "--filter", "label=kiwi.fleet.provider="+p.name,
		"--filter", "label=kiwi.fleet.profile="+profile,
		"--format", "{{.Names}} {{.Status}}")
	if err != nil {
		return nil, err
	}
	var bad []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		status := strings.Join(parts[1:], " ")
		if strings.Contains(status, "Restarting") || strings.Contains(status, "Exited") {
			bad = append(bad, parts[0])
		}
	}
	return bad, nil
}
