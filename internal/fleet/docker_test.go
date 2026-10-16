package fleet

import (
	"context"
	"strings"
	"testing"
)

// A missing docker CLI is a HARD error — never a silent no-op that would
// let Reconcile believe capacity exists.
func TestDockerProviderFailsClosedWithoutCLI(t *testing.T) {
	p := NewDockerProvider("docker", "alpine:3.20")
	// Point PATH at an empty dir so docker cannot be found.
	t.Setenv("PATH", t.TempDir())
	_, err := p.Capacity(context.Background())
	if err == nil {
		t.Fatal("missing docker CLI must fail closed")
	}
	if !strings.Contains(err.Error(), "docker") {
		t.Fatalf("error must name docker: %v", err)
	}
	if _, err := p.Provision(context.Background(), Profile{Name: "pool"}, 1); err == nil {
		t.Fatal("Provision without docker must fail closed")
	}
}

// DockerProvider satisfies the same optional extensions StaticProvider does.
func TestDockerProviderConformance(t *testing.T) {
	p := NewDockerProvider("docker", "alpine:3.20")
	var _ Provisioner = p
	var _ CountDrainer = p
	var _ HealthScanner = p
	if p.Name() != "docker" {
		t.Fatalf("name = %q", p.Name())
	}
	if _, err := p.Cost(context.Background(), "x"); err != nil {
		t.Fatalf("cost: %v", err)
	}
}
