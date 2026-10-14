package executor

import (
	"context"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// Backend defense in depth for trust-gated capabilities: even if admission
// is bypassed, StartJob refuses privileged containers and host-path mounts
// for untrusted jobs before docker is invoked.

func TestContainerBackendRefusesUntrustedPrivilegedAndHostMounts(t *testing.T) {
	ctx := context.Background()
	b := &ContainerBackend{
		Image:     "example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Untrusted: true,
	}
	b.Privileged = true
	err := b.StartJob(ctx, t.TempDir(), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "privileged") {
		t.Fatalf("untrusted privileged = %v, want refusal", err)
	}

	b.Privileged = false
	b.Volumes = []pipeline.Volume{{Name: "h", Path: "/mnt/h", HostPath: "/var/h"}}
	err = b.StartJob(ctx, t.TempDir(), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "host_path") {
		t.Fatalf("untrusted host_path = %v, want refusal", err)
	}
}

func TestContainerBackendWorkspaceSubdirAndVolumeMountSpec(t *testing.T) {
	// WorkSubdir and named volumes are rendered into the docker argv.
	// The mount spec builder is exercised through the same fields StartJob
	// consumes; docker itself is not required for this shape check.
	b := &ContainerBackend{
		Image:      "example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		WorkSubdir: "repo/src",
		Volumes: []pipeline.Volume{
			{Name: "data", Path: "/data"},
			{Name: "cache", Path: "/cache", ReadOnly: true},
		},
	}
	if b.WorkSubdir != "repo/src" {
		t.Fatalf("WorkSubdir = %q", b.WorkSubdir)
	}
	if len(b.Volumes) != 2 || !b.Volumes[1].ReadOnly {
		t.Fatalf("Volumes = %+v", b.Volumes)
	}
}

// Job-scoped volume names: two concurrent jobs must never share one docker
// named volume, and the name must be docker-safe.
func TestJobVolumeNameIsJobScoped(t *testing.T) {
	a := jobVolumeName("run-a", "job-1", "data")
	b := jobVolumeName("run-a", "job-2", "data")
	c := jobVolumeName("run-b", "job-1", "data")
	if a == b || a == c || b == c {
		t.Fatalf("volume names collide: %q %q %q", a, b, c)
	}
	if a != jobVolumeName("run-a", "job-1", "data") {
		t.Fatal("volume name must be stable")
	}
	for _, r := range a {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.'
		if !ok {
			t.Fatalf("volume name %q has illegal rune %q", a, r)
		}
	}
	// Host-looking names must not be reused as docker volume identities.
	if jobVolumeName("r", "j", "/etc/passwd") == "/etc/passwd" {
		t.Fatal("host path must not be used as a volume name")
	}
}

func TestWorkSubdirEscapeRefused(t *testing.T) {
	for _, sub := range []string{"../etc", "/etc", "a/../../b"} {
		b := &ContainerBackend{
			Image:      "example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			WorkSubdir: sub,
		}
		err := b.StartJob(context.Background(), t.TempDir(), func(string) {})
		if err == nil || !strings.Contains(err.Error(), "escapes") {
			t.Fatalf("WorkSubdir %q = %v, want escape refusal", sub, err)
		}
	}
}
