package executor

import (
	"context"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestReservedWorkspaceMountExplained: K9 — mounting a volume at /workspace
// must fail with our reason, not a raw "Duplicate mount point" from docker.
func TestReservedWorkspaceMountExplained(t *testing.T) {
	installFakeBins(t)
	b := &ContainerBackend{
		Image:   "alpine:3.20",
		Volumes: []pipeline.Volume{{Name: "ws", Path: "/workspace"}},
	}
	err := b.StartJob(context.Background(), t.TempDir(), func(string) {})
	if err == nil {
		t.Fatal("want reserved-path refusal")
	}
	if !strings.Contains(err.Error(), "reserved for the job checkout") {
		t.Fatalf("error = %v, want reserved-path explanation", err)
	}
	if strings.Contains(err.Error(), "Duplicate mount") {
		t.Fatalf("raw docker error leaked: %v", err)
	}
}
