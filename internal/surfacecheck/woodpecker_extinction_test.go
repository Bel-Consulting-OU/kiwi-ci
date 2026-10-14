package surfacecheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Woodpecker extinction readiness: .kiwi/ is the authoritative self-host
// pipeline. The gate fails when the Kiwi pipeline stops covering a lane the
// Woodpecker tree still owns, or when the Kiwi pipeline claims to mirror
// Woodpecker (the dependency must point the other way, and eventually to
// nothing).
func TestKiwiPipelineIsAuthoritativeOverWoodpecker(t *testing.T) {
	root := filepath.Join("..", "..")
	kiwiRaw, err := os.ReadFile(filepath.Join(root, ".kiwi", "pipeline.yaml"))
	if err != nil {
		t.Fatalf(".kiwi/pipeline.yaml: %v", err)
	}
	// The self-hosted pipeline must not describe itself as a mirror of
	// Woodpecker. Kiwi is canonical.
	if strings.Contains(string(kiwiRaw), "reused verbatim from the Woodpecker") ||
		strings.Contains(string(kiwiRaw), "keep them in sync with the Woodpecker") {
		t.Fatal(".kiwi/pipeline.yaml still defers to Woodpecker as canonical; invert the dependency")
	}

	// Lanes the Woodpecker tree owns today must have a Kiwi-side home.
	// Name-only check: the lane is covered when the concatenated job/step
	// text mentions it.
	var spec struct {
		Jobs map[string]any `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(kiwiRaw, &spec); err != nil {
		t.Fatalf("parse .kiwi/pipeline.yaml: %v", err)
	}
	text := string(kiwiRaw)
	requiredLanes := []string{
		"quality", "unit", "coverage", "staticcheck", "govulncheck", "release", "fuzz",
	}
	for _, lane := range requiredLanes {
		if _, ok := spec.Jobs[lane]; !ok && !strings.Contains(text, lane) {
			t.Fatalf(".kiwi/pipeline.yaml no longer covers lane %q", lane)
		}
	}

	// When .woodpecker/ is gone this test is satisfied trivially; while it
	// exists, every workflow file name must have a Kiwi-side counterpart
	// signal (the platform lanes are named in the Kiwi pipeline).
	wd := filepath.Join(root, ".woodpecker")
	entries, err := os.ReadDir(wd)
	if err != nil {
		if os.IsNotExist(err) {
			return // extinct — the goal state
		}
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") {
			continue
		}
		// Each Woodpecker workflow must be either already extinct by name
		// or acknowledged as a lane Kiwi owns. The Kiwi pipeline is allowed
		// to name the platform explicitly.
		base := strings.TrimSuffix(name, ".yml")
		if !strings.Contains(text, base) && !strings.Contains(text, strings.ReplaceAll(base, "-", " ")) {
			// Nightly / diagnostic workflows are roadmap, not a blocker for
			// the core platform lanes — only fail on the platform set.
			switch base {
			case "linux-amd64", "linux-arm64", "native-macos", "native-windows", "integration-coverage":
				t.Fatalf(".kiwi/pipeline.yaml does not acknowledge Woodpecker lane %q", name)
			}
		}
	}
}
