package surfacecheck

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// dogfoodMarkers is the contract between this guard and .kiwi/pipeline.yaml:
// the self-hosted pipeline must exercise every verification surface the
// repository exposes. The pipeline may organize them into any jobs/steps;
// only the concatenated step `run` text matters.
var dogfoodMarkers = []string{
	"gofmt",
	"go vet",
	"go build",
	"make test-unit",
	"make test-race",
	"make coverage-ci",
	"make surface-check",
	"make staticcheck",
	"make govulncheck",
	"make schema-check",
	"make docs-check",
	"make license-check",
	"make cross",
	"make repro-build",
	"make fuzz",
}

// TestDogfoodPipelineCoversVerificationSurfaces parses .kiwi/pipeline.yaml
// with the production pipeline parser and fails closed, listing every
// missing marker, when the dogfooding pipeline stops covering a verification
// surface. It is deliberately string-based: the pipeline names the exact
// `make <target>` strings, so renaming a Makefile target or dropping a step
// from the self-hosted pipeline fails the surface guard before CI can go
// green with an incomplete definition of "tested".
func TestDogfoodPipelineCoversVerificationSurfaces(t *testing.T) {
	root := repoRoot(t)
	pipelinePath := filepath.Join(root, ".kiwi", "pipeline.yaml")
	data, err := os.ReadFile(pipelinePath)
	if err != nil {
		t.Fatalf("dogfood gate: read %s: %v (the guard fails closed until the self-hosted pipeline exists)", pipelinePath, err)
	}
	spec, err := pipeline.Parse(data)
	if err != nil {
		t.Fatalf("dogfood gate: parse %s: %v", pipelinePath, err)
	}
	if len(spec.Jobs) == 0 {
		t.Fatalf("dogfood gate: %s declares no jobs; nothing is dogfooded", pipelinePath)
	}

	names := make([]string, 0, len(spec.Jobs))
	for name := range spec.Jobs {
		names = append(names, name)
	}
	sort.Strings(names)
	var runs []string
	for _, name := range names {
		for _, step := range spec.Jobs[name].Steps {
			if r := strings.TrimSpace(step.Run); r != "" {
				runs = append(runs, r)
			}
		}
	}
	all := strings.Join(runs, "\n")
	var missing []string
	for _, marker := range dogfoodMarkers {
		if !strings.Contains(all, marker) {
			missing = append(missing, marker)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("dogfood gate: %s is missing %d required verification marker(s):\n  %s\nEvery repository verification surface must run in the self-hosted pipeline. If the pipeline rewrite has not landed yet, this failure is expected; re-run once .kiwi/pipeline.yaml contains the markers above.",
			pipelinePath, len(missing), strings.Join(missing, "\n  "))
	}
}
