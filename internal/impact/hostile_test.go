package impact

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// TestValidateRejectsOversizedGraph is the H1-E hostile-graph regression: a
// graph past the documented package bound is refused before the O(n^2)
// path-overlap comparison and the dependency walk run.
func TestValidateRejectsOversizedGraph(t *testing.T) {
	pkgs := make(map[string]pipeline.Package, maxImpactPackages+1)
	prev := ""
	for i := 0; i <= maxImpactPackages; i++ {
		name := fmt.Sprintf("p%05d", i)
		p := pipeline.Package{}
		if prev != "" {
			p.DependsOn = []string{prev}
		}
		pkgs[name] = p
		prev = name
	}
	g := New(pkgs)
	start := time.Now()
	err := g.Validate()
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized graph Validate = %v, want a limit error", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("oversized graph validation took %v", elapsed)
	}
}

// TestValidateLongChainWithinLimit proves the cycle probe no longer recurses
// per dependency: a maximal acyclic chain validates without stack growth.
func TestValidateLongChainWithinLimit(t *testing.T) {
	pkgs := make(map[string]pipeline.Package, maxImpactPackages)
	prev := ""
	for i := 0; i < maxImpactPackages; i++ {
		name := fmt.Sprintf("p%05d", i)
		p := pipeline.Package{}
		if prev != "" {
			p.DependsOn = []string{prev}
		}
		pkgs[name] = p
		prev = name
	}
	g := New(pkgs)
	if err := g.Validate(); err != nil {
		t.Fatalf("long acyclic chain rejected: %v", err)
	}
	// A cycle at the deep end is still detected (not merely missed by the
	// iterative walk).
	g.Packages["p00000"] = Package{DependsOn: []string{prev}}
	if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("deep cycle not detected: %v", err)
	}
}
