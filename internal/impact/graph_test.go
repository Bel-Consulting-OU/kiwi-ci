package impact

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func chainGraph() *Graph {
	return New(map[string]pipeline.Package{
		"a": {Paths: []string{"pkg/a/**"}},
		"b": {Paths: []string{"pkg/b/**"}, DependsOn: []string{"a"}},
		"c": {Paths: []string{"pkg/c/**"}, DependsOn: []string{"b"}},
	})
}

func TestAffectedPackagesChain(t *testing.T) {
	g := chainGraph()
	// Change in a marks a, b, c (reverse-dependency closure).
	got := g.AffectedPackages([]string{"pkg/a/file.go"})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("change in a: %v, want %v", got, want)
	}
	// Change in c marks c only.
	got = g.AffectedPackages([]string{"pkg/c/file.go"})
	if !reflect.DeepEqual(got, []string{"c"}) {
		t.Fatalf("change in c: %v", got)
	}
	// Change in b marks b and c.
	got = g.AffectedPackages([]string{"pkg/b/file.go"})
	if !reflect.DeepEqual(got, []string{"b", "c"}) {
		t.Fatalf("change in b: %v", got)
	}
	// Unrelated change marks nothing.
	if got := g.AffectedPackages([]string{"docs/readme.md"}); len(got) != 0 {
		t.Fatalf("unrelated: %v", got)
	}
	// Empty change set marks nothing.
	if got := g.AffectedPackages(nil); len(got) != 0 {
		t.Fatalf("empty: %v", got)
	}
}

func TestAffectedJobs(t *testing.T) {
	g := chainGraph()
	jobs := map[string]pipeline.Job{
		"build-a":   {Paths: []string{"pkg/a/**"}},
		"test-b":    {Paths: []string{"pkg/b/**"}},
		"docs":      {Paths: []string{"docs/**"}},
		"unrelated": {},
	}
	got := g.AffectedJobs(jobs, []string{"pkg/a/main.go"})
	want := []string{"build-a", "test-b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("jobs: %v, want %v", got, want)
	}
	// Direct job path match without any package.
	jobs["extra"] = pipeline.Job{Paths: []string{"tools/**"}}
	got = g.AffectedJobs(jobs, []string{"tools/gen.go"})
	if !reflect.DeepEqual(got, []string{"extra"}) {
		t.Fatalf("direct: %v", got)
	}
	// Paths_ignore excludes a job from its own path match, but the job's
	// paths still intersect affected package a's paths.
	jobs["skip-me"] = pipeline.Job{Paths: []string{"pkg/a/**"}, PathsIgnore: []string{"pkg/a/*_test.go"}}
	got = g.AffectedJobs(jobs, []string{"pkg/a/x_test.go"})
	if !reflect.DeepEqual(got, []string{"build-a", "skip-me", "test-b"}) {
		t.Fatalf("paths_ignore: %v", got)
	}
}

func TestValidate(t *testing.T) {
	g := chainGraph()
	if err := g.Validate(); err != nil {
		t.Fatalf("valid graph rejected: %v", err)
	}
	// Missing depends_on reference.
	bad := New(map[string]pipeline.Package{
		"a": {DependsOn: []string{"ghost"}},
	})
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("missing dep: %v", err)
	}
	// Cycle.
	cyc := New(map[string]pipeline.Package{
		"a": {DependsOn: []string{"b"}},
		"b": {DependsOn: []string{"a"}},
	})
	if err := cyc.Validate(); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle: %v", err)
	}
	// Self-cycle.
	self := New(map[string]pipeline.Package{
		"a": {DependsOn: []string{"a"}},
	})
	if err := self.Validate(); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("self-cycle: %v", err)
	}
	// Path overlap warning.
	overlap := New(map[string]pipeline.Package{
		"a": {Paths: []string{"pkg/a/**"}},
		"b": {Paths: []string{"pkg/a/**"}},
	})
	if err := overlap.Validate(); err == nil || !strings.Contains(err.Error(), "share path patterns") {
		t.Fatalf("overlap: %v", err)
	}
}
