// Package impact computes monorepo package dependency graphs and the
// transitive set of affected packages/jobs for a change set.
package impact

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// Graph is the package dependency graph of one repository: every declared
// package with its paths and depends_on edges.
type Graph struct {
	Packages map[string]Package
}

// Package mirrors pipeline.Package with stable JSON naming.
type Package struct {
	Paths     []string `json:"paths,omitempty"`
	DependsOn []string `json:"depends_on,omitempty"`
}

// New builds a Graph from a pipeline's declared packages.
func New(spec map[string]pipeline.Package) *Graph {
	g := &Graph{Packages: map[string]Package{}}
	for name, p := range spec {
		g.Packages[name] = Package{
			Paths:     append([]string(nil), p.Paths...),
			DependsOn: append([]string(nil), p.DependsOn...),
		}
	}
	return g
}

// AffectedPackages returns the sorted names of packages directly touched by
// the changed paths plus the reverse-dependency closure (everything that
// depends, transitively, on a touched package). A package is directly
// touched when one of its path patterns matches a changed file.
func (g *Graph) AffectedPackages(changed []string) []string {
	direct := map[string]bool{}
	for name, p := range g.Packages {
		if pipeline.PathsMatch(changed, p.Paths, nil) {
			direct[name] = true
		}
	}
	// Reverse edges: dep -> dependents.
	rev := map[string][]string{}
	for name, p := range g.Packages {
		for _, dep := range p.DependsOn {
			rev[dep] = append(rev[dep], name)
		}
	}
	affected := map[string]bool{}
	stack := []string{}
	for name := range direct {
		if !affected[name] {
			affected[name] = true
			stack = append(stack, name)
		}
	}
	for len(stack) > 0 {
		name := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, dependent := range rev[name] {
			if !affected[dependent] {
				affected[dependent] = true
				stack = append(stack, dependent)
			}
		}
	}
	out := make([]string, 0, len(affected))
	for name := range affected {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// AffectedJobs returns the sorted IDs of jobs affected by the changed paths:
// a job is affected when its own paths/paths_ignore filters match a changed
// file, or when its path patterns intersect the path patterns of an
// affected package (the job consumes code of a touched package).
func (g *Graph) AffectedJobs(jobs map[string]pipeline.Job, changed []string) []string {
	affectedPkgs := g.AffectedPackages(changed)
	affected := map[string]bool{}
	for id, j := range jobs {
		if len(j.Paths) == 0 && len(j.PathsIgnore) == 0 {
			continue
		}
		// Own paths/paths_ignore filter.
		if pipeline.PathsMatch(changed, j.Paths, j.PathsIgnore) {
			affected[id] = true
			continue
		}
		// Intersection with an affected package's path patterns.
		for _, name := range affectedPkgs {
			p, ok := g.Packages[name]
			if ok && pathsOverlap(j.Paths, p.Paths) {
				affected[id] = true
				break
			}
		}
	}
	out := make([]string, 0, len(affected))
	for id := range affected {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Validate checks the graph's integrity: every depends_on edge must
// reference a declared package, the graph must be acyclic, and packages
// that share path patterns are reported as warnings.
func (g *Graph) Validate() error {
	var errs []string
	for name, p := range g.Packages {
		for _, dep := range p.DependsOn {
			if _, ok := g.Packages[dep]; !ok {
				errs = append(errs, fmt.Sprintf("package %s: depends_on %q is not declared", name, dep))
			}
		}
	}
	if cycle, ok := g.findCycle(); ok {
		errs = append(errs, "dependency cycle: "+strings.Join(cycle, " -> "))
	}
	for _, w := range g.pathOverlaps() {
		errs = append(errs, "warning: "+w)
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// findCycle returns one dependency cycle as a name chain, if any.
func (g *Graph) findCycle() ([]string, bool) {
	const (
		unvisited = 0
		visiting  = 1
		done      = 2
	)
	state := map[string]int{}
	names := make([]string, 0, len(g.Packages))
	for name := range g.Packages {
		names = append(names, name)
	}
	sort.Strings(names)
	var dfs func(name string) ([]string, bool)
	dfs = func(name string) ([]string, bool) {
		state[name] = visiting
		for _, dep := range g.Packages[name].DependsOn {
			switch state[dep] {
			case visiting:
				return []string{name, dep}, true
			case unvisited:
				if chain, ok := dfs(dep); ok {
					return append([]string{name}, chain...), true
				}
			}
		}
		state[name] = done
		return nil, false
	}
	for _, name := range names {
		if state[name] == unvisited {
			if chain, ok := dfs(name); ok {
				return chain, true
			}
		}
	}
	return nil, false
}

// pathOverlaps warns when two packages declare overlapping path patterns,
// which makes impact attribution ambiguous.
func (g *Graph) pathOverlaps() []string {
	names := make([]string, 0, len(g.Packages))
	for name := range g.Packages {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []string
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			a, b := names[i], names[j]
			if pathsOverlap(g.Packages[a].Paths, g.Packages[b].Paths) {
				out = append(out, fmt.Sprintf("packages %s and %s share path patterns", a, b))
			}
		}
	}
	return out
}

func pathsOverlap(a, b []string) bool {
	for _, pa := range a {
		for _, pb := range b {
			if pa == pb {
				return true
			}
			if globSubsumes(pa, pb) || globSubsumes(pb, pa) {
				return true
			}
		}
	}
	return false
}

// globSubsumes reports whether pattern a matches every path pattern b could
// match: a must be a prefix-glob of b (e.g. "src/**" subsumes "src/pkg/**").
func globSubsumes(a, b string) bool {
	sa, sb := strings.TrimSuffix(a, "/**"), strings.TrimSuffix(b, "/**")
	if sa == a && sb != b {
		// a has no trailing /** but b does: a cannot subsume b unless
		// a is a plain directory prefix of sb.
		if strings.HasPrefix(sb, sa+"/") {
			return true
		}
		return false
	}
	if sb == b && sa != a {
		return false
	}
	return strings.HasPrefix(sb, strings.TrimSuffix(sa, "*"))
}
