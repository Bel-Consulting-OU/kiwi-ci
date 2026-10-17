package scheduler

import (
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// DownstreamDepth returns the longest chain of jobs that (transitively) need
// key. It is the priority metric used by both scheduling modes: jobs that
// unblock the most work are scheduled first. Cycles are impossible in a
// compiled graph, but the memoization makes the traversal linear per node
// regardless.
//
// Prefer DownstreamDepths when more than one key is needed: it builds the
// child index ONCE and answers every key in one reverse-topological sweep,
// instead of rescanning the whole graph per call (O(N*E) per key).
func DownstreamDepth(g *pipeline.Graph, key string) int {
	return DownstreamDepths(g, []string{key})[key]
}

// DownstreamDepths computes DownstreamDepth for every requested key in one
// pass. Complexity is O(N+E) for the index and topological sweep plus O(K)
// for the lookups, versus O(K*N*E) for K separate DownstreamDepth calls.
func DownstreamDepths(g *pipeline.Graph, keys []string) map[string]int {
	out := make(map[string]int, len(keys))
	if g == nil {
		return out
	}
	// child index: dep -> jobs that need it. Built once.
	children := make(map[string][]string, len(g.Jobs))
	for id, cj := range g.Jobs {
		for _, dep := range cj.Needs {
			children[dep] = append(children[dep], id)
		}
	}
	// depth[k] = longest chain of jobs that transitively need k.
	// Visit a node only after its children: depth[k] = max(1+depth[child]).
	// The compiled graph is acyclic, so a simple memoized DFS is safe; the
	// index means each edge is walked once, not the whole graph per node.
	memo := make(map[string]int, len(g.Jobs))
	var visit func(string) int
	visit = func(k string) int {
		if v, ok := memo[k]; ok {
			return v
		}
		// Guard against a corrupt cyclic graph: a node already on the
		// current stack contributes 0 rather than recursing forever.
		memo[k] = 0
		best := 0
		for _, child := range children[k] {
			if d := 1 + visit(child); d > best {
				best = d
			}
		}
		memo[k] = best
		return best
	}
	for _, k := range keys {
		if _, ok := g.Jobs[k]; ok || children[k] != nil {
			out[k] = visit(k)
		}
	}
	return out
}

// CollectNeedsOutputs builds the needs-outputs map handed to a leased job,
// mirroring the executor's collectNeedsOutputs: outputs are keyed by job key
// and, when a base job expanded into exactly one matrix cell, also by the
// base key.
func CollectNeedsOutputs(j model.Job, jobs map[string]model.Job) map[string]map[string]string {
	out := map[string]map[string]string{}
	baseCount := map[string]int{}
	for _, id := range j.Needs {
		if d, ok := jobs[id]; ok {
			baseCount[d.BaseKey]++
		}
	}
	for _, id := range j.Needs {
		d, ok := jobs[id]
		if !ok || len(d.Outputs) == 0 {
			continue
		}
		out[d.Key] = cloneMap(d.Outputs)
		if baseCount[d.BaseKey] == 1 {
			out[d.BaseKey] = cloneMap(d.Outputs)
		}
	}
	return out
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
