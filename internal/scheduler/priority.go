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
func DownstreamDepth(g *pipeline.Graph, key string) int {
	memo := map[string]int{}
	var visit func(string) int
	visit = func(k string) int {
		if v, ok := memo[k]; ok {
			return v
		}
		best := 0
		for child, cj := range g.Jobs {
			for _, dep := range cj.Needs {
				if dep == k {
					if d := 1 + visit(child); d > best {
						best = d
					}
				}
			}
		}
		memo[k] = best
		return best
	}
	return visit(key)
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
