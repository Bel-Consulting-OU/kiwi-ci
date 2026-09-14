package pipeline

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/expr"
)

type CompiledJob struct {
	ID     string            `json:"id"`
	BaseID string            `json:"base_id"`
	Job    Job               `json:"job"`
	Matrix map[string]string `json:"matrix,omitempty"`
	Needs  []string          `json:"needs,omitempty"`
}

type Graph struct {
	Spec *Spec                  `json:"spec"`
	Jobs map[string]CompiledJob `json:"jobs"`
}

func Compile(s *Spec) (*Graph, error) {
	if err := Validate(s); err != nil {
		return nil, err
	}
	g := &Graph{Spec: s, Jobs: map[string]CompiledJob{}}
	expanded := map[string][]string{}
	for id, j := range s.Jobs {
		combos := matrixCombinations(j.Matrix)
		if len(combos) == 0 {
			combos = []map[string]string{{}}
		}
		for _, m := range combos {
			cid := id
			if len(m) > 0 {
				keys := make([]string, 0, len(m))
				for k := range m {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				parts := make([]string, 0, len(keys))
				for _, k := range keys {
					parts = append(parts, fmt.Sprintf("%s=%s", k, m[k]))
				}
				cid += "[" + strings.Join(parts, ",") + "]"
			}
			cj := CompiledJob{ID: cid, BaseID: id, Job: interpolateJob(j, m), Matrix: m}
			cj.Job.Env = mergeStringMaps(cj.Job.Env, matrixEnv(m))
			g.Jobs[cid] = cj
			expanded[id] = append(expanded[id], cid)
		}
	}
	for id, cj := range g.Jobs {
		var deps []string
		for _, base := range cj.Job.Needs {
			deps = append(deps, expanded[base]...)
		}
		cj.Needs = deps
		g.Jobs[id] = cj
	}
	return g, nil
}

func matrixCombinations(m map[string][]any) []map[string]string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []map[string]string{{}}
	for _, k := range keys {
		vals := m[k]
		if len(vals) == 0 {
			continue
		}
		next := make([]map[string]string, 0, len(out)*len(vals))
		for _, base := range out {
			for _, v := range vals {
				n := map[string]string{}
				for bk, bv := range base {
					n[bk] = bv
				}
				n[k] = fmt.Sprint(v)
				next = append(next, n)
			}
		}
		out = next
	}
	return out
}

func interpolateJob(j Job, m map[string]string) Job {
	j.Name = Interpolate(j.Name, m)
	j.If = Interpolate(j.If, m)
	j.Image = Interpolate(j.Image, m)
	j.Network = Interpolate(j.Network, m)
	j.VM = Interpolate(j.VM, m)
	j.Shell = Interpolate(j.Shell, m)
	j.Env = interpolateMap(j.Env, m)
	j.Outputs = interpolateMap(j.Outputs, m)
	j.Steps = interpolateSteps(j.Steps, m)
	for i := range j.Services {
		j.Services[i].Name = Interpolate(j.Services[i].Name, m)
		j.Services[i].Image = Interpolate(j.Services[i].Image, m)
		j.Services[i].Healthcheck = Interpolate(j.Services[i].Healthcheck, m)
		j.Services[i].Env = interpolateMap(j.Services[i].Env, m)
	}
	for i := range j.Cache {
		j.Cache[i].Name = Interpolate(j.Cache[i].Name, m)
		j.Cache[i].Key = Interpolate(j.Cache[i].Key, m)
		for k := range j.Cache[i].Paths {
			j.Cache[i].Paths[k] = Interpolate(j.Cache[i].Paths[k], m)
		}
		for k := range j.Cache[i].HashFiles {
			j.Cache[i].HashFiles[k] = Interpolate(j.Cache[i].HashFiles[k], m)
		}
		for k := range j.Cache[i].RestoreKeys {
			j.Cache[i].RestoreKeys[k] = Interpolate(j.Cache[i].RestoreKeys[k], m)
		}
	}
	for i := range j.TestReports {
		j.TestReports[i] = Interpolate(j.TestReports[i], m)
	}
	for i := range j.Downloads {
		j.Downloads[i].From = Interpolate(j.Downloads[i].From, m)
		j.Downloads[i].Name = Interpolate(j.Downloads[i].Name, m)
		j.Downloads[i].Path = Interpolate(j.Downloads[i].Path, m)
	}
	for i := range j.Artifacts {
		j.Artifacts[i].Name = Interpolate(j.Artifacts[i].Name, m)
		j.Artifacts[i].If = Interpolate(j.Artifacts[i].If, m)
		for k := range j.Artifacts[i].Paths {
			j.Artifacts[i].Paths[k] = Interpolate(j.Artifacts[i].Paths[k], m)
		}
	}
	return j
}

func interpolateMap(in map[string]string, m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = Interpolate(v, m)
	}
	return out
}

func interpolateSteps(in []Step, m map[string]string) []Step {
	out := make([]Step, len(in))
	copy(out, in)
	for i := range out {
		out[i].ID = Interpolate(out[i].ID, m)
		out[i].Name = Interpolate(out[i].Name, m)
		out[i].Run = Interpolate(out[i].Run, m)
		out[i].WorkingDirectory = Interpolate(out[i].WorkingDirectory, m)
		out[i].Shell = Interpolate(out[i].Shell, m)
		env := map[string]string{}
		for k, v := range out[i].Env {
			env[k] = Interpolate(v, m)
		}
		out[i].Env = env
	}
	return out
}

// Interpolate resolves matrix holes at compile time. Holes are parsed and
// evaluated with the expression engine against a matrix-only Context. Only
// holes that reference the matrix context (and whose referenced keys exist)
// are substituted; everything else is left untouched, preserving the exact
// legacy behavior for non-matrix holes (needs/steps/env/... are resolved
// later, at execution time). Both "${{ matrix.X }}" and the tight
// "${{matrix.X}}" form are accepted, and substitution is a single
// deterministic pass.
func Interpolate(s string, m map[string]string) string {
	if !strings.Contains(s, "${{") {
		return s
	}
	holes, err := expr.Holes(s)
	if err != nil || len(holes) == 0 {
		return s
	}
	c := expr.Context{Matrix: m}
	return interpolateLenient(s, holes, c, map[string]bool{"matrix": true})
}

// interpolateLenient substitutes the holes that reference only the allowed
// contexts and evaluate cleanly against the given context; every other hole
// stays as literal text. At least one context reference is required so pure
// literal holes are never expanded here.
func interpolateLenient(s string, holes []expr.Hole, c expr.Context, allowed map[string]bool) string {
	var b strings.Builder
	last := 0
	replaced := false
	for _, h := range holes {
		e, err := expr.Parse(h.Body)
		if err != nil {
			continue
		}
		refs := e.Contexts()
		if len(refs) == 0 || !contextsAllowed(refs, allowed) {
			continue
		}
		v, err := e.Eval(c)
		if err != nil {
			continue
		}
		b.WriteString(s[last:h.Start])
		b.WriteString(v)
		last = h.End
		replaced = true
	}
	if !replaced {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func contextsAllowed(refs []string, allowed map[string]bool) bool {
	for _, r := range refs {
		if !allowed[r] {
			return false
		}
	}
	return true
}

func matrixEnv(m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out["KIWI_MATRIX_"+strings.ToUpper(strings.ReplaceAll(k, "-", "_"))] = v
	}
	return out
}

func mergeStringMaps(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// InterpolateOutputs resolves runtime output contexts after upstream jobs or
// earlier steps have completed. Unlike matrix interpolation this happens at
// execution time because values do not exist when the DAG is compiled.
// Holes are evaluated with the expression engine against flattened
// needs/steps output maps ("job.outputs.name" keys); holes that do not
// resolve (missing outputs, other contexts such as env) stay literal, which
// matches the previous ReplaceAll-based behavior.
func InterpolateOutputs(v string, needs, steps map[string]map[string]string) string {
	if !strings.Contains(v, "${{") {
		return v
	}
	holes, err := expr.Holes(v)
	if err != nil || len(holes) == 0 {
		return v
	}
	c := expr.Context{
		Needs: flattenOutputs(needs),
		Steps: flattenOutputs(steps),
	}
	return interpolateLenient(v, holes, c, map[string]bool{"needs": true, "steps": true})
}

// flattenOutputs rewrites a nested outputs map ("job" -> "name" -> value)
// into the engine's flat key form ("job.outputs.name").
func flattenOutputs(in map[string]map[string]string) map[string]string {
	out := map[string]string{}
	for owner, outputs := range in {
		for name, value := range outputs {
			out[owner+".outputs."+name] = value
		}
	}
	return out
}

func InterpolateOutputMap(in map[string]string, needs, steps map[string]map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = InterpolateOutputs(v, needs, steps)
	}
	return out
}
