package pipeline

import (
	"encoding/json"
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

// Compile validates and compiles a pipeline with no pipeline inputs. Holes
// referencing the inputs context are left literal, preserving the legacy
// behavior for callers that resolve inputs later (server enqueue).
func Compile(s *Spec) (*Graph, error) {
	return CompileWithInputs(s, nil)
}

// CompileWithInputs validates and compiles a pipeline with the given
// pipeline inputs. Inputs participate in compile-time interpolation
// alongside the matrix: "${{ inputs.<name> }}" holes resolve against the
// map, and each input is also injected into every job's environment as
// KIWI_INPUT_<NAME> (the executor-visible form, matching server enqueue).
// When inputs is non-nil a hole that references a missing input key is a
// compile error (the expr engine's missing-key error); a nil map keeps the
// legacy lenient behavior and leaves inputs holes untouched.
func CompileWithInputs(s *Spec, inputs map[string]string) (*Graph, error) {
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
			cj := CompiledJob{ID: cid, BaseID: id, Job: interpolateJob(j, m, inputs), Matrix: m}
			cj.Job.Env = mergeStringMaps(cj.Job.Env, matrixEnv(m))
			if inputs != nil {
				cj.Job.Env = mergeStringMaps(cj.Job.Env, inputEnv(inputs))
				if err := validateInputsResolved(cid, cj.Job, m, inputs); err != nil {
					return nil, err
				}
			}
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

func interpolateJob(j Job, m map[string]string, inputs map[string]string) Job {
	interp := func(s string) string { return InterpolateWithInputs(s, m, inputs) }
	j.Name = interp(j.Name)
	j.If = interp(j.If)
	j.Image = interp(j.Image)
	j.Network = interp(j.Network)
	j.VM = interp(j.VM)
	j.Shell = interp(j.Shell)
	j.Env = interpolateMap(j.Env, m, inputs)
	j.Outputs = interpolateMap(j.Outputs, m, inputs)
	j.Steps = interpolateSteps(j.Steps, m, inputs)
	for i := range j.Services {
		j.Services[i].Name = interp(j.Services[i].Name)
		j.Services[i].Image = interp(j.Services[i].Image)
		j.Services[i].Healthcheck = interp(j.Services[i].Healthcheck)
		j.Services[i].Env = interpolateMap(j.Services[i].Env, m, inputs)
	}
	for i := range j.Cache {
		j.Cache[i].Name = interp(j.Cache[i].Name)
		j.Cache[i].Key = interp(j.Cache[i].Key)
		for k := range j.Cache[i].Paths {
			j.Cache[i].Paths[k] = interp(j.Cache[i].Paths[k])
		}
		for k := range j.Cache[i].HashFiles {
			j.Cache[i].HashFiles[k] = interp(j.Cache[i].HashFiles[k])
		}
		for k := range j.Cache[i].RestoreKeys {
			j.Cache[i].RestoreKeys[k] = interp(j.Cache[i].RestoreKeys[k])
		}
	}
	for i := range j.TestReports {
		j.TestReports[i] = interp(j.TestReports[i])
	}
	for i := range j.Downloads {
		j.Downloads[i].From = interp(j.Downloads[i].From)
		j.Downloads[i].Name = interp(j.Downloads[i].Name)
		j.Downloads[i].Path = interp(j.Downloads[i].Path)
	}
	for i := range j.Artifacts {
		j.Artifacts[i].Name = interp(j.Artifacts[i].Name)
		j.Artifacts[i].If = interp(j.Artifacts[i].If)
		for k := range j.Artifacts[i].Paths {
			j.Artifacts[i].Paths[k] = interp(j.Artifacts[i].Paths[k])
		}
	}
	return j
}

func interpolateMap(in map[string]string, m map[string]string, inputs map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = InterpolateWithInputs(v, m, inputs)
	}
	return out
}

func interpolateSteps(in []Step, m map[string]string, inputs map[string]string) []Step {
	out := make([]Step, len(in))
	copy(out, in)
	for i := range out {
		out[i].ID = InterpolateWithInputs(out[i].ID, m, inputs)
		out[i].Name = InterpolateWithInputs(out[i].Name, m, inputs)
		out[i].Run = InterpolateWithInputs(out[i].Run, m, inputs)
		out[i].WorkingDirectory = InterpolateWithInputs(out[i].WorkingDirectory, m, inputs)
		out[i].Shell = InterpolateWithInputs(out[i].Shell, m, inputs)
		env := map[string]string{}
		for k, v := range out[i].Env {
			env[k] = InterpolateWithInputs(v, m, inputs)
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
	return InterpolateWithInputs(s, m, nil)
}

// InterpolateWithInputs resolves matrix and pipeline-input holes at compile
// time. With a nil inputs map it behaves exactly like Interpolate (inputs
// holes stay literal, the legacy behavior); with a non-nil map, holes that
// reference the inputs context are evaluated against it and substituted
// when all their referenced keys resolve. Unresolvable holes stay literal:
// callers that provided inputs (CompileWithInputs) reject leftover inputs
// holes as compile errors.
func InterpolateWithInputs(s string, m map[string]string, inputs map[string]string) string {
	if !strings.Contains(s, "${{") {
		return s
	}
	holes, err := expr.Holes(s)
	if err != nil || len(holes) == 0 {
		return s
	}
	c := expr.Context{Matrix: m, Inputs: inputs}
	allowed := map[string]bool{"matrix": true}
	if inputs != nil {
		allowed["inputs"] = true
	}
	return interpolateLenient(s, holes, c, allowed)
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

// inputEnv mirrors the server's enqueue-time injection: every pipeline
// input reaches the executor as KIWI_INPUT_<NAME>.
func inputEnv(inputs map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range inputs {
		out["KIWI_INPUT_"+strings.ToUpper(strings.ReplaceAll(k, "-", "_"))] = v
	}
	return out
}

// validateInputsResolved enforces the compile-time inputs contract after
// interpolation: with inputs in play, a hole that still references the
// inputs context must not evaluate against the provided map. Missing input
// keys surface as the expr engine's missing-key error (key ... not found in
// context "inputs"), wrapped with the job and hole body. Holes that also
// reference runtime contexts (needs/steps) legitimately stay literal and
// are skipped because their evaluation error names a different context.
func validateInputsResolved(jobID string, j Job, m, inputs map[string]string) error {
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	holes, err := expr.Holes(string(b))
	if err != nil {
		return nil
	}
	for _, h := range holes {
		e, err := expr.Parse(h.Body)
		if err != nil {
			continue
		}
		refsInputs := false
		for _, c := range e.Contexts() {
			if c == "inputs" {
				refsInputs = true
				break
			}
		}
		if !refsInputs {
			continue
		}
		if _, err := e.Eval(expr.Context{Matrix: m, Inputs: inputs}); err != nil && strings.Contains(err.Error(), "inputs") {
			return fmt.Errorf("job %q: ${{ %s }}: %w", jobID, h.Body, err)
		}
	}
	return nil
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
