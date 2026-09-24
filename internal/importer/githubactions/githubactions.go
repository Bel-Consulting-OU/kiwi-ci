// Package githubactions converts GitHub Actions workflow files into Kiwi
// pipeline specs.
//
// Mapped: on (push/pull_request branches/tags/paths), top-level and job
// env, jobs (runs-on → runner labels, needs, timeout-minutes, if →
// condition mapping, strategy.matrix → matrix, outputs), run steps (name,
// run, env, working-directory, shell, continue-on-error, timeout-minutes,
// if).
//
// Reported instead of approximated: services, job containers, workflow/
// job secrets, concurrency groups, permissions, environment, reusable
// workflow references, strategy include/exclude/fail-fast, and every
// `uses:` action (checkout and setup-* produce TODOs; unknown actions are
// emitted as a never-running placeholder step with a TODO so no behavior
// is silently lost).
package githubactions

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/importer"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// Importer implements importer.Importer for GitHub Actions.
type Importer struct{}

func New() *Importer { return &Importer{} }

// Import converts one workflow document (the contents of
// .github/workflows/*.yml).
func (i *Importer) Import(src string) (*importer.Result, error) {
	res := &importer.Result{}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		return nil, fmt.Errorf("parse workflow: %w", err)
	}
	doc := importer.Document(&root)
	if doc == nil || doc.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("workflow must be a YAML mapping")
	}

	spec := &pipeline.Spec{Version: 1, Name: importer.StrScalar(importer.Key(doc, "name"))}
	supported := 0

	if on := importer.Key(doc, "on"); on != nil {
		convertOn(res, on, spec)
		supported++
	}
	if env := importer.Key(doc, "env"); env != nil {
		spec.Env = importer.EnvMap(env)
		supported++
	}
	if defaults := importer.Key(doc, "defaults"); defaults != nil {
		if run := importer.Key(defaults, "run"); run != nil {
			if shell := importer.StrScalar(importer.Key(run, "shell")); shell != "" {
				spec.Defaults.Shell = shell
			}
		}
		supported++
	}
	if importer.Key(doc, "concurrency") != nil {
		res.AddUnsupported("workflow-level concurrency group is not supported; declare per-run concurrency via the server or repository policy")
	}
	if perm := importer.Key(doc, "permissions"); perm != nil {
		res.AddUnsupported("workflow-level permissions (%s) are not supported; Kiwi grants id_token via job permissions", strings.Join(importer.SeqScalars(perm), ", "))
	}
	if importer.Key(doc, "secrets") != nil {
		res.AddUnsupported("workflow-level secrets are not supported")
	}

	jobs := importer.Mapping(importer.Key(doc, "jobs"))
	if len(jobs) == 0 {
		res.AddWarning("workflow declares no jobs")
	}
	spec.Jobs = map[string]pipeline.Job{}
	taken := map[string]bool{}
	ids := map[string]string{}
	keys := make([]string, 0, len(jobs))
	for k := range jobs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// First pass assigns sanitized ids so needs references (which may point
	// at jobs converted later) resolve to the same ids.
	for _, name := range keys {
		ids[name] = importer.SanitizeID(name, taken)
	}
	for _, name := range keys {
		job := convertJob(res, importer.Key(doc, "jobs"), name, ids)
		spec.Jobs[ids[name]] = job
		supported++
	}

	out, err := importer.MarshalSpec(spec)
	if err != nil {
		return nil, err
	}
	res.PipelineYAML = out
	res.Finalize(supported)
	return res, nil
}

// convertOn maps the `on` trigger value onto spec.On. GitHub Actions accepts
// three shapes:
//
//	on: push                      (scalar: one event, no config)
//	on: [push, pull_request]      (sequence: each entry is an event, no config)
//	on:                           (mapping: event → config)
//	  push:
//	    branches: [main]
//
// Reading a scalar/sequence as a mapping yields no events, which would leave
// spec.On empty — and an empty `on` matches EVERY event, silently widening
// the trigger. All three shapes are therefore handled explicitly. Events
// Kiwi cannot trigger on (workflow_dispatch, schedule, release, ...) are
// reported as unsupported rather than silently dropped.
func convertOn(res *importer.Result, on *yaml.Node, spec *pipeline.Spec) {
	if spec.On == nil {
		spec.On = map[string]pipeline.Trigger{}
	}
	add := func(event string, cfg *yaml.Node) {
		switch event {
		case "push", "pull_request":
			spec.On[event] = triggerFrom(cfg)
		default:
			res.AddUnsupported("trigger %q has no Kiwi equivalent; Kiwi triggers on push/pull_request webhooks only", event)
		}
	}
	switch on.Kind {
	case yaml.ScalarNode:
		// A null `on:` (on: with no value) carries no event names; a scalar
		// with a value names exactly one event.
		if strings.TrimSpace(on.Value) != "" {
			add(strings.TrimSpace(on.Value), nil)
		}
	case yaml.SequenceNode:
		for _, item := range on.Content {
			if item.Kind != yaml.ScalarNode {
				res.AddUnsupported("trigger entry at line %d is not a scalar event name", item.Line)
				continue
			}
			if name := strings.TrimSpace(item.Value); name != "" {
				add(name, nil)
			}
		}
	case yaml.MappingNode:
		for event, cfg := range importer.Mapping(on) {
			add(event, cfg)
		}
	default:
		res.AddUnsupported("trigger `on` must be an event name, a list of event names, or an event mapping")
	}
}

func triggerFrom(cfg *yaml.Node) pipeline.Trigger {
	var t pipeline.Trigger
	if cfg == nil {
		return t
	}
	t.Branches = importer.SeqScalars(importer.Key(cfg, "branches"))
	t.BranchesIgnore = importer.SeqScalars(importer.Key(cfg, "branches-ignore"))
	t.Tags = importer.SeqScalars(importer.Key(cfg, "tags"))
	t.TagsIgnore = importer.SeqScalars(importer.Key(cfg, "tags-ignore"))
	t.Paths = importer.SeqScalars(importer.Key(cfg, "paths"))
	t.PathsIgnore = importer.SeqScalars(importer.Key(cfg, "paths-ignore"))
	if act := importer.Key(cfg, "types"); act != nil {
		t.Actions = importer.SeqScalars(act)
	}
	return t
}

// convertJob converts one job node. ids is the precomputed name→sanitized-id
// map so needs references resolve consistently regardless of order.
func convertJob(res *importer.Result, jobsNode *yaml.Node, name string, ids map[string]string) pipeline.Job {
	jobNode := importer.Key(jobsNode, name)
	j := pipeline.Job{Name: name}
	if jobNode == nil {
		res.AddWarning("job %q has no definition", name)
		return j
	}

	if ro := importer.Key(jobNode, "runs-on"); ro != nil {
		j.Runner = importer.SeqScalars(ro)
		if ro.Kind == yaml.ScalarNode && ro.Value != "" {
			j.Runner = []string{ro.Value}
		}
	}
	if needs := importer.Key(jobNode, "needs"); needs != nil {
		for _, dep := range importer.SeqScalars(needs) {
			if id, ok := ids[dep]; ok && dep != "" {
				j.Needs = append(j.Needs, id)
			}
		}
	}
	if ifc := importer.Key(jobNode, "if"); ifc != nil {
		expr, ok := importer.MapCondition(importer.StrScalar(ifc))
		if !ok {
			res.AddUnsupported("job %q: condition %q uses contexts Kiwi cannot evaluate; the job keeps the default success() gate", name, importer.StrScalar(ifc))
			res.AddTODO("job %q: review the condition %q by hand", name, importer.StrScalar(ifc))
		} else {
			j.If = expr
		}
	}
	if tm := importer.Key(jobNode, "timeout-minutes"); tm != nil {
		if mins, ok := importer.IntScalar(tm); ok && mins > 0 {
			j.Timeout = pipeline.Duration{Duration: time.Duration(mins) * time.Minute, Set: true}
		}
	}
	if env := importer.Key(jobNode, "env"); env != nil {
		j.Env = importer.EnvMap(env)
	}
	if out := importer.Key(jobNode, "outputs"); out != nil {
		j.Outputs = importer.EnvMap(out)
	}
	if strat := importer.Key(jobNode, "strategy"); strat != nil {
		convertStrategy(res, strat, name, &j)
	}
	if importer.Key(jobNode, "container") != nil {
		res.AddUnsupported("job %q: container is not supported; set runtime: container and image: <image> manually (never approximated)", name)
		res.AddTODO("job %q: container block needs manual conversion to runtime: container + image", name)
	}
	if svc := importer.Key(jobNode, "services"); svc != nil {
		for svcName := range importer.Mapping(svc) {
			res.AddUnsupported("job %q: service %q has no direct Kiwi equivalent; declare a services: entry with the image manually", name, svcName)
		}
	}
	if importer.Key(jobNode, "secrets") != nil {
		res.AddUnsupported("job %q: job-level secrets are not supported", name)
	}
	if importer.Key(jobNode, "environment") != nil {
		res.AddUnsupported("job %q: environment is not supported; use environment: with approval for gated deployments", name)
	}
	if importer.Key(jobNode, "permissions") != nil {
		res.AddUnsupported("job %q: job-level permissions are not supported; use permissions.id_token", name)
	}
	if importer.Key(jobNode, "concurrency") != nil {
		res.AddUnsupported("job %q: job-level concurrency group is not supported", name)
	}

	if steps := importer.Key(jobNode, "steps"); steps != nil {
		for _, stepNode := range steps.Content {
			if stepNode.Kind != yaml.MappingNode {
				continue
			}
			if st, ok := convertStep(res, name, stepNode); ok {
				j.Steps = append(j.Steps, st)
			}
		}
	}
	return j
}

// convertStrategy maps strategy.matrix into Kiwi matrix dimensions.
// include/exclude/fail-fast are reported, never approximated.
func convertStrategy(res *importer.Result, strat *yaml.Node, job string, j *pipeline.Job) {
	if ff := importer.Key(strat, "fail-fast"); ff != nil {
		if v, ok := importer.BoolScalar(ff); ok && !v {
			res.AddUnsupported("job %q: strategy.fail-fast: false has no Kiwi equivalent; Kiwi runs all matrix combinations independently", job)
		}
	}
	matrix := importer.Key(strat, "matrix")
	if matrix == nil || matrix.Kind != yaml.MappingNode {
		return
	}
	j.Matrix = map[string][]any{}
	for dim, vals := range importer.Mapping(matrix) {
		if dim == "include" || dim == "exclude" {
			res.AddUnsupported("job %q: strategy.matrix.%s is not supported; Kiwi matrices are cartesian-only", job, dim)
			continue
		}
		var out []any
		scalarValues := true
		for _, v := range vals.Content {
			if v.Kind != yaml.ScalarNode {
				scalarValues = false
				break
			}
			var decoded any
			if err := v.Decode(&decoded); err != nil {
				scalarValues = false
				break
			}
			out = append(out, decoded)
		}
		if !scalarValues {
			// A partly (or wholly) non-scalar dimension cannot be represented
			// faithfully: keeping only its scalar values would silently
			// change the matrix, so the dimension is dropped whole with an
			// explicit diagnosis.
			res.AddWarning("job %q: matrix dimension %q contains non-scalar values; the dimension is omitted", job, dim)
			res.AddUnsupported("job %q: matrix dimension %q is not representable in Kiwi (scalar values only); the dimension was dropped", job, dim)
			continue
		}
		if len(out) == 0 {
			// An empty dimension would make the generated YAML rejected by
			// pipeline.Parse ("matrix dimension has no values"), so it is
			// never emitted.
			res.AddWarning("job %q: matrix dimension %q is empty; the dimension is omitted", job, dim)
			res.AddUnsupported("job %q: matrix dimension %q has no values and cannot be represented; the dimension was dropped", job, dim)
			continue
		}
		j.Matrix[dim] = out
	}
	if len(j.Matrix) == 0 {
		j.Matrix = nil
	}
}

// convertStep converts one step node. It returns ok=false when the step has
// no runnable Kiwi equivalent (checkout and setup-* actions become TODOs;
// anything without a run or uses is skipped with a warning).
func convertStep(res *importer.Result, job string, step *yaml.Node) (pipeline.Step, bool) {
	id := importer.StrScalar(importer.Key(step, "id"))
	name := importer.StrScalar(importer.Key(step, "name"))
	if uses := importer.Key(step, "uses"); uses != nil {
		ref := importer.StrScalar(uses)
		switch {
		case strings.HasPrefix(ref, "actions/checkout@"):
			res.AddTODO("job %q: checkout is implicit in Kiwi; drop the actions/checkout step (submodules/depth need a manual git step)", job)
		case strings.HasPrefix(ref, "actions/setup-"):
			res.AddTODO("job %q: %s has no Kiwi equivalent; bake the toolchain into the container image or set it in env", job, ref)
		default:
			res.AddUnsupported("job %q: action %s cannot be approximated; emitted as a disabled placeholder step", job, ref)
			res.AddTODO("job %q: replace the action %s with an equivalent script step", job, ref)
			title := name
			if title == "" {
				title = ref
			}
			return pipeline.Step{
				ID: id, Name: title, If: "false",
				Run: fmt.Sprintf("# TODO(importer): action %s has no Kiwi equivalent; re-implement or drop", ref),
			}, true
		}
		return pipeline.Step{}, false
	}
	st := pipeline.Step{ID: id, Name: name, Run: importer.StrScalar(importer.Key(step, "run"))}
	if st.Run == "" {
		res.AddWarning("job %q: step %q has no run or uses; skipped", job, name)
		return pipeline.Step{}, false
	}
	if env := importer.Key(step, "env"); env != nil {
		st.Env = importer.EnvMap(env)
	}
	if wd := importer.StrScalar(importer.Key(step, "working-directory")); wd != "" {
		st.WorkingDirectory = wd
	}
	if shell := importer.StrScalar(importer.Key(step, "shell")); shell != "" && shell != "bash" {
		st.Shell = shell
	}
	if tm := importer.Key(step, "timeout-minutes"); tm != nil {
		if mins, ok := importer.IntScalar(tm); ok && mins > 0 {
			st.Timeout = pipeline.Duration{Duration: time.Duration(mins) * time.Minute, Set: true}
		}
	}
	if ce := importer.Key(step, "continue-on-error"); ce != nil {
		if v, ok := importer.BoolScalar(ce); ok {
			st.ContinueOnError = v
		}
	}
	if ifc := importer.Key(step, "if"); ifc != nil {
		expr, ok := importer.MapCondition(importer.StrScalar(ifc))
		if !ok {
			res.AddUnsupported("job %q step %q: condition %q uses contexts Kiwi cannot evaluate; dropped", job, name, importer.StrScalar(ifc))
			res.AddTODO("job %q step %q: review the condition %q by hand", job, name, importer.StrScalar(ifc))
		} else {
			st.If = expr
		}
	}
	if with := importer.Key(step, "with"); with != nil {
		res.AddTODO("job %q step %q: `with` parameters (%s) need manual conversion into the run script or env", job, name, strings.Join(mapKeys(with), ", "))
	}
	return st, true
}

func mapKeys(n *yaml.Node) []string {
	var out []string
	for k := range importer.Mapping(n) {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
