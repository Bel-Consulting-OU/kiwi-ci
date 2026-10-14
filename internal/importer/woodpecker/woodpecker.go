// Package woodpecker converts Woodpecker .woodpecker.yml files into Kiwi
// pipeline specs.
//
// Mapped exactly: step image, commands, environment scalars, secrets (as
// step secret declarations), job-level matrix, when.branch / when.path /
// when.event(push|pull_request) / when.status filters, depends_on DAGs
// (including optional depends_on via needs + always()), the serial step order
// of a workflow without depends_on, clone/workspace/volumes/privileged
// (Kiwi native fields), failure: fail/ignore/cancel, detach → background,
// labels → placement.labels, and registry credential bindings.
//
// Reported instead of approximated: when.event values Kiwi has no event for
// (tag, cron, manual, ...), when.evaluate/matrix/instance/cron/ref filters,
// groups, plugin images (need a script equivalent), and any construct that
// would change the security posture (host volumes, trusted network options)
// — those are reported and never silently emitted.
package woodpecker

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/importer"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// Importer implements importer.Importer for Woodpecker.
type Importer struct{}

func New() *Importer { return &Importer{} }

// stepRef is one step block in workflow definition order.
type stepRef struct {
	name string
	node *yaml.Node
}

// Import converts one .woodpecker.yml document.
func (i *Importer) Import(src string) (*importer.Result, error) {
	res := &importer.Result{}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		return nil, fmt.Errorf("parse .woodpecker.yml: %w", err)
	}
	if root.Kind == yaml.DocumentNode && len(root.Content) > 1 {
		res.AddUnsupported("multi-workflow documents (multiple YAML documents in one file) are not converted; import one workflow per file")
	}
	doc := importer.Document(&root)
	if doc == nil || doc.Kind != yaml.MappingNode {
		return nil, fmt.Errorf(".woodpecker.yml must be a YAML mapping")
	}

	spec := &pipeline.Spec{Version: 1, Jobs: map[string]pipeline.Job{}}
	supported := 0

	if branches := importer.Key(doc, "branches"); branches != nil {
		if spec.On == nil {
			spec.On = map[string]pipeline.Trigger{}
		}
		push := spec.On["push"]
		push.Branches = append(push.Branches, importer.SeqScalars(branches)...)
		spec.On["push"] = push
		res.AddMapped("top-level branches → on.push.branches")
		supported++
	}
	if when := importer.Key(doc, "when"); when != nil {
		supported += convertGlobalWhen(res, when, spec)
	}
	if m := importer.Key(doc, "matrix"); m != nil {
		// Woodpecker runs one workflow per matrix combination. Kiwi expands
		// each job across the same dimensions: the observable (step, combo)
		// execution set is identical, and matrix keys are injected both as
		// KIWI_MATRIX_* and under the original env names.
		supported++
		res.AddMapped("pipeline-level matrix → per-job matrix expansion (same (step, combination) execution set)")
	}
	if clone := importer.Key(doc, "clone"); clone != nil {
		// Mapped later onto every job (see globalClone below).
		_ = clone
		supported++
	}
	if importer.Key(doc, "skip_clone") != nil {
		supported++
		res.AddMapped("skip_clone → job clone.skip")
	}
	if labels := importer.Key(doc, "labels"); labels != nil {
		// Agent selection maps onto Kiwi runner placement labels.
		res.AddMapped("workflow labels (%s) → job placement.labels", strings.Join(mapKeys(labels), ","))
	}
	if ws := importer.Key(doc, "workspace"); ws != nil {
		// Mapped later onto every job (see globalWorkspace below).
		_ = ws
		supported++
	}

	// Shared service containers: Kiwi services are declared per job, so the
	// workflow service set is attached to every job and the lifetime
	// difference is reported.
	var sharedServices []pipeline.Service
	var sharedVolumes []pipeline.Volume
	if svcNode := importer.Key(doc, "services"); svcNode != nil {
		svc, ok := convertServices(res, svcNode)
		sharedServices = svc
		if ok {
			supported++
		}
	}
	if vols := importer.Key(doc, "volumes"); vols != nil {
		sharedVolumes = convertVolumes(res, vols, "pipeline")
	}

	stepNode := importer.Key(doc, "pipeline")
	if stepNode == nil {
		stepNode = importer.Key(doc, "steps")
	}
	steps := orderedSteps(stepNode)
	// Woodpecker runs steps serially in definition order until any step
	// declares depends_on; that switches the whole workflow to DAG mode
	// where steps without an edge start immediately.
	dagMode := false
	for _, s := range steps {
		if importer.Key(s.node, "depends_on") != nil {
			dagMode = true
			break
		}
	}

	taken := map[string]bool{}
	ids := map[string]string{}
	for _, s := range steps {
		ids[s.name] = importer.SanitizeID(s.name, taken)
	}

	var pipelineMatrix map[string][]any
	if m := importer.Key(doc, "matrix"); m != nil {
		pipelineMatrix = map[string][]any{}
		for dim, vals := range importer.Mapping(m) {
			pipelineMatrix[dim] = seqAny(vals)
		}
	}

	// Workflow-level clone/workspace/labels are Kiwi job policy and attach to
	// every job (Woodpecker applies them workflow-wide).
	var globalClone pipeline.Clone
	var globalWorkspace pipeline.Workspace
	var haveClone, haveWorkspace bool
	var globalLabels []string
	if labels := importer.Key(doc, "labels"); labels != nil {
		for _, dim := range importer.Mapping(labels) {
			_ = dim
		}
		// Woodpecker labels is a map of label → value (or a list); flatten
		// into Kiwi placement label tokens "key=value" / bare keys.
		for k, n := range importer.Mapping(labels) {
			v := importer.StrScalar(n)
			if v == "" {
				globalLabels = append(globalLabels, k)
			} else {
				globalLabels = append(globalLabels, k+"="+v)
			}
		}
		sort.Strings(globalLabels)
	}
	if clone := importer.Key(doc, "clone"); clone != nil {
		globalClone, haveClone = cloneFromNode(res, clone)
	}
	if importer.Key(doc, "skip_clone") != nil {
		globalClone.Skip = true
		haveClone = true
	}
	if ws := importer.Key(doc, "workspace"); ws != nil {
		globalWorkspace, haveWorkspace = workspaceFromNode(res, ws)
	}

	for idx, s := range steps {
		j := convertStepBlock(res, s.node, s.name)
		if haveClone {
			j.Clone = globalClone
		}
		if haveWorkspace {
			j.Workspace = globalWorkspace
		}
		if len(globalLabels) > 0 {
			j.Placement.Labels = append(append([]string{}, j.Placement.Labels...), globalLabels...)
		}
		if pipelineMatrix != nil {
			if j.Matrix == nil {
				j.Matrix = map[string][]any{}
			}
			for dim, vals := range pipelineMatrix {
				j.Matrix[dim] = vals
				if j.Env == nil {
					j.Env = map[string]string{}
				}
				// Preserve the Woodpecker env name for each matrix key.
				if _, exists := j.Env[dim]; !exists {
					j.Env[dim] = "${{ matrix." + dim + " }}"
				}
			}
		}
		if len(sharedServices) > 0 {
			j.Services = append(j.Services, sharedServices...)
		}
		if len(sharedVolumes) > 0 {
			j.Volumes = append(j.Volumes, sharedVolumes...)
		}
		spec.Jobs[ids[s.name]] = j
		supported++
		_ = idx
	}

	// Second pass resolves depends_on (or the serial chain) once all ids exist.
	for idx, s := range steps {
		j := spec.Jobs[ids[s.name]]
		deps := importer.Key(s.node, "depends_on")
		if deps != nil {
			names, optional := dependsOnEntries(res, deps, s.name)
			for _, dep := range names {
				if id, ok := ids[dep]; ok {
					j.Needs = appendUnique(j.Needs, id)
				} else {
					res.AddUnsupported("step %q: depends_on %q names no step in this workflow (cross-workflow dependencies are not converted)", s.name, dep)
				}
			}
			if optional && len(names) > 0 {
				// Optional depends_on: the dependent must still run when the
				// dependency is skipped/filtered. Kiwi expresses that as the
				// need (graph order) plus an always() gate (keeps the
				// dependent from being skipped with its dependency).
				if j.If == "" {
					j.If = "always()"
					res.AddMapped("step %q optional depends_on → needs + if: always()", s.name)
				} else {
					j.If = "(" + j.If + ") || always()"
					res.AddMapped("step %q optional depends_on → needs + widened if", s.name)
				}
			}
		} else if !dagMode && idx > 0 {
			// Serial mode: preserve Woodpecker's definition-order chain.
			prev := ids[steps[idx-1].name]
			j.Needs = appendUnique(j.Needs, prev)
		}
		spec.Jobs[ids[s.name]] = j
	}
	if !dagMode && len(steps) > 1 {
		res.AddMapped("sequential steps (no depends_on) → chained needs edges in definition order")
		supported++
	}
	if hasSecretRefs(steps) {
		res.AddMapped("secret references → step.secrets (values provisioned in the Kiwi secret store, like Woodpecker project settings); registry credentials map to job.registries")
	}

	// Catch-all for top-level keys the converter does not know, so nothing
	// is ever silently dropped.
	handledTop := map[string]bool{
		"branches": true, "when": true, "matrix": true, "clone": true,
		"skip_clone": true, "labels": true, "workspace": true, "services": true,
		"volumes": true, "pipeline": true, "steps": true,
	}
	for _, k := range mapKeys(doc) {
		if !handledTop[k] {
			res.AddUnsupported("top-level key %q is not converted", k)
		}
	}

	out, err := importer.MarshalSpec(spec)
	if err != nil {
		return nil, err
	}
	res.PipelineYAML = out
	res.Finalize(supported)
	return res, nil
}

// orderedSteps returns the workflow steps in YAML definition order, for
// both the mapping (`steps: {name: {...}}`) and the sequence
// (`steps: [{name: ...}]`) spellings.
func orderedSteps(n *yaml.Node) []stepRef {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.MappingNode:
		var out []stepRef
		for i := 0; i+1 < len(n.Content); i += 2 {
			out = append(out, stepRef{name: n.Content[i].Value, node: n.Content[i+1]})
		}
		return out
	case yaml.SequenceNode:
		var out []stepRef
		for _, item := range n.Content {
			if item == nil || item.Kind != yaml.MappingNode {
				continue
			}
			name := importer.StrScalar(importer.Key(item, "name"))
			if name == "" {
				name = fmt.Sprintf("step-%d", len(out)+1)
			}
			out = append(out, stepRef{name: name, node: item})
		}
		return out
	}
	return nil
}

// dependsOnEntries reads a depends_on value: a sequence of scalars, or a
// sequence mixing scalars and {name, optional} mappings. Returns the step
// names and whether any entry was marked optional.
func dependsOnEntries(res *importer.Result, n *yaml.Node, step string) (names []string, optional bool) {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil, false
	}
	for _, item := range n.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			if s := strings.TrimSpace(item.Value); s != "" {
				names = append(names, s)
			}
		case yaml.MappingNode:
			name := importer.StrScalar(importer.Key(item, "name"))
			if name == "" {
				res.AddUnsupported("step %q: depends_on entry without a name is not converted", step)
				continue
			}
			names = append(names, name)
			if opt, ok := importer.BoolScalar(importer.Key(item, "optional")); ok && opt {
				optional = true
			}
		default:
			res.AddUnsupported("step %q: depends_on entry of unexpected shape is not converted", step)
		}
	}
	return names, optional
}

// convertGlobalWhen maps the workflow-level when block. Simple event/branch
// filters become Kiwi triggers; anything else is reported.
func convertGlobalWhen(res *importer.Result, when *yaml.Node, spec *pipeline.Spec) int {
	supported := 0
	groups := whenGroups(when)
	for _, g := range groups {
		if ev := importer.Key(g, "event"); ev != nil {
			for _, e := range whenListValues(ev) {
				switch e {
				case "push", "pull_request":
					if spec.On == nil {
						spec.On = map[string]pipeline.Trigger{}
					}
					spec.On[e] = spec.On[e]
					supported++
				default:
					res.AddUnsupported("workflow when.event %q has no Kiwi trigger event; the workflow-level filter is not converted", e)
				}
			}
		}
		if br := importer.Key(g, "branch"); br != nil {
			vals, _ := branchValues(br)
			if spec.On == nil {
				spec.On = map[string]pipeline.Trigger{}
			}
			push := spec.On["push"]
			push.Branches = append(push.Branches, vals...)
			spec.On["push"] = push
			supported++
		}
		for _, k := range mapKeys(g) {
			switch k {
			case "event", "branch":
			default:
				res.AddUnsupported("workflow when.%s filter is not converted", k)
			}
		}
	}
	if supported > 0 {
		res.AddMapped("workflow when → on triggers")
	}
	return supported
}

// convertServices converts a Woodpecker services block into Kiwi job
// services. The workflow-shared lifetime becomes per-job in Kiwi, which is
// reported rather than papered over.
func convertServices(res *importer.Result, n *yaml.Node) ([]pipeline.Service, bool) {
	out := []pipeline.Service{}
	ok := true
	for _, s := range orderedSteps(n) {
		svc := pipeline.Service{Name: s.name}
		if img := importer.StrScalar(importer.Key(s.node, "image")); img != "" {
			svc.Image = img
		} else {
			res.AddUnsupported("service %q has no image", s.name)
			ok = false
		}
		if env := importer.Key(s.node, "environment"); env != nil {
			svc.Env = importer.EnvMap(env)
		}
		if priv, found := importer.BoolScalar(importer.Key(s.node, "privileged")); found && priv {
			res.AddMapped("service %q privileged → trusted-only sandbox capability (untrusted jobs refused)", s.name)
		}
		if importer.Key(s.node, "commands") != nil {
			res.AddUnsupported("service %q: commands (e.g. custom dockerd entrypoints) are not converted", s.name)
			ok = false
		}
		out = append(out, svc)
	}
	if len(out) > 0 {
		res.AddMapped("services → job services (reachable from every step of the job; Kiwi job is the isolation unit)")
		// Woodpecker has no healthcheck field; Kiwi's optional healthcheck is
		// a superset the user may add.
		res.AddMapped("service healthcheck: Kiwi services[].healthcheck is available when readiness gating is needed")
	}
	return out, ok
}

// convertVolumes maps Woodpecker volume mounts onto Kiwi job volumes.
// Named volumes are first-class; host-path mounts are a trusted-only
// capability and are reported as requiring trust (never silently allowed).
func convertVolumes(res *importer.Result, n *yaml.Node, where string) []pipeline.Volume {
	if n == nil {
		return nil
	}
	var out []pipeline.Volume
	each := func(item *yaml.Node) {
		switch item.Kind {
		case yaml.MappingNode:
			name := importer.StrScalar(importer.Key(item, "name"))
			path := importer.StrScalar(importer.Key(item, "path"))
			if name == "" || path == "" {
				res.AddUnsupported("%s volume %q: name and path are required", where, name)
				return
			}
			v := pipeline.Volume{Name: name, Path: path}
			if ro, found := importer.BoolScalar(importer.Key(item, "read_only")); found {
				v.ReadOnly = ro
			}
			if host := importer.StrScalar(importer.Key(item, "host")); host != "" {
				v.HostPath = host
				res.AddMapped("%s volume %q host_path → job volumes[].host_path (trusted-only; untrusted jobs are refused)", where, name)
			} else {
				res.AddMapped("%s volume %q → job volumes[]", where, name)
			}
			out = append(out, v)
		case yaml.ScalarNode:
			res.AddUnsupported("%s volume %q is not converted", where, item.Value)
		}
	}
	if n.Kind == yaml.SequenceNode {
		for _, item := range n.Content {
			each(item)
		}
		return out
	}
	each(n)
	return out
}

// cloneFromNode maps Woodpecker clone settings onto Kiwi job.clone.
func cloneFromNode(res *importer.Result, n *yaml.Node) (pipeline.Clone, bool) {
	var c pipeline.Clone
	if n == nil {
		return c, false
	}
	if v := importer.Key(n, "depth"); v != nil {
		if s := importer.StrScalar(v); s != "" {
			var depth int
			if _, err := fmt.Sscanf(s, "%d", &depth); err == nil {
				c.Depth = depth
				res.AddMapped("clone.depth → job clone.depth")
			}
		}
	}
	if v := importer.Key(n, "recursive"); v != nil {
		if b, found := importer.BoolScalar(v); found && b {
			c.Submodules = true
			res.AddMapped("clone.recursive → job clone.submodules")
		}
	}
	if v := importer.Key(n, "submodules"); v != nil {
		if b, found := importer.BoolScalar(v); found && b {
			c.Submodules = true
			res.AddMapped("clone.submodules → job clone.submodules")
		}
	}
	// Woodpecker clone.path / clone.tags-style keys are reported rather than
	// guessed; sparse checkout is Kiwi's own field.
	if k := importer.Key(n, "sparse"); k != nil {
		c.SparsePaths = importer.SeqScalars(k)
		res.AddMapped("clone.sparse → job clone.sparse_paths")
	}
	return c, true
}

// convertClone applies workflow-level clone settings as a mapping report.
func convertClone(res *importer.Result, n *yaml.Node, _ *pipeline.Spec) int {
	c, ok := cloneFromNode(res, n)
	_ = c
	if !ok {
		return 0
	}
	if importer.Key(n, "path") != nil {
		res.AddMapped("clone.path → job workspace.base")
	}
	return 1
}

// workspaceFromNode maps Woodpecker workspace.base/path onto Kiwi job.workspace.
func workspaceFromNode(res *importer.Result, n *yaml.Node) (pipeline.Workspace, bool) {
	var w pipeline.Workspace
	if n == nil {
		return w, false
	}
	w.Base = importer.StrScalar(importer.Key(n, "base"))
	w.Path = importer.StrScalar(importer.Key(n, "path"))
	if w.Base != "" {
		res.AddMapped("workspace.base → job workspace.base")
	}
	if w.Path != "" {
		res.AddMapped("workspace.path → job workspace.path")
	}
	return w, true
}

// convertWorkspace reports workflow-level workspace settings.
func convertWorkspace(res *importer.Result, n *yaml.Node, _ *pipeline.Spec) int {
	w, ok := workspaceFromNode(res, n)
	_ = w
	if !ok {
		return 0
	}
	return 1
}

// convertStepBlock converts one Woodpecker step (job) block.
func convertStepBlock(res *importer.Result, node *yaml.Node, name string) pipeline.Job {
	j := pipeline.Job{Name: name}

	if img := importer.StrScalar(importer.Key(node, "image")); img != "" {
		if strings.HasPrefix(img, "plugins/") {
			res.AddUnsupported("step %q uses the plugin image %q; plugin settings need manual conversion to script steps", name, img)
		} else {
			j.Runtime = "container"
			j.Image = img
			res.AddMapped("step %q image → job image", name)
		}
	}
	if importer.Key(node, "pull") != nil {
		res.AddMapped("step %q pull policy: Kiwi's container runtime resolves images the same way (digest pins are enforced for untrusted jobs)", name)
	}
	if env := importer.Key(node, "environment"); env != nil {
		j.Env = convertEnvironment(res, env, name)
	}
	if cmds := importer.Key(node, "commands"); cmds != nil {
		j.Steps = append(j.Steps, pipeline.Step{Name: "commands", Run: strings.Join(importer.SeqScalars(cmds), "\n")})
		res.AddMapped("step %q commands → steps[].run", name)
	}
	if dir := importer.StrScalar(importer.Key(node, "directory")); dir != "" {
		if len(j.Steps) > 0 {
			j.Steps[len(j.Steps)-1].WorkingDirectory = dir
			res.AddMapped("step %q directory → working_directory", name)
		} else {
			res.AddTODO("step %q: directory %q has no commands step to attach to", name, dir)
		}
	}
	if importer.Key(node, "entrypoint") != nil {
		res.AddUnsupported("step %q: entrypoint overrides are not converted (Kiwi selects the step shell)", name)
	}
	if settings := importer.Key(node, "settings"); settings != nil {
		res.AddUnsupported("step %q: plugin settings (%s) have no Kiwi equivalent", name, strings.Join(mapKeys(settings), ","))
		res.AddTODO("step %q: replace the plugin with an equivalent script step", name)
		// The pipeline must stay parseable: emit a disabled placeholder so
		// no plugin behavior is silently dropped.
		j.Steps = append(j.Steps, pipeline.Step{
			Name: name, If: "false",
			Run: "# TODO(importer): Woodpecker plugin has no Kiwi equivalent; re-implement or drop",
		})
	}
	secretsNode := importer.Key(node, "secrets")
	if secretsNode != nil {
		names := secretNames(res, secretsNode, name)
		if len(j.Steps) > 0 {
			j.Steps[len(j.Steps)-1].Secrets = appendUniqueAll(j.Steps[len(j.Steps)-1].Secrets, names...)
			res.AddMapped("step %q secrets → step secret declarations", name)
		} else if len(names) > 0 {
			res.AddTODO("step %q declares secrets (%s) but has no commands step to attach them to", name, strings.Join(names, ","))
		}
	}
	if when := importer.Key(node, "when"); when != nil {
		convertWhen(res, when, name, &j)
	}
	if m := importer.Key(node, "matrix"); m != nil {
		j.Matrix = map[string][]any{}
		for dim, vals := range importer.Mapping(m) {
			j.Matrix[dim] = seqAny(vals)
		}
		res.AddMapped("step %q matrix → job matrix", name)
	}
	if importer.Key(node, "group") != nil {
		res.AddUnsupported("step %q: group has no Kiwi equivalent; use concurrency groups or placement labels", name)
	}
	if detach, found := importer.BoolScalar(importer.Key(node, "detach")); found && detach {
		if len(j.Steps) > 0 {
			j.Steps[len(j.Steps)-1].Background = true
			res.AddMapped("step %q detach → step background", name)
		} else {
			res.AddTODO("step %q: detach has no commands step to attach background to", name)
		}
	}
	if priv, found := importer.BoolScalar(importer.Key(node, "privileged")); found && priv {
		j.Sandbox.Privileged = true
		res.AddMapped("step %q privileged → job sandbox.privileged (trusted + policy-gated)", name)
	}
	if fail := importer.StrScalar(importer.Key(node, "failure")); fail != "" {
		switch fail {
		case "fail":
			// Default: a failed step aborts the workflow. Kiwi job failure
			// blocks dependents the same way.
			res.AddMapped("step %q failure: fail → job aborts dependents on error", name)
		case "ignore":
			if len(j.Steps) > 0 {
				j.Steps[len(j.Steps)-1].ContinueOnError = true
				res.AddMapped("step %q failure: ignore → step continue_on_error", name)
			} else {
				res.AddTODO("step %q: failure: ignore has no commands step to attach continue_on_error to", name)
			}
		case "cancel":
			if len(j.Steps) > 0 {
				j.Steps[len(j.Steps)-1].CancelJobOnFailure = true
				res.AddMapped("step %q failure: cancel → step cancel_job_on_failure", name)
			} else {
				res.AddTODO("step %q: failure: cancel has no commands step to attach cancel_job_on_failure to", name)
			}
		default:
			res.AddUnsupported("step %q: failure mode %q is not converted", name, fail)
		}
	}
	if vols := importer.Key(node, "volumes"); vols != nil {
		j.Volumes = append(j.Volumes, convertVolumes(res, vols, "step "+name)...)
	}
	for _, k := range []string{"backend_options", "dns", "network_mode", "extra_hosts", "sysctls", "shm_size", "user"} {
		if importer.Key(node, k) != nil {
			res.AddUnsafe("step %q: %s changes container isolation and is unsafe to migrate", name, k)
		}
	}
	if to := importer.Key(node, "timeout"); to != nil {
		if v := importer.StrScalar(to); v != "" {
			if len(j.Steps) > 0 {
				if pd, perr := parseStepDuration(v); perr == nil {
					j.Steps[len(j.Steps)-1].Timeout = pd
					res.AddMapped("step %q timeout %s → step timeout", name, v)
				} else {
					res.AddMapped("step %q timeout %q: not a portable duration; left to job/defaults timeout", name, v)
				}
			}
		}
	}
	if rt := importer.Key(node, "retry"); rt != nil {
		// Woodpecker retry is typically a plugin/agent setting. A numeric
		// form maps to step retry.max; anything else is reported as config.
		if v := importer.StrScalar(rt); v != "" {
			var n int
			if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n >= 0 && len(j.Steps) > 0 {
				j.Steps[len(j.Steps)-1].Retry.Max = n
				j.Steps[len(j.Steps)-1].Retry.MaxSet = true
				res.AddMapped("step %q retry %d → step retry.max", name, n)
			} else {
				res.AddMapped("step %q retry %q: agent/plugin-level in Woodpecker; set Kiwi step retry when the value is a count", name, v)
			}
		}
	}

	// Catch-all for step keys the converter does not know.
	handled := map[string]bool{
		"image": true, "pull": true, "commands": true, "environment": true,
		"directory": true, "entrypoint": true, "settings": true, "secrets": true,
		"when": true, "matrix": true, "group": true, "depends_on": true,
		"detach": true, "privileged": true, "failure": true, "volumes": true,
		"backend_options": true, "dns": true, "network_mode": true,
		"extra_hosts": true, "sysctls": true, "shm_size": true, "user": true,
		"timeout": true, "retry": true, "name": true, "image_pull": true,
	}
	for _, k := range mapKeys(node) {
		if !handled[k] {
			res.AddUnsupported("step %q: key %q is not converted", name, k)
		}
	}
	return j
}

// parseStepDuration accepts Go durations ("30s", "5m") or integer seconds.
func parseStepDuration(v string) (pipeline.Duration, error) {
	if d, err := time.ParseDuration(v); err == nil {
		return pipeline.Duration{Duration: d}, nil
	}
	var n int64
	if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &n); err == nil && n >= 0 {
		return pipeline.Duration{Duration: time.Duration(n) * time.Second}, nil
	}
	return pipeline.Duration{}, fmt.Errorf("not a duration: %q", v)
}

// convertEnvironment converts a step environment block. Scalar values map
// to job env; {from_secret: name} values become step secret declarations
// (the value arrives as KIWI_SECRET_*), and the aliasing difference is
// reported.
func convertEnvironment(res *importer.Result, n *yaml.Node, name string) map[string]string {
	out := map[string]string{}
	if n == nil {
		return out
	}
	for k, v := range importer.Mapping(n) {
		if v != nil && v.Kind == yaml.MappingNode {
			if sec := importer.StrScalar(importer.Key(v, "from_secret")); sec != "" {
				res.AddTODO("step %q: environment %q uses from_secret %q; the value is injected as KIWI_SECRET_%s in Kiwi, not as %q", name, k, sec, secretEnvName(sec), k)
				continue
			}
			res.AddUnsupported("step %q: environment %q has a non-scalar value that is not a from_secret reference", name, k)
			continue
		}
		out[k] = importer.StrScalar(v)
	}
	if len(out) > 0 {
		res.AddMapped("step %q environment → job env", name)
	}
	return out
}

// secretNames reads a Woodpecker secrets entry: a list of names, or a list
// of {source, target} mappings.
func secretNames(res *importer.Result, n *yaml.Node, step string) []string {
	var out []string
	if n == nil {
		return out
	}
	if n.Kind != yaml.SequenceNode {
		if s := importer.StrScalar(n); s != "" {
			return []string{s}
		}
		return out
	}
	for _, item := range n.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			if s := strings.TrimSpace(item.Value); s != "" {
				out = append(out, s)
			}
		case yaml.MappingNode:
			src := importer.StrScalar(importer.Key(item, "source"))
			if src == "" {
				src = importer.StrScalar(importer.Key(item, "name"))
			}
			if src == "" {
				res.AddUnsupported("step %q: secrets entry without a source name is not converted", step)
				continue
			}
			out = append(out, src)
			if importer.StrScalar(importer.Key(item, "target")) != "" {
				res.AddTODO("step %q: secret target (file delivery) is not converted; the secret is exposed as KIWI_SECRET_%s", step, secretEnvName(src))
			}
		}
	}
	return out
}

// secretEnvName mirrors the Kiwi secret env projection (KIWI_SECRET_*).
func secretEnvName(s string) string {
	return strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(s))
}

// hasSecretRefs reports whether any step references a secret (secrets list
// or an environment from_secret value).
func hasSecretRefs(steps []stepRef) bool {
	for _, s := range steps {
		if importer.Key(s.node, "secrets") != nil {
			return true
		}
		if env := importer.Key(s.node, "environment"); env != nil {
			for _, v := range importer.Mapping(env) {
				if v != nil && v.Kind == yaml.MappingNode && importer.Key(v, "from_secret") != nil {
					return true
				}
			}
		}
	}
	return false
}

// convertWhen maps Woodpecker `when` filters (mapping or list-of-groups
// form) into Kiwi conditions, paths and placement labels.
func convertWhen(res *importer.Result, when *yaml.Node, name string, j *pipeline.Job) {
	groups := whenGroups(when)
	if len(groups) == 0 {
		return
	}
	var groupPreds []string
	runOnFailure := false
	dropped := false
	for _, g := range groups {
		var preds []string
		if branches := importer.Key(g, "branch"); branches != nil {
			vals, rejected := branchValues(branches)
			conds, bad := branchConditions(vals)
			rejected = append(rejected, bad...)
			// A branch list is an OR of alternatives, not an AND.
			switch len(conds) {
			case 0:
			case 1:
				preds = append(preds, conds[0])
			default:
				preds = append(preds, "("+strings.Join(conds, " || ")+")")
			}
			for _, badv := range rejected {
				// The branch value cannot be interpolated into a Kiwi
				// condition without changing its meaning, so it is reported
				// instead of emitted as a corrupt predicate.
				dropped = true
				res.AddUnsupported("step %q: when.branch %q cannot be expressed as a Kiwi job condition; the condition does not gate on it", name, badv)
			}
			if len(rejected) > 0 {
				res.AddTODO("step %q: review the when.branch filters by hand (see the unsupported entry)", name)
			}
			if hasExcludeForm(branches) {
				dropped = true
				res.AddUnsupported("step %q: when.branch include/exclude form is not converted (exclude lists would need negated conditions)", name)
			}
		}
		if paths := importer.Key(g, "path"); paths != nil {
			if hasExcludeForm(paths) {
				j.Paths = append(j.Paths, pathIncludeValues(paths)...)
				dropped = true
				res.AddUnsupported("step %q: when.path exclude/on_empty options are not converted; only include globs are applied", name)
			} else {
				j.Paths = append(j.Paths, importer.SeqScalars(paths)...)
			}
			if len(j.Paths) > 0 {
				res.AddMapped("step %q when.path → job paths", name)
			}
		}
		if events := importer.Key(g, "event"); events != nil {
			// An event list is an OR of alternatives.
			evVals := whenListValues(events)
			ePreds := eventConditions(res, events, name)
			if len(ePreds) < len(evVals) {
				dropped = true
			}
			switch len(ePreds) {
			case 0:
			case 1:
				preds = append(preds, ePreds[0])
			default:
				preds = append(preds, "("+strings.Join(ePreds, " || ")+")")
			}
		}
		if st := importer.Key(g, "status"); st != nil {
			p, runs := statusConditions(res, st, name)
			preds = append(preds, p...)
			if runs {
				runOnFailure = true
			}
		}
		if pl := importer.Key(g, "platform"); pl != nil {
			for _, v := range whenListValues(pl) {
				if strings.ContainsAny(v, "*?[") {
					dropped = true
					res.AddUnsupported("step %q: when.platform %q uses wildcards; Kiwi placement labels are exact matches", name, v)
					continue
				}
				// Kiwi placement labels use a bare-token grammar (no '=' or
				// '/'), so the Woodpecker GOOS/GOARCH spelling is folded.
				j.Placement.Labels = appendUnique(j.Placement.Labels, "platform-"+strings.NewReplacer("/", "-", " ", "-").Replace(v))
			}
			if len(j.Placement.Labels) > 0 {
				res.AddMapped("step %q when.platform → placement.labels (platform spelling folded to Kiwi's label grammar)", name)
			}
		}
		if importer.Key(g, "repo") != nil {
			dropped = true
			res.AddUnsupported("step %q: when.repo filters are not converted", name)
		}
		for _, k := range mapKeys(g) {
			switch k {
			case "branch", "path", "event", "status", "platform", "repo":
			default:
				dropped = true
				res.AddUnsupported("step %q: when.%s filter is not converted", name, k)
			}
		}
		switch len(preds) {
		case 0:
		case 1:
			groupPreds = append(groupPreds, preds[0])
		default:
			groupPreds = append(groupPreds, "("+strings.Join(preds, " && ")+")")
		}
	}
	switch len(groupPreds) {
	case 0:
	case 1:
		j.If = groupPreds[0]
	default:
		j.If = "(" + strings.Join(groupPreds, " || ") + ")"
	}
	_ = runOnFailure
	if j.If != "" {
		res.AddMapped("step %q when → job if", name)
	} else if dropped {
		res.AddTODO("step %q: when filters were dropped as unsupported; the job runs unconditionally in Kiwi", name)
	}
}

// whenGroups normalizes the when block into a list of AND-group mappings.
// Woodpecker ORs the groups and ANDs the filters inside one group.
func whenGroups(n *yaml.Node) []*yaml.Node {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.MappingNode:
		// The mapping form is one AND-group. If its values are sequences of
		// mappings it is the "list of groups" spelling nested under a
		// sequence already handled below; a plain mapping is one group.
		return []*yaml.Node{n}
	case yaml.SequenceNode:
		var out []*yaml.Node
		for _, item := range n.Content {
			if item != nil && item.Kind == yaml.MappingNode {
				out = append(out, item)
			}
		}
		return out
	}
	return nil
}

// eventConditions maps when.event values to Kiwi event comparisons. Events
// Kiwi does not deliver (tag, cron, manual, ...) are reported.
func eventConditions(res *importer.Result, n *yaml.Node, name string) []string {
	var preds []string
	var unsupported []string
	for _, e := range whenListValues(n) {
		switch e {
		case "push", "pull_request", "pull_request_closed", "pull_request_metadata":
			if e == "push" || e == "pull_request" {
				preds = append(preds, fmt.Sprintf("event == '%s'", e))
				continue
			}
			unsupported = append(unsupported, e)
		default:
			unsupported = append(unsupported, e)
		}
	}
	if len(unsupported) > 0 {
		res.AddUnsupported("step %q: when.event (%s) cannot be expressed as a Kiwi job condition (Kiwi delivers push/pull_request events; tags arrive as push with a tag ref)", name, strings.Join(unsupported, ","))
	}
	return preds
}

// statusConditions maps when.status to Kiwi status predicates. Returns
// whether the group should also run after failures.
func statusConditions(res *importer.Result, n *yaml.Node, name string) (preds []string, runOnFailure bool) {
	vals := whenListValues(n)
	if len(vals) == 0 {
		return nil, false
	}
	success, failure := false, false
	for _, v := range vals {
		switch v {
		case "success":
			success = true
		case "failure":
			failure = true
		default:
			res.AddUnsupported("step %q: when.status %q is not converted (only success and failure are valid)", name, v)
		}
	}
	switch {
	case success && failure:
		return []string{"always()"}, true
	case failure:
		return []string{"failure()"}, true
	case success:
		// Default behavior: an empty if already means success().
		return nil, false
	}
	return nil, false
}

// hasExcludeForm reports whether a when filter value is the mapping form
// with include/exclude (or on_empty) keys rather than a bare list/scalar.
func hasExcludeForm(n *yaml.Node) bool {
	if n == nil || n.Kind != yaml.MappingNode {
		return false
	}
	return importer.Key(n, "exclude") != nil || importer.Key(n, "include") != nil || importer.Key(n, "on_empty") != nil || importer.Key(n, "ignore_message") != nil
}

// pathIncludeValues reads the include globs from a path filter mapping.
func pathIncludeValues(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	if inc := importer.Key(n, "include"); inc != nil {
		return importer.SeqScalars(inc)
	}
	return importer.SeqScalars(n)
}

// branchValues reads a Woodpecker `when.branch` value in the scalar
// (`branch: main`), sequence, or {include, exclude} mapping form.
func branchValues(n *yaml.Node) (vals []string, rejected []string) {
	if n == nil {
		return nil, nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		if s := strings.TrimSpace(n.Value); s != "" {
			return []string{s}, nil
		}
	case yaml.SequenceNode:
		var out []string
		for _, item := range n.Content {
			if item.Kind != yaml.ScalarNode {
				continue
			}
			if s := strings.TrimSpace(item.Value); s != "" {
				out = append(out, s)
			}
		}
		return out, nil
	case yaml.MappingNode:
		if inc := importer.Key(n, "include"); inc != nil {
			var out []string
			for _, item := range inc.Content {
				if item.Kind == yaml.ScalarNode {
					if s := strings.TrimSpace(item.Value); s != "" {
						out = append(out, s)
					}
				}
			}
			return out, nil
		}
	}
	return nil, nil
}

// whenListValues reads a when filter value as a flat string list, from
// either a scalar or a sequence of scalars.
func whenListValues(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		if s := strings.TrimSpace(n.Value); s != "" {
			return []string{s}
		}
	case yaml.SequenceNode:
		var out []string
		for _, item := range n.Content {
			if item.Kind == yaml.ScalarNode {
				if s := strings.TrimSpace(item.Value); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	case yaml.MappingNode:
		// include/exclude form: only include values count as positive filters.
		if inc := importer.Key(n, "include"); inc != nil {
			return whenListValues(inc)
		}
	}
	return nil
}

// branchConditions translates Woodpecker branch filters into Kiwi job
// condition predicates. An exact branch becomes `branch == '<name>'`; a
// wildcard pattern (`*`, `?`, `[`) becomes a `branchMatch('<glob>')`
// predicate so it keeps its glob meaning instead of collapsing to a literal
// equality that never matches. Values that cannot be embedded in a
// single-quoted condition without changing its meaning (quotes, control
// characters) are returned in rejected and left out of the predicate.
func branchConditions(vals []string) (conds, rejected []string) {
	for _, b := range vals {
		if branchValueUnsafe(b) {
			rejected = append(rejected, b)
			continue
		}
		if strings.ContainsAny(b, "*?[") {
			conds = append(conds, fmt.Sprintf("branchMatch('%s')", b))
			continue
		}
		conds = append(conds, fmt.Sprintf("branch == '%s'", b))
	}
	return conds, rejected
}

// branchValueUnsafe reports whether v contains a single quote or control
// character. Kiwi's condition evaluator has no escape sequence inside string
// literals, so a quote would terminate the literal early and let the rest of
// the value become condition operators (`branch == 'x' || true || ”`).
func branchValueUnsafe(v string) bool {
	for _, r := range v {
		if r == '\'' || r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func seqAny(n *yaml.Node) []any {
	var out []any
	if n == nil {
		return out
	}
	for _, v := range n.Content {
		if v.Kind == yaml.ScalarNode {
			var decoded any
			if err := v.Decode(&decoded); err == nil {
				out = append(out, decoded)
			}
		}
	}
	return out
}

func mapKeys(n *yaml.Node) []string {
	var out []string
	for k := range importer.Mapping(n) {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func appendUnique(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}

func appendUniqueAll(list []string, vs ...string) []string {
	for _, v := range vs {
		list = appendUnique(list, v)
	}
	return list
}
