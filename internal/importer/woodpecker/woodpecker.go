// Package woodpecker converts Woodpecker .woodpecker.yml files into Kiwi
// pipeline specs.
//
// Mapped: pipeline steps (image → runtime container + image, commands →
// run steps, environment → env, secrets → step secrets, when.branch →
// condition, when.path → paths, depends_on → needs, job matrix), top-level
// branches filters (→ on.push.branches).
//
// Reported instead of approximated: plugin steps (image plugins/* with
// settings), pipeline-level matrix (applies to the whole pipeline), when
// events other than push, groups, and top-level clone/skip_clone settings.
package woodpecker

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/importer"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// Importer implements importer.Importer for Woodpecker.
type Importer struct{}

func New() *Importer { return &Importer{} }

// Import converts one .woodpecker.yml document.
func (i *Importer) Import(src string) (*importer.Result, error) {
	res := &importer.Result{}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		return nil, fmt.Errorf("parse .woodpecker.yml: %w", err)
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
		supported++
	}
	if importer.Key(doc, "matrix") != nil {
		res.AddUnsupported("pipeline-level matrix is not converted (Kiwi matrices are per-job); split the pipeline into matrix jobs manually")
	}
	if clone := importer.Key(doc, "clone"); clone != nil {
		res.AddTODO("clone settings (%s) are runner-managed in Kiwi", strings.Join(mapKeys(clone), ","))
	}
	if importer.Key(doc, "skip_clone") != nil {
		res.AddTODO("skip_clone is runner-managed in Kiwi")
	}

	stepsNode := importer.Key(doc, "pipeline")
	if stepsNode == nil {
		stepsNode = importer.Key(doc, "steps")
	}
	steps := importer.Mapping(stepsNode)
	names := make([]string, 0, len(steps))
	for name := range steps {
		names = append(names, name)
	}
	sort.Strings(names)

	taken := map[string]bool{}
	ids := map[string]string{}
	for _, name := range names {
		ids[name] = importer.SanitizeID(name, taken)
	}
	for _, name := range names {
		j := convertStepBlock(res, steps[name], name)
		spec.Jobs[ids[name]] = j
		supported++
	}
	// Second pass resolves depends_on once all ids exist.
	for _, name := range names {
		j := spec.Jobs[ids[name]]
		if deps := importer.Key(steps[name], "depends_on"); deps != nil {
			for _, dep := range importer.SeqScalars(deps) {
				if id, ok := ids[dep]; ok {
					j.Needs = appendUnique(j.Needs, id)
				}
			}
		}
		spec.Jobs[ids[name]] = j
	}

	out, err := importer.MarshalSpec(spec)
	if err != nil {
		return nil, err
	}
	res.PipelineYAML = out
	res.Finalize(supported)
	return res, nil
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
		}
	}
	if env := importer.Key(node, "environment"); env != nil {
		j.Env = importer.EnvMap(env)
	}
	if cmds := importer.Key(node, "commands"); cmds != nil {
		j.Steps = append(j.Steps, pipeline.Step{Name: "commands", Run: strings.Join(importer.SeqScalars(cmds), "\n")})
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
	if secrets := importer.Key(node, "secrets"); secrets != nil {
		// Woodpecker secrets become step secret declarations.
		if len(j.Steps) > 0 {
			j.Steps[len(j.Steps)-1].Secrets = importer.SeqScalars(secrets)
		} else {
			res.AddTODO("step %q declares secrets (%s) but has no commands step to attach them to", name, strings.Join(importer.SeqScalars(secrets), ","))
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
	}
	if importer.Key(node, "group") != nil {
		res.AddUnsupported("step %q: group has no Kiwi equivalent; use concurrency groups or placement labels", name)
	}
	if importer.Key(node, "detach") != nil || importer.Key(node, "privileged") != nil {
		res.AddUnsupported("step %q: detach/privileged flags are not converted (Kiwi sandbox policies differ)", name)
	}
	return j
}

// convertWhen maps Woodpecker `when` filters: branch lists become Kiwi
// conditions, path lists become job paths, events other than push are
// reported.
func convertWhen(res *importer.Result, when *yaml.Node, name string, j *pipeline.Job) {
	if branches := importer.Key(when, "branch"); branches != nil {
		vals := importer.SeqScalars(branches)
		if len(vals) == 1 {
			j.If = fmt.Sprintf("branch == '%s'", vals[0])
		} else if len(vals) > 1 {
			parts := make([]string, 0, len(vals))
			for _, b := range vals {
				parts = append(parts, fmt.Sprintf("branch == '%s'", b))
			}
			j.If = "(" + strings.Join(parts, " || ") + ")"
		}
	}
	if paths := importer.Key(when, "path"); paths != nil {
		j.Paths = append(j.Paths, importer.SeqScalars(paths)...)
	}
	if events := importer.Key(when, "event"); events != nil {
		ev := importer.SeqScalars(events)
		nonPush := false
		for _, e := range ev {
			if e != "push" {
				nonPush = true
			}
		}
		if nonPush {
			res.AddUnsupported("step %q: when.event (%s) is not converted; Kiwi triggers on push webhooks", name, strings.Join(ev, ","))
		}
	}
	if importer.Key(when, "repo") != nil || importer.Key(when, "platform") != nil {
		res.AddUnsupported("step %q: when.repo/platform filters are not converted", name)
	}
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
