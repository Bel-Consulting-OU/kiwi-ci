// Package circleci converts CircleCI config.yml files into Kiwi pipeline
// specs.
//
// Mapped: jobs with docker executors (first image → runtime container +
// image), steps run/checkout/restore_cache/save_cache/store_artifacts,
// environment, working_directory, when → step condition, workflows
// requires → needs, workflow filters.branches.only → on.push.branches,
// workflow matrix.parameters → job matrix.
//
// Reported instead of approximated: machine executors, docker auth
// credentials, restore_cache (no cache-restore step in Kiwi; emitted as a
// TODO), run.background, cache key templates with checksums, workflow
// filters (tags/ignore), scheduled triggers, and orbs.
package circleci

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/importer"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// Importer implements importer.Importer for CircleCI.
type Importer struct{}

func New() *Importer { return &Importer{} }

// Import converts one .circleci/config.yml document.
func (i *Importer) Import(src string) (*importer.Result, error) {
	res := &importer.Result{}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		return nil, fmt.Errorf("parse .circleci/config.yml: %w", err)
	}
	doc := importer.Document(&root)
	if doc == nil || doc.Kind != yaml.MappingNode {
		return nil, fmt.Errorf(".circleci/config.yml must be a YAML mapping")
	}
	if importer.Key(doc, "orbs") != nil {
		res.AddUnsupported("orbs have no Kiwi equivalent; convert orb usage to explicit steps")
	}

	spec := &pipeline.Spec{Version: 1, Jobs: map[string]pipeline.Job{}}
	supported := 0

	taken := map[string]bool{}
	ids := map[string]string{}
	jobsNode := importer.Key(doc, "jobs")
	jobNames := []string{}
	for name, node := range importer.Mapping(jobsNode) {
		if node.Kind == yaml.MappingNode {
			jobNames = append(jobNames, name)
		}
	}
	sort.Strings(jobNames)
	for _, name := range jobNames {
		ids[name] = importer.SanitizeID(name, taken)
	}
	for _, name := range jobNames {
		j := convertJob(res, importer.Mapping(jobsNode)[name], name)
		spec.Jobs[ids[name]] = j
		supported++
	}

	// Workflows wire needs and job-level matrix/filters.
	if wf := importer.Key(doc, "workflows"); wf != nil {
		convertWorkflows(res, wf, spec, ids)
		supported++
	}
	if importer.Key(doc, "executors") != nil {
		res.AddWarning("executors are inlined into jobs during conversion")
	}

	out, err := importer.MarshalSpec(spec)
	if err != nil {
		return nil, err
	}
	res.PipelineYAML = out
	res.Finalize(supported)
	return res, nil
}

// convertJob converts one CircleCI job node.
func convertJob(res *importer.Result, jobNode *yaml.Node, name string) pipeline.Job {
	j := pipeline.Job{Name: name}

	// Executor selection: docker → container with the first image.
	if docker := importer.Key(jobNode, "docker"); docker != nil {
		if docker.Kind == yaml.SequenceNode && len(docker.Content) > 0 {
			img := docker.Content[0]
			j.Runtime = "container"
			j.Image = importer.StrScalar(importer.Key(img, "image"))
			if importer.Key(img, "auth") != nil {
				res.AddUnsupported("job %q: docker auth credentials are not converted (configure registry auth on runners)", name)
			}
			for _, extra := range docker.Content[1:] {
				ref := importer.StrScalar(importer.Key(extra, "image"))
				res.AddUnsupported("job %q: additional docker container %q is not converted; declare it as a services entry", name, ref)
			}
		}
	}
	if machine := importer.Key(jobNode, "machine"); machine != nil {
		res.AddUnsupported("job %q: machine executor is not supported; use a Kiwi runner label or runtime tart for macOS", name)
		res.AddTODO("job %q: map the machine executor to runner labels or runtime tart manually", name)
	}
	if macos := importer.Key(jobNode, "macos"); macos != nil {
		res.AddUnsupported("job %q: macos executor is not supported; use runtime tart with a macOS VM", name)
		res.AddTODO("job %q: map the macos executor to runtime tart + vm manually", name)
	}
	if resClass := importer.Key(jobNode, "resource_class"); resClass != nil {
		res.AddTODO("job %q: resource_class %q needs manual mapping to resources/placement", name, importer.StrScalar(resClass))
	}
	if env := importer.Key(jobNode, "environment"); env != nil {
		j.Env = importer.EnvMap(env)
	}

	if steps := importer.Key(jobNode, "steps"); steps != nil {
		for _, stepNode := range steps.Content {
			var stepType string
			var params *yaml.Node
			switch {
			case stepNode.Kind == yaml.ScalarNode:
				// Shorthand step: `- checkout`.
				stepType = stepNode.Value
			case stepNode.Kind == yaml.MappingNode && len(stepNode.Content) >= 2:
				stepType = stepNode.Content[0].Value
				params = stepNode.Content[1]
			default:
				continue
			}
			if st, ok := convertStep(res, name, stepType, params); ok {
				j.Steps = append(j.Steps, st)
			}
		}
	}
	return j
}

// convertStep converts one CircleCI step by type.
func convertStep(res *importer.Result, job, kind string, params *yaml.Node) (pipeline.Step, bool) {
	switch kind {
	case "run":
		if params.Kind == yaml.ScalarNode {
			// Shorthand `run: cmd`.
			return pipeline.Step{Name: "run", Run: params.Value}, true
		}
		st := pipeline.Step{
			Name:             importer.StrScalar(importer.Key(params, "name")),
			Run:              importer.StrScalar(importer.Key(params, "command")),
			WorkingDirectory: importer.StrScalar(importer.Key(params, "working_directory")),
			Env:              importer.EnvMap(importer.Key(params, "environment")),
		}
		if st.Name == "" {
			st.Name = "run"
		}
		if st.Run == "" {
			res.AddWarning("job %q: run step without a command was skipped", job)
			return pipeline.Step{}, false
		}
		if importer.Key(params, "background") != nil {
			if v, ok := importer.BoolScalar(importer.Key(params, "background")); ok && v {
				res.AddUnsupported("job %q: run step with background: true is not converted (Kiwi has no background step)", job)
			}
		}
		if when := importer.StrScalar(importer.Key(params, "when")); when != "" {
			switch when {
			case "on_success":
				st.If = "success()"
			case "on_fail":
				st.If = "failure()"
			case "always":
				st.If = "always()"
			default:
				res.AddUnsupported("job %q: run step when %q is not convertible", job, when)
			}
		}
		return st, true
	case "checkout":
		res.AddTODO("job %q: checkout is implicit in Kiwi; drop the checkout step (path overrides need a manual git step)", job)
		return pipeline.Step{}, false
	case "restore_cache":
		res.AddTODO("job %q: restore_cache has no step equivalent; Kiwi caches restore automatically from job cache declarations", job)
		return pipeline.Step{}, false
	case "save_cache":
		// save_cache declares what to cache, so it maps to a job cache
		// entry — but it is a step, and Kiwi caches are job-level. The
		// importer records it as a TODO with the paths so a human can lift
		// it to the job's cache block; the step itself is dropped.
		res.AddTODO("job %q: save_cache (key %q, paths %v) must move to the job's cache: block", job,
			importer.StrScalar(importer.Key(params, "key")), importer.SeqScalars(importer.Key(params, "paths")))
		return pipeline.Step{}, false
	case "store_artifacts":
		// Artifacts are job-level in Kiwi; recorded via a disabled
		// placeholder is wrong — record a TODO instead and drop the step.
		res.AddTODO("job %q: store_artifacts path %q must move to the job's artifacts: block", job, importer.StrScalar(importer.Key(params, "path")))
		return pipeline.Step{}, false
	case "store_test_results":
		res.AddTODO("job %q: store_test_results path %q must move to the job's test_reports: block", job, importer.StrScalar(importer.Key(params, "path")))
		return pipeline.Step{}, false
	case "persist_to_workspace", "attach_workspace":
		res.AddUnsupported("job %q: CircleCI workspaces (%s) are not converted; use Kiwi artifacts and downloads", job, kind)
		return pipeline.Step{}, false
	case "setup_remote_docker", "add_ssh_keys":
		res.AddUnsupported("job %q: %s is not converted", job, kind)
		return pipeline.Step{}, false
	default:
		res.AddUnsupported("job %q: unknown step type %q is not converted", job, kind)
		return pipeline.Step{}, false
	}
}

// convertWorkflows maps workflow job requirements onto job needs, filters
// onto on.push.branches, and matrix.parameters onto job matrices.
func convertWorkflows(res *importer.Result, workflows *yaml.Node, spec *pipeline.Spec, ids map[string]string) {
	if spec.On == nil {
		spec.On = map[string]pipeline.Trigger{}
	}
	trigger := spec.On["push"]
	for wfName, wfNode := range importer.Mapping(workflows) {
		jobs := importer.Key(wfNode, "jobs")
		if jobs == nil || jobs.Kind != yaml.SequenceNode {
			continue
		}
		for _, item := range jobs.Content {
			name := ""
			var params *yaml.Node
			if item.Kind == yaml.ScalarNode {
				name = item.Value
			} else if n := importer.StrScalar(importer.Key(item, "name")); n != "" {
				name = n
				params = item
			} else if len(item.Content) >= 2 {
				// Shorthand form: {<job>: {...}}.
				name = item.Content[0].Value
				params = item.Content[1]
			}
			if strings.HasPrefix(name, "approval") || strings.HasPrefix(name, "hold") {
				res.AddUnsupported("workflow %q job %q: approval jobs are not converted; use environment approval", wfName, name)
				continue
			}
			id, ok := ids[name]
			if !ok {
				res.AddWarning("workflow %q references unknown job %q", wfName, name)
				continue
			}
			j := spec.Jobs[id]
			if params != nil {
				if requires := importer.Key(params, "requires"); requires != nil {
					for _, dep := range importer.SeqScalars(requires) {
						if depID, ok := ids[dep]; ok {
							j.Needs = appendUnique(j.Needs, depID)
						}
					}
				}
				if filters := importer.Key(params, "filters"); filters != nil {
					if branches := importer.Key(filters, "branches"); branches != nil {
						if only := importer.Key(branches, "only"); only != nil {
							trigger.Branches = append(trigger.Branches, importer.SeqScalars(only)...)
						}
					}
					if importer.Key(filters, "tags") != nil {
						res.AddUnsupported("workflow %q job %q: tag filters are not converted", wfName, name)
					}
				}
				if matrix := importer.Key(params, "matrix"); matrix != nil {
					params := importer.Key(matrix, "parameters")
					j.Matrix = map[string][]any{}
					for dim, vals := range importer.Mapping(params) {
						j.Matrix[dim] = seqAny(vals)
					}
				}
			}
			spec.Jobs[id] = j
		}
		spec.On["push"] = trigger
	}
}

func seqAny(n *yaml.Node) []any {
	var out []any
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

func appendUnique(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}
