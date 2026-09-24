// Package gitlab converts .gitlab-ci.yml files into Kiwi pipeline specs.
//
// Mapped: stages (→ needs ordering), image (→ runtime container + image),
// variables (→ env), script/before_script (→ steps), tags (→ runner
// labels), cache (→ cache), artifacts (→ artifacts), rules (changes → job
// paths, when: never → if "false"), needs, allow_failure (→ step
// continue_on_error), retry (→ job retry), timeout, environment,
// services (simple name/image entries).
//
// Reported instead of approximated: rules referencing predefined
// variables ($CI_COMMIT_*), after_script, job-level allow_failure result
// semantics, when: manual/delayed, `needs` artifact/output fan-in, and
// non-container images (e.g. shell executors are assumed unavailable).
package gitlab

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/importer"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// Importer implements importer.Importer for GitLab CI.
type Importer struct{}

func New() *Importer { return &Importer{} }

// Import converts one .gitlab-ci.yml document.
func (i *Importer) Import(src string) (*importer.Result, error) {
	res := &importer.Result{}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		return nil, fmt.Errorf("parse .gitlab-ci.yml: %w", err)
	}
	doc := importer.Document(&root)
	if doc == nil || doc.Kind != yaml.MappingNode {
		return nil, fmt.Errorf(".gitlab-ci.yml must be a YAML mapping")
	}

	spec := &pipeline.Spec{Version: 1, Jobs: map[string]pipeline.Job{}}
	supported := 0

	// Global variables become pipeline env.
	if vars := importer.Key(doc, "variables"); vars != nil {
		spec.Env = importer.EnvMap(vars)
		supported++
	}
	// The global default image applies to jobs without their own image.
	defaultImage := ""
	if img := importer.Key(doc, "image"); img != nil {
		defaultImage = imageRef(img)
		supported++
	}
	if def := importer.Key(doc, "default"); def != nil {
		if img := importer.Key(def, "image"); img != nil && defaultImage == "" {
			defaultImage = imageRef(img)
		}
		if c := importer.Key(def, "cache"); c != nil {
			res.AddTODO("top-level default.cache needs per-job conversion; add cache: blocks to each job")
		}
	}
	// Global cache applies to every job.
	var globalCache *pipeline.Cache
	if c := importer.Key(doc, "cache"); c != nil {
		cache, ok := convertCache(res, c)
		if ok {
			globalCache = &cache
		}
		supported++
	}
	// Workflow-level rules are advisory; only warn.
	if wf := importer.Key(doc, "workflow"); wf != nil {
		res.AddWarning("workflow: rules are not converted; Kiwi triggering is configured server-side (on: triggers)")
	}

	// Stages define the implicit needs ordering.
	stageOrder := []string{}
	if st := importer.Key(doc, "stages"); st != nil {
		stageOrder = importer.SeqScalars(st)
		supported++
	}

	jobNames := []string{}
	for name, node := range importer.Mapping(doc) {
		if reservedKeywords[name] {
			continue
		}
		if node.Kind == yaml.MappingNode {
			jobNames = append(jobNames, name)
		}
	}
	sort.Strings(jobNames)
	stageOf := map[string]string{}
	for _, name := range jobNames {
		stageOf[name] = importer.StrScalar(importer.Key(importer.Mapping(doc)[name], "stage"))
	}
	if len(stageOrder) == 0 {
		// Derive stage order from first-seen job order.
		seen := map[string]bool{}
		for _, name := range jobNames {
			s := stageOf[name]
			if s == "" {
				s = "test"
			}
			if !seen[s] {
				stageOrder = append(stageOrder, s)
				seen[s] = true
			}
		}
	}
	stageIndex := map[string]int{}
	for idx, s := range stageOrder {
		stageIndex[s] = idx
	}

	taken := map[string]bool{}
	ids := map[string]string{}
	for _, name := range jobNames {
		ids[name] = importer.SanitizeID(name, taken)
	}
	stageJobs := map[string][]string{}
	for _, name := range jobNames {
		s := stageOf[name]
		if s == "" {
			s = "test"
		}
		stageJobs[s] = append(stageJobs[s], name)
	}

	for _, name := range jobNames {
		jobNode := importer.Mapping(doc)[name]
		j := convertJob(res, jobNode, name, defaultImage, ids)
		// Implicit needs: all jobs in earlier stages.
		explicitNeeds := importer.Key(jobNode, "needs")
		if explicitNeeds == nil {
			s := stageOf[name]
			if s == "" {
				s = "test"
			}
			idx := stageIndex[s]
			for si := 0; si < idx; si++ {
				for _, dep := range stageJobs[stageOrder[si]] {
					j.Needs = append(j.Needs, ids[dep])
				}
			}
		}
		if globalCache != nil && len(j.Cache) == 0 {
			j.Cache = []pipeline.Cache{*globalCache}
		}
		spec.Jobs[ids[name]] = j
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

// reservedKeywords are the top-level .gitlab-ci.yml keywords that are not
// job definitions.
var reservedKeywords = map[string]bool{
	"stages": true, "variables": true, "default": true, "image": true,
	"cache": true, "workflow": true, "include": true, "before_script": true,
	"after_script": true, "services": true,
}

// imageRef extracts the image reference from an image node (string form or
// {name: ...} form).
func imageRef(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	if n.Kind == yaml.ScalarNode {
		return n.Value
	}
	return importer.StrScalar(importer.Key(n, "name"))
}

// convertJob converts one GitLab job node.
func convertJob(res *importer.Result, jobNode *yaml.Node, name, defaultImage string, ids map[string]string) pipeline.Job {
	j := pipeline.Job{Name: name}

	if img := importer.Key(jobNode, "image"); img != nil {
		j.Runtime = "container"
		j.Image = imageRef(img)
	} else if defaultImage != "" {
		j.Runtime = "container"
		j.Image = defaultImage
	}
	if tags := importer.Key(jobNode, "tags"); tags != nil {
		j.Runner = importer.SeqScalars(tags)
	}
	if vars := importer.Key(jobNode, "variables"); vars != nil {
		j.Env = importer.EnvMap(vars)
	}
	if needs := importer.Key(jobNode, "needs"); needs != nil {
		needsJob := func(n *yaml.Node) string {
			if n.Kind == yaml.ScalarNode {
				if id, ok := ids[n.Value]; ok {
					return id
				}
			}
			if ref := importer.StrScalar(importer.Key(n, "job")); ref != "" {
				if id, ok := ids[ref]; ok {
					return id
				}
			}
			return ""
		}
		if needs.Kind == yaml.SequenceNode {
			for _, item := range needs.Content {
				if id := needsJob(item); id != "" && !contains(j.Needs, id) {
					j.Needs = append(j.Needs, id)
				}
			}
		} else if id := needsJob(needs); id != "" {
			j.Needs = append(j.Needs, id)
		}
		if needsArtifacts(needs) {
			res.AddTODO("job %q: `needs` artifact/output fan-in is not converted; Kiwi consumes outputs via needs_outputs", name)
		}
	}
	if to := importer.Key(jobNode, "timeout"); to != nil {
		if d, ok := parseGitLabDuration(importer.StrScalar(to)); ok {
			j.Timeout = pipeline.Duration{Duration: d, Set: true}
		}
	}
	if retry := importer.Key(jobNode, "retry"); retry != nil {
		convertRetry(res, retry, name, &j)
	}
	allowFailure := false
	if af := importer.Key(jobNode, "allow_failure"); af != nil {
		if v, ok := importer.BoolScalar(af); ok && v {
			res.AddUnsupported("job %q: allow_failure marks the job successful on failure; Kiwi has no job-level equivalent (steps get continue_on_error)", name)
			res.AddTODO("job %q: review allow_failure: steps were given continue_on_error, but the job result semantics differ", name)
			allowFailure = true
		}
	}
	if rules := importer.Key(jobNode, "rules"); rules != nil {
		convertRules(res, rules, name, &j)
	}
	if cache := importer.Key(jobNode, "cache"); cache != nil {
		if c, ok := convertCache(res, cache); ok {
			j.Cache = append(j.Cache, c)
		}
	}
	if arts := importer.Key(jobNode, "artifacts"); arts != nil {
		convertArtifacts(res, arts, name, &j)
	}
	if env := importer.Key(jobNode, "environment"); env != nil {
		if env.Kind == yaml.ScalarNode {
			j.Environment.Name = env.Value
		} else {
			j.Environment.Name = importer.StrScalar(importer.Key(env, "name"))
			j.Environment.URL = importer.StrScalar(importer.Key(env, "url"))
		}
	}
	if svcs := importer.Key(jobNode, "services"); svcs != nil {
		convertServices(res, svcs, name, &j)
	}

	if script := importer.Key(jobNode, "script"); script != nil {
		j.Steps = scriptSteps(script)
	}
	if before := importer.Key(jobNode, "before_script"); before != nil {
		j.Steps = append(scriptSteps(before), j.Steps...)
	}
	if allowFailure {
		for i := range j.Steps {
			j.Steps[i].ContinueOnError = true
		}
	}
	if after := importer.Key(jobNode, "after_script"); after != nil {
		res.AddUnsupported("job %q: after_script has no Kiwi equivalent (no guaranteed-on-failure phase); emitted as a TODO", name)
		res.AddTODO("job %q: move after_script cleanup into explicit steps", name)
	}
	if importer.Key(jobNode, "when") != nil {
		res.AddUnsupported("job %q: when: manual/delayed has no Kiwi equivalent; use environment approval", name)
	}
	return j
}

// scriptSteps renders a GitLab script sequence as one Kiwi step per line
// (script arrays execute line-by-line in one shell, matching a single step
// with a joined command).
func scriptSteps(script *yaml.Node) []pipeline.Step {
	lines := importer.SeqScalars(script)
	if len(lines) == 0 {
		return nil
	}
	return []pipeline.Step{{Name: "script", Run: strings.Join(lines, "\n")}}
}

func convertRetry(res *importer.Result, retry *yaml.Node, job string, j *pipeline.Job) {
	if retry.Kind == yaml.ScalarNode {
		if n, ok := importer.IntScalar(retry); ok {
			j.Retry = pipeline.Retry{Max: n}
		}
		return
	}
	if max := importer.Key(retry, "max"); max != nil {
		if n, ok := importer.IntScalar(max); ok {
			j.Retry = pipeline.Retry{Max: n}
		}
	}
	if when := importer.Key(retry, "when"); when != nil {
		// GitLab retry.when triggers retries on infrastructure failures;
		// Kiwi's infra_retries is the equivalent, retry.on the closest for
		// command failures.
		res.AddTODO("job %q: retry.when (%s) maps loosely to infra_retries; verify the intended failure class", job, strings.Join(importer.SeqScalars(when), ","))
	}
}

// convertRules maps the subset of GitLab rules Kiwi can express: an
// unguarded when: never → if "false"; changes → job paths. Rules using
// predefined variables ($CI_*) are reported, never approximated.
//
// A when: never that carries a guard (a sibling changes/if, or any earlier
// rule that had a condition) is NOT an unconditional "never": GitLab
// evaluates rules top-to-bottom and the guard decides whether the never
// applies. Forcing if "false" there silently disables a job the source would
// run on the guarded condition, so the rule is reported and no If is set.
func convertRules(res *importer.Result, rules *yaml.Node, job string, j *pipeline.Job) {
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return
	}
	sawGuard := false
	for _, rule := range rules.Content {
		if rule.Kind != yaml.MappingNode {
			continue
		}
		if ifc := importer.StrScalar(importer.Key(rule, "if")); ifc != "" {
			res.AddUnsupported("job %q: rule `if: %s` uses GitLab predefined variables Kiwi cannot evaluate; review by hand", job, ifc)
			sawGuard = true
			continue
		}
		changes := importer.Key(rule, "changes")
		if when := importer.StrScalar(importer.Key(rule, "when")); when == "never" {
			if guard := ruleGuardKeys(rule); len(guard) > 0 || sawGuard {
				detail := "an earlier rule"
				if len(guard) > 0 {
					detail = "its sibling " + strings.Join(guard, "/")
				}
				res.AddUnsupported("job %q: `when: never` is guarded by %s; Kiwi cannot express a conditional exclusion, so the job's `if` was left unset", job, detail)
				res.AddTODO("job %q: decide whether this job should ever run and set `if` explicitly by hand", job)
				continue
			}
			j.If = "false"
		}
		if changes != nil {
			j.Paths = append(j.Paths, importer.SeqScalars(changes)...)
			sawGuard = true
		}
	}
}

// ruleGuardKeys returns the rule keys other than "when" (sorted). A when:
// never rule with any other key is a guarded rule, not an unconditional
// disable.
func ruleGuardKeys(rule *yaml.Node) []string {
	var out []string
	for i := 0; i+1 < len(rule.Content); i += 2 {
		if rule.Content[i].Value != "when" {
			out = append(out, rule.Content[i].Value)
		}
	}
	sort.Strings(out)
	return out
}

func convertCache(res *importer.Result, c *yaml.Node) (pipeline.Cache, bool) {
	var out pipeline.Cache
	out.Paths = importer.SeqScalars(importer.Key(c, "paths"))
	if out.Paths == nil {
		if c.Kind == yaml.SequenceNode {
			for _, item := range c.Content {
				out.Paths = append(out.Paths, importer.SeqScalars(importer.Key(item, "paths"))...)
			}
		}
	}
	if k := importer.Key(c, "key"); k != nil {
		if k.Kind == yaml.ScalarNode {
			out.Key = k.Value
		} else if files := importer.Key(k, "files"); files != nil {
			out.Key = "gitlab-" + strings.Join(importer.SeqScalars(files), "+")
			out.HashFiles = importer.SeqScalars(files)
		}
	}
	if out.Key == "" {
		out.Key = "default"
	}
	if len(out.Paths) == 0 {
		res.AddUnsupported("cache entry with no paths was dropped")
		return pipeline.Cache{}, false
	}
	return out, true
}

func convertArtifacts(res *importer.Result, arts *yaml.Node, job string, j *pipeline.Job) {
	paths := importer.SeqScalars(importer.Key(arts, "paths"))
	if len(paths) == 0 {
		res.AddUnsupported("job %q: artifacts with no paths were dropped", job)
		return
	}
	a := pipeline.Artifact{Paths: paths}
	if name := importer.StrScalar(importer.Key(arts, "name")); name != "" {
		a.Name = name
	} else {
		a.Name = job + "-artifacts"
	}
	if exp := importer.StrScalar(importer.Key(arts, "expire_in")); exp != "" {
		res.AddTODO("job %q: artifacts.expire_in %q needs manual mapping to artifact retention", job, exp)
	}
	j.Artifacts = append(j.Artifacts, a)
}

func convertServices(res *importer.Result, svcs *yaml.Node, job string, j *pipeline.Job) {
	for _, item := range svcs.Content {
		var name, image string
		if item.Kind == yaml.ScalarNode {
			image = item.Value
			name = strings.SplitN(image, ":", 2)[0]
		} else {
			image = importer.StrScalar(importer.Key(item, "name"))
			name = importer.StrScalar(importer.Key(item, "alias"))
			if name == "" {
				name = strings.SplitN(image, ":", 2)[0]
			}
			if importer.Key(item, "command") != nil {
				res.AddTODO("job %q: service %q has a custom command that needs a dedicated service image", job, name)
			}
		}
		if image == "" {
			res.AddUnsupported("job %q: a service with no image was dropped", job)
			continue
		}
		j.Services = append(j.Services, pipeline.Service{Name: name, Image: image})
	}
}

// parseGitLabDuration converts GitLab timeout syntax ("1h", "30m",
// "1h 30m") into a time.Duration.
func parseGitLabDuration(s string) (time.Duration, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	var total time.Duration
	for _, part := range strings.Fields(s) {
		if len(part) < 2 {
			return 0, false
		}
		n, err := strconv.Atoi(part[:len(part)-1])
		if err != nil || n < 0 {
			return 0, false
		}
		switch part[len(part)-1] {
		case 'h':
			total += time.Duration(n) * time.Hour
		case 'm':
			total += time.Duration(n) * time.Minute
		case 's':
			total += time.Duration(n) * time.Second
		default:
			return 0, false
		}
	}
	return total, true
}

func needsArtifacts(needs *yaml.Node) bool {
	if needs == nil || needs.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range needs.Content {
		if importer.Key(item, "artifacts") != nil || importer.Key(item, "optional") != nil {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}
