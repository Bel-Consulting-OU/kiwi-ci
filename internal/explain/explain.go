// Package explain implements the `kiwi explain --why JOB` engine: it
// answers why a compiled job would (or would not) run for a given event,
// branch and change set, exposing every scheduling-relevant input in one
// pure data model.
package explain

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/forge"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/impact"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// Why is the explanation data model for one job.
type Why struct {
	JobID           string   `json:"job_id"`
	EventMatched    bool     `json:"event_matched"`
	BranchMatched   bool     `json:"branch_matched"`
	PathMatched     bool     `json:"path_matched"`
	TriggerKey      string   `json:"trigger_key,omitempty"`
	PathRule        string   `json:"path_rule,omitempty"`
	ChangedPaths    []string `json:"changed_paths,omitempty"`
	Packages        []string `json:"packages,omitempty"`
	Condition       string   `json:"condition,omitempty"`
	ConditionResult bool     `json:"condition_result"`
	Needs           []string `json:"needs,omitempty"`
	Approval        bool     `json:"approval"`
	RequiredLabels  []string `json:"required_labels,omitempty"`
	Regions         []string `json:"regions,omitempty"`
	CacheKeys       []string `json:"cache_keys,omitempty"`
	Policy          []string `json:"policy,omitempty"`
	QueueReason     string   `json:"queue_reason,omitempty"`
}

// ExplainContext is the event context the explanation is evaluated against.
type ExplainContext struct {
	Event        string
	Branch       string
	ChangedFiles []string
}

// ExplainWhy evaluates why compiled job jobID would run for ctx. spec and g
// must come from the same pipeline (compile it first). It is a pure
// function: no I/O, no mutable state.
func ExplainWhy(spec *pipeline.Spec, g *pipeline.Graph, jobID string, ctx ExplainContext) (*Why, error) {
	if spec == nil {
		return nil, fmt.Errorf("nil pipeline spec")
	}
	if g == nil {
		return nil, fmt.Errorf("nil pipeline graph")
	}
	cj, ok := g.Jobs[jobID]
	if !ok {
		return nil, fmt.Errorf("job %q not found (compiled jobs: %s)", jobID, strings.Join(sortedKeys(g.Jobs), ", "))
	}
	j := cj.Job
	w := &Why{
		JobID:          jobID,
		ChangedPaths:   append([]string(nil), ctx.ChangedFiles...),
		Condition:      j.If,
		Needs:          append([]string(nil), cj.Needs...),
		Approval:       j.Environment.Approval,
		RequiredLabels: labelsForJob(j),
		Regions:        append([]string(nil), j.Placement.Regions...),
		QueueReason:    "",
	}

	// Trigger evaluation reuses the forge evaluator so explain and the
	// webhook path decide identically.
	matched, triggerKey := forge.MatchesTrigger(spec.On, forge.EventContext{
		Event:        ctx.Event,
		Ref:          "refs/heads/" + ctx.Branch,
		ChangedFiles: ctx.ChangedFiles,
	})
	w.EventMatched = matched
	w.TriggerKey = triggerKey
	if matched {
		if trg, ok := spec.On[triggerKey]; ok && triggerKey != "" {
			w.BranchMatched = branchAllowed(ctx.Branch, trg.Branches, trg.BranchesIgnore)
		} else {
			w.BranchMatched = true
		}
	}

	// Job-level path filter is the authoritative rule for this job; the
	// trigger-level path rule is reported as a fallback.
	w.PathMatched = pipeline.PathsMatch(ctx.ChangedFiles, j.Paths, j.PathsIgnore)
	if rule, ok := firstMatchingPathRule(ctx.ChangedFiles, j.Paths, j.PathsIgnore); ok {
		w.PathRule = rule
	} else if matched {
		if trg, ok := spec.On[triggerKey]; ok && triggerKey != "" {
			if rule, ok := firstMatchingPathRule(ctx.ChangedFiles, trg.Paths, trg.PathsIgnore); ok {
				w.PathRule = rule
			}
		}
	}

	// Affected packages for the change set.
	if len(spec.Packages) > 0 {
		w.Packages = impact.New(spec.Packages).AffectedPackages(ctx.ChangedFiles)
	}

	// Condition evaluation with the shared pipeline evaluator (empty
	// condition defaults to success()). Event and branch contexts are
	// supplied so conditions like `branch == 'main'` evaluate.
	ok, condErr := pipeline.Eval(j.If, pipeline.EvalContext{Status: model.StatusSuccess, Event: ctx.Event, Branch: ctx.Branch})
	w.ConditionResult = condErr == nil && ok

	// Cache keys declared by the job.
	for _, c := range j.Cache {
		if c.Key != "" {
			w.CacheKeys = append(w.CacheKeys, c.Key)
		}
	}

	// Effective policy statements for the job.
	w.Policy = policyLines(j)

	return w, nil
}

// branchAllowed mirrors forge's ref matching for branch filters.
func branchAllowed(branch string, include, exclude []string) bool {
	if len(include) == 0 && len(exclude) == 0 {
		return true
	}
	if len(include) > 0 && !matchPattern(branch, include) {
		return false
	}
	return !matchPattern(branch, exclude)
}

func matchPattern(name string, patterns []string) bool {
	for _, ptn := range patterns {
		ptn = strings.TrimSpace(ptn)
		if ptn == "" {
			continue
		}
		if ptn == name {
			return true
		}
		if ok, err := path.Match(ptn, name); err == nil && ok {
			return true
		}
	}
	return false
}

// firstMatchingPathRule returns the first include pattern that matched a
// changed file, or "!(exclude)" semantics are not applied here — exclusion
// is handled by the PathsMatch caller.
func firstMatchingPathRule(changed, include, exclude []string) (string, bool) {
	if len(include) == 0 {
		return "", false
	}
	for _, f := range changed {
		f = strings.TrimPrefix(strings.ReplaceAll(f, "\\", "/"), "./")
		if pipeline.PathsMatch([]string{f}, include, exclude) {
			for _, ptn := range include {
				if pipeline.PathsMatch([]string{f}, []string{ptn}, nil) {
					return ptn, true
				}
			}
		}
	}
	return "", false
}

// labelsForJob mirrors the server's required-label computation so explain
// output matches what the control plane enforces.
func labelsForJob(j pipeline.Job) []string {
	set := map[string]bool{}
	rt := j.Runtime
	if rt == "" {
		rt = "native"
	}
	set[rt] = true
	if rt == "tart" {
		set["os:darwin"] = true
	}
	for _, l := range j.Runner {
		if l != "" {
			set[l] = true
		}
	}
	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// policyLines renders the job's effective admission policy as stable,
// human-readable statements.
func policyLines(j pipeline.Job) []string {
	lines := []string{}
	network := j.Network
	if network == "" {
		network = "bridge"
	}
	lines = append(lines, "network="+network)
	if j.Sandbox.ReadOnlyRootFS {
		lines = append(lines, "sandbox.read_only_rootfs=true")
	}
	if j.Sandbox.Rootless {
		lines = append(lines, "sandbox.rootless=true")
	}
	if j.Permissions.IDToken {
		lines = append(lines, "oidc.id_token=true")
	}
	sort.Strings(lines)
	return lines
}

func sortedKeys(m map[string]pipeline.CompiledJob) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
