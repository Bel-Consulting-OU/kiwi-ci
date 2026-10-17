package woodpecker

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/importer"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// Verdict is the migration verdict for one Woodpecker document. Exactly one
// verdict is reported per document; the four values are the whole vocabulary.
type Verdict string

const (
	// VerdictExact: every recognized construct maps 1:1; no difference,
	// unsupported semantic, or unsafe construct was found.
	VerdictExact Verdict = "EXACT"
	// VerdictCompatible: the document migrates, with explicit differences
	// that a human must accept or adjust (reported individually).
	VerdictCompatible Verdict = "COMPATIBLE WITH EXPLICIT DIFFERENCES"
	// VerdictUnsupported: at least one construct has no Kiwi equivalent and
	// was dropped; the migration is incomplete.
	VerdictUnsupported Verdict = "UNSUPPORTED"
	// VerdictUnsafe: at least one construct would change the security
	// posture if migrated (privileged, host mounts, trusted-network
	// options). Do not migrate without a security review.
	VerdictUnsafe Verdict = "UNSAFE TO MIGRATE"
)

// TraceSchema identifies the normalized corpus trace encoding.
const TraceSchema = "kiwi.woodpecker-compat-trace/v1"

// Trace is the normalized import trace asserted by the compatibility corpus
// and printed by `kiwi migrate woodpecker`. It records the trigger, the job
// graph, the step order, env, and skip/fail states together with every
// report the importer produced.
type Trace struct {
	Schema  string  `json:"schema"`
	Source  string  `json:"source"`
	Verdict Verdict `json:"verdict"`

	Trigger TriggerView `json:"trigger"`
	// DefinitionOrder lists the source step names in YAML definition order.
	DefinitionOrder []string `json:"definition_order"`
	// StepOrder lists the Kiwi job ids in execution order (topological,
	// ties broken by definition order).
	StepOrder []string `json:"step_order"`
	// Graph maps each Kiwi job id to its needs edges (sorted).
	Graph map[string][]string `json:"graph"`
	Jobs  map[string]JobView  `json:"jobs"`
	// Env maps each job id to its environment (sorted keys on render).
	Env map[string]map[string]string `json:"env"`
	// SkipStates maps each job id to how it can be skipped:
	// "run" | "condition_gated" | "disabled_placeholder".
	SkipStates map[string]string `json:"skip_states"`
	// FailStates maps each job id to its error behavior:
	// "abort_on_error" | "continue_on_error" | "run_on_failure".
	FailStates map[string]string `json:"fail_states"`
	// Matrix maps each job id to its matrix dimensions.
	Matrix map[string]map[string][]any `json:"matrix,omitempty"`

	Exact       []string `json:"exact"`
	Differences []string `json:"differences"`
	Unsupported []string `json:"unsupported"`
	Unsafe      []string `json:"unsafe"`
	TODOs       []string `json:"todos"`
	Warnings    []string `json:"warnings"`
	Confidence  float64  `json:"confidence"`
}

// TriggerView is the normalized trigger of the imported pipeline.
type TriggerView struct {
	Events   []string `json:"events"`
	Branches []string `json:"branches"`
}

// JobView is the normalized view of one imported job.
type JobView struct {
	Name     string   `json:"name"`
	Needs    []string `json:"needs"`
	Image    string   `json:"image,omitempty"`
	Runtime  string   `json:"runtime,omitempty"`
	If       string   `json:"if,omitempty"`
	Paths    []string `json:"paths,omitempty"`
	Secrets  []string `json:"secrets,omitempty"`
	Steps    []string `json:"steps,omitempty"`
	Services []string `json:"services,omitempty"`
}

// Compat is the full compatibility evaluation of one Woodpecker document.
type Compat struct {
	Verdict      Verdict
	Confidence   float64
	Exact        []string
	Differences  []string
	Unsupported  []string
	Unsafe       []string
	TODOs        []string
	Warnings     []string
	Trace        *Trace
	PipelineYAML string
}

// Evaluate runs the Woodpecker importer over src and classifies the result.
func Evaluate(src string) (*Compat, error) {
	res, err := New().Import(src)
	if err != nil {
		return nil, err
	}
	spec, perr := pipeline.Parse([]byte(res.PipelineYAML))
	if perr != nil {
		return nil, fmt.Errorf("importer output does not parse: %w", perr)
	}
	trace := buildTrace(src, res, spec)
	// Differences are the compatible-with-diffs report items: TODOs that a
	// human must accept, plus non-fatal warnings.
	differences := append([]string{}, res.TODOs...)
	differences = append(differences, res.Warnings...)
	c := &Compat{
		Confidence:   res.Confidence,
		Exact:        append([]string{}, res.Mapped...),
		Differences:  differences,
		Unsupported:  append([]string{}, res.Unsupported...),
		Unsafe:       append([]string{}, res.Unsafe...),
		TODOs:        append([]string{}, res.TODOs...),
		Warnings:     append([]string{}, res.Warnings...),
		PipelineYAML: res.PipelineYAML,
		Trace:        trace,
	}
	c.Verdict = classify(c)
	trace.Verdict = c.Verdict
	return c, nil
}

// EvaluateFile reads path and evaluates it.
func EvaluateFile(path string) (*Compat, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := Evaluate(string(data))
	if err != nil {
		return nil, err
	}
	c.Trace.Source = path
	return c, nil
}

// classify derives the single verdict from the report lists. Precedence:
// unsafe > unsupported > differences > exact.
func classify(c *Compat) Verdict {
	if len(c.Unsafe) > 0 {
		return VerdictUnsafe
	}
	if len(c.Unsupported) > 0 {
		return VerdictUnsupported
	}
	if len(c.Differences) > 0 {
		return VerdictCompatible
	}
	return VerdictExact
}

// buildTrace normalizes the import into the corpus trace shape.
func buildTrace(src string, res *importer.Result, spec *pipeline.Spec) *Trace {
	t := &Trace{
		Schema:      TraceSchema,
		Graph:       map[string][]string{},
		Jobs:        map[string]JobView{},
		Env:         map[string]map[string]string{},
		SkipStates:  map[string]string{},
		FailStates:  map[string]string{},
		Exact:       sortedCopy(res.Mapped),
		Differences: sortedCopy(append(append([]string{}, res.TODOs...), res.Warnings...)),
		Unsupported: sortedCopy(res.Unsupported),
		Unsafe:      sortedCopy(res.Unsafe),
		TODOs:       sortedCopy(res.TODOs),
		Warnings:    sortedCopy(res.Warnings),
		Confidence:  res.Confidence,
	}

	// Definition order comes from the source document's step block.
	if stepsNode := firstKeyNode(src, "steps", "pipeline"); stepsNode != nil {
		for _, s := range orderedSteps(stepsNode) {
			t.DefinitionOrder = append(t.DefinitionOrder, s.name)
		}
	}

	if spec.On != nil {
		for ev, tr := range spec.On {
			t.Trigger.Events = append(t.Trigger.Events, ev)
			t.Trigger.Branches = append(t.Trigger.Branches, tr.Branches...)
		}
		sort.Strings(t.Trigger.Events)
		t.Trigger.Branches = sortedCopy(t.Trigger.Branches)
	}

	defIndex := map[string]int{}
	for i, n := range t.DefinitionOrder {
		defIndex[n] = i
	}
	idIndex := map[string]int{}
	for id, j := range spec.Jobs {
		needs := sortedCopy(j.Needs)
		t.Graph[id] = needs
		secrets := []string{}
		stepNames := []string{}
		for _, st := range j.Steps {
			stepNames = append(stepNames, st.Name)
			secrets = append(secrets, st.Secrets...)
		}
		var svcNames []string
		for _, s := range j.Services {
			svcNames = append(svcNames, s.Name)
		}
		t.Jobs[id] = JobView{
			Name:     j.Name,
			Needs:    needs,
			Image:    j.Image,
			Runtime:  j.Runtime,
			If:       j.If,
			Paths:    sortedCopy(j.Paths),
			Secrets:  sortedCopy(secrets),
			Steps:    stepNames,
			Services: sortedCopy(svcNames),
		}
		if len(j.Env) > 0 {
			t.Env[id] = j.Env
		}
		if len(j.Matrix) > 0 {
			if t.Matrix == nil {
				t.Matrix = map[string]map[string][]any{}
			}
			t.Matrix[id] = j.Matrix
		}
		t.SkipStates[id] = skipState(j)
		t.FailStates[id] = failState(j)
		idIndex[id] = defIndex[j.Name]
	}
	t.StepOrder = topoOrder(spec.Jobs, idIndex)
	return t
}

// skipState classifies how an imported job can be skipped.
func skipState(j pipeline.Job) string {
	for _, st := range j.Steps {
		if st.If == "false" {
			return "disabled_placeholder"
		}
	}
	if j.If != "" {
		return "condition_gated"
	}
	return "run"
}

// failState classifies the imported job's error behavior.
func failState(j pipeline.Job) string {
	for _, st := range j.Steps {
		if st.If == "failure()" || st.If == "always()" || strings.Contains(st.If, "failure()") || strings.Contains(st.If, "always()") {
			return "run_on_failure"
		}
	}
	if strings.Contains(j.If, "failure()") || strings.Contains(j.If, "always()") {
		return "run_on_failure"
	}
	for _, st := range j.Steps {
		if st.ContinueOnError {
			return "continue_on_error"
		}
	}
	return "abort_on_error"
}

// topoOrder returns job ids in execution order: dependencies first, ties
// broken by the source definition index then id.
func topoOrder(jobs map[string]pipeline.Job, idIndex map[string]int) []string {
	indeg := map[string]int{}
	reverse := map[string][]string{}
	ids := make([]string, 0, len(jobs))
	for id := range jobs {
		ids = append(ids, id)
		indeg[id] = 0
	}
	for id, j := range jobs {
		for _, n := range j.Needs {
			if _, ok := jobs[n]; !ok {
				continue
			}
			reverse[n] = append(reverse[n], id)
			indeg[id]++
		}
	}
	sort.Slice(ids, func(a, b int) bool {
		ia, ib := idIndex[ids[a]], idIndex[ids[b]]
		if ia != ib {
			return ia < ib
		}
		return ids[a] < ids[b]
	})
	var ready []string
	for _, id := range ids {
		if indeg[id] == 0 {
			ready = append(ready, id)
		}
	}
	// Insert-sorted ready list: each pop is O(1) from the front and each
	// new node is inserted in idIndex order. Re-sorting the whole ready set
	// on every pop was O(V² log V) on wide graphs.
	sortReady := func() {
		sort.SliceStable(ready, func(a, b int) bool {
			ia, ib := idIndex[ready[a]], idIndex[ready[b]]
			if ia != ib {
				return ia < ib
			}
			return ready[a] < ready[b]
		})
	}
	sortReady()
	out := make([]string, 0, len(jobs))
	for len(ready) > 0 {
		id := ready[0]
		ready = ready[1:]
		out = append(out, id)
		added := false
		for _, dep := range reverse[id] {
			indeg[dep]--
			if indeg[dep] != 0 {
				continue
			}
			// Append in bulk and sort once per pop that added nodes. A
			// per-insert sorted splice was O(|ready|) memmove each time →
			// O(V²) on a wide DAG (one parent, V−1 children).
			ready = append(ready, dep)
			added = true
		}
		if added {
			sortReady()
		}
	}
	// Cycles cannot occur (pipeline.Parse rejects them) but never drop jobs.
	if len(out) < len(jobs) {
		present := make(map[string]bool, len(out))
		for _, o := range out {
			present[o] = true
		}
		for _, id := range ids {
			if !present[id] {
				out = append(out, id)
			}
		}
	}
	return out
}

// firstKeyNode returns the YAML node of the first present key among names.
func firstKeyNode(src string, names ...string) *yaml.Node {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		return nil
	}
	doc := importer.Document(&root)
	for _, n := range names {
		if k := importer.Key(doc, n); k != nil {
			return k
		}
	}
	return nil
}

func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

// FormatReport renders the compatibility report for CLI output.
func FormatReport(w interface{ WriteString(string) (int, error) }, c *Compat) error {
	line := func(s string) {
		_, _ = w.WriteString(s)
	}
	line(fmt.Sprintf("verdict: %s\n", c.Verdict))
	if len(c.Exact) > 0 {
		line("exact:\n")
		for _, s := range c.Exact {
			line("  - " + s + "\n")
		}
	}
	if len(c.Differences) > 0 {
		line("differences:\n")
		for _, s := range c.Differences {
			line("  - " + s + "\n")
		}
	}
	if len(c.Unsupported) > 0 {
		line("unsupported:\n")
		for _, s := range c.Unsupported {
			line("  - " + s + "\n")
		}
	}
	if len(c.Unsafe) > 0 {
		line("unsafe:\n")
		for _, s := range c.Unsafe {
			line("  - " + s + "\n")
		}
	}
	if len(c.TODOs) > 0 {
		line("todos:\n")
		for _, s := range c.TODOs {
			line("  - " + s + "\n")
		}
	}
	line(fmt.Sprintf("confidence: %.0f%%\n", c.Confidence*100))
	return nil
}
