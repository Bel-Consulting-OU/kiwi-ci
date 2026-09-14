// Package importer converts foreign CI configuration into Kiwi pipeline
// YAML. Each subpackage implements one source system (GitHub Actions,
// GitLab CI, CircleCI, Woodpecker) behind the shared Importer interface.
//
// The conversion contract is honesty over completeness: constructs that map
// cleanly are converted, constructs that cannot be represented faithfully
// are reported in Result.Unsupported (structural, cannot be approximated)
// or Result.TODOs (actionable follow-ups, e.g. "set this env var in the
// image instead"), and every such report lowers Result.Confidence. An
// importer must never silently approximate behavior it cannot express.
package importer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// Result is the output of an import: the generated Kiwi pipeline YAML plus
// the human-reviewable trail of everything that did not map cleanly.
type Result struct {
	// PipelineYAML is a complete pipeline document that parses with
	// pipeline.Parse.
	PipelineYAML string
	// Warnings are non-fatal observations (e.g. default assumptions that
	// were applied).
	Warnings []string
	// Unsupported lists constructs that cannot be expressed in Kiwi at all
	// and were therefore dropped from the output.
	Unsupported []string
	// TODOs lists constructs that need human action to finish the
	// migration (e.g. actions/setup-go has no Kiwi equivalent).
	TODOs []string
	// Confidence in [0,1] rates how much of the source mapped cleanly.
	// Unsupported constructs cost twice as much as TODOs.
	Confidence float64
}

// Importer converts the raw text of one foreign CI document into a Result.
type Importer interface {
	Import(src string) (*Result, error)
}

// AddWarning appends a formatted warning.
func (r *Result) AddWarning(format string, args ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

// AddUnsupported records a construct that has no Kiwi representation.
func (r *Result) AddUnsupported(format string, args ...any) {
	r.Unsupported = append(r.Unsupported, fmt.Sprintf(format, args...))
}

// AddTODO records an actionable migration step for a human.
func (r *Result) AddTODO(format string, args ...any) {
	r.TODOs = append(r.TODOs, fmt.Sprintf(format, args...))
}

// Finalize computes Confidence from the number of constructs that mapped
// cleanly versus the reports. supported counts constructs that were
// converted; unsupported counts dropped constructs; todos counts
// human-action items. Unsupported constructs weigh double.
func (r *Result) Finalize(supported int) {
	total := supported + 2*len(r.Unsupported) + len(r.TODOs)
	if total <= 0 {
		r.Confidence = 1
		return
	}
	c := float64(supported) / float64(total)
	if c < 0 {
		c = 0
	}
	if c > 1 {
		c = 1
	}
	r.Confidence = c
}

// Confidence is the standalone scoring function used by importers that
// compute their score incrementally.
func Confidence(supported, unsupported, todos int) float64 {
	r := &Result{Unsupported: make([]string, unsupported), TODOs: make([]string, todos)}
	r.Finalize(supported)
	return r.Confidence
}

// MarshalSpec renders a pipeline.Spec as YAML suitable for pipeline.Parse.
// pipeline.Duration is a struct wrapping time.Duration, so yaml.v3 encodes it
// as a nested {duration: "5m0s"} mapping; a post-encode pass collapses those
// mappings back into plain duration string scalars that pipeline.Parse
// accepts.
func MarshalSpec(spec *pipeline.Spec) (string, error) {
	var doc yaml.Node
	if err := doc.Encode(spec); err != nil {
		return "", fmt.Errorf("encode spec: %w", err)
	}
	fixDurationNodes(&doc)
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return "", fmt.Errorf("marshal spec: %w", err)
	}
	return string(out), nil
}

// fixDurationNodes rewrites the encoded form of pipeline.Duration (a mapping
// whose only key is "duration" with a scalar duration-string value) into a
// plain string scalar ("5m0s"). No other spec field produces a single-key
// "duration" mapping, so the match is unambiguous.
func fixDurationNodes(n *yaml.Node) {
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			fixDurationNodes(c)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Value == "duration" && len(n.Content) == 2 && v.Kind == yaml.ScalarNode {
				*n = *v
				return
			}
			fixDurationNodes(v)
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			fixDurationNodes(c)
		}
	}
}

// idRegexp mirrors pipeline's job id grammar: the importer must only emit
// ids pipeline.Parse accepts.
var idRegexp = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)

// SanitizeID converts an arbitrary source job name into a valid Kiwi job id,
// avoiding collisions with the ids already in taken (which is updated).
func SanitizeID(name string, taken map[string]bool) string {
	name = strings.TrimSpace(name)
	var b strings.Builder
	lastDash := false
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '.':
			b.WriteRune(r)
			lastDash = false
		case r == '-':
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	id := strings.Trim(b.String(), "-")
	if id == "" {
		id = "job"
	}
	if id[0] >= '0' && id[0] <= '9' {
		id = "job-" + id
	}
	if len(id) > 128 {
		id = id[:128]
	}
	base := id
	for i := 2; taken[id]; i++ {
		id = fmt.Sprintf("%s-%d", base, i)
	}
	taken[id] = true
	return id
}

// MapCondition translates a GitHub Actions style `if` expression into a Kiwi
// condition expression. It understands the status functions success(),
// failure(), always() and cancelled(), negation, &&, ||, parentheses and
// ${{ }} wrappers. Anything else (predefined context references such as
// github.ref) is reported as not mappable rather than approximated.
func MapCondition(expr string) (string, bool) {
	s := strings.TrimSpace(expr)
	for strings.HasPrefix(s, "${{") && strings.HasSuffix(s, "}}") {
		s = strings.TrimSpace(s[3 : len(s)-2])
	}
	// Mark the status function calls before tokenizing so their parentheses
	// are not split apart by the operator tokenizer.
	const (
		mkSuccess   = "\x00s"
		mkFailure   = "\x00f"
		mkAlways    = "\x00a"
		mkCancelled = "\x00c"
	)
	s = strings.ReplaceAll(s, "success()", mkSuccess)
	s = strings.ReplaceAll(s, "failure()", mkFailure)
	s = strings.ReplaceAll(s, "always()", mkAlways)
	s = strings.ReplaceAll(s, "cancelled()", mkCancelled)
	repl := strings.NewReplacer("&&", " && ", "||", " || ", "(", " ( ", ")", " ) ", "!", " ! ", "==", " == ", "!=", " != ")
	fields := strings.Fields(repl.Replace(s))
	if len(fields) == 0 {
		return "", true
	}
	var b strings.Builder
	for _, f := range fields {
		switch f {
		case "&&", "||":
			b.WriteString(" " + f + " ")
		case "(", ")", "!":
			b.WriteString(f)
		case mkSuccess:
			b.WriteString("success()")
		case mkFailure:
			b.WriteString("failure()")
		case mkAlways:
			b.WriteString("always()")
		case mkCancelled:
			b.WriteString("cancelled()")
		case "true", "false":
			b.WriteString(f)
		default:
			return "", false
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return "", true
	}
	return out, true
}

// DecodeYAML parses the raw source document into out with yaml.v3.
func DecodeYAML(src string, out any) error {
	if err := yaml.Unmarshal([]byte(src), out); err != nil {
		return fmt.Errorf("parse source: %w", err)
	}
	return nil
}

// Node helpers shared by the source-system importers. All four importer
// front ends decode into a yaml.Node tree and walk it with these accessors
// so unknown fields are tolerated (they surface as Unsupported/TODOs
// instead of parse errors).

// Document returns the root mapping node of a parsed document.
func Document(root *yaml.Node) *yaml.Node {
	n := root
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	return n
}

// Mapping returns the first-level key/value pairs of a mapping node.
func Mapping(n *yaml.Node) map[string]*yaml.Node {
	out := map[string]*yaml.Node{}
	if n == nil {
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		out[n.Content[i].Value] = n.Content[i+1]
	}
	return out
}

// Key returns the mapping value for key, or nil.
func Key(n *yaml.Node, name string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == name {
			return n.Content[i+1]
		}
	}
	return nil
}

// StrScalar returns the scalar string value of n (empty for mappings/seqs).
func StrScalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// BoolScalar returns the scalar boolean value of n.
func BoolScalar(n *yaml.Node) (bool, bool) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return false, false
	}
	var v bool
	if err := n.Decode(&v); err != nil {
		return false, false
	}
	return v, true
}

// IntScalar returns the scalar integer value of n.
func IntScalar(n *yaml.Node) (int, bool) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return 0, false
	}
	var v int
	if err := n.Decode(&v); err != nil {
		return 0, false
	}
	return v, true
}

// SeqScalars returns the scalar values of a sequence node (items that are
// not scalars are skipped).
func SeqScalars(n *yaml.Node) []string {
	var out []string
	if n == nil || n.Kind != yaml.SequenceNode {
		return out
	}
	for _, item := range n.Content {
		if s := StrScalar(item); s != "" || (item != nil && item.Kind == yaml.ScalarNode) {
			out = append(out, s)
		}
	}
	return out
}

// EnvMap converts a mapping of scalars into a string map.
func EnvMap(n *yaml.Node) map[string]string {
	out := map[string]string{}
	if n == nil {
		return out
	}
	for k, v := range Mapping(n) {
		out[k] = StrScalar(v)
	}
	return out
}
