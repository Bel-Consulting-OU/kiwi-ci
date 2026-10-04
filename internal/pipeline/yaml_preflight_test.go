package pipeline

// Pre-decode YAML complexity budget regressions: a compact document whose
// structural indicator count exceeds the budget must be rejected BEFORE
// yaml.v3 builds a node tree, so a 2 MiB adversarial document cannot cause a
// large peak allocation through the parser.

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestYAMLPreflightRejectsCompactPathologicalDocumentBeforeDecode(t *testing.T) {
	// A compact flow document with far more structural indicators than the
	// budget: yaml.v3 would allocate one node per '[' before any post-decode
	// check could run.
	pathological := []byte("[" + strings.Repeat("[", maxYAMLStructuralTokens+10))

	decoded := false
	prevDecode := yamlDecodeDocument
	yamlDecodeDocument = func(data []byte) (yaml.Node, error) {
		decoded = true
		return prevDecode(data)
	}
	t.Cleanup(func() { yamlDecodeDocument = prevDecode })

	var out map[string]any
	err := parseYAML(pathological, &out)
	if err == nil || !strings.Contains(err.Error(), "complexity budget") {
		t.Fatalf("pathological document = %v, want the preflight complexity-budget rejection", err)
	}
	if decoded {
		t.Fatal("yaml.v3 was invoked for a document the preflight should have rejected")
	}
}

func TestYAMLPreflightCountsStructuralIndicatorsOutsideScalars(t *testing.T) {
	// Structural characters inside quoted scalars and comments must not count:
	// a document full of "a:b,c[d]" strings stays well under the budget.
	var b strings.Builder
	b.WriteString("version: 1\njobs:\n  a:\n    steps:\n")
	for i := 0; i < 200; i++ {
		b.WriteString("      - run: \"echo a:b,c[d] # not a comment\"\n")
	}
	if err := preflightYAMLStructure([]byte(b.String())); err != nil {
		t.Fatalf("quoted structural characters counted: %v", err)
	}
	// A comment-only flood likewise stays under the budget.
	comment := []byte("# " + strings.Repeat("[[[{{{,,,:::", 20_000) + "\nversion: 1\njobs: {}\n")
	if err := preflightYAMLStructure(comment); err != nil {
		t.Fatalf("comment structural characters counted: %v", err)
	}
}

func TestYAMLPreflightAcceptsLegitimatePipelineDocument(t *testing.T) {
	doc := []byte("version: 1\njobs:\n  build:\n    steps:\n      - run: make\n        retry:\n          max: 2\n")
	if err := preflightYAMLStructure(doc); err != nil {
		t.Fatalf("legitimate document rejected by preflight: %v", err)
	}
	var spec Spec
	if err := parseYAML(doc, &spec); err != nil {
		t.Fatalf("legitimate document failed to parse: %v", err)
	}
}

// TestYAMLCommentOnlyLineDoesNotPanic is the FuzzYAML regression for the
// crash input "0:\n  0 \n #00000000000": a line whose only content is a
// comment must not be treated as a block-scalar opener (and must never
// index the now-empty trimmed line).
func TestYAMLCommentOnlyLineDoesNotPanic(t *testing.T) {
	if yamlOpensBlockScalar([]byte(" #00000000000")) {
		t.Fatal("comment-only line reported as a block scalar opener")
	}
	for _, in := range []string{
		"0:\n  0 \n #00000000000",
		" #comment",
		"  # spaced",
		"key: value # trailing",
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Fatalf("Parse(%q) succeeded, want a validation error", in)
		}
	}
}
