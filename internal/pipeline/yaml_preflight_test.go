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

// yamlBlockScalarDoc builds a one-step pipeline whose run value is a block
// scalar with the given header and bodyLines "::" content lines (each line
// carries two structural ':' characters, so a body the preflight counts
// instead of skipping blows the structural-token budget). bodyBlankAt >= 0
// inserts one blank line after that many body lines.
func yamlBlockScalarDoc(header string, bodyLines, bodyBlankAt int) []byte {
	var b strings.Builder
	b.WriteString("version: 1\njobs:\n  a:\n    steps:\n      - run: " + header + "\n")
	for i := 0; i < bodyLines; i++ {
		if bodyBlankAt >= 0 && i == bodyBlankAt {
			b.WriteString("\n")
		}
		b.WriteString("          ::\n")
	}
	return []byte(b.String())
}

// TestYAMLPreflightBlockScalarHeaderForms pins the header scanner for the
// forms the old last-character heuristic got wrong: chomping and indentation
// indicators in either order, indicators followed by a trailing comment, and
// sequence-item headers. A plain scalar that merely ends in a spaced '>' or
// '|' must NOT be treated as a header, including an interior ' - |' (the '-'
// is scalar content, not a sequence indicator).
func TestYAMLPreflightBlockScalarHeaderForms(t *testing.T) {
	for _, line := range []string{
		"run: |",
		"run: |+",
		"run: |-2",
		"run: |2-",
		"run: >-",
		"run: |2 # explicit indent",
		"run: |+ # keep trailing newlines",
		"run: >-2 # strip",
		"- |",
		"key:\t|+",
		"run: |\r",
		"run: |-2 # strip\r",
		"run: >- # fold\r",
		"  - |+\r",
	} {
		if !yamlOpensBlockScalar([]byte(line)) {
			t.Errorf("yamlOpensBlockScalar(%q) = false, want true", line)
		}
	}
	for _, line := range []string{
		"",
		" # comment-only",
		"key: value # trailing",
		"run: echo x >",
		"run: echo x > # redirect",
		"run: a|b",
		"run: |0",
		"run: echo a - |",
		"run: echo a - |\r",
		"run: echo a ? |",
	} {
		if yamlOpensBlockScalar([]byte(line)) {
			t.Errorf("yamlOpensBlockScalar(%q) = true, want false", line)
		}
	}
}

// TestYAMLPreflightSkipsBlockScalarBodiesWithIndicatorsAndComments is the
// adversarial regression for the mis-parse where a block-scalar header with
// indicators and/or a trailing comment was not recognized, so the body was
// scanned as YAML and a legitimate single-scalar document was rejected with
// the complexity-budget error. It also pins that blank lines inside a block
// scalar do not terminate the body.
func TestYAMLPreflightSkipsBlockScalarBodiesWithIndicatorsAndComments(t *testing.T) {
	// More than maxYAMLStructuralTokens/2 body lines, each contributing two
	// ':' indicators if (and only if) the preflight fails to skip the body.
	bodyLines := maxYAMLStructuralTokens/2 + 10
	docs := map[string][]byte{
		"chomping+comment": yamlBlockScalarDoc("|+ # keep trailing newlines", bodyLines, -1),
		"indent+comment":   yamlBlockScalarDoc("|-2 # strip", bodyLines, -1),
		"indent only":      yamlBlockScalarDoc("|2", bodyLines, -1),
		"folded":           yamlBlockScalarDoc(">- # fold", bodyLines, -1),
		"blank line body":  yamlBlockScalarDoc("|", bodyLines, 5),
	}
	for name, doc := range docs {
		if err := preflightYAMLStructure(doc); err != nil {
			t.Errorf("%s: preflight rejected a block-scalar body it must skip: %v", name, err)
		}
	}
	// End to end: the document is one huge scalar, not a structural flood,
	// so the parser must accept it (the body stays under maxScalarBytes).
	if _, err := Parse(docs["chomping+comment"]); err != nil {
		t.Fatalf("Parse of a large block scalar failed: %v", err)
	}
	if _, err := Parse(docs["blank line body"]); err != nil {
		t.Fatalf("Parse of a block scalar with a blank line failed: %v", err)
	}
}

// yamlBlockScalarDocCRLF is yamlBlockScalarDoc rendered with CRLF line
// endings, the document shape that used to defeat the header scanner: the
// header line ended in '\r', so the block body was counted as YAML and a
// legitimately parseable document was rejected by the structural budget.
func yamlBlockScalarDocCRLF(header string, bodyLines, bodyBlankAt int) []byte {
	var b strings.Builder
	b.WriteString("version: 1\r\njobs:\r\n  a:\r\n    steps:\r\n      - run: " + header + "\r\n")
	for i := 0; i < bodyLines; i++ {
		if bodyBlankAt >= 0 && i == bodyBlankAt {
			b.WriteString("\r\n")
		}
		b.WriteString("          ::\r\n")
	}
	return []byte(b.String())
}

// TestYAMLPreflightSkipsCRLFBlockScalarBodies is the CRLF regression: a
// literal/folded block scalar with indicators or chomping and a CRLF header
// must have its whole body (blank lines included) skipped by the preflight,
// so the document parses end to end instead of being rejected by the 100k
// structural-token budget.
func TestYAMLPreflightSkipsCRLFBlockScalarBodies(t *testing.T) {
	bodyLines := maxYAMLStructuralTokens/2 + 10
	docs := map[string][]byte{
		"literal":          yamlBlockScalarDocCRLF("|", bodyLines, -1),
		"chomping":         yamlBlockScalarDocCRLF("|-2 # strip", bodyLines, -1),
		"keep+comment":     yamlBlockScalarDocCRLF("|+ # keep trailing newlines", bodyLines, -1),
		"folded":           yamlBlockScalarDocCRLF(">- # fold", bodyLines, -1),
		"blank line body":  yamlBlockScalarDocCRLF("|", bodyLines, 5),
		"indent indicator": yamlBlockScalarDocCRLF("|2", bodyLines, -1),
	}
	for name, doc := range docs {
		if err := preflightYAMLStructure(doc); err != nil {
			t.Errorf("%s: CRLF block-scalar body counted as YAML: %v", name, err)
		}
		if _, err := Parse(doc); err != nil {
			t.Errorf("%s: CRLF block scalar failed to parse: %v", name, err)
		}
	}
}

// TestYAMLPreflightPlainScalarSpacedPipeIsNotHeader pins that an interior
// " - |" is plain-scalar content, not a block-scalar header: its indented
// continuation lines are counted as YAML (so an over-budget continuation is
// rejected), while the same step line parses as a scalar end to end.
func TestYAMLPreflightPlainScalarSpacedPipeIsNotHeader(t *testing.T) {
	if yamlOpensBlockScalar([]byte("run: echo a - |")) {
		t.Fatal("interior ' - |' treated as a block-scalar header")
	}
	bodyLines := maxYAMLStructuralTokens/2 + 10
	doc := []byte("version: 1\njobs:\n  a:\n    steps:\n      - run: echo a - |\n" +
		strings.Repeat("          ::\n", bodyLines))
	if err := preflightYAMLStructure(doc); err == nil || !strings.Contains(err.Error(), "complexity budget") {
		t.Fatalf("plain-scalar continuation not counted: err = %v", err)
	}
	// A plain scalar that merely contains a spaced '-' and '|' is valid.
	var spec Spec
	if err := parseYAML([]byte("version: 1\njobs:\n  a:\n    steps:\n      - run: echo a - | continued\n"), &spec); err != nil {
		t.Fatalf("valid plain scalar rejected: %v", err)
	}
}
