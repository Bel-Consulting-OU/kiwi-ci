package importer

import (
	"errors"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"gopkg.in/yaml.v3"
)

func TestResultAddHelpers(t *testing.T) {
	var r Result
	r.AddWarning("warn %d", 1)
	r.AddUnsupported("drop %s", "x")
	r.AddTODO("todo %s", "y")
	if len(r.Warnings) != 1 || r.Warnings[0] != "warn 1" {
		t.Fatalf("warnings = %v", r.Warnings)
	}
	if len(r.Unsupported) != 1 || r.Unsupported[0] != "drop x" {
		t.Fatalf("unsupported = %v", r.Unsupported)
	}
	if len(r.TODOs) != 1 || r.TODOs[0] != "todo y" {
		t.Fatalf("todos = %v", r.TODOs)
	}
}

func TestFinalizeConfidenceBounds(t *testing.T) {
	cases := []struct {
		name        string
		supported   int
		unsupported int
		todos       int
		want        float64
	}{
		{"no constructs at all", 0, 0, 0, 1},
		{"negative supported", -1, 0, 0, 1},
		{"negative ratio clamps to zero", -1, 1, 0, 0},
		{"all supported", 4, 0, 0, 1},
		{"unsupported weigh double", 2, 1, 0, 0.5},
		{"todos weigh once", 2, 0, 2, 0.5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Result{
				Unsupported: make([]string, tc.unsupported),
				TODOs:       make([]string, tc.todos),
			}
			r.Finalize(tc.supported)
			if r.Confidence != tc.want {
				t.Fatalf("Confidence = %v, want %v", r.Confidence, tc.want)
			}
		})
	}
	if got := Confidence(0, 0, 0); got != 1 {
		t.Fatalf("Confidence(0,0,0) = %v, want 1", got)
	}
	if got := Confidence(3, 1, 0); got != 3.0/5.0 {
		t.Fatalf("Confidence(3,1,0) = %v, want 0.6", got)
	}
}

type failingMarshaler struct{}

func (failingMarshaler) MarshalYAML() (any, error) {
	return nil, errors.New("boom")
}

func TestMarshalSpecRejectsUnencodable(t *testing.T) {
	spec := &pipeline.Spec{Version: 1, Name: "bad", Jobs: map[string]pipeline.Job{
		"job": {Runtime: "container", Image: "alpine", Matrix: map[string][]any{"BAD": {failingMarshaler{}}}},
	}}
	out, err := MarshalSpec(spec)
	if err == nil {
		t.Fatalf("MarshalSpec must fail for uncodable value, got:\n%s", out)
	}
	if !strings.Contains(err.Error(), "encode spec") {
		t.Fatalf("error = %v, want encode failure", err)
	}
}

func TestFixDurationNodesNestedAndNonScalar(t *testing.T) {
	const src = `
version: 1
name: nested
jobs:
  ok:
    runtime: container
    image: alpine
    steps:
      - name: one
        run: "true"
        timeout: 30s
`
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	fixDurationNodes(&doc)
	out, err := yaml.Marshal(&doc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "duration:") {
		t.Fatalf("duration mapping survived:\n%s", out)
	}
	if !strings.Contains(string(out), "timeout: 30s") {
		t.Fatalf("timeout scalar missing:\n%s", out)
	}

	mapping := &yaml.Node{Kind: yaml.MappingNode}
	mapping.Content = []*yaml.Node{
		{Kind: yaml.ScalarNode, Value: "duration"},
		{Kind: yaml.MappingNode, Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "nested"},
			{Kind: yaml.ScalarNode, Value: "1s"},
		}},
	}
	fixDurationNodes(mapping)
	if mapping.Kind != yaml.MappingNode {
		t.Fatalf("non-scalar duration value must not be collapsed")
	}

	multi := &yaml.Node{Kind: yaml.MappingNode}
	multi.Content = []*yaml.Node{
		{Kind: yaml.ScalarNode, Value: "duration"},
		{Kind: yaml.ScalarNode, Value: "1s"},
		{Kind: yaml.ScalarNode, Value: "other"},
		{Kind: yaml.ScalarNode, Value: "x"},
	}
	fixDurationNodes(multi)
	if multi.Content[1].Value != "1s" {
		t.Fatalf("multi-key mapping must not be collapsed")
	}

	fixDurationNodes(&yaml.Node{Kind: yaml.ScalarNode, Value: "plain"})
}

func TestSanitizeIDLongNameIsTruncated(t *testing.T) {
	long := strings.Repeat("a", 200)
	got := SanitizeID(long, map[string]bool{})
	if len(got) != 128 {
		t.Fatalf("len(SanitizeID(long)) = %d, want 128", len(got))
	}
	if !idRegexp.MatchString(got) {
		t.Fatalf("SanitizeID(long) = %q does not match pipeline id grammar", got)
	}
	taken := map[string]bool{}
	first := SanitizeID(long+"-x", taken)
	second := SanitizeID(long+"-y", taken)
	if first == second {
		t.Fatalf("colliding long ids: %q == %q", first, second)
	}
	if len(first) != 128 || !strings.HasPrefix(first, "job-") {
		t.Fatalf("unexpected truncation: %q (len %d)", first, len(first))
	}
	if second != first[:126]+"-2" {
		t.Fatalf("unexpected collision id: %q", second)
	}
	// The collision suffix is carved out of the truncated base, so a
	// colliding 200-char name still yields a 128-char id that matches the
	// pipeline id grammar.
	if len(second) != 128 || !idRegexp.MatchString(second) {
		t.Fatalf("SanitizeID collision id = %q (len %d) violates the grammar", second, len(second))
	}
}

func TestMapConditionTable(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"", "", true},
		{"   ", "", true},
		{"success()", "success()", true},
		{"${{ success() }}", "success()", true},
		{"${{success()}}", "success()", true},
		{"always()", "always()", true},
		{"cancelled()", "cancelled()", true},
		{"failure()", "failure()", true},
		{"!cancelled()", "!cancelled()", true},
		{"! failure()", "!failure()", true},
		{"success() && !cancelled()", "success() && !cancelled()", true},
		{"success() || failure()", "success() || failure()", true},
		{"(success() || failure()) && !cancelled()", "(success() || failure()) && !cancelled()", true},
		{"true", "true", true},
		{"false", "false", true},
		{"!true", "!true", true},
		{"github.ref == 'refs/heads/main'", "", false},
		{"github.event_name != 'push'", "", false},
		{"env.CI", "", false},
		{"success() && github.ref == 'x'", "", false},
	}
	for _, tc := range cases {
		got, ok := MapCondition(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("MapCondition(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestDecodeYAML(t *testing.T) {
	var m map[string]any
	if err := DecodeYAML("a: 1\nb: two\n", &m); err != nil {
		t.Fatalf("DecodeYAML: %v", err)
	}
	if m["a"] != 1 || m["b"] != "two" {
		t.Fatalf("decoded = %v", m)
	}
	var out map[string]any
	err := DecodeYAML("a: [unclosed\n", &out)
	if err == nil {
		t.Fatal("DecodeYAML must reject malformed input")
	}
	if !strings.Contains(err.Error(), "parse source") {
		t.Fatalf("error = %v, want parse source prefix", err)
	}
}

func nodeFrom(t *testing.T, src string) *yaml.Node {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(src), &n); err != nil {
		t.Fatalf("unmarshal %q: %v", src, err)
	}
	return &n
}

func TestDocument(t *testing.T) {
	doc := nodeFrom(t, "a: 1\n")
	root := Document(doc)
	if root.Kind != yaml.MappingNode {
		t.Fatalf("Document kind = %v, want mapping", root.Kind)
	}
	scalar := nodeFrom(t, "just a string")
	if got := Document(scalar); got.Kind != yaml.ScalarNode || got.Value != "just a string" {
		t.Fatalf("Document(scalar doc) = kind %v value %q", got.Kind, got.Value)
	}
	plain := &yaml.Node{Kind: yaml.ScalarNode, Value: "plain"}
	if got := Document(plain); got != plain {
		t.Fatal("Document must return non-document nodes unchanged")
	}
	empty := &yaml.Node{Kind: yaml.DocumentNode}
	if got := Document(empty); got != empty {
		t.Fatalf("Document with no content must return the same node")
	}
}

func TestMappingKeyStrScalar(t *testing.T) {
	doc := Document(nodeFrom(t, "name: build\ncount: 3\nnested:\n  a: b\nlist:\n  - x\n"))
	if got := Mapping(nil); len(got) != 0 {
		t.Fatalf("Mapping(nil) = %v", got)
	}
	m := Mapping(doc)
	if len(m) != 4 {
		t.Fatalf("Mapping len = %d, want 4", len(m))
	}
	if StrScalar(m["name"]) != "build" {
		t.Fatalf("StrScalar(name) = %q", StrScalar(m["name"]))
	}
	if StrScalar(nil) != "" || StrScalar(m["nested"]) != "" || StrScalar(m["list"]) != "" {
		t.Fatal("StrScalar must be empty for nil/mapping/sequence nodes")
	}
	if Key(doc, "name") == nil || Key(doc, "missing") != nil {
		t.Fatal("Key lookup mismatch")
	}
	if Key(nil, "x") != nil || Key(m["name"], "x") != nil {
		t.Fatal("Key must be nil for nil/non-mapping nodes")
	}
}

func TestBoolAndIntScalar(t *testing.T) {
	doc := Document(nodeFrom(t, "yes: true\nno: false\nn: 7\nbad: notanumber\nquoted: \"9\"\nseq: [1]\n"))
	m := Mapping(doc)
	if v, ok := BoolScalar(m["yes"]); !ok || !v {
		t.Fatalf("BoolScalar(yes) = %v,%v", v, ok)
	}
	if v, ok := BoolScalar(m["no"]); !ok || v {
		t.Fatalf("BoolScalar(no) = %v,%v", v, ok)
	}
	if _, ok := BoolScalar(m["bad"]); ok {
		t.Fatal("BoolScalar(bad) must not parse")
	}
	for name, n := range map[string]*yaml.Node{"nil": nil, "seq": m["seq"]} {
		if _, ok := BoolScalar(n); ok {
			t.Fatalf("BoolScalar(%s) must not parse", name)
		}
		if _, ok := IntScalar(n); ok {
			t.Fatalf("IntScalar(%s) must not parse", name)
		}
	}
	if v, ok := IntScalar(m["n"]); !ok || v != 7 {
		t.Fatalf("IntScalar(n) = %v,%v", v, ok)
	}
	if _, ok := IntScalar(m["quoted"]); ok {
		t.Fatal("IntScalar must not coerce a quoted string into an int")
	}
	if _, ok := IntScalar(m["bad"]); ok {
		t.Fatal("IntScalar(bad) must not parse")
	}
	if _, ok := IntScalar(m["yes"]); ok {
		t.Fatal("IntScalar must not decode a boolean into an int")
	}
}

func TestSeqScalarsAndEnvMap(t *testing.T) {
	if got := SeqScalars(nil); got != nil {
		t.Fatalf("SeqScalars(nil) = %v", got)
	}
	doc := Document(nodeFrom(t, "items:\n  - a\n  - 2\n  - true\n  - {k: v}\n  - [x]\n  - ''\nenv:\n  A: one\n  B: 2\n  NESTED:\n    a: b\n"))
	m := Mapping(doc)
	if got := SeqScalars(m["env"]); got != nil {
		t.Fatalf("SeqScalars(mapping) = %v", got)
	}
	got := SeqScalars(m["items"])
	want := []string{"a", "2", "true", ""}
	if len(got) != len(want) {
		t.Fatalf("SeqScalars(items) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SeqScalars(items)[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	env := EnvMap(m["env"])
	if len(env) != 3 || env["A"] != "one" || env["B"] != "2" || env["NESTED"] != "" {
		t.Fatalf("EnvMap = %v", env)
	}
	if got := EnvMap(nil); len(got) != 0 {
		t.Fatalf("EnvMap(nil) = %v", got)
	}
	if got := EnvMap(m["items"]); len(got) == 0 {
		t.Fatalf("EnvMap(sequence) = %v", got)
	}
}
