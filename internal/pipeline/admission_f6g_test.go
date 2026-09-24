package pipeline

import (
	"strings"
	"testing"
)

func doc(job string) string {
	return "version: 1\njobs:\n  a:\n" + job
}

// TestAdmissionRejectsNonEvalCondition locks the F6-G `if` grammar check:
// a condition the evaluator cannot run fails at admission instead of as a job
// failure at execution time.
func TestAdmissionRejectsNonEvalCondition(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{"job if", doc("    if: github.ref == 'refs/heads/main'\n    steps:\n      - run: r\n")},
		{"step if", doc("    steps:\n      - run: r\n        if: github.ref == 'x'\n")},
		{"artifact if", doc("    artifacts:\n      - name: a\n        paths: [out]\n        if: github.ref == 'x'\n    steps:\n      - run: r\n")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.doc)); err == nil || !strings.Contains(err.Error(), "not a valid condition") {
				t.Fatalf("Parse = %v, want invalid-condition error", err)
			}
		})
	}
	for _, good := range []string{
		"    if: success() && branch == 'main'\n    steps:\n      - run: r\n",
		"    if: branchMatch('release/*')\n    steps:\n      - run: r\n",
		"    steps:\n      - run: r\n        if: always()\n",
	} {
		if _, err := Parse([]byte(doc(good))); err != nil {
			t.Fatalf("valid condition rejected: %v\n%s", err, good)
		}
	}
}

// TestSchemaRequiresNonEmptyCacheAndArtifactPaths pins the F6-G path rule at
// the schema level: the schema already requires the paths field, and an empty
// list must be rejected too (the server's enqueue path intentionally accepts
// artifacts whose paths are supplied by the compiled contract, so this is a
// schema-checker rule, not a Parse rule).
func TestSchemaRequiresNonEmptyCacheAndArtifactPaths(t *testing.T) {
	schemaErrs := func(job string) string {
		return strings.Join(ValidateAgainstSchema([]byte("version: 1\njobs:\n  a:\n"+job)), "; ")
	}
	if errs := schemaErrs("    cache:\n      - paths: []\n    steps:\n      - run: r\n"); !strings.Contains(errs, "has no paths") {
		t.Fatalf("empty cache paths errors = %q, want has-no-paths", errs)
	}
	if errs := schemaErrs("    artifacts:\n      - name: a\n        paths: []\n    steps:\n      - run: r\n"); !strings.Contains(errs, "has no paths") {
		t.Fatalf("empty artifact paths errors = %q, want has-no-paths", errs)
	}
	if errs := schemaErrs("    cache:\n      - paths: [.cache]\n    steps:\n      - run: r\n"); errs != "" {
		t.Fatalf("cache with paths rejected: %q", errs)
	}
	if errs := schemaErrs("    artifacts:\n      - name: a\n        paths: [out]\n    steps:\n      - run: r\n"); errs != "" {
		t.Fatalf("artifact with paths rejected: %q", errs)
	}
}

// TestAdmissionValidatesInputType locks the F6-G input vocabulary
// (string|boolean|integer|enum) and the enum/options requirement.
func TestAdmissionValidatesInputType(t *testing.T) {
	withInput := func(body string) string {
		return "version: 1\ninputs:\n  x:\n" + body + "jobs:\n  a:\n    steps:\n      - run: r\n"
	}
	if _, err := Parse([]byte(withInput("    type: bogus\n"))); err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Fatalf("bogus input type = %v, want rejection", err)
	}
	if _, err := Parse([]byte(withInput("    type: enum\n"))); err == nil || !strings.Contains(err.Error(), "declares no options") {
		t.Fatalf("enum without options = %v, want rejection", err)
	}
	if _, err := Parse([]byte(withInput("    type: enum\n    options: [a, b]\n"))); err != nil {
		t.Fatalf("enum with options rejected: %v", err)
	}
	for _, typ := range []string{"string", "boolean", "integer"} {
		if _, err := Parse([]byte(withInput("    type: " + typ + "\n"))); err != nil {
			t.Fatalf("input type %q rejected: %v", typ, err)
		}
	}
}

// TestAdmissionRejectsMixedTriggerSiblings pins the F6-G on.<event> sibling
// rule: the cron trigger form and the event-filter trigger form are mutually
// exclusive.
func TestAdmissionRejectsMixedTriggerSiblings(t *testing.T) {
	mixed := "version: 1\non:\n  push:\n    actions: [opened]\n    cron: \"0 0 * * *\"\njobs:\n  a:\n    steps:\n      - run: r\n"
	if _, err := Parse([]byte(mixed)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("cron mixed with actions = %v, want unknown field", err)
	}
	okCron := "version: 1\non:\n  schedule:\n    cron: \"0 0 * * *\"\n    branches: [main]\njobs:\n  a:\n    steps:\n      - run: r\n"
	if _, err := Parse([]byte(okCron)); err != nil {
		t.Fatalf("cron+branches rejected: %v", err)
	}
	okEvent := "version: 1\non:\n  push:\n    branches: [main]\n    paths: [src/**]\njobs:\n  a:\n    steps:\n      - run: r\n"
	if _, err := Parse([]byte(okEvent)); err != nil {
		t.Fatalf("event filters rejected: %v", err)
	}
}

// TestCheckInterpolationQuoteAware locks the F6-G hole scanning: a "}}" inside
// a string literal must not terminate the hole. The naive splitter accepted
// `${{ env.A == '}}'` (unterminated) because it mistook the quoted "}}" for
// the terminator.
func TestCheckInterpolationQuoteAware(t *testing.T) {
	if err := checkInterpolation("${{ env.A == '}}'", "test"); err == nil {
		t.Fatal("unterminated hole with a quoted }} must be rejected")
	}
	if err := checkInterpolation("${{ env.A == '}}' }}", "test"); err != nil {
		t.Fatalf("quoted }} inside a closed hole rejected: %v", err)
	}
	if err := checkInterpolation("${{ }}", "test"); err == nil || !strings.Contains(err.Error(), "empty interpolation") {
		t.Fatalf("empty hole = %v, want empty interpolation", err)
	}
}
