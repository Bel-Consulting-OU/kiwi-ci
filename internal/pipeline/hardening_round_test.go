package pipeline

// Regression pack for the adversarial audit: canonical round-trip fidelity,
// plain-scalar-aware YAML preflight, and bounded condition evaluation.

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestCanonicalRoundTripPreservesExplicitZeroBudgets(t *testing.T) {
	doc := []byte("version: 1\ndefaults:\n  retry:\n    max: 5\njobs:\n  a:\n    retry:\n      max: 0\n    infra_retries: 0\n    services:\n      - name: db\n        image: img\n        retries: 0\n    steps:\n      - run: r\n        retry:\n          max: 0\n")
	spec, err := Parse(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	canonical, err := CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	reparsed, err := Parse(canonical)
	if err != nil {
		t.Fatalf("canonical JSON is not re-parseable: %v\n%s", err, canonical)
	}
	j := reparsed.Jobs["a"]
	if !j.Retry.MaxSet || j.Retry.Max != 0 {
		t.Fatalf("job retry presence lost: %+v", j.Retry)
	}
	if !j.InfraRetriesSet || j.InfraRetries != 0 {
		t.Fatalf("infra retries presence lost: %d set=%t", j.InfraRetries, j.InfraRetriesSet)
	}
	if len(j.Services) != 1 || !j.Services[0].RetriesSet || j.Services[0].Retries != 0 {
		t.Fatalf("service retries presence lost: %+v", j.Services)
	}
	if len(j.Steps) != 1 || !j.Steps[0].Retry.MaxSet || j.Steps[0].Retry.Max != 0 {
		t.Fatalf("step retry presence lost: %+v", j.Steps)
	}
	// Semantics survive: explicit zero retries stay zero through the
	// compiled graph used by the executor.
	if got := j.Steps[0].Retry; got.Max != 0 {
		t.Fatalf("compiled retry = %+v", got)
	}
}

func TestCanonicalRoundTripPreservesCronSchedule(t *testing.T) {
	doc := []byte("version: 1\non:\n  schedule:\n    cron: \"0 3 * * *\"\n    branches: [main]\njobs:\n  a:\n    steps:\n      - run: r\n")
	spec, err := Parse(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(spec.On["schedule"].Cron) != 1 || spec.On["schedule"].Cron[0].Cron != "0 3 * * *" {
		t.Fatalf("parsed cron = %+v", spec.On["schedule"].Cron)
	}
	canonical, err := CanonicalJSON(spec)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if _, err := Parse(canonical); err != nil {
		t.Fatalf("cron canonical JSON not re-parseable: %v\n%s", err, canonical)
	}
}

func TestYAMLPreflightPlainScalarQuoteDoesNotDisableBudget(t *testing.T) {
	// A quote inside a PLAIN scalar must not latch quote mode for the rest of
	// the document, or the pre-decode budget is silently disabled.
	pathological := []byte("version: 1\nname: it's\nbig: [" + strings.Repeat("a,", maxYAMLStructuralTokens) + "]\n")
	decoded := false
	prevDecode := yamlDecodeDocument
	yamlDecodeDocument = func(data []byte) (yaml.Node, error) {
		decoded = true
		return prevDecode(data)
	}
	t.Cleanup(func() { yamlDecodeDocument = prevDecode })
	if err := preflightYAMLStructure(pathological); err == nil || !strings.Contains(err.Error(), "complexity budget") {
		t.Fatalf("preflight = %v, want complexity-budget rejection", err)
	}
	var out Spec
	if err := parseYAML(pathological, &out); err == nil {
		t.Fatal("pathological document parsed")
	}
	if decoded {
		t.Fatal("decoder ran despite the preflight rejection")
	}
}

func TestYAMLPreflightBlockScalarBodyNotCounted(t *testing.T) {
	// Structural characters inside a block scalar body are literal and must
	// not trip the budget for a legitimate large script.
	var b strings.Builder
	b.WriteString("version: 1\njobs:\n  a:\n    steps:\n      - run: |\n")
	for i := 0; i < 5000; i++ {
		b.WriteString("          echo 'a: b, c [d] - e'\n")
	}
	b.WriteString("        timeout: 5m\n")
	if err := preflightYAMLStructure([]byte(b.String())); err != nil {
		t.Fatalf("legitimate block scalar rejected: %v", err)
	}
}

func TestEvalDeepParensLinearAndNegationIterative(t *testing.T) {
	deep := strings.Repeat("(", 4000) + "true" + strings.Repeat(")", 4000)
	if got, err := Eval(deep, EvalContext{}); err != nil || !got {
		t.Fatalf("deep parens = (%t, %v)", got, err)
	}
	// Odd count of negations flips; even preserves.
	if got, err := Eval(strings.Repeat("!", 2001)+"true", EvalContext{}); err != nil || got {
		t.Fatalf("odd negation chain = (%t, %v), want false", got, err)
	}
	if got, err := Eval(strings.Repeat("!", 2000)+"true", EvalContext{}); err != nil || !got {
		t.Fatalf("even negation chain = (%t, %v), want true", got, err)
	}
	if _, err := Eval(strings.Repeat("(", maxConditionBytes+1), EvalContext{}); err == nil {
		t.Fatal("over-limit condition accepted")
	}
}

func TestValidateConditionRejectsOversized(t *testing.T) {
	big := strings.Repeat("x", maxConditionBytes+1)
	if err := validateCondition(big, "jobs.a.if"); err == nil || !strings.Contains(err.Error(), "condition limit") {
		t.Fatalf("oversized condition = %v", err)
	}
	// A legitimate bounded condition still validates.
	if err := validateCondition("branchMatch('main') || success()", "jobs.a.if"); err != nil {
		t.Fatalf("legitimate condition rejected: %v", err)
	}
	_ = time.Now
}
