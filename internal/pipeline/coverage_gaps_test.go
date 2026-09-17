package pipeline

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"gopkg.in/yaml.v3"
)

func TestLoadFileBranches(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pipeline.yaml")
	if err := os.WriteFile(path, []byte("version: 1\njobs:\n  a:\n    steps:\n      - run: echo hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load valid file: %v", err)
	}
	if len(s.Jobs) != 1 {
		t.Fatalf("jobs = %d, want 1", len(s.Jobs))
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("Load missing file must error")
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load directory must error")
	}
}

func TestParseRetentionVariants(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		bad  bool
	}{
		{"", 0, false},
		{"default", 0, false},
		{"  Default ", 0, false},
		{"forever", -1, false},
		{"FOREVER", -1, false},
		{"infinite", -1, false},
		{"never", -1, false},
		{" 30m ", 30 * time.Minute, false},
		{"24h", 24 * time.Hour, false},
		{"junk", 0, true},
	}
	for _, c := range cases {
		got, err := ParseRetention(c.in)
		if c.bad {
			if err == nil {
				t.Errorf("ParseRetention(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseRetention(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseRetention(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestDurationYAMLAndByteSizeYAMLEdges(t *testing.T) {
	s, err := Parse([]byte("version: 1\njobs:\n  a:\n    timeout: \"\"\n    steps:\n      - run: r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Jobs["a"].Timeout.Set {
		t.Error("an empty timeout string must decode as unset")
	}
	s, err = Parse([]byte("version: 1\njobs:\n  a:\n    steps:\n      - run: r\n    services:\n      - name: db\n        image: i\n        interval: \"\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Jobs["a"].Services[0].Interval.Set {
		t.Error("an empty interval string must decode as unset")
	}
	for _, doc := range []string{
		"version: 1\njobs:\n  a:\n    timeout: [1]\n    steps:\n      - run: r\n",
		"version: 1\njobs:\n  a:\n    timeout: {a: 1}\n    steps:\n      - run: r\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("non-scalar duration accepted:\n%s", doc)
		}
	}
}

func TestYAMLHelperBranches(t *testing.T) {
	var out Spec
	if err := parseYAML([]byte(strings.Repeat("a", maxPipelineBytes+1)), &out); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("parseYAML oversized source = %v", err)
	}
	if err := parseYAML([]byte("version: ["), &out); err == nil || !strings.Contains(err.Error(), "yaml:") {
		t.Errorf("parseYAML syntax error = %v", err)
	}
	if err := parseYAML([]byte("version: 1\njobs: {}\n---\n[a"), &out); err == nil || !strings.Contains(err.Error(), "yaml:") {
		t.Errorf("parseYAML second-document error = %v", err)
	}
	for _, doc := range []string{"---\n", "- a\n- b\n"} {
		if err := parseYAML([]byte(doc), &out); err == nil || !strings.Contains(err.Error(), "must be a mapping") {
			t.Errorf("parseYAML %q = %v, want mapping error", doc, err)
		}
	}
	if err := yamlError(nil); err != nil {
		t.Errorf("yamlError(nil) = %v", err)
	}
	if err := yamlError(errors.New("boom")); err == nil || !strings.HasPrefix(err.Error(), "yaml: boom") {
		t.Errorf("yamlError(generic) = %v", err)
	}
	if got := firstInvalidUTF8Offset([]byte("ok")); got != -1 {
		t.Errorf("firstInvalidUTF8Offset(valid) = %d", got)
	}
	if got := firstInvalidUTF8Offset([]byte{0xff}); got != 0 {
		t.Errorf("firstInvalidUTF8Offset(invalid) = %d", got)
	}
	if got := firstInvalidUTF8Offset([]byte("ok\xff")); got != 2 {
		t.Errorf("firstInvalidUTF8Offset(offset) = %d", got)
	}

	items := make([]string, maxYAMLNodes)
	for i := range items {
		items[i] = "a"
	}
	if err := parseYAML([]byte("["+strings.Join(items, ",")+"]"), &out); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("parseYAML node limit = %v", err)
	}

	nodes := 0
	if err := validateYAMLNode(&yaml.Node{Kind: yaml.AliasNode, Line: 7}, 0, &nodes); err == nil || !strings.Contains(err.Error(), "aliases are not allowed") {
		t.Errorf("validateYAMLNode(alias) = %v", err)
	}

	for doc, want := range map[string]string{
		"version: 1\njobs:\n  a:\n    steps:\n      - run: r\nx: !!merge {}\n": "merge keys",
		"version: 1\njobs:\n  a:\n    steps: [{badkey: 1}]\n":                  "unknown field",
		"version: 1\njobs:\n  a:\n    steps: [[{badkey: 1}]]\n":                "unknown field",
		"version: 1\ndefaults: [{badkey: 1}]\njobs:\n  a:\n    steps: []\n":    "unknown field",
	} {
		_, err := Parse([]byte(doc))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("doc %q error = %v, want %q", doc, err, want)
		}
	}
}

func TestDurationJSONBranches(t *testing.T) {
	cases := []struct {
		in      string
		wantDur time.Duration
		wantSet bool
		wantErr bool
	}{
		{"null", 0, false, false},
		{`""`, 0, false, false},
		{`"5m"`, 5 * time.Minute, true, false},
		{`"0s"`, 0, true, false},
		{`123`, 0, false, true},
		{`{}`, 0, false, true},
		{`"junk"`, 0, false, true},
	}
	for _, c := range cases {
		var d Duration
		err := json.Unmarshal([]byte(c.in), &d)
		if c.wantErr {
			if err == nil {
				t.Errorf("json.Unmarshal(%s) = %v, want error", c.in, d)
			}
			continue
		}
		if err != nil {
			t.Errorf("json.Unmarshal(%s): %v", c.in, err)
			continue
		}
		if d.Duration != c.wantDur || d.Set != c.wantSet {
			t.Errorf("json.Unmarshal(%s) = (%v, set=%v), want (%v, set=%v)", c.in, d.Duration, d.Set, c.wantDur, c.wantSet)
		}
	}

	b, err := json.Marshal(Duration{Duration: time.Minute, Set: true})
	if err != nil || string(b) != `"1m0s"` {
		t.Errorf("marshal set duration = %s (%v), want \"1m0s\"", b, err)
	}
	b, err = json.Marshal(Duration{})
	if err != nil || string(b) != "null" {
		t.Errorf("marshal unset duration = %s (%v), want null", b, err)
	}
}

func TestByteSizeUnmarshalBranches(t *testing.T) {
	cases := []struct {
		mem     string
		want    ByteSize
		wantErr string
	}{
		{`1234`, 1234, ""},
		{`"1234"`, 1234, ""},
		{`""`, 0, ""},
		{`"1.5Gi"`, ByteSize(1.5 * float64(int64(1)<<30)), ""},
		{`"1kb"`, 1 << 10, ""},
		{`"1tb"`, 1 << 40, ""},
		{`[1]`, 0, "byte size must be a scalar"},
		{`nope`, 0, "invalid byte size"},
		{`"nope"`, 0, "invalid byte size"},
		{`"` + strings.Repeat("9", 400) + `"`, 0, "invalid byte size"},
	}
	for _, c := range cases {
		doc := "version: 1\njobs:\n  a:\n    runtime: container\n    resources:\n      memory: " + c.mem + "\n    steps:\n      - run: echo hi\n"
		s, err := Parse([]byte(doc))
		if c.wantErr != "" {
			if err == nil {
				t.Errorf("memory %s parsed, want error containing %q", c.mem, c.wantErr)
				continue
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("memory %s error = %v, want %q", c.mem, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("memory %s: %v", c.mem, err)
			continue
		}
		if got := s.Jobs["a"].Resources.Memory; got != c.want {
			t.Errorf("memory %s = %d, want %d", c.mem, got, c.want)
		}
	}
}

func TestTriggerUnmarshalForms(t *testing.T) {
	s, err := Parse([]byte(`version: 1
on:
  schedule: "*/5 * * * *"
jobs:
  a:
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.On["schedule"].Cron; len(got) != 1 || got[0].Cron != "*/5 * * * *" {
		t.Fatalf("bare cron = %+v", got)
	}

	s, err = Parse([]byte(`version: 1
on:
  schedule:
    - cron: "0 0 * * *"
      branches: [main]
    - cron: "0 12 * * *"
jobs:
  a:
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.On["schedule"].Cron; len(got) != 2 || got[0].Cron != "0 0 * * *" || got[0].Branches[0] != "main" {
		t.Fatalf("cron sequence = %+v", got)
	}

	s, err = Parse([]byte(`version: 1
on:
  schedule:
    cron: "0 6 * * 1"
    branches: [main]
jobs:
  a:
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.On["schedule"].Cron; len(got) != 1 || got[0].Cron != "0 6 * * 1" || got[0].Branches[0] != "main" {
		t.Fatalf("cron mapping = %+v", got)
	}

	s, err = Parse([]byte(`version: 1
on:
  push:
    branches: [main]
jobs:
  a:
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.On["push"].Branches; len(got) != 1 || got[0] != "main" {
		t.Fatalf("plain trigger = %+v", got)
	}

	for _, doc := range []string{
		"version: 1\non:\n  schedule: [oops]\njobs:\n  a:\n    steps:\n      - run: echo hi\n",
		"version: 1\non:\n  schedule:\n    cron: [1]\njobs:\n  a:\n    steps:\n      - run: echo hi\n",
		"version: 1\non:\n  push:\n    branches: {a: 1}\njobs:\n  a:\n    steps:\n      - run: echo hi\n",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("Parse accepted malformed trigger:\n%s", doc)
		}
	}

	var tr Trigger
	if err := tr.UnmarshalYAML(&yaml.Node{}); err == nil {
		t.Fatal("zero-kind node must be rejected as a trigger")
	}
}

func TestNetworkPolicyUnmarshalForms(t *testing.T) {
	for value, want := range map[string]NetworkPolicy{
		"default":       NetworkPolicyDefault,
		"bridge":        NetworkPolicyDefault,
		`""`:            NetworkPolicyDefault,
		"none":          NetworkPolicyNone,
		"services-only": NetworkPolicyServicesOnly,
		"services_only": NetworkPolicyServicesOnly,
		"internet":      NetworkPolicyInternet,
		"host":          NetworkPolicyInternet,
		"2":             NetworkPolicyServicesOnly,
		"3":             NetworkPolicyInternet,
	} {
		doc := "version: 1\njobs:\n  a:\n    sandbox:\n      network: " + value + "\n    steps:\n      - run: echo hi\n"
		s, err := Parse([]byte(doc))
		if err != nil {
			t.Errorf("network %s: %v", value, err)
			continue
		}
		if got := s.Jobs["a"].Sandbox.Network; got != want {
			t.Errorf("network %s = %d, want %d", value, got, want)
		}
	}
	for _, value := range []string{"vpn", "9", "[none]"} {
		doc := "version: 1\njobs:\n  a:\n    sandbox:\n      network: " + value + "\n    steps:\n      - run: echo hi\n"
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("network %s must be rejected", value)
		}
	}
}

func TestEvalConditionBranches(t *testing.T) {
	ctx := EvalContext{Status: "success", Event: "push", Branch: "main", Env: map[string]string{"FOO": "bar"}}
	cases := []struct {
		expr string
		want bool
	}{
		{"", true},
		{"   ", true},
		{"true", true},
		{"false", false},
		{"(true)", true},
		{"(false)", false},
		{"((false))", false},
		// Outer parentheses are stripped before the empty/true/false literal
		// shortcuts, so whitespace-only parentheses match the empty condition.
		{"( )", true},
		{"(success())", true},
		{"((success()))", true},
		{"(success()) && !failure()", true},
		{"always() && (true)", true},
		{"always() || (false)", true},
		{"(false) || true", true},
		{"(!false)", true},
		{"true || false", true},
		{"false || true", true},
		{"false || false", false},
		{"true && true", true},
		{"true && false", false},
		{"!true", false},
		{"!false", true},
		{"success()", true},
		{"always()", true},
		{"failure()", false},
		{"cancelled()", false},
		{"event == 'push'", true},
		{"event != 'push'", false},
		{"event == nope", false},
		{"branch == 'main'", true},
		{"status == 'success'", true},
		{"env.FOO == 'bar'", true},
		{"env.MISSING == ''", true},
		{`event == "push"`, true},
		{"event == unquoted", false},
		{"'a' == 'a'", true},
		{"'a' != 'b'", true},
	}
	for _, c := range cases {
		got, err := Eval(c.expr, ctx)
		if err != nil {
			t.Errorf("Eval(%q): %v", c.expr, err)
			continue
		}
		if got != c.want {
			t.Errorf("Eval(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
	failing := []string{
		"errors || true",
		"true && errors",
		"!errors",
		"unquoted == event",
		"somefunc()",
	}
	for _, expr := range failing {
		if _, err := Eval(expr, ctx); err == nil {
			t.Errorf("Eval(%q) succeeded, want error", expr)
		}
	}
	if got, err := Eval("false || errors", ctx); err == nil {
		_ = got
	} else if _, err2 := Eval("false || errors", ctx); err2 == nil {
		t.Fatal("expected error to propagate through ||")
	}
}

func TestConditionAllowsMatrix(t *testing.T) {
	cases := []struct {
		expr   string
		status string
		want   bool
	}{
		{"", "success", true},
		{"", "failure", false},
		{"always()", "failure", true},
		{"failure()", "failure", true},
		{"success()", "blocked", false},
		{"cancelled()", "cancelled", true},
		{"garbage(", "success", false},
		{"success()", "cancelled", false},
	}
	for _, c := range cases {
		if got := ConditionAllows(c.expr, model.Status(c.status)); got != c.want {
			t.Errorf("ConditionAllows(%q, %s) = %v, want %v", c.expr, c.status, got, c.want)
		}
	}
}

func TestConditionHelperFunctions(t *testing.T) {
	if got := trimLiteral("  'x' "); got != "x" {
		t.Errorf("trimLiteral quoted = %q", got)
	}
	if got := trimLiteral("  x "); got != "x" {
		t.Errorf("trimLiteral bare = %q", got)
	}
	if !isQuoted(`"x"`) || !isQuoted(`'x'`) || isQuoted(`"x`) || isQuoted(`x"`) || isQuoted(`a`) {
		t.Error("isQuoted misclassified a value")
	}
	if !hasOuterParens("(a)") || hasOuterParens("(a) && (b)") || hasOuterParens("(a") || hasOuterParens("a)") || hasOuterParens("") {
		t.Error("hasOuterParens misclassified a value")
	}
	if !hasOuterParens(`("(")`) || !hasOuterParens("()") {
		t.Error("hasOuterParens must be quote aware")
	}
	if got := indexTopLevelFrom(`"a\"b" || c`, "||", 0); got < 0 {
		t.Error("indexTopLevelFrom must skip escaped quotes")
	}
	if got := indexTopLevelFrom("(a || b) || c", "||", 0); got != 9 {
		t.Errorf("indexTopLevelFrom depth handling = %d, want 9", got)
	}
	if got := indexTopLevelFrom("plain", "||", 0); got != -1 {
		t.Errorf("indexTopLevelFrom no-match = %d, want -1", got)
	}
	parts := splitLogical("a || (b || c)", "||")
	if len(parts) != 2 || parts[0] != "a" || parts[1] != "(b || c)" {
		t.Errorf("splitLogical = %v", parts)
	}
	if got := splitLogical("plain", "||"); len(got) != 1 || got[0] != "plain" {
		t.Errorf("splitLogical no-match = %v", got)
	}
	if _, op, _, ok := comparison("a != b"); !ok || op != "!=" {
		t.Error("comparison must prefer !=")
	}
	if _, _, _, ok := comparison("a = b"); ok {
		t.Error("comparison must not match a single =")
	}
	for input, want := range map[string]string{
		" event ": "push",
		"branch":  "main",
		"status":  "success",
		"env.FOO": "bar",
		"'lit'":   "lit",
	} {
		got, err := resolveConditionValue(input, EvalContext{Status: "success", Event: "push", Branch: "main", Env: map[string]string{"FOO": "bar"}})
		if err != nil || got != want {
			t.Errorf("resolveConditionValue(%q) = (%q, %v), want %q", input, got, err, want)
		}
	}
	if _, err := resolveConditionValue("nope", EvalContext{}); err == nil {
		t.Error("resolveConditionValue(unknown) must error")
	}
}

func TestValidateBranchesFromYAML(t *testing.T) {
	doc := func(job string) string {
		return "version: 1\njobs:\n  a:\n" + job
	}
	longValue := strings.Repeat("x", maxEnvValueBytes+1)
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"unknown dependency", doc("    needs: [nope]\n    steps:\n      - run: r\n"), "needs unknown job"},
		{"self dependency", doc("    needs: [a]\n    steps:\n      - run: r\n"), "depends on itself"},
		{"duplicate dependency", doc("    needs: [b, b]\n    steps:\n      - run: r\n  b:\n    steps:\n      - run: r\n"), "more than once"},
		{"defaults shell", "version: 1\ndefaults:\n  shell: csh\njobs:\n  a:\n    steps:\n      - run: r\n", "unsupported default shell"},
		{"defaults timeout", "version: 1\ndefaults:\n  timeout: 0s\njobs:\n  a:\n    steps:\n      - run: r\n", "positive duration"},
		{"defaults retry", "version: 1\ndefaults:\n  retry:\n    max: -1\njobs:\n  a:\n    steps:\n      - run: r\n", "max must not be negative"},
		{"concurrency interp", "version: 1\nconcurrency:\n  group: \"${{ nope.x }}\"\njobs:\n  a:\n    steps:\n      - run: r\n", "unknown interpolation context"},
		{"pipeline env size", "version: 1\nenv:\n  BIG: \"" + longValue + "\"\njobs:\n  a:\n    steps:\n      - run: r\n", "exceeds"},
		{"empty secret name", "version: 1\nsecrets: [\"\"]\njobs:\n  a:\n    steps:\n      - run: r\n", "secret name cannot be empty"},
		{"queue_timeout zero", doc("    queue_timeout: 0s\n    steps:\n      - run: r\n"), "positive duration"},
		{"negative infra retries", doc("    infra_retries: -1\n    steps:\n      - run: r\n"), "negative infra_retries"},
		{"environment concurrency", doc("    environment:\n      concurrency: -1\n    steps:\n      - run: r\n"), "concurrency must not be negative"},
		{"placement region", doc("    placement:\n      regions: [\"bad region\"]\n    steps:\n      - run: r\n"), "invalid placement region"},
		{"placement label", doc("    placement:\n      labels: [\"bad label\"]\n    steps:\n      - run: r\n"), "invalid placement label"},
		{"job env interp", doc("    env:\n      K: \"${{ nope.x }}\"\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"output value interp", doc("    outputs:\n      k: \"${{ nope.x }}\"\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"name interp", doc("    name: \"${{ nope.x }}\"\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"with interp", doc("    with:\n      k: \"${{ nope.x }}\"\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"empty interpolation", doc("    name: \"${{ }}\"\n    steps:\n      - run: r\n"), "empty interpolation"},
		{"canary step", doc("    deployment:\n      canary:\n        - name: x\n    steps:\n      - run: r\n"), "empty run command"},
		{"verify step", doc("    deployment:\n      verify:\n        - name: x\n    steps:\n      - run: r\n"), "empty run command"},
		{"rollback step", doc("    deployment:\n      rollback:\n        - name: x\n    steps:\n      - run: r\n"), "empty run command"},
		{"cache absolute path", doc("    cache:\n      - paths: [/abs]\n    steps:\n      - run: r\n"), "absolute path"},
		{"cache hash traversal", doc("    cache:\n      - paths: [a]\n        hash_files: [../x]\n    steps:\n      - run: r\n"), ".. component"},
		{"cache key interp", doc("    cache:\n      - paths: [a]\n        key: \"${{ nope.x }}\"\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"cache name interp", doc("    cache:\n      - paths: [a]\n        name: \"${{ nope.x }}\"\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"cache restore key interp", doc("    cache:\n      - paths: [a]\n        restore_keys: [\"${{ nope.x }}\"]\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"cache paths interp", doc("    cache:\n      - paths: [\"${{ nope.x }}\"]\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"artifact empty name", doc("    artifacts:\n      - paths: [out]\n    steps:\n      - run: r\n"), "has empty name"},
		{"artifact name interp", doc("    artifacts:\n      - name: \"${{ nope.x }}\"\n        paths: [out]\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"artifact if interp", doc("    artifacts:\n      - name: a\n        if: \"${{ nope.x }}\"\n        paths: [out]\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"artifact path interp", doc("    artifacts:\n      - name: a\n        paths: [\"${{ nope.x }}\"]\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"bad sbom", doc("    artifacts:\n      - name: a\n        paths: [out]\n        sbom: bogus\n    steps:\n      - run: r\n"), "invalid sbom format"},
		{"sigstore incomplete", doc("    artifacts:\n      - name: a\n        paths: [out]\n        sigstore:\n          required: true\n    steps:\n      - run: r\n"), "sigstore.required demands both issuer and identity"},
		{"sigstore issuer only", doc("    artifacts:\n      - name: a\n        paths: [out]\n        sigstore:\n          required: true\n          issuer: i\n    steps:\n      - run: r\n"), "sigstore.required demands both issuer and identity"},
		{"download path absolute", doc("    downloads:\n      - from: a\n        name: n\n        path: /abs\n    steps:\n      - run: r\n"), "absolute path"},
		{"download name interp", doc("    downloads:\n      - from: a\n        name: \"${{ nope.x }}\"\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"download path interp", doc("    downloads:\n      - from: a\n        name: n\n        path: \"${{ nope.x }}\"\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"download from unknown", doc("    downloads:\n      - from: nope\n        name: n\n    steps:\n      - run: r\n"), "downloads from unknown job"},
		{"download not a dependency", doc("    downloads:\n      - from: b\n        name: n\n    steps:\n      - run: r\n  b:\n    steps:\n      - run: r\n"), "not a declared dependency"},
		{"test reports interp", doc("    test_reports: [\"${{ nope.x }}\"]\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"environment branches interp", doc("    environment:\n      branches: [\"${{ nope.x }}\"]\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"generate path absolute", doc("    generate:\n      path: /abs\n    steps:\n      - run: r\n"), "absolute path"},
		{"generate path interp", doc("    generate:\n      path: \"${{ nope.x }}\"\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"generate negative", doc("    generate:\n      max_jobs: -1\n    steps:\n      - run: r\n"), "generate limits must not be negative"},
		{"downstream repository interp", doc("    downstream:\n      repository: \"${{ nope.x }}\"\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"downstream ref interp", doc("    downstream:\n      ref: \"${{ nope.x }}\"\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"downstream event interp", doc("    downstream:\n      event: \"${{ nope.x }}\"\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"downstream inputs interp", doc("    downstream:\n      inputs:\n        K: \"${{ nope.x }}\"\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"package path absolute", "version: 1\npackages:\n  p:\n    paths: [/abs]\njobs:\n  a:\n    steps:\n      - run: r\n", "absolute path"},
		{"service empty name", doc("    services:\n      - image: i\n    steps:\n      - run: r\n"), "service has empty name"},
		{"service interval", doc("    services:\n      - name: db\n        image: i\n        interval: 0s\n    steps:\n      - run: r\n"), "positive duration"},
		{"service timeout", doc("    services:\n      - name: db\n        image: i\n        timeout: 0s\n    steps:\n      - run: r\n"), "positive duration"},
		{"service retries", doc("    services:\n      - name: db\n        image: i\n        retries: -1\n    steps:\n      - run: r\n"), "negative retries"},
		{"service env size", doc("    services:\n      - name: db\n        image: i\n        env:\n          BIG: \"" + longValue + "\"\n    steps:\n      - run: r\n"), "exceeds"},
		{"service env interp", doc("    services:\n      - name: db\n        image: i\n        env:\n          K: \"${{ nope.x }}\"\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"service image interp", doc("    services:\n      - name: db\n        image: \"${{ nope.x }}\"\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"service healthcheck interp", doc("    services:\n      - name: db\n        image: i\n        healthcheck: \"${{ nope.x }}\"\n    steps:\n      - run: r\n"), "unknown interpolation context"},
		{"service alias invalid", doc("    services:\n      - name: \"-bad\"\n        image: i\n    steps:\n      - run: r\n"), "invalid service alias"},
		{"service alias duplicate", doc("    services:\n      - name: db\n        image: i\n      - name: db\n        image: i\n    steps:\n      - run: r\n"), "declares service alias"},
		{"step invalid id", doc("    steps:\n      - id: 9bad\n        run: r\n"), "invalid id"},
		{"step duplicate id", doc("    steps:\n      - id: s\n        run: r\n      - id: s\n        run: r\n"), "duplicate step id"},
		{"step shell", doc("    steps:\n      - run: r\n        shell: csh\n"), "unsupported shell"},
		{"step timeout", doc("    steps:\n      - run: r\n        timeout: 0s\n"), "positive duration"},
		{"step retry", doc("    steps:\n      - run: r\n        retry:\n          max: -1\n"), "max must not be negative"},
		{"step working directory", doc("    steps:\n      - run: r\n        working_directory: /abs\n"), "absolute path"},
		{"step empty secret", doc("    steps:\n      - run: r\n        secrets: [\"\"]\n"), "empty secret name"},
		{"step invalid secret", doc("    steps:\n      - run: r\n        secrets: [\"bad-name\"]\n"), "invalid secret name"},
		{"step duplicate secret", doc("    steps:\n      - run: r\n        secrets: [S, S]\n"), "more than once"},
		{"step env size", doc("    steps:\n      - run: r\n        env:\n          BIG: \"" + longValue + "\"\n"), "exceeds"},
		{"step env interp", doc("    steps:\n      - run: r\n        env:\n          K: \"${{ nope.x }}\"\n"), "unknown interpolation context"},
		{"step name interp", doc("    steps:\n      - run: r\n        name: \"${{ nope.x }}\"\n"), "unknown interpolation context"},
		{"tests manifest absolute", doc("    tests:\n      manifest: /abs\n    steps:\n      - run: r\n"), "absolute path"},
		{"tests negative shards", doc("    tests:\n      shards: -1\n    steps:\n      - run: r\n"), "must not be negative"},
		{"runtime unsupported", doc("    runtime: kubernetes\n    steps:\n      - run: r\n"), "unsupported runtime"},
		{"network unsupported", doc("    network: vpn\n    steps:\n      - run: r\n"), "unsupported network"},
		{"job shell unsupported", doc("    shell: csh\n    steps:\n      - run: r\n"), "unsupported shell"},
		{"environment name invalid", doc("    environment:\n      name: \"-bad\"\n    steps:\n      - run: r\n"), "invalid environment name"},
		{"artifacts duplicate", doc("    artifacts:\n      - name: a\n        paths: [out]\n      - name: a\n        paths: [out]\n    steps:\n      - run: r\n"), "more than once"},
		{"artifacts retention invalid", doc("    artifacts:\n      - name: a\n        paths: [out]\n        retention: junk\n    steps:\n      - run: r\n"), "invalid retention"},
		{"artifacts retention zero", doc("    artifacts:\n      - name: a\n        paths: [out]\n        retention: default\n    steps:\n      - run: r\n"), "retention must be positive"},
		{"artifacts retention forever", doc("    artifacts:\n      - name: a\n        paths: [out]\n        retention: forever\n    steps:\n      - run: r\n"), ""},
		{"shard matrix reserved", doc("    tests:\n      shards: 2\n    matrix:\n      test_shard: [0]\n    steps:\n      - run: r\n"), "reserved"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.doc))
			if c.want == "" {
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Parse succeeded, want error containing %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want it to contain %q", err, c.want)
			}
		})
	}
}

func TestValidateDirectStructBranches(t *testing.T) {
	if err := Validate(nil); err == nil || !strings.Contains(err.Error(), "nil pipeline") {
		t.Fatalf("Validate(nil) = %v", err)
	}
	if err := ValidateLimits(nil); err == nil || !strings.Contains(err.Error(), "nil pipeline") {
		t.Fatalf("ValidateLimits(nil) = %v", err)
	}
	if err := validateDuration(Duration{Duration: -time.Second}, "where"); err == nil {
		t.Fatal("negative unset duration must be rejected")
	}

	s := &Spec{Version: 1, Jobs: map[string]Job{"a": oneStepJob()}}
	s.Jobs["a"] = Job{Steps: []Step{{Run: "r"}}, Sandbox: Sandbox{Network: NetworkPolicy(9)}}
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "invalid sandbox.network") {
		t.Fatalf("sandbox network out of range = %v", err)
	}

	env := map[string]string{}
	for i := 0; i <= maxEnvVarsPerJob; i++ {
		env["K"+string(rune('a'+i%26))+string(rune('a'+i/26))] = "v"
	}
	s = &Spec{Version: 1, Env: env, Jobs: map[string]Job{"a": oneStepJob()}}
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "env vars") {
		t.Fatalf("pipeline env limit = %v", err)
	}

	stepEnv := map[string]string{}
	for i := 0; i <= maxEnvVarsPerJob; i++ {
		stepEnv["K"+string(rune('a'+i%26))+string(rune('a'+i/26))] = "v"
	}
	s = &Spec{Version: 1, Jobs: map[string]Job{"a": {Steps: []Step{{Run: "r", Env: stepEnv}}}}}
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "env vars") {
		t.Fatalf("step env limit = %v", err)
	}
}

func TestIsPortableAbsPathMatrix(t *testing.T) {
	cases := map[string]bool{
		"/abs":              true,
		"\\abs":             true,
		"\\\\server\\share": true,
		"C:\\x":             true,
		"c:/x":              true,
		"Z:relative":        true,
		"1:notdrive":        false,
		":nope":             false,
		"rel/path":          false,
		"":                  false,
		"./rel":             false,
	}
	for p, want := range cases {
		if got := IsPortableAbsPath(p); got != want {
			t.Errorf("IsPortableAbsPath(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestValidateCompiledJobErrorMatrix(t *testing.T) {
	valid := func() CompiledJob {
		return CompiledJob{
			ID:     "a[GO=1]",
			BaseID: "a",
			Job:    Job{Steps: []Step{{Run: "echo hi"}}},
		}
	}
	if err := ValidateCompiledJob(valid()); err != nil {
		t.Fatalf("baseline compiled job must validate: %v", err)
	}
	longValue := strings.Repeat("x", maxEnvValueBytes+1)
	bigEnv := func() map[string]string {
		m := map[string]string{}
		for i := 0; i <= maxEnvVarsPerJob; i++ {
			m["K"+string(rune('a'+i%26))+string(rune('a'+i/26))] = "v"
		}
		return m
	}
	bigCommand := strings.Repeat("x", maxCommandBytes+1)
	cases := []struct {
		name string
		mut  func(*CompiledJob)
		want string
	}{
		{"bad id", func(c *CompiledJob) { c.ID = "9bad" }, "is invalid"},
		{"bad base id", func(c *CompiledJob) { c.BaseID = "9bad" }, "invalid base id"},
		{"runtime", func(c *CompiledJob) { c.Job.Runtime = "kubernetes" }, "unsupported runtime"},
		{"native image", func(c *CompiledJob) { c.Job.Image = "img" }, "native runtime must not set image"},
		{"native vm", func(c *CompiledJob) { c.Job.VM = "vm" }, "native runtime must not set image"},
		{"tart no vm", func(c *CompiledJob) { c.Job.Runtime = "tart" }, "tart runtime requires a vm"},
		{"network", func(c *CompiledJob) { c.Job.Network = "vpn" }, "unsupported network"},
		{"sandbox", func(c *CompiledJob) { c.Job.Sandbox.Network = NetworkPolicy(9) }, "invalid sandbox.network"},
		{"shell", func(c *CompiledJob) { c.Job.Shell = "csh" }, "unsupported shell"},
		{"timeout", func(c *CompiledJob) { c.Job.Timeout = Duration{Set: true} }, "positive duration"},
		{"queue timeout", func(c *CompiledJob) { c.Job.QueueTimeout = Duration{Set: true} }, "positive duration"},
		{"retry", func(c *CompiledJob) { c.Job.Retry = Retry{Max: -1} }, "max must not be negative"},
		{"infra retries", func(c *CompiledJob) { c.Job.InfraRetries = -1 }, "negative infra_retries"},
		{"environment name", func(c *CompiledJob) { c.Job.Environment.Name = "-bad" }, "invalid environment name"},
		{"environment concurrency", func(c *CompiledJob) { c.Job.Environment.Concurrency = -1 }, "concurrency must not be negative"},
		{"runner label", func(c *CompiledJob) { c.Job.Runner = []string{"bad label"} }, "invalid runner label"},
		{"placement region", func(c *CompiledJob) { c.Job.Placement.Regions = []string{"bad region"} }, "invalid placement region"},
		{"placement label", func(c *CompiledJob) { c.Job.Placement.Labels = []string{"bad label"} }, "invalid placement label"},
		{"env count", func(c *CompiledJob) { c.Job.Env = bigEnv() }, "env vars, limit is"},
		{"env value", func(c *CompiledJob) { c.Job.Env = map[string]string{"K": longValue} }, "exceeds"},
		{"output id", func(c *CompiledJob) { c.Job.Outputs = map[string]string{"9bad": "v"} }, "invalid output identifier"},
		{"cpu nan", func(c *CompiledJob) { c.Job.Resources.CPU = math.NaN() }, "finite number"},
		{"cpu inf", func(c *CompiledJob) { c.Job.Resources.CPU = math.Inf(1) }, "finite number"},
		{"cpu negative", func(c *CompiledJob) { c.Job.Resources.CPU = -1 }, "must not be negative"},
		{"cpu over", func(c *CompiledJob) { c.Job.Resources.CPU = maxCPURequest + 1 }, "exceeds the limit"},
		{"memory negative", func(c *CompiledJob) { c.Job.Resources.Memory = -1 }, "must not be negative"},
		{"memory over", func(c *CompiledJob) { c.Job.Resources.Memory = maxMemoryRequest + 1 }, "exceeds the limit"},
		{"disk negative", func(c *CompiledJob) { c.Job.Resources.Disk = -1 }, "must not be negative"},
		{"disk over", func(c *CompiledJob) { c.Job.Resources.Disk = maxDiskRequest + 1 }, "exceeds the limit"},
		{"pids negative", func(c *CompiledJob) { c.Job.Resources.PIDs = -1 }, "must not be negative"},
		{"pids over", func(c *CompiledJob) { c.Job.Resources.PIDs = maxPIDsRequest + 1 }, "exceeds the limit"},
		{"native resources", func(c *CompiledJob) { c.Job.Resources.CPU = 1 }, "native backend does not enforce"},
		{"tart disk", func(c *CompiledJob) { c.Job.Runtime = "tart"; c.Job.VM = "vm"; c.Job.Resources.Disk = 1 }, "tart backend does not honor disk"},
		{"tart pids", func(c *CompiledJob) { c.Job.Runtime = "tart"; c.Job.VM = "vm"; c.Job.Resources.PIDs = 1 }, "tart backend does not honor pid"},
		{"service empty name", func(c *CompiledJob) { c.Job.Services = []Service{{Image: "i"}} }, "service 1 has empty name"},
		{"service alias", func(c *CompiledJob) { c.Job.Services = []Service{{Name: "-bad", Image: "i"}} }, "invalid service alias"},
		{"service alias dup", func(c *CompiledJob) {
			c.Job.Services = []Service{{Name: "db", Image: "i"}, {Name: "db", Image: "i"}}
		}, "declares service alias"},
		{"service empty image", func(c *CompiledJob) { c.Job.Services = []Service{{Name: "db"}} }, "has empty image"},
		{"service interval", func(c *CompiledJob) {
			c.Job.Services = []Service{{Name: "db", Image: "i", Interval: Duration{Set: true}}}
		}, "positive duration"},
		{"service timeout", func(c *CompiledJob) {
			c.Job.Services = []Service{{Name: "db", Image: "i", Timeout: Duration{Set: true}}}
		}, "positive duration"},
		{"service retries", func(c *CompiledJob) { c.Job.Services = []Service{{Name: "db", Image: "i", Retries: -1}} }, "negative retries"},
		{"service env", func(c *CompiledJob) {
			c.Job.Services = []Service{{Name: "db", Image: "i", Env: map[string]string{"K": longValue}}}
		}, "exceeds"},
		{"step cap", func(c *CompiledJob) {
			steps := make([]Step, maxStepsPerJob+1)
			for i := range steps {
				steps[i] = Step{Run: "r"}
			}
			c.Job.Steps = steps
		}, "across steps and deployment phases"},
		{"canary step", func(c *CompiledJob) { c.Job.Deployment.Canary = []Step{{Name: "x"}} }, "empty run command"},
		{"verify step", func(c *CompiledJob) { c.Job.Deployment.Verify = []Step{{Name: "x"}} }, "empty run command"},
		{"rollback step", func(c *CompiledJob) { c.Job.Deployment.Rollback = []Step{{Name: "x"}} }, "empty run command"},
		{"step dup id", func(c *CompiledJob) {
			c.Job.Steps = []Step{{ID: "s", Run: "r"}, {ID: "s", Run: "r"}}
		}, "duplicate step id"},
		{"step id", func(c *CompiledJob) { c.Job.Steps = []Step{{ID: "9bad", Run: "r"}} }, "invalid id"},
		{"step command cap", func(c *CompiledJob) { c.Job.Steps = []Step{{Run: bigCommand}} }, "command exceeds"},
		{"step shell", func(c *CompiledJob) { c.Job.Steps = []Step{{Run: "r", Shell: "csh"}} }, "unsupported shell"},
		{"step timeout", func(c *CompiledJob) { c.Job.Steps = []Step{{Run: "r", Timeout: Duration{Set: true}}} }, "positive duration"},
		{"step retry", func(c *CompiledJob) { c.Job.Steps = []Step{{Run: "r", Retry: Retry{Max: -1}}} }, "max must not be negative"},
		{"step working dir", func(c *CompiledJob) {
			c.Job.Steps = []Step{{Run: "r", WorkingDirectory: "/abs"}}
		}, "absolute path"},
		{"step env count", func(c *CompiledJob) { c.Job.Steps = []Step{{Run: "r", Env: bigEnv()}} }, "env vars, limit is"},
		{"step env value", func(c *CompiledJob) {
			c.Job.Steps = []Step{{Run: "r", Env: map[string]string{"K": longValue}}}
		}, "exceeds"},
		{"step empty secret", func(c *CompiledJob) { c.Job.Steps = []Step{{Run: "r", Secrets: []string{""}}} }, "empty secret name"},
		{"cache hash files", func(c *CompiledJob) { c.Job.Cache = []Cache{{Paths: []string{"a"}, HashFiles: []string{"/abs"}}} }, "absolute path"},
		{"artifact empty name", func(c *CompiledJob) { c.Job.Artifacts = []Artifact{{Paths: []string{"out"}}} }, "has empty name"},
		{"artifact dup", func(c *CompiledJob) {
			c.Job.Artifacts = []Artifact{{Name: "a", Paths: []string{"out"}}, {Name: "a", Paths: []string{"out"}}}
		}, "more than once"},
		{"artifact path", func(c *CompiledJob) { c.Job.Artifacts = []Artifact{{Name: "a", Paths: []string{"/abs"}}} }, "absolute path"},
		{"artifact retention", func(c *CompiledJob) {
			c.Job.Artifacts = []Artifact{{Name: "a", Paths: []string{"out"}, Retention: "junk"}}
		}, "invalid retention"},
		{"artifact retention zero", func(c *CompiledJob) {
			c.Job.Artifacts = []Artifact{{Name: "a", Paths: []string{"out"}, Retention: "default"}}
		}, "must be positive"},
		{"artifact sbom", func(c *CompiledJob) {
			c.Job.Artifacts = []Artifact{{Name: "a", Paths: []string{"out"}, SBOM: "bogus"}}
		}, "invalid sbom format"},
		{"artifact sigstore", func(c *CompiledJob) {
			c.Job.Artifacts = []Artifact{{Name: "a", Paths: []string{"out"}, Sigstore: &SigstoreConfig{Required: true}}}
		}, "sigstore.required demands both issuer and identity"},
		{"download from", func(c *CompiledJob) { c.Job.Downloads = []ArtifactInput{{Name: "n"}} }, "empty from job"},
		{"download name", func(c *CompiledJob) { c.Job.Downloads = []ArtifactInput{{From: "a"}} }, "empty name"},
		{"download path", func(c *CompiledJob) {
			c.Job.Downloads = []ArtifactInput{{From: "a", Name: "n", Path: "/abs"}}
		}, "absolute path"},
		{"tests manifest", func(c *CompiledJob) { c.Job.Tests.Manifest = "/abs" }, "absolute path"},
		{"generate path", func(c *CompiledJob) { c.Job.Generate.Path = "/abs" }, "absolute path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cj := valid()
			c.mut(&cj)
			err := ValidateCompiledJob(cj)
			if err == nil {
				t.Fatalf("ValidateCompiledJob succeeded, want error containing %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want it to contain %q", err, c.want)
			}
		})
	}
}

func TestResourceCapabilitiesMatrix(t *testing.T) {
	for runtime, want := range map[string][4]bool{
		"container": {true, true, false, true},
		"tart":      {true, true, false, false},
		"":          {false, false, false, false},
		"native":    {false, false, false, false},
		"unknown":   {false, false, false, false},
	} {
		cpu, memory, disk, pids := ResourceCapabilities(runtime)
		if cpu != want[0] || memory != want[1] || disk != want[2] || pids != want[3] {
			t.Errorf("ResourceCapabilities(%q) = %v %v %v %v, want %v", runtime, cpu, memory, disk, pids, want)
		}
	}
}

func TestPathMatchBranches(t *testing.T) {
	if !PathsMatch(nil, nil, nil) {
		t.Error("no changed paths and no includes must match")
	}
	if PathsMatch(nil, []string{"a"}, nil) {
		t.Error("no changed paths with includes must not match")
	}
	if !PathsMatch([]string{"a"}, nil, nil) {
		t.Error("changed path with no includes must match")
	}
	if !PathsMatch([]string{"./a\\b.go"}, []string{"a/b.go"}, nil) {
		t.Error("backslash and ./ normalization failed")
	}
	if !PathsMatch([]string{"abc"}, []string{"a?c"}, nil) {
		t.Error("? glob must match one character")
	}
	if PathsMatch([]string{"abbc"}, []string{"a?c"}, nil) {
		t.Error("? glob must match exactly one character")
	}
	if !PathsMatch([]string{"a/b/c.go"}, []string{"a/**/c.go"}, nil) {
		t.Error("**/ glob must match zero or more directories")
	}
	if !PathsMatch([]string{"a/c.go"}, []string{"a/**/c.go"}, nil) {
		t.Error("**/ glob must match zero directories")
	}
	if PathsMatch([]string{"x"}, []string{"x"}, []string{"x"}) {
		t.Error("exclude must win")
	}
}

func TestCanonicalJSONDurationsServicesComponents(t *testing.T) {
	s := &Spec{
		Version: 1,
		Defaults: Defaults{
			Shell:   "bash",
			Timeout: Duration{Duration: 5 * time.Minute, Set: true},
			Retry:   Retry{Max: 2, Backoff: Duration{Duration: time.Second, Set: true}},
		},
		Components: map[string]ComponentUse{"z": {Ref: "z"}, "a": {Ref: "r", With: map[string]string{"k": "v"}}},
		Jobs: map[string]Job{
			"a": {
				Timeout:      Duration{Duration: time.Minute, Set: true},
				QueueTimeout: Duration{Duration: 2 * time.Minute, Set: true},
				Services: []Service{{
					Name: "db", Image: "pg",
					Env:      map[string]string{"P": "x"},
					Interval: Duration{Duration: 10 * time.Second, Set: true},
					Timeout:  Duration{Duration: 5 * time.Second, Set: true},
				}},
				Deployment: DeploymentSpec{Canary: []Step{{Run: "c", Timeout: Duration{Duration: time.Second, Set: true}}}},
				Steps: []Step{{
					Run:     "echo",
					Timeout: Duration{Duration: 30 * time.Second, Set: true},
					Retry:   Retry{Max: 1, Backoff: Duration{Duration: time.Second, Set: true}},
				}},
			},
		},
	}
	b, err := CanonicalJSON(s)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, want := range []string{`"timeout":"5m0s"`, `"backoff":"1s"`, `"queue_timeout":"2m0s"`, `"interval":"10s"`, `"components"`, `"services"`} {
		if !strings.Contains(text, want) {
			t.Errorf("canonical JSON missing %s: %s", want, text)
		}
	}
	if strings.Index(text, `"a"`) > strings.Index(text, `"z"`) {
		t.Error("components must be rendered in sorted key order")
	}
	if _, err := CanonicalJSON(nil); err == nil {
		t.Error("CanonicalJSON(nil) must error")
	}
	if _, err := PipelineDigest(nil); err == nil {
		t.Error("PipelineDigest(nil) must error")
	}
}

func TestOrderedMapMarshalError(t *testing.T) {
	if _, err := (orderedMap{{Key: "k", Value: math.NaN()}}).MarshalJSON(); err == nil {
		t.Fatal("marshaling a NaN value must fail")
	}
}

func TestCompileNilAndInputValidation(t *testing.T) {
	if _, err := Compile(nil); err == nil {
		t.Fatal("Compile(nil) must error")
	}
	s := &Spec{Version: 1, Jobs: map[string]Job{"a": oneStepJob()}}
	if _, err := CompileWithInputs(s, map[string]string{"bad name": "x"}); err == nil {
		t.Fatal("CompileWithInputs must reject invalid provided input names")
	}
	if _, err := ResolveInputs(nil, nil); err == nil || !strings.Contains(err.Error(), "nil pipeline") {
		t.Fatalf("ResolveInputs(nil) = %v", err)
	}
	if _, err := ResolveInputs(s, map[string]string{"bad name": "x"}); err == nil {
		t.Fatal("ResolveInputs must reject invalid provided input names")
	}
}

func TestInterpolateMalformedHoles(t *testing.T) {
	for _, in := range []string{"${{ 'unterminated }}", "plain ${{ \"x }}"} {
		if got := InterpolateWithInputs(in, nil, nil); got != in {
			t.Errorf("InterpolateWithInputs(%q) = %q, want unchanged", in, got)
		}
		if got := Interpolate(in, nil); got != in {
			t.Errorf("Interpolate(%q) = %q, want unchanged", in, got)
		}
		if got := InterpolateOutputs(in, nil, nil); got != in {
			t.Errorf("InterpolateOutputs(%q) = %q, want unchanged", in, got)
		}
	}
	if got := Interpolate("${{ matrix.GO }}", map[string]string{"GO": "1.23"}); got != "1.23" {
		t.Errorf("Interpolate matrix = %q", got)
	}
	if got := matrixSuffix(nil); got != "" {
		t.Errorf("matrixSuffix(nil) = %q, want empty", got)
	}
	if got := matrixCombinations(map[string][]any{"a": {}}); len(got) != 1 {
		t.Errorf("matrixCombinations with an empty dimension = %v, want one empty combination", got)
	}
	if got := matrixCombinations(map[string][]any{"a": {"x"}, "b": {}}); len(got) != 1 || got[0]["a"] != "x" {
		t.Errorf("matrixCombinations must skip empty dimensions: %v", got)
	}
}

func TestResolveInputsMalformedHoleJob(t *testing.T) {
	s := &Spec{Version: 1, Jobs: map[string]Job{
		"a": {Steps: []Step{{Run: "x ${{ 'unterminated }}"}}},
	}}
	out, err := ResolveInputs(s, map[string]string{"in": "v"})
	if err != nil {
		t.Fatalf("ResolveInputs: %v", err)
	}
	if got := out.Jobs["a"].Steps[0].Run; got != "x ${{ 'unterminated }}" {
		t.Fatalf("run = %q, want the literal hole preserved", got)
	}

	s = &Spec{Version: 1, Jobs: map[string]Job{
		"a": {Steps: []Step{{Run: "x ${{ || }}"}}},
	}}
	if _, err := ResolveInputs(s, map[string]string{"in": "v"}); err != nil {
		t.Fatalf("ResolveInputs with an unparseable hole must stay lenient: %v", err)
	}
}

func TestInterpolateJobCompositeFields(t *testing.T) {
	doc := `version: 1
jobs:
  build:
    steps:
      - run: echo build
  x:
    needs: [build]
    matrix:
      GO: [a, b]
    env:
      E: "e-${{ matrix.GO }}"
    services:
      - name: db
        image: "postgres:16"
        healthcheck: pg_isready
        env:
          K: "v-${{ matrix.GO }}"
    cache:
      - name: "n-${{ matrix.GO }}"
        key: "k-${{ matrix.GO }}"
        paths: ["p-${{ matrix.GO }}"]
        hash_files: ["h-${{ matrix.GO }}"]
        restore_keys: ["r-${{ matrix.GO }}"]
    artifacts:
      - name: "art-${{ matrix.GO }}"
        paths: ["o-${{ matrix.GO }}"]
        if: "success()"
    downloads:
      - from: build
        name: "d-${{ matrix.GO }}"
        path: "dp-${{ matrix.GO }}"
    test_reports: ["tr-${{ matrix.GO }}"]
    steps:
      - run: echo run
        env:
          S: "s-${{ matrix.GO }}"
`
	s, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	g, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	cj, ok := g.Jobs["x[GO=a]"]
	if !ok {
		t.Fatalf("compiled job x[GO=a] missing: %v", jobIDs(g))
	}
	j := cj.Job
	if j.Env["E"] != "e-a" {
		t.Errorf("env = %v", j.Env)
	}
	if len(j.Services) != 1 || j.Services[0].Name != "db" || j.Services[0].Image != "postgres:16" || j.Services[0].Healthcheck != "pg_isready" || j.Services[0].Env["K"] != "v-a" {
		t.Errorf("services = %+v", j.Services)
	}
	if len(j.Cache) != 1 || j.Cache[0].Name != "n-a" || j.Cache[0].Key != "k-a" || j.Cache[0].Paths[0] != "p-a" || j.Cache[0].HashFiles[0] != "h-a" || j.Cache[0].RestoreKeys[0] != "r-a" {
		t.Errorf("cache = %+v", j.Cache)
	}
	if len(j.Artifacts) != 1 || j.Artifacts[0].Name != "art-a" || j.Artifacts[0].Paths[0] != "o-a" {
		t.Errorf("artifacts = %+v", j.Artifacts)
	}
	if len(j.Downloads) != 1 || j.Downloads[0].Name != "d-a" || j.Downloads[0].Path != "dp-a" {
		t.Errorf("downloads = %+v", j.Downloads)
	}
	if len(j.TestReports) != 1 || j.TestReports[0] != "tr-a" {
		t.Errorf("test_reports = %v", j.TestReports)
	}
	if j.Steps[0].Env["S"] != "s-a" {
		t.Errorf("step env = %v", j.Steps[0].Env)
	}
}

func TestValidateAgainstSchemaBranches(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"oversized", "x: " + strings.Repeat("a", maxPipelineBytes+1), "exceeds"},
		{"bad utf8", string([]byte{0xff, 0xfe}), "invalid UTF-8"},
		{"empty", "", "empty pipeline"},
		{"syntax", "version: [", "yaml:"},
		{"multiple docs", "version: 1\njobs:\n  a:\n    steps:\n      - run: r\n---\nversion: 1\n", "multiple documents"},
		{"scalar root", "just a scalar\n", "must be a mapping"},
		{"sequence root", "- a\n- b\n", "must be a mapping"},
		{"version not int", "version: one\njobs:\n  a:\n    steps:\n      - run: r\n", "must be an integer"},
		{"version null", "version:\njobs:\n  a:\n    steps:\n      - run: r\n", "must be an integer"},
		{"version huge", "version: !!int 99999999999999999999999999\njobs:\n  a:\n    steps:\n      - run: r\n", "must be an integer"},
		{"second doc error", "version: 1\njobs: {}\n---\n[a", "yaml:"},
		{"shell null", "version: 1\njobs:\n  a:\n    shell: null\n    steps:\n      - run: r\n", ""},
		{"timeout null", "version: 1\njobs:\n  a:\n    timeout: null\n    steps:\n      - run: r\n", ""},
		{"defaults scalar", "version: 1\ndefaults: nope\njobs:\n  a:\n    steps:\n      - run: r\n", "defaults must be a mapping"},
		{"job scalar", "version: 1\njobs:\n  a: nope\n", "must be a mapping"},
		{"job no steps", "version: 1\njobs:\n  a:\n    name: x\n", "has no steps"},
		{"step scalar", "version: 1\njobs:\n  a:\n    steps:\n      - nope\n", "must be a mapping"},
		{"services scalar", "version: 1\njobs:\n  a:\n    services: nope\n    steps:\n      - run: r\n", "services must be a sequence"},
		{"service scalar", "version: 1\njobs:\n  a:\n    services:\n      - nope\n    steps:\n      - run: r\n", "must be a mapping"},
		{"cache scalar", "version: 1\njobs:\n  a:\n    cache: nope\n    steps:\n      - run: r\n", "cache must be a sequence"},
		{"cache item scalar", "version: 1\njobs:\n  a:\n    cache:\n      - nope\n    steps:\n      - run: r\n", "must be a mapping"},
		{"cache missing paths", "version: 1\njobs:\n  a:\n    cache:\n      - name: c\n    steps:\n      - run: r\n", "missing required field paths"},
		{"artifacts scalar", "version: 1\njobs:\n  a:\n    artifacts: nope\n    steps:\n      - run: r\n", "artifacts must be a sequence"},
		{"artifact item scalar", "version: 1\njobs:\n  a:\n    artifacts:\n      - nope\n    steps:\n      - run: r\n", "must be a mapping"},
		{"artifact missing paths", "version: 1\njobs:\n  a:\n    artifacts:\n      - name: a\n    steps:\n      - run: r\n", "missing required field paths"},
		{"deployment scalar", "version: 1\njobs:\n  a:\n    deployment: nope\n    steps:\n      - run: r\n", "deployment must be a mapping"},
		{"deployment phase scalar", "version: 1\njobs:\n  a:\n    deployment:\n      canary: nope\n    steps:\n      - run: r\n", "must be a sequence"},
		{"deployment step scalar", "version: 1\njobs:\n  a:\n    deployment:\n      canary:\n        - nope\n    steps:\n      - run: r\n", "must be a mapping"},
		{"retry scalar", "version: 1\njobs:\n  a:\n    retry: nope\n    steps:\n      - run: r\n", "retry must be a mapping"},
		{"retry max not int", "version: 1\njobs:\n  a:\n    retry:\n      max: one\n    steps:\n      - run: r\n", "max must be an integer"},
		{"enum not scalar", "version: 1\njobs:\n  a:\n    shell: [bash]\n    steps:\n      - run: r\n", "must be a string"},
		{"duration not scalar", "version: 1\njobs:\n  a:\n    timeout: {a: 1}\n    steps:\n      - run: r\n", "must be a duration string"},
		{"duration invalid", "version: 1\njobs:\n  a:\n    timeout: nope\n    steps:\n      - run: r\n", "not a valid duration"},
		{"service missing image", "version: 1\njobs:\n  a:\n    services:\n      - name: db\n    steps:\n      - run: r\n", "has empty image"},
		{"service interval invalid", "version: 1\njobs:\n  a:\n    services:\n      - name: db\n        image: i\n        interval: nope\n    steps:\n      - run: r\n", "not a valid duration"},
		{"service timeout invalid", "version: 1\njobs:\n  a:\n    services:\n      - name: db\n        image: i\n        timeout: nope\n    steps:\n      - run: r\n", "not a valid duration"},
		{"defaults timeout node", "version: 1\ndefaults:\n  timeout: nope\njobs:\n  a:\n    steps:\n      - run: r\n", "not a valid duration"},
		{"defaults retry node", "version: 1\ndefaults:\n  retry:\n    max: -1\njobs:\n  a:\n    steps:\n      - run: r\n", "max must not be negative"},
		{"job step node", "version: 1\njobs:\n  a:\n    steps:\n      - run:\n          nested: yes\n", "has empty run command"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := ValidateAgainstSchema([]byte(c.doc))
			if c.want == "" {
				if len(errs) != 0 {
					t.Fatalf("ValidateAgainstSchema = %v, want none", errs)
				}
				return
			}
			if len(errs) == 0 {
				t.Fatalf("ValidateAgainstSchema = none, want %q", c.want)
			}
			joined := strings.Join(errs, "; ")
			if !strings.Contains(joined, c.want) {
				t.Fatalf("errors = %v, want %q", errs, c.want)
			}
		})
	}
}
