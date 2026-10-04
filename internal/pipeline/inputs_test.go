package pipeline

import (
	"strings"
	"testing"
)

func inputsSpecFixture(t *testing.T) *Spec {
	t.Helper()
	s, err := Parse([]byte(`version: 1
inputs:
  who:
    default: world
  count:
    default: 3
    type: integer
  flag:
    type: boolean
    default: "false"
  tier:
    type: enum
    options: [dev, prod]
    default: dev
jobs:
  a:
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestValidateRunInputsContract(t *testing.T) {
	spec := inputsSpecFixture(t)

	got, err := ValidateRunInputs(spec, nil)
	if err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if got["who"] != "world" || got["count"] != "3" || got["flag"] != "false" || got["tier"] != "dev" {
		t.Fatalf("defaults = %v", got)
	}

	got, err = ValidateRunInputs(spec, map[string]string{"who": "kiwi", "count": "7", "flag": "true", "tier": "prod"})
	if err != nil {
		t.Fatalf("provided: %v", err)
	}
	if got["who"] != "kiwi" || got["count"] != "7" || got["flag"] != "true" || got["tier"] != "prod" {
		t.Fatalf("provided = %v", got)
	}

	for name, in := range map[string]map[string]string{
		"unknown name": {"ghost": "1"},
		"bad integer":  {"count": "many"},
		"bad boolean":  {"flag": "yes"},
		"bad enum":     {"tier": "staging"},
	} {
		if _, err := ValidateRunInputs(spec, in); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}

	req, err := Parse([]byte("version: 1\ninputs:\n  needed:\n    required: true\njobs:\n  a:\n    steps:\n      - run: echo hi\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateRunInputs(req, nil); err == nil {
		t.Fatal("required input missing accepted")
	}
	if _, err := ValidateRunInputs(req, map[string]string{"needed": "x"}); err != nil {
		t.Fatalf("required provided: %v", err)
	}

	if _, err := ValidateRunInputs(nil, nil); err == nil {
		t.Fatal("nil spec accepted")
	}
}

// TestEnvNamesRejectControlCharacters: env names must not smuggle control
// characters or '=' past the exec boundary (log/argv/environment injection);
// dotted and dashed names stay valid for printenv-style access.
func TestEnvNamesRejectControlCharacters(t *testing.T) {
	bad := []string{"A\x0bB", "A\nB", "A\rB", "A\x00B", "A\x1b[31m", "A=B", "", string(make([]byte, 300))}
	for _, name := range bad {
		src := "version: 1\njobs:\n  x:\n    env:\n      " + yamlQuote(name) + ": v\n    steps:\n      - run: echo hi\n"
		if _, err := Parse([]byte(src)); err == nil {
			t.Fatalf("job env name %q accepted, want rejection", name)
		}
	}
	for _, name := range []string{"A", "_x1", "A.B", "A-B", "lower_case"} {
		src := "version: 1\njobs:\n  x:\n    env:\n      " + yamlQuote(name) + ": v\n    steps:\n      - run: echo hi\n"
		if _, err := Parse([]byte(src)); err != nil {
			t.Fatalf("env name %q rejected: %v", name, err)
		}
	}
	// pipeline-level and step-level are covered by the same helper
	if _, err := Parse([]byte("version: 1\nenv:\n  \"A\\x0bB\": v\njobs:\n  x:\n    steps:\n      - run: echo hi\n")); err == nil {
		t.Fatal("pipeline-level control-char env accepted")
	}
	if _, err := Parse([]byte("version: 1\njobs:\n  x:\n    steps:\n      - run: echo hi\n        env:\n          \"A\\x0bB\": v\n")); err == nil {
		t.Fatal("step-level control-char env accepted")
	}
}

// yamlQuote renders a YAML double-quoted scalar with Go-style escapes.
func yamlQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if c < 0x20 || c == 0x7f {
				b.WriteString("\\x")
				const hex = "0123456789abcdef"
				b.WriteByte(hex[c>>4])
				b.WriteByte(hex[c&0xf])
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
