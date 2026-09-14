package pipeline

import (
	"strings"
	"testing"
)

func TestProjectInputName(t *testing.T) {
	cases := map[string]string{
		"foo-bar": "FOO_BAR",
		"foo_bar": "FOO_BAR",
		"foo.bar": "FOO_BAR",
		"Foo":     "FOO",
		"foo":     "FOO",
		"a b":     "A_B",
		"a9":      "A9",
		"tar-get": "TAR_GET",
		"":        "",
	}
	for in, want := range cases {
		if got := ProjectInputName(in); got != want {
			t.Errorf("ProjectInputName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateRejectsInvalidInputNames(t *testing.T) {
	for _, name := range []string{"1bad", "-lead", "has space", "dot.ted", "éclair", strings.Repeat("a", 65)} {
		s := &Spec{Version: 1, Inputs: map[string]Input{name: {}}, Jobs: map[string]Job{"x": {Steps: []Step{{Run: "echo hi"}}}}}
		if err := Validate(s); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Errorf("input name %q error = %v, want invalid-name error", name, err)
		}
	}
	for _, name := range []string{"ok", "_under", "with-hyphen", "with9", strings.Repeat("a", 64)} {
		s := &Spec{Version: 1, Inputs: map[string]Input{name: {}}, Jobs: map[string]Job{"x": {Steps: []Step{{Run: "echo hi"}}}}}
		if err := Validate(s); err != nil {
			t.Errorf("input name %q rejected: %v", name, err)
		}
	}
}

func TestValidateRejectsProjectionCollisions(t *testing.T) {
	cases := []struct {
		names []string
		want  string
	}{
		{[]string{"foo-bar", "foo_bar"}, "KIWI_INPUT_FOO_BAR"},
		{[]string{"Foo", "foo"}, "KIWI_INPUT_FOO"},
		{[]string{"A-B", "a_b"}, "KIWI_INPUT_A_B"},
	}
	for _, tc := range cases {
		inputs := map[string]Input{}
		for _, n := range tc.names {
			inputs[n] = Input{}
		}
		s := &Spec{Version: 1, Inputs: inputs, Jobs: map[string]Job{"x": {Steps: []Step{{Run: "echo hi"}}}}}
		err := Validate(s)
		if err == nil || !strings.Contains(err.Error(), "both project") || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("inputs %v error = %v, want projection collision naming %s", tc.names, err, tc.want)
		}
	}
}

func TestCompileWithInputsRejectsInvalidProvidedInputs(t *testing.T) {
	s, err := Parse([]byte(`version: 1
jobs:
  x:
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompileWithInputs(s, map[string]string{"bad name": "v"}); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("invalid provided input name error = %v, want invalid-name error", err)
	}
	if _, err := CompileWithInputs(s, map[string]string{"foo-bar": "a", "foo_bar": "b"}); err == nil || !strings.Contains(err.Error(), "both project") {
		t.Errorf("colliding provided inputs error = %v, want projection collision", err)
	}
}

func TestCompileWithInputsProjectsEnvCanonically(t *testing.T) {
	s, err := Parse([]byte(`version: 1
inputs:
  tar-get:
    type: string
  Version:
    type: string
jobs:
  x:
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	g, err := CompileWithInputs(s, map[string]string{"tar-get": "v1", "Version": "2"})
	if err != nil {
		t.Fatal(err)
	}
	cj := g.Jobs["x"]
	if got := cj.Job.Env["KIWI_INPUT_TAR_GET"]; got != "v1" {
		t.Errorf("KIWI_INPUT_TAR_GET = %q, want v1 (hyphen projected to underscore)", got)
	}
	if got := cj.Job.Env["KIWI_INPUT_VERSION"]; got != "2" {
		t.Errorf("KIWI_INPUT_VERSION = %q, want 2 (upper-cased projection)", got)
	}
	if _, ok := cj.Job.Env["KIWI_INPUT_tar-get"]; ok {
		t.Error("raw input name leaked into env as a non-canonical key")
	}
}
