package pipeline

import (
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
	"gopkg.in/yaml.v3"
)

// FuzzYAML drives the full admission parser (size limits, strict YAML node
// checks, known-field strictness, decode, Validate, canonicalization) over
// arbitrary input. A parser that admits untrusted documents must never panic
// and must never return a spec outside the supported version.
func FuzzYAML(f *testing.F) {
	f.Add([]byte("version: 1\njobs:\n  a:\n    steps:\n      - run: echo hi\n"))
	f.Add([]byte("version: 1\njobs: {}\n"))
	f.Add([]byte(""))
	f.Add([]byte("jobs:\n  a:\n    steps:\n      - run: \"true\"\n"))
	f.Add([]byte("version: 1\nname: x\njobs:\n  a:\n    needs: [b]\n    steps:\n      - run: y\n  b:\n    steps:\n      - run: z\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		spec, err := Parse(data)
		if err == nil {
			if spec == nil {
				t.Fatal("Parse returned (nil, nil)")
			}
			if spec.Version != 1 {
				t.Fatalf("Parse admitted version %d", spec.Version)
			}
			if len(spec.Jobs) == 0 {
				t.Fatal("Parse admitted a spec with no jobs")
			}
		}
	})
}

// FuzzConditionParser drives the condition expression evaluator with a
// status derived from the input. Eval must never panic, and every error it
// returns must be deterministic given the same expression and context.
func FuzzConditionParser(f *testing.F) {
	f.Add("success()")
	f.Add("always() && branch == 'main'")
	f.Add("!failure() || cancelled()")
	f.Add("event == \"push\"")
	f.Add("")
	f.Add("(((success())))")
	f.Fuzz(func(t *testing.T, expr string) {
		statuses := []model.Status{
			model.StatusSuccess, model.StatusFailure, model.StatusCancelled,
			model.StatusBlocked, model.StatusPending, model.StatusRunning,
		}
		c := EvalContext{
			Status: statuses[len(expr)%len(statuses)],
			Env:    map[string]string{"A": "b", "B": ""},
			Event:  "push",
			Branch: "main",
		}
		first, firstErr := Eval(expr, c)
		second, secondErr := Eval(expr, c)
		if first != second || (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("Eval(%q) is not deterministic: (%v, %v) vs (%v, %v)", expr, first, firstErr, second, secondErr)
		}
	})
}

// FuzzPathGlob drives the path glob compiler. Compiling attacker-controlled
// patterns must never panic and must be deterministic.
func FuzzPathGlob(f *testing.F) {
	f.Add("src/**/*.go", "src/a/b.go")
	f.Add("*", "x")
	f.Add("docs/**", "docs/x.md")
	f.Add("[", "x")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, pattern, value string) {
		first := globMatch(pattern, value)
		second := globMatch(pattern, value)
		if first != second {
			t.Fatalf("globMatch(%q, %q) is not deterministic: %v vs %v", pattern, value, first, second)
		}
	})
}

// FuzzPipelineValidation drives both schema-level and structural validation.
// Validators run on adversarial input and must never panic.
func FuzzPipelineValidation(f *testing.F) {
	f.Add([]byte("version: 1\njobs:\n  a:\n    steps:\n      - run: echo hi\n"))
	f.Add([]byte("version: 1\njobs:\n  a:\n    steps:\n      - run: echo hi\n    environment:\n      concurrency: 2\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ValidateAgainstSchema(data)
		var s Spec
		_ = yaml.Unmarshal(data, &s)
		_ = Validate(&s)
		_ = ValidateLimits(&s)
	})
}
