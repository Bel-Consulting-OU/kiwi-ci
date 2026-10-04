package pipeline

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/model"
)

// benchPipelineYAML builds a representative pipeline: 20 jobs, each with
// needs, multiple steps, env, artifacts and a condition.
func benchPipelineYAML() string {
	var b strings.Builder
	b.WriteString("version: 1\nname: bench\nenv:\n  GLOBAL: g\njobs:\n")
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&b, "  job%02d:\n    runtime: native\n", i)
		if i > 0 {
			fmt.Fprintf(&b, "    needs: [job%02d]\n", i-1)
		}
		fmt.Fprintf(&b, "    if: \"branch == 'main'\"\n")
		b.WriteString("    env:\n      LOCAL: l\n")
		b.WriteString("    steps:\n")
		for s := 0; s < 4; s++ {
			fmt.Fprintf(&b, "      - name: step%d\n        run: echo job%d-step%d\n", s, i, s)
		}
		fmt.Fprintf(&b, "    artifacts:\n      - name: art%d\n        paths: [\"out%d.txt\"]\n", i, i)
	}
	return b.String()
}

func BenchmarkParsePipeline(b *testing.B) {
	raw := []byte(benchPipelineYAML())
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for i := 0; i < b.N; i++ {
		if _, err := Parse(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompilePipeline(b *testing.B) {
	spec, err := Parse([]byte(benchPipelineYAML()))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		g, err := Compile(spec)
		if err != nil {
			b.Fatal(err)
		}
		if len(g.Jobs) != 20 {
			b.Fatalf("compiled %d jobs", len(g.Jobs))
		}
	}
}

// BenchmarkConditionEval measures the per-job condition evaluator on the
// common forms (the scheduler evaluates these per candidate).
func BenchmarkConditionEval(b *testing.B) {
	c := EvalContext{Branch: "main", Event: "push", Status: model.StatusSuccess}
	for _, expr := range []string{"branch == 'main'", "event == 'push' && branch == 'main'", "branchMatch('release/**')", "!cancelled()", "success() || failure()"} {
		b.Run(expr, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := Eval(expr, c); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
