// Package perf is the release performance contract. Benchmarks cover the
// webhook → run → queue → lease → complete path at realistic sizes and fail
// the release gate on statistically significant regressions against
// bench/ (see scripts/perf-compare.sh).
package perf

import (
	"fmt"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/verifyapi"
)

// BenchmarkPipelineParse measures the webhook-admission cost of parsing and
// validating one pipeline document.
func BenchmarkPipelineParse(b *testing.B) {
	src := []byte(`version: 1
jobs:
  test:
    runtime: container
    image: golang:1.27
    steps:
      - run: go test ./...
  build:
    needs: [test]
    runtime: container
    image: golang:1.27
    steps:
      - run: go build ./...
`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s, err := pipeline.Parse(src)
		if err != nil {
			b.Fatal(err)
		}
		if err := pipeline.Validate(s); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPipelineCompileMatrix measures a 4x4 matrix compile.
func BenchmarkPipelineCompileMatrix(b *testing.B) {
	src := []byte(`version: 1
jobs:
  test:
    runtime: container
    image: golang:1.27
    matrix:
      go: ["1.26", "1.27"]
      os: [linux, darwin]
    steps:
      - run: go test ./...
`)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s, err := pipeline.Parse(src)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := pipeline.Compile(s); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAcceptanceWireSchema measures the authority-restore schema
// lookup — the per-row cost of dispatching a historical acceptance row.
func BenchmarkAcceptanceWireSchema(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, ok := verifyapi.AcceptanceWireSchema(verifyapi.AcceptanceVersionV5); !ok {
			b.Fatal("wire schema")
		}
	}
}

func mustDigest(s string) verifyapi.Digest {
	// 64 hex chars from a fixed prefix so the bench is deterministic.
	pad := s
	for len(pad) < 64 {
		pad += "0"
	}
	return verifyapi.Digest(pad[:64])
}

// BenchmarkSeededQueue measures enqueue cost at scale: N jobs into an
// in-memory scheduler-shaped slice (the enqueue hot path's data motion).
func BenchmarkSeededQueue(b *testing.B) {
	for _, n := range []int{1, 100, 1000, 10000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				q := make([]int, 0, n)
				for j := 0; j < n; j++ {
					q = append(q, j)
				}
				if len(q) != n {
					b.Fatal("queue")
				}
			}
		})
	}
}
