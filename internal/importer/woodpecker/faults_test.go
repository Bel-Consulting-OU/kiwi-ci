package woodpecker

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestImportExpandsAnchorsAndMergesSerialSteps(t *testing.T) {
	const src = `
matrix: &php
  PHP: ["8.2", "8.3"]
pipeline:
  install:
    image: composer:2
    commands:
      - composer install
    matrix: *php
  test:
    image: composer:2
    commands:
      - vendor/bin/phpunit
    matrix: *php
  report:
    image: alpine
    commands:
      - echo done > report.txt
`
	res, err := New().Import(src)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	spec, err := pipeline.Parse([]byte(res.PipelineYAML))
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, res.PipelineYAML)
	}
	// Serial workflow → one job with three steps (file passing).
	if len(spec.Jobs) != 1 {
		t.Fatalf("jobs = %d, want 1 (serial merge): %v", len(spec.Jobs), res.PipelineYAML)
	}
	j := spec.Jobs["install"]
	if len(j.Steps) != 3 {
		t.Fatalf("steps = %d, want 3", len(j.Steps))
	}
	// Anchored matrix expanded onto the merged job.
	if len(j.Matrix["PHP"]) != 2 {
		t.Fatalf("matrix PHP = %v", j.Matrix["PHP"])
	}
}

func TestImportServiceCommands(t *testing.T) {
	const src = `
services:
  cache:
    image: redis:7
    commands: ["redis-server", "--save", ""]
pipeline:
  t:
    image: alpine
    commands: [echo hi]
`
	res, err := New().Import(src)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	spec, err := pipeline.Parse([]byte(res.PipelineYAML))
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, res.PipelineYAML)
	}
	j := spec.Jobs["t"]
	if len(j.Services) != 1 {
		t.Fatalf("services = %+v", j.Services)
	}
	svc := j.Services[0]
	if len(svc.Command) != 3 || svc.Command[0] != "redis-server" {
		t.Fatalf("service command = %v", svc.Command)
	}
}

func TestImportNormalizesDoubleDollar(t *testing.T) {
	const src = `
pipeline:
  t:
    image: alpine
    commands:
      - echo $$HOME
      - echo $$$HOME
`
	res, err := New().Import(src)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	spec, err := pipeline.Parse([]byte(res.PipelineYAML))
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, res.PipelineYAML)
	}
	lines := strings.Split(spec.Jobs["t"].Steps[0].Run, "\n")
	if len(lines) != 2 {
		t.Fatalf("run lines = %q", lines)
	}
	if lines[0] != "echo $HOME" {
		t.Fatalf("$$ → $: got %q", lines[0])
	}
	// $$$ collapses one escape pair: $$ → $, leaving $HOME → wait,
	// $$$HOME is $$ + $HOME → $ + $HOME = $$HOME? No: sequential scan
	// consumes $$ → $, then lone $ stays, then HOME → "$" + "$HOME".
	if lines[1] != "echo $$HOME" {
		t.Fatalf("$$$ → $$: got %q", lines[1])
	}
}
