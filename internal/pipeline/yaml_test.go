package pipeline

import (
	"strings"
	"testing"
	"time"
)

func TestYAMLUnknownFieldRejected(t *testing.T) {
	_, err := Parse([]byte(`version: 1
secrects: [x]
jobs:
  x:
    steps:
      - run: echo hi
`))
	if err == nil {
		t.Fatal("expected unknown field error")
	}
	if !strings.Contains(err.Error(), `unknown field "secrects"`) {
		t.Fatalf("error should name the unknown field: %v", err)
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("error should carry the line number: %v", err)
	}
}

func TestYAMLUnknownFieldInJobRejected(t *testing.T) {
	_, err := Parse([]byte(`version: 1
jobs:
  x:
    secrects: [x]
    steps:
      - run: echo hi
`))
	if err == nil || !strings.Contains(err.Error(), `unknown field "secrects"`) {
		t.Fatalf("expected job-level unknown field error, got %v", err)
	}
}

func TestYAMLDuplicateKeyRejected(t *testing.T) {
	_, err := Parse([]byte(`version: 1
version: 1
jobs:
  x:
    steps:
      - run: echo hi
`))
	if err == nil {
		t.Fatal("expected duplicate key error")
	}
	if !strings.Contains(err.Error(), `duplicate key "version"`) {
		t.Fatalf("error should name the duplicate key: %v", err)
	}
	if !strings.Contains(err.Error(), "line") {
		t.Fatalf("error should carry a line number: %v", err)
	}
}

func TestYAMLAliasRejected(t *testing.T) {
	_, err := Parse([]byte(`version: 1
a: &x 1
b: *x
jobs:
  x:
    steps:
      - run: echo hi
`))
	if err == nil {
		t.Fatal("expected alias/anchor error")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("error should reject the anchor/alias: %v", err)
	}
	if !strings.Contains(err.Error(), "line") {
		t.Fatalf("error should carry a line number: %v", err)
	}
}

func TestYAMLMergeKeyRejected(t *testing.T) {
	_, err := Parse([]byte(`version: 1
<<: {x: 1}
jobs:
  x:
    steps:
      - run: echo hi
`))
	if err == nil {
		t.Fatal("expected merge key error")
	}
	if !strings.Contains(err.Error(), "merge keys") {
		t.Fatalf("error should mention merge keys: %v", err)
	}
}

func TestYAMLCustomTagRejected(t *testing.T) {
	_, err := Parse([]byte(`version: 1
jobs:
  x:
    steps:
      - run: !custom echo hi
`))
	if err == nil {
		t.Fatal("expected custom tag error")
	}
	if !strings.Contains(err.Error(), `unsupported tag "!custom"`) {
		t.Fatalf("error should name the tag: %v", err)
	}
}

func TestYAMLOversizedSourceRejected(t *testing.T) {
	doc := "version: 1\njobs:\n  x:\n    steps:\n      - run: \"" + strings.Repeat("a", maxPipelineBytes+1) + "\"\n"
	if _, err := Parse([]byte(doc)); err == nil {
		t.Fatal("expected oversized source error")
	} else if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error should mention the size limit: %v", err)
	}
}

func TestYAMLDeepNestingRejected(t *testing.T) {
	doc := "version: 1\njobs: " + strings.Repeat("{a: ", 150) + "1" + strings.Repeat("}", 150) + "\n"
	_, err := Parse([]byte(doc))
	if err == nil {
		t.Fatal("expected nesting depth error")
	}
	if !strings.Contains(err.Error(), "nesting exceeds") {
		t.Fatalf("error should mention nesting: %v", err)
	}
}

func TestYAMLBadUTF8Rejected(t *testing.T) {
	doc := []byte("version: 1\njobs:\n  x:\n    steps:\n      - run: echo \xff\xfe hi\n")
	_, err := Parse(doc)
	if err == nil {
		t.Fatal("expected invalid UTF-8 error")
	}
	if !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Fatalf("error should mention UTF-8: %v", err)
	}
	if !strings.Contains(err.Error(), "line") {
		t.Fatalf("error should carry a line number: %v", err)
	}
}

func TestYAMLLargeScalarRejected(t *testing.T) {
	doc := "version: 1\njobs:\n  x:\n    steps:\n      - run: \"" + strings.Repeat("a", maxScalarBytes+1) + "\"\n"
	_, err := Parse([]byte(doc))
	if err == nil {
		t.Fatal("expected oversized scalar error")
	}
	if !strings.Contains(err.Error(), "scalar exceeds") {
		t.Fatalf("error should mention the scalar limit: %v", err)
	}
}

func TestYAMLErrorsContainLineNumbers(t *testing.T) {
	cases := map[string]string{
		"unknown field": `version: 1
jobs:
  x:
    badkey: 1
    steps:
      - run: echo hi
`,
		"duplicate key": `version: 1
jobs:
  x:
    steps:
      - run: a
        run: b
`,
		"merge key": `version: 1
jobs:
  x:
    <<: {a: 1}
    steps:
      - run: echo hi
`,
	}
	for name, doc := range cases {
		_, err := Parse([]byte(doc))
		if err == nil {
			t.Fatalf("%s: expected error", name)
		}
		if !strings.Contains(err.Error(), "line ") {
			t.Fatalf("%s: error should contain a line number, got %v", name, err)
		}
	}
}

func TestYAMLNewSectionsParse(t *testing.T) {
	s, err := Parse([]byte(`version: 1
name: full
on:
  push:
    branches: [main]
    actions: [opened]
    draft: false
inputs:
  flavor:
    type: string
    default: "vanilla"
    options: [vanilla, chocolate]
    description: pick one
packages:
  lib:
    paths: [pkg/lib]
    depends_on: [other]
components:
  db:
    ref: postgres
    with:
      version: "16"
jobs:
  x:
    placement:
      regions: [eu-west-1]
      labels: [fast]
    resources:
      cpu: 1.5
      memory: 512Mi
      disk: 2Gi
      pids: 100
    tests:
      reports: [report.xml]
      manifest: tests.txt
      shards: 2
      retry_failed: 1
      quarantine_flaky: true
    generate:
      path: .kiwi/generated.yaml
      max_jobs: 10
      max_depth: 2
    downstream:
      repository: org/repo
      ref: main
      event: push
      inputs: {A: b}
      wait: true
    snapshot:
      on: [push]
    deployment:
      canary:
        - run: echo canary
      verify:
        - run: echo verify
      rollback:
        - run: echo rollback
    component: db
    with:
      flag: "on"
    queue_timeout: 5m
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	j := s.Jobs["x"]
	if j.Resources.Memory != 512<<20 {
		t.Fatalf("memory = %d, want %d", j.Resources.Memory, 512<<20)
	}
	if j.Resources.Disk != 2<<30 {
		t.Fatalf("disk = %d, want %d", j.Resources.Disk, 2<<30)
	}
	if j.QueueTimeout.Duration != 5*time.Minute {
		t.Fatalf("queue_timeout = %v, want 5m", j.QueueTimeout.Duration)
	}
	if got := s.On["push"].Actions; len(got) != 1 || got[0] != "opened" {
		t.Fatalf("on.push.actions = %v", got)
	}
	if s.On["push"].Draft == nil || *s.On["push"].Draft {
		t.Fatalf("on.push.draft = %v, want false", s.On["push"].Draft)
	}
	if s.Inputs["flavor"].Default != "vanilla" {
		t.Fatalf("inputs.flavor.default = %v", s.Inputs["flavor"].Default)
	}
	if s.Components["db"].Ref != "postgres" || s.Components["db"].With["version"] != "16" {
		t.Fatalf("components.db = %+v", s.Components["db"])
	}
	if len(s.Packages["lib"].DependsOn) != 1 || s.Packages["lib"].DependsOn[0] != "other" {
		t.Fatalf("packages.lib.depends_on = %v", s.Packages["lib"].DependsOn)
	}
	if len(j.Deployment.Canary) != 1 || j.Deployment.Canary[0].Run != "echo canary" {
		t.Fatalf("deployment.canary = %+v", j.Deployment.Canary)
	}
	if j.Downstream.Repository != "org/repo" || !j.Downstream.Wait {
		t.Fatalf("downstream = %+v", j.Downstream)
	}
	if j.Placement.Regions[0] != "eu-west-1" || j.Placement.Labels[0] != "fast" {
		t.Fatalf("placement = %+v", j.Placement)
	}
}

func TestByteSizeUnmarshal(t *testing.T) {
	s, err := Parse([]byte(`version: 1
jobs:
  x:
    resources:
      memory: "512Mi"
      disk: 2Gi
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	j := s.Jobs["x"]
	if j.Resources.Memory != 512<<20 {
		t.Fatalf("512Mi = %d", j.Resources.Memory)
	}
	if j.Resources.Disk != 2<<30 {
		t.Fatalf("2Gi = %d", j.Resources.Disk)
	}
	if _, err := Parse([]byte("version: 1\njobs:\n  x:\n    resources:\n      memory: nope\n    steps:\n      - run: echo hi\n")); err == nil {
		t.Fatal("invalid byte size should fail")
	}
}
