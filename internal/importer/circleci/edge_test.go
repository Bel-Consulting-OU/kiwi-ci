package circleci

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/importer"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"gopkg.in/yaml.v3"
)

const edgeFixture = `version: 2.1

executors:
  default-exec:
    docker:
      - image: alpine:3.20

jobs:
  edge:
    docker:
      - image: cimg/base:stable
    macos:
      xcode: "15.0"
    resource_class: large
    steps:
      - checkout
      - {checkout: {}}
      - [a, b]
      - run: echo hello
      - run:
          name: server
          command: serve.sh
          background: true
          when: on_success
      - run:
          name: nobackground
          command: y
          background: false
      - run:
          name: always-run
          command: z
          when: always
      - run:
          name: no command
          when: sometimes
      - run:
          name: bogus when
          command: x
          when: maybe
      - store_test_results:
          path: results/
      - persist_to_workspace:
          root: /tmp
          paths: [x]
      - attach_workspace:
          at: /tmp
      - setup_remote_docker: {}
      - add_ssh_keys: {}
      - unknown_step: {}
      - run:
          command: last
          when: on_fail

  other:
    docker:
      - image: alpine:3.20
    steps:
      - run: echo other

workflows:
  main:
    jobs:
      - edge
      - other:
          requires: [edge, edge]
          filters:
            tags:
              only: [v1]
      - unknown-ref
      - {name: other}
      - {approval-gate: {}}
  second:
    jobs:
      nope: 1
`

func TestImportEdgeFixture(t *testing.T) {
	res, err := New().Import(edgeFixture)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	spec, err := pipeline.Parse([]byte(res.PipelineYAML))
	if err != nil {
		t.Fatalf("generated pipeline does not parse: %v\n%s", err, res.PipelineYAML)
	}

	if !hasNote(res.Warnings, "executors are inlined") {
		t.Fatalf("executors warning missing: %v", res.Warnings)
	}

	edge := spec.Jobs["edge"]
	if edge.Image != "cimg/base:stable" {
		t.Fatalf("edge image = %q", edge.Image)
	}

	// Runnable steps only: shorthand run, background:true run, when
	// variants; background:false runs without a report.
	var names []string
	for _, st := range edge.Steps {
		names = append(names, st.Name)
	}
	want := []string{"run", "server", "nobackground", "always-run", "bogus when", "run"}
	if len(names) != len(want) {
		t.Fatalf("steps = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("steps = %v, want %v", names, want)
		}
	}
	if edge.Steps[0].Run != "echo hello" {
		t.Fatalf("shorthand run step = %+v", edge.Steps[0])
	}
	if edge.Steps[1].If != "success()" {
		t.Fatalf("when on_success = %q", edge.Steps[1].If)
	}
	if edge.Steps[3].If != "always()" {
		t.Fatalf("when always = %q", edge.Steps[3].If)
	}
	if edge.Steps[4].If != "" {
		t.Fatalf("unconvertible when must leave the step ungated, got %q", edge.Steps[4].If)
	}
	if edge.Steps[5].If != "failure()" {
		t.Fatalf("when on_fail = %q", edge.Steps[5].If)
	}

	for _, wantNote := range []string{"macos executor", "resource_class", "background: true", `when "maybe"`, "store_test_results", "persist_to_workspace", "attach_workspace", "setup_remote_docker", "add_ssh_keys", "unknown step type", "run step without a command"} {
		if !hasNote(res.Unsupported, wantNote) && !hasNote(res.TODOs, wantNote) && !hasNote(res.Warnings, wantNote) {
			t.Errorf("note %q missing: unsupported=%v todos=%v warnings=%v", wantNote, res.Unsupported, res.TODOs, res.Warnings)
		}
	}

	// Workflow wiring.
	other := spec.Jobs["other"]
	if len(other.Needs) != 1 || other.Needs[0] != "edge" {
		t.Fatalf("other needs = %v", other.Needs)
	}
	if !hasNote(res.Unsupported, "approval jobs") {
		t.Fatalf("approval job not reported: %v", res.Unsupported)
	}
	if !hasNote(res.Warnings, `unknown job "unknown-ref"`) {
		t.Fatalf("unknown workflow job not warned: %v", res.Warnings)
	}
	if !hasNote(res.Unsupported, "tag filters") {
		t.Fatalf("tag filters not reported: %v", res.Unsupported)
	}
}

func TestImportRejectsMalformedInput(t *testing.T) {
	if _, err := New().Import("a: [unclosed\n"); err == nil || !strings.Contains(err.Error(), "parse .circleci/config.yml") {
		t.Fatalf("error = %v", err)
	}
	if _, err := New().Import("- a\n"); err == nil || !strings.Contains(err.Error(), "must be a YAML mapping") {
		t.Fatalf("error = %v", err)
	}
}

func TestAppendUnique(t *testing.T) {
	got := appendUnique(nil, "a")
	got = appendUnique(got, "b")
	got = appendUnique(got, "a")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("appendUnique = %v", got)
	}
}

func TestSeqAny(t *testing.T) {
	node := func(t *testing.T, src string) *yaml.Node {
		t.Helper()
		var root yaml.Node
		if err := yaml.Unmarshal([]byte(src), &root); err != nil {
			t.Fatal(err)
		}
		return importer.Document(&root)
	}
	got := seqAny(node(t, "- [1, 2]\n- 3\n- name: x\n- true\n"))
	if len(got) != 2 {
		t.Fatalf("seqAny = %v, want only scalar values", got)
	}
	if got[0] != 3 || got[1] != true {
		t.Fatalf("seqAny = %#v", got)
	}
	if got := seqAny(node(t, "[]\n")); got != nil {
		t.Fatalf("seqAny(empty) = %v", got)
	}
}

func TestConvertJobWithoutDocker(t *testing.T) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("jobs:\n  bare:\n    steps:\n      - run: echo hi\n"), &root); err != nil {
		t.Fatal(err)
	}
	jobs := importer.Key(importer.Document(&root), "jobs")
	res := &importer.Result{}
	j := convertJob(res, importer.Key(jobs, "bare"), "bare")
	if j.Runtime != "" || j.Image != "" {
		t.Fatalf("job without executor got runtime/image %q/%q", j.Runtime, j.Image)
	}
	if len(j.Steps) != 1 {
		t.Fatalf("steps = %+v", j.Steps)
	}
}

func hasNote(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
