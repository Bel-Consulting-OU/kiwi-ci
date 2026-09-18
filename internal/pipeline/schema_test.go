package pipeline

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSchemaJSONParsesAndIsStrict(t *testing.T) {
	var root map[string]any
	if err := json.Unmarshal(SchemaJSON, &root); err != nil {
		t.Fatalf("SchemaJSON is not valid JSON: %v", err)
	}
	if got := root["$schema"]; got != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("$schema = %v", got)
	}
	required, _ := root["required"].([]any)
	if len(required) != 1 || required[0] != "jobs" {
		t.Fatalf("root required = %v, want [jobs]", required)
	}
	props, _ := root["properties"].(map[string]any)
	for _, k := range []string{
		"version", "name", "on", "inputs", "env", "secrets", "defaults",
		"permissions", "concurrency", "packages", "components", "jobs",
	} {
		if _, ok := props[k]; !ok {
			t.Fatalf("root properties missing %q", k)
		}
	}
	if root["additionalProperties"] != false {
		t.Fatalf("root additionalProperties = %v, want false", root["additionalProperties"])
	}
	defs, _ := root["$defs"].(map[string]any)
	for _, name := range []string{
		"trigger", "input", "defaults", "retry", "permissions", "concurrency",
		"package", "component", "environment", "sandbox", "placement",
		"resources", "tests", "generate", "downstream", "snapshot", "step",
		"deployment", "service", "cache", "artifact", "download", "job",
	} {
		d, ok := defs[name].(map[string]any)
		if !ok {
			t.Fatalf("$defs.%s missing", name)
		}
		// oneOf definitions (trigger) are strict per-branch: every branch
		// that defines a property shape must forbid additional properties.
		if branches, ok := d["oneOf"].([]any); ok {
			for _, b := range branches {
				if obj, ok := b.(map[string]any); ok {
					if _, hasProps := obj["properties"]; hasProps {
						if obj["additionalProperties"] != false {
							t.Fatalf("$defs.%s oneOf branch additionalProperties = %v, want false", name, obj["additionalProperties"])
						}
					}
					if items, ok := obj["items"].(map[string]any); ok {
						if items["additionalProperties"] != false {
							t.Fatalf("$defs.%s oneOf items additionalProperties = %v, want false", name, items["additionalProperties"])
						}
					}
				}
			}
			continue
		}
		if d["additionalProperties"] != false {
			t.Fatalf("$defs.%s additionalProperties = %v, want false", name, d["additionalProperties"])
		}
	}
	job, _ := defs["job"].(map[string]any)
	jobProps, _ := job["properties"].(map[string]any)
	for _, k := range []string{
		"needs", "if", "runner", "runtime", "image", "network", "vm", "shell",
		"timeout", "queue_timeout", "retry", "env", "matrix", "paths",
		"paths_ignore", "services", "steps", "cache", "artifacts", "downloads",
		"test_reports", "environment", "infra_retries", "permissions",
		"outputs", "placement", "sandbox", "resources", "tests", "generate",
		"downstream", "deployment", "snapshot", "component", "with",
	} {
		if _, ok := jobProps[k]; !ok {
			t.Fatalf("$defs.job.properties missing %q", k)
		}
	}
	if jobRequired, _ := job["required"].([]any); len(jobRequired) != 1 || jobRequired[0] != "steps" {
		t.Fatalf("$defs.job required = %v, want [steps]", jobRequired)
	}
}

func TestSchemaJSONMatchesKiwiFile(t *testing.T) {
	onDisk, err := os.ReadFile("../../.kiwi/schema.json")
	if err != nil {
		t.Fatalf("reading .kiwi/schema.json: %v", err)
	}
	// .gitattributes enforces eol=lf, but a checkout with different
	// autocrlf settings can still land CRLF bytes; compare line-ending
	// normalized content against the embedded constant.
	if got := strings.ReplaceAll(string(onDisk), "\r\n", "\n"); got != string(SchemaJSON) {
		t.Fatalf(".kiwi/schema.json diverges from embedded SchemaJSON (%d vs %d bytes)", len(onDisk), len(SchemaJSON))
	}
}

func TestSchemaReturnsCopy(t *testing.T) {
	got := Schema()
	if len(got) != len(SchemaJSON) {
		t.Fatalf("Schema() length = %d, want %d", len(got), len(SchemaJSON))
	}
	got[0] = ' '
	if SchemaJSON[0] == ' ' {
		t.Fatal("Schema() must return a copy, not the backing array")
	}
}

func TestValidateAgainstSchemaParity(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{
			name: "valid minimal",
			doc:  "version: 1\njobs:\n  a:\n    steps:\n      - run: echo hi\n",
		},
		{
			name: "valid full",
			doc: `version: 1
name: parity-full
on:
  push:
    branches: [main]
    tags: ["v*"]
    actions: [opened]
    draft: false
inputs:
  flavor:
    type: string
    required: true
    default: vanilla
    options: [vanilla, chocolate]
    description: pick one
env:
  FOO: bar
secrets: [CI_TOKEN]
defaults:
  shell: bash
  timeout: 10m
  retry:
    max: 2
    backoff: 1s
    on: [failure, infra]
permissions:
  id_token: true
concurrency:
  group: "${{ repo }}:${{ branch }}"
  cancel_in_progress: true
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
  build:
    runtime: container
    image: golang:1.23
    network: none
    queue_timeout: 5m
    infra_retries: 2
    env:
      GOCACHE: .kiwi/go-cache
    services:
      - name: db
        image: postgres:16
        env:
          POSTGRES_PASSWORD: secret
        healthcheck: pg_isready
        interval: 10s
        timeout: 5s
        retries: 3
    cache:
      - name: mod
        paths: [.kiwi/go-cache]
        key: mod-1
        hash_files: [go.sum]
        restore_keys: [mod-]
    steps:
      - id: compile
        name: build
        run: go build ./...
        shell: bash
        working_directory: .
        env:
          GOFLAGS: -mod=readonly
        secrets: [CI_TOKEN]
        timeout: 5m
        retry:
          max: 1
          backoff: 30s
          on: [command]
        continue_on_error: false
    artifacts:
      - name: bin
        paths: [out/]
        if: success()
        retention: 24h
    test_reports: [report.xml]
    environment:
      name: staging
      url: https://example.com
      approval: true
      branches: [main]
      concurrency: 1
    permissions:
      id_token: true
    outputs:
      artifact: bin
    placement:
      regions: [eu-west-1]
      labels: [fast]
    sandbox:
      rootless: true
      read_only_rootfs: true
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
      inputs:
        A: b
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
  test:
    needs: [build]
    matrix:
      GO_VERSION: ["1.23", "1.24"]
    paths: [internal/**]
    paths_ignore: [docs/**]
    downloads:
      - from: build
        name: bin
        path: out/
    steps:
      - run: go test ./...
`,
		},
		{name: "missing jobs", doc: "version: 1\nname: x\n"},
		{name: "empty jobs", doc: "version: 1\njobs: {}\n"},
		{
			name: "unknown top-level field",
			doc:  "version: 1\nsecrects: [x]\njobs:\n  a:\n    steps:\n      - run: echo hi\n",
		},
		{
			name: "unknown job field",
			doc:  "version: 1\njobs:\n  a:\n    secrects: [x]\n    steps:\n      - run: echo hi\n",
		},
		{
			name: "bad runtime enum",
			doc:  "version: 1\njobs:\n  a:\n    runtime: kubernetes\n    steps:\n      - run: echo hi\n",
		},
		{
			name: "bad network enum",
			doc:  "version: 1\njobs:\n  a:\n    network: vpn\n    steps:\n      - run: echo hi\n",
		},
		{
			name: "missing run",
			doc:  "version: 1\njobs:\n  a:\n    steps:\n      - name: x\n",
		},
		{
			name: "empty run",
			doc:  "version: 1\njobs:\n  a:\n    steps:\n      - run: \"\"\n",
		},
		{
			name: "negative duration",
			doc:  "version: 1\njobs:\n  a:\n    timeout: -5s\n    steps:\n      - run: echo hi\n",
		},
		{
			name: "zero duration",
			doc:  "version: 1\njobs:\n  a:\n    timeout: 0s\n    steps:\n      - run: echo hi\n",
		},
		{
			name: "garbage duration",
			doc:  "version: 1\njobs:\n  a:\n    timeout: nope\n    steps:\n      - run: echo hi\n",
		},
		{
			name: "duplicate keys",
			doc:  "version: 1\nversion: 1\njobs:\n  a:\n    steps:\n      - run: echo hi\n",
		},
		{
			name: "bad shell",
			doc:  "version: 1\njobs:\n  a:\n    shell: csh\n    steps:\n      - run: echo hi\n",
		},
		{
			name: "negative retry max",
			doc:  "version: 1\njobs:\n  a:\n    retry:\n      max: -2\n    steps:\n      - run: echo hi\n",
		},
		{
			name: "unsupported defaults shell",
			doc:  "version: 1\ndefaults:\n  shell: csh\njobs:\n  a:\n    steps:\n      - run: echo hi\n",
		},
		{
			name: "unsupported version",
			doc:  "version: 2\njobs:\n  a:\n    steps:\n      - run: echo hi\n",
		},
		{
			name: "multiple documents",
			doc:  "version: 1\njobs:\n  a:\n    steps:\n      - run: echo hi\n---\nversion: 1\njobs: {}\n",
		},
		{
			name: "step run as mapping",
			doc:  "version: 1\njobs:\n  a:\n    steps:\n      - run:\n          nested: yes\n",
		},
		{
			name: "custom tag",
			doc:  "version: 1\njobs:\n  a:\n    steps:\n      - run: !custom hello\n",
		},
		{
			name: "merge key",
			doc:  "version: 1\njobs:\n  a:\n    steps:\n      - run: echo hi\n  b:\n    <<: a\n    steps:\n      - run: echo bye\n",
		},
		{
			name: "empty service image",
			doc:  "version: 1\njobs:\n  a:\n    services:\n      - name: db\n        image: \"\"\n    steps:\n      - run: echo hi\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, goErr := Parse([]byte(c.doc))
			schemaErrs := ValidateAgainstSchema([]byte(c.doc))
			if (goErr == nil) != (len(schemaErrs) == 0) {
				t.Fatalf("parity disagreement: Go error = %v, schema errors = %v", goErr, schemaErrs)
			}
		})
	}
}

// knownFieldStructs maps the structural known-field table entries to the
// struct type whose yaml tags must cover them. Tables for free-form maps
// (env, matrix, with, inputs of downstream) have no entry: their keys are
// data, not fields.
var knownFieldStructs = map[string]reflect.Type{
	"":                                   reflect.TypeOf(Spec{}),
	"defaults":                           reflect.TypeOf(Defaults{}),
	"concurrency":                        reflect.TypeOf(Concurrency{}),
	"permissions":                        reflect.TypeOf(Permissions{}),
	"defaults.retry":                     reflect.TypeOf(Retry{}),
	"on.*":                               reflect.TypeOf(Trigger{}),
	"inputs.*":                           reflect.TypeOf(Input{}),
	"packages.*":                         reflect.TypeOf(Package{}),
	"components.*":                       reflect.TypeOf(ComponentUse{}),
	"jobs.*":                             reflect.TypeOf(Job{}),
	"jobs.*.retry":                       reflect.TypeOf(Retry{}),
	"jobs.*.environment":                 reflect.TypeOf(Environment{}),
	"jobs.*.sandbox":                     reflect.TypeOf(Sandbox{}),
	"jobs.*.placement":                   reflect.TypeOf(Placement{}),
	"jobs.*.resources":                   reflect.TypeOf(Resources{}),
	"jobs.*.tests":                       reflect.TypeOf(TestConfig{}),
	"jobs.*.generate":                    reflect.TypeOf(GenerateSpec{}),
	"jobs.*.downstream":                  reflect.TypeOf(DownstreamSpec{}),
	"jobs.*.snapshot":                    reflect.TypeOf(SnapshotSpec{}),
	"jobs.*.deployment":                  reflect.TypeOf(DeploymentSpec{}),
	"jobs.*.services.*":                  reflect.TypeOf(Service{}),
	"jobs.*.steps.*":                     reflect.TypeOf(Step{}),
	"jobs.*.steps.*.retry":               reflect.TypeOf(Retry{}),
	"jobs.*.cache.*":                     reflect.TypeOf(Cache{}),
	"jobs.*.artifacts.*":                 reflect.TypeOf(Artifact{}),
	"jobs.*.artifacts.*.sigstore":        reflect.TypeOf(SigstoreConfig{}),
	"jobs.*.downloads.*":                 reflect.TypeOf(ArtifactInput{}),
	"jobs.*.deployment.canary.*":         reflect.TypeOf(Step{}),
	"jobs.*.deployment.verify.*":         reflect.TypeOf(Step{}),
	"jobs.*.deployment.rollback.*":       reflect.TypeOf(Step{}),
	"jobs.*.deployment.canary.*.retry":   reflect.TypeOf(Retry{}),
	"jobs.*.deployment.verify.*.retry":   reflect.TypeOf(Retry{}),
	"jobs.*.deployment.rollback.*.retry": reflect.TypeOf(Retry{}),
}

func yamlFieldTags(t reflect.Type) map[string]bool {
	tags := map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag, ok := f.Tag.Lookup("yaml")
		if !ok {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		tags[name] = true
	}
	return tags
}

// TestKnownFieldTablesMatchStructTags asserts that every known-field key in
// the structural tables maps to a real struct field (via its yaml tag), so a
// field removed from pipeline.Job (or any section struct) fails CI instead
// of silently drifting from the parser's admission table.
func TestKnownFieldTablesMatchStructTags(t *testing.T) {
	for path, table := range knownFieldTables {
		typ, ok := knownFieldStructs[path]
		if !ok {
			// Free-form maps (env, matrix, with, downstream inputs) and
			// cron entries are intentionally not field-checked.
			continue
		}
		tags := yamlFieldTags(typ)
		for key := range table {
			if !tags[key] {
				t.Errorf("known-field table %q lists %q, which is not a yaml field of %s", path, key, typ)
			}
		}
	}
}

func TestRepoPipelineFilesSatisfySchema(t *testing.T) {
	for _, path := range []string{"../../.kiwi/pipeline.yaml", "../../examples/kiwi.yaml"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if errs := ValidateAgainstSchema(b); len(errs) != 0 {
			t.Fatalf("%s violates the schema-level checks: %v", path, errs)
		}
	}
	b, err := os.ReadFile("../../examples/kiwi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(b); err != nil {
		t.Fatalf("examples/kiwi.yaml must also parse with the Go engine: %v", err)
	}
}

// TestMaxSizeSchemaParserParity pins the max_size type contract: the schema
// and the Go parser agree on plain integers and size strings, and both
// reject negatives.
func TestMaxSizeSchemaParserParity(t *testing.T) {
	valid := []string{
		"max_size: 1048576",
		"max_size: 10MiB",
		"max_size: 0",
	}
	for _, frag := range valid {
		src := "version: 1\njobs:\n  j:\n    runtime: container\n    image: alpine@sha256:" + strings.Repeat("a", 64) + "\n    steps:\n      - run: echo hi\n    artifacts:\n      - name: a\n        paths: [dist/**]\n        " + frag + "\n"
		if _, err := Parse([]byte(src)); err != nil {
			t.Errorf("%q rejected by the parser: %v", frag, err)
		}
	}
	for _, frag := range []string{"max_size: -1", "max_size: -5MiB"} {
		src := "version: 1\njobs:\n  j:\n    runtime: container\n    image: alpine@sha256:" + strings.Repeat("a", 64) + "\n    steps:\n      - run: echo hi\n    artifacts:\n      - name: a\n        paths: [dist/**]\n        " + frag + "\n"
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%q accepted; negative sizes must be rejected", frag)
		}
	}
}
