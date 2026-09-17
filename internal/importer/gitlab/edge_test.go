package gitlab

import (
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/importer"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
	"gopkg.in/yaml.v3"
)

// edgeFixture deliberately omits `stages` (derived ordering), uses a
// top-level image, default.cache, scalar needs, scalar retry, scalar
// environment, services and cache/artifact edge cases.
const edgeFixture = `image: alpine:3.20

variables:
  GLOBAL: "1"

default:
  cache:
    paths:
      - default-cache/

workflow:
  rules:
    - if: '$CI_PIPELINE_SOURCE == "push"'

services:
  - postgres:16

alpha:
  script:
    - echo alpha

beta:
  stage: build
  image:
    name: golang:1.23
  services:
    - postgres:16
    - name: redis:7
      alias: cache
    - name: memcached:1
      command: ["-m", "64"]
    - alias: noghost
  script:
    - echo beta
  artifacts:
    paths: []
  cache:
    paths:
      - beta-cache/

gamma:
  stage: build
  needs:
    - unknown-scalar
    - job: unknown-mapping
    - job: beta
    - beta
  environment: staging
  retry: 3
  rules:
    - changes:
        - "docs/**"
    - when: never
  script:
    - echo gamma
    - echo gamma-again

delta:
  stage: deploy
  needs: alpha
  script:
    - echo delta
  artifacts:
    paths:
      - out/
  timeout: 90s
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

	// Top-level image becomes the default for jobs without their own image.
	alpha := spec.Jobs["alpha"]
	if alpha.Runtime != "container" || alpha.Image != "alpine:3.20" {
		t.Fatalf("alpha runtime/image = %q/%q", alpha.Runtime, alpha.Image)
	}
	// Mapping image form.
	beta := spec.Jobs["beta"]
	if beta.Image != "golang:1.23" {
		t.Fatalf("beta image = %q", beta.Image)
	}
	if !hasNote(res.TODOs, "default.cache") {
		t.Fatalf("default.cache TODO missing: %v", res.TODOs)
	}

	// Derived stage order: alpha has no stage (→ test), beta is build, so
	// beta implicitly needs every test-stage job listed before it.
	if len(beta.Needs) != 1 || beta.Needs[0] != "alpha" {
		t.Fatalf("beta implicit needs = %v, want [alpha]", beta.Needs)
	}

	// Scalar needs.
	delta := spec.Jobs["delta"]
	if len(delta.Needs) != 1 || delta.Needs[0] != "alpha" {
		t.Fatalf("delta needs = %v", delta.Needs)
	}

	// Sequence needs: unknown entries dropped, duplicates collapsed.
	gamma := spec.Jobs["gamma"]
	if len(gamma.Needs) != 1 || gamma.Needs[0] != "beta" {
		t.Fatalf("gamma needs = %v, want [beta]", gamma.Needs)
	}
	// needs artifact fan-in TODO (only when artifacts/optional appear).
	if hasNote(res.TODOs, "artifact/output fan-in") {
		t.Fatalf("gamma needs no artifacts/optional, fan-in TODO must not fire: %v", res.TODOs)
	}

	// Scalar environment and scalar retry.
	if gamma.Environment.Name != "staging" {
		t.Fatalf("gamma environment = %+v", gamma.Environment)
	}
	if gamma.Retry.Max != 3 {
		t.Fatalf("gamma retry = %+v", gamma.Retry)
	}

	// rules: changes → paths; when: never → if false.
	if len(gamma.Paths) != 1 || gamma.Paths[0] != "docs/**" {
		t.Fatalf("gamma paths = %v", gamma.Paths)
	}
	if gamma.If != "false" {
		t.Fatalf("gamma if = %q, want false", gamma.If)
	}

	// Job cache.
	if len(beta.Cache) != 1 || beta.Cache[0].Paths[0] != "beta-cache/" {
		t.Fatalf("beta cache = %+v", beta.Cache)
	}

	// Services: scalar, alias, custom command, missing image.
	if len(beta.Services) != 3 {
		t.Fatalf("beta services = %+v", beta.Services)
	}
	if beta.Services[0].Name != "postgres" || beta.Services[0].Image != "postgres:16" {
		t.Fatalf("service[0] = %+v", beta.Services[0])
	}
	if beta.Services[1].Name != "cache" || beta.Services[1].Image != "redis:7" {
		t.Fatalf("service[1] = %+v", beta.Services[1])
	}
	if beta.Services[2].Name != "memcached" {
		t.Fatalf("service[2] = %+v", beta.Services[2])
	}
	if !hasNote(res.TODOs, "custom command") {
		t.Fatalf("service custom command TODO missing: %v", res.TODOs)
	}
	if !hasNote(res.Unsupported, "no image") {
		t.Fatalf("service without image not reported: %v", res.Unsupported)
	}

	// Artifacts with no paths are dropped; artifacts without a name get a
	// derived name.
	if len(beta.Artifacts) != 0 {
		t.Fatalf("beta artifacts must be dropped: %+v", beta.Artifacts)
	}
	if len(delta.Artifacts) != 1 || delta.Artifacts[0].Name != "delta-artifacts" {
		t.Fatalf("delta artifacts = %+v", delta.Artifacts)
	}
	if !hasNote(res.Unsupported, "artifacts with no paths") {
		t.Fatalf("empty artifacts not reported: %v", res.Unsupported)
	}

	// Duration parsing.
	if delta.Timeout.Duration.String() != "1m30s" {
		t.Fatalf("delta timeout = %v", delta.Timeout.Duration)
	}

	if res.Confidence <= 0 || res.Confidence >= 1 {
		t.Fatalf("confidence = %v", res.Confidence)
	}
}

func TestImportRejectsMalformedInput(t *testing.T) {
	if _, err := New().Import("a: [unclosed\n"); err == nil || !strings.Contains(err.Error(), "parse .gitlab-ci.yml") {
		t.Fatalf("error = %v", err)
	}
	if _, err := New().Import("- a\n- b\n"); err == nil || !strings.Contains(err.Error(), "must be a YAML mapping") {
		t.Fatalf("error = %v", err)
	}
}

func TestScriptStepsEmpty(t *testing.T) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("script: []\n"), &root); err != nil {
		t.Fatal(err)
	}
	doc := importer.Document(&root)
	if got := scriptSteps(importer.Key(doc, "script")); got != nil {
		t.Fatalf("scriptSteps(empty) = %+v", got)
	}
	if got := scriptSteps(nil); got != nil {
		t.Fatalf("scriptSteps(nil) = %+v", got)
	}
}

func TestImageRefForms(t *testing.T) {
	if got := imageRef(nil); got != "" {
		t.Fatalf("imageRef(nil) = %q", got)
	}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("img: {name: redis:7, entrypoint: [x]}\nother: 3\n"), &root); err != nil {
		t.Fatal(err)
	}
	doc := importer.Document(&root)
	if got := imageRef(importer.Key(doc, "img")); got != "redis:7" {
		t.Fatalf("imageRef(mapping) = %q", got)
	}
	if got := imageRef(importer.Key(doc, "other")); got != "3" {
		t.Fatalf("imageRef(scalar) = %q", got)
	}
}

func TestConvertCacheVariants(t *testing.T) {
	parse := func(t *testing.T, src string) *yaml.Node {
		t.Helper()
		var root yaml.Node
		if err := yaml.Unmarshal([]byte(src), &root); err != nil {
			t.Fatal(err)
		}
		return importer.Key(importer.Document(&root), "cache")
	}

	res := &importer.Result{}
	c, ok := convertCache(res, parse(t, "cache: {paths: [vendor/], key: {files: [go.sum, go.mod]}}\n"))
	if !ok || c.Key != "gitlab-go.sum+go.mod" || len(c.HashFiles) != 2 {
		t.Fatalf("files-key cache = %+v (ok=%v)", c, ok)
	}

	res = &importer.Result{}
	c, ok = convertCache(res, parse(t, "cache: {paths: [vendor/], key: v1}\n"))
	if !ok || c.Key != "v1" {
		t.Fatalf("scalar-key cache = %+v (ok=%v)", c, ok)
	}

	res = &importer.Result{}
	c, ok = convertCache(res, parse(t, "cache: {paths: [vendor/]}\n"))
	if !ok || c.Key != "default" {
		t.Fatalf("default-key cache = %+v (ok=%v)", c, ok)
	}

	// Sequence form: paths are collected from each item.
	res = &importer.Result{}
	c, ok = convertCache(res, parse(t, "cache:\n  - paths: [a/]\n  - paths: [b/]\n"))
	if !ok || len(c.Paths) != 2 || c.Paths[0] != "a/" || c.Paths[1] != "b/" {
		t.Fatalf("sequence cache = %+v (ok=%v)", c, ok)
	}

	// No paths anywhere: dropped and reported.
	res = &importer.Result{}
	if _, ok := convertCache(res, parse(t, "cache: {key: k}\n")); ok {
		t.Fatal("cache without paths must be dropped")
	}
	if len(res.Unsupported) != 1 || !strings.Contains(res.Unsupported[0], "no paths") {
		t.Fatalf("unsupported = %v", res.Unsupported)
	}
}

func TestConvertRulesNonSequence(t *testing.T) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("rules: {if: x}\n"), &root); err != nil {
		t.Fatal(err)
	}
	j := pipeline.Job{}
	res := &importer.Result{}
	convertRules(res, importer.Key(importer.Document(&root), "rules"), "job", &j)
	if j.If != "" || j.Paths != nil || len(res.Unsupported) != 0 {
		t.Fatalf("non-sequence rules must be ignored: %+v %+v", j, res.Unsupported)
	}
	convertRules(res, nil, "job", &j)
}

func TestNeedsArtifacts(t *testing.T) {
	parse := func(t *testing.T, src string) *yaml.Node {
		t.Helper()
		var root yaml.Node
		if err := yaml.Unmarshal([]byte(src), &root); err != nil {
			t.Fatal(err)
		}
		return importer.Key(importer.Document(&root), "needs")
	}
	if needsArtifacts(nil) {
		t.Fatal("needsArtifacts(nil) = true")
	}
	if needsArtifacts(parse(t, "needs: [build]\n")) {
		t.Fatal("plain needs list must not report artifact fan-in")
	}
	if !needsArtifacts(parse(t, "needs:\n  - job: build\n    artifacts: true\n")) {
		t.Fatal("artifacts fan-in not detected")
	}
	if !needsArtifacts(parse(t, "needs:\n  - job: build\n    optional: true\n")) {
		t.Fatal("optional fan-in not detected")
	}
}

func TestParseGitLabDurationEdges(t *testing.T) {
	if _, ok := parseGitLabDuration(""); ok {
		t.Fatal("empty duration must not parse")
	}
	if _, ok := parseGitLabDuration("   "); ok {
		t.Fatal("blank duration must not parse")
	}
	if _, ok := parseGitLabDuration("5"); ok {
		t.Fatal("unit-less duration must not parse")
	}
	if _, ok := parseGitLabDuration("5d"); ok {
		t.Fatal("unknown unit must not parse")
	}
	if _, ok := parseGitLabDuration("-5m"); ok {
		t.Fatal("negative duration must not parse")
	}
	if _, ok := parseGitLabDuration("1h+bogus"); ok {
		t.Fatal("bogus component must not parse")
	}
	for in, want := range map[string]string{
		"2h": "2h0m0s", "1h 30m 15s": "1h30m15s", "0s": "0s", "120m": "2h0m0s",
	} {
		d, ok := parseGitLabDuration(in)
		if !ok || d.String() != want {
			t.Errorf("parseGitLabDuration(%q) = %v (ok=%v), want %s", in, d, ok, want)
		}
	}
}

func TestContains(t *testing.T) {
	if !contains([]string{"a", "b"}, "b") {
		t.Fatal("contains must find an existing element")
	}
	if contains([]string{"a", "b"}, "c") {
		t.Fatal("contains must not find a missing element")
	}
	if contains(nil, "a") {
		t.Fatal("contains(nil) must be false")
	}
}

func TestConvertServicesEmptyEntry(t *testing.T) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte("services: [\"\"]\n"), &root); err != nil {
		t.Fatal(err)
	}
	res := &importer.Result{}
	j := pipeline.Job{}
	convertServices(res, importer.Key(importer.Document(&root), "services"), "job", &j)
	if len(j.Services) != 0 || len(res.Unsupported) != 1 {
		t.Fatalf("services = %+v, unsupported = %v", j.Services, res.Unsupported)
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
