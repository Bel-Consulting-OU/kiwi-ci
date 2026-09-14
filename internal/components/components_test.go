package components

import (
	"context"
	"strings"
	"testing"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

func TestResolveComponentRef(t *testing.T) {
	valid := []string{
		"build@sha256:" + strings.Repeat("a", 64),
		"org/build@sha256:" + strings.Repeat("0", 64),
		"components/build.yaml",
		"components/build",
		"build-tool",
	}
	for _, ref := range valid {
		if err := ResolveComponentRef(ref); err != nil {
			t.Errorf("ResolveComponentRef(%q) = %v, want nil", ref, err)
		}
	}
	invalid := []string{
		"",
		"   ",
		"build@sha256:short",
		"build@sha256:" + strings.Repeat("g", 64),
		"build@latest",
		"name@sha256:" + strings.Repeat("a", 63),
		"../etc/passwd",
		"/etc/passwd",
		"components/../../secrets",
		`components\win.yaml`,
		"a b",
	}
	for _, ref := range invalid {
		if err := ResolveComponentRef(ref); err == nil {
			t.Errorf("ResolveComponentRef(%q) = nil, want error", ref)
		}
	}
	// A bare name is a valid local path; only digest-pinned refs are remote.
	if err := ResolveComponentRef("build"); err != nil {
		t.Errorf("bare local path rejected: %v", err)
	}
}

func testSpec() Spec {
	return Spec{
		Name:    "build",
		Version: "1.0.0",
		Inputs: []Input{
			{Name: "environment", Type: "enum", Required: true, Options: []string{"staging", "production"}},
			{Name: "verbose", Type: "boolean", Default: "false"},
			{Name: "workers", Type: "integer", Default: "2"},
			{Name: "label", Type: "string"},
		},
		Steps: []pipeline.Step{{ID: "build", Run: "make build"}},
		Env:   map[string]string{"CI": "1"},
		Cache: []pipeline.Cache{{Name: "deps", Paths: []string{".cache"}}},
	}
}

func TestValidateInvocation(t *testing.T) {
	spec := testSpec()
	ok := map[string]string{"environment": "staging", "verbose": "true", "workers": "4"}
	if err := ValidateInvocation(spec, ok); err != nil {
		t.Fatalf("valid invocation rejected: %v", err)
	}
	cases := []struct {
		name string
		with map[string]string
	}{
		{"unknown key", map[string]string{"nope": "x"}},
		{"privileged field", map[string]string{"environment": "staging", "steps": "echo pwn"}},
		{"bad boolean", map[string]string{"environment": "staging", "verbose": "yes"}},
		{"bad integer", map[string]string{"environment": "staging", "workers": "many"}},
		{"enum not member", map[string]string{"environment": "dev"}},
		{"missing required", map[string]string{"verbose": "true"}},
	}
	for _, tc := range cases {
		if err := ValidateInvocation(spec, tc.with); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}

func TestValidateInvocationDefaults(t *testing.T) {
	spec := testSpec()
	if err := ValidateInvocation(spec, nil); err != nil {
		// Only the required enum input is missing.
		if !strings.Contains(err.Error(), "environment") {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	allDefaults := Spec{
		Name:   "d",
		Inputs: []Input{{Name: "x", Required: true, Default: "yes"}},
		Steps:  []pipeline.Step{{Run: "true"}},
	}
	if err := ValidateInvocation(allDefaults, nil); err != nil {
		t.Fatalf("required-with-default rejected: %v", err)
	}
}

func TestApply(t *testing.T) {
	spec := testSpec()
	job := pipeline.Job{
		Runtime: "container",
		Env:     map[string]string{"JOB": "1", "CI": "job"},
		Steps:   []pipeline.Step{{ID: "after", Run: "echo after"}},
	}
	with := map[string]string{"environment": "production"}
	if err := Apply(spec, &job, with); err != nil {
		t.Fatal(err)
	}
	if len(job.Steps) != 2 || job.Steps[0].Run != "make build" {
		t.Fatalf("component steps not prepended: %+v", job.Steps)
	}
	if job.Env["CI"] != "job" {
		t.Fatalf("job env should override component env, got %q", job.Env["CI"])
	}
	if job.Env["environment"] != "production" {
		t.Fatalf("with value not applied: %+v", job.Env)
	}
	if job.Env["verbose"] != "false" || job.Env["workers"] != "2" {
		t.Fatalf("input defaults not applied: %+v", job.Env)
	}
	if job.Env["JOB"] != "1" {
		t.Fatalf("job env lost: %+v", job.Env)
	}
	if len(job.Cache) != 1 {
		t.Fatalf("component cache not merged")
	}
	if job.Runtime != "container" {
		t.Fatalf("job runtime clobbered: %+v", job.Runtime)
	}
}

func TestApplyInvalid(t *testing.T) {
	spec := testSpec()
	job := &pipeline.Job{}
	if err := Apply(spec, job, map[string]string{"environment": "nope"}); err == nil {
		t.Fatal("expected enum error")
	}
	if err := Apply(spec, nil, nil); err == nil {
		t.Fatal("expected nil job error")
	}
}

func TestApplySandbox(t *testing.T) {
	spec := Spec{
		Name:    "s",
		Steps:   []pipeline.Step{{Run: "true"}},
		Sandbox: &pipeline.Sandbox{Rootless: true},
	}
	job := pipeline.Job{}
	if err := Apply(spec, &job, nil); err != nil {
		t.Fatal(err)
	}
	if !job.Sandbox.Rootless {
		t.Fatal("component sandbox not applied")
	}
	// An explicit job sandbox wins.
	job = pipeline.Job{Sandbox: pipeline.Sandbox{ReadOnlyRootFS: true}}
	if err := Apply(spec, &job, nil); err != nil {
		t.Fatal(err)
	}
	if job.Sandbox.Rootless || !job.Sandbox.ReadOnlyRootFS {
		t.Fatalf("job sandbox clobbered: %+v", job.Sandbox)
	}
}

func TestLocalRegistryDigestPinning(t *testing.T) {
	reg := NewLocalRegistry()
	reg.Register(testSpec())
	digest, err := Digest(testSpec())
	if err != nil {
		t.Fatal(err)
	}
	spec, got, err := reg.Resolve(context.Background(), "build@sha256:"+digest)
	if err != nil {
		t.Fatalf("resolve pinned: %v", err)
	}
	if got != digest || spec.Name != "build" {
		t.Fatalf("bad resolve result: %q %+v", got, spec.Name)
	}
	// A tampered pin must fail.
	bad := strings.Repeat("b", 64)
	if _, _, err := reg.Resolve(context.Background(), "build@sha256:"+bad); err == nil {
		t.Fatal("digest mismatch not rejected")
	}
	// Unknown component.
	if _, _, err := reg.Resolve(context.Background(), "missing@sha256:"+digest); err == nil {
		t.Fatal("unknown component not rejected")
	}
	// Local path resolution.
	reg.RegisterPath("components/build.yaml", testSpec())
	spec, got, err = reg.Resolve(context.Background(), "components/build.yaml")
	if err != nil {
		t.Fatalf("resolve local: %v", err)
	}
	if got != digest {
		t.Fatalf("local resolve digest = %q, want %q", got, digest)
	}
	_ = spec
	// Invalid refs are rejected before any lookup.
	if _, _, err := reg.Resolve(context.Background(), "../x"); err == nil {
		t.Fatal("traversal ref not rejected")
	}
}
