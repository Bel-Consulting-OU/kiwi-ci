// Package components implements reusable job components: versioned,
// digest-pinned building blocks that a pipeline job can invoke with
// `component: name@sha256:...` plus a `with` map of typed inputs.
//
// Resolution happens server-side at enqueue time: the component's steps,
// env, cache, secrets and sandbox are merged into the invoking job and the
// resulting pipeline is rendered into its canonical form before compilation,
// so runners never see or resolve component references themselves.
package components

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// Spec is the definition of one component. It is a fragment of a pipeline
// job: steps plus the surrounding env/secrets/cache/sandbox context they run
// in. Invocation-scoped fields (inputs) are declared separately so `with`
// values can be validated and injected as env vars.
type Spec struct {
	Name    string            `json:"name"`
	Version string            `json:"version,omitempty"`
	Inputs  []Input           `json:"inputs,omitempty"`
	Steps   []pipeline.Step   `json:"steps"`
	Env     map[string]string `json:"env,omitempty"`
	Secrets []string          `json:"secrets,omitempty"`
	Cache   []pipeline.Cache  `json:"cache,omitempty"`
	Sandbox *pipeline.Sandbox `json:"sandbox,omitempty"`
}

// Input declares one invocation parameter. Type is one of "string",
// "boolean", "integer" or "enum" (empty means "string"). Enum inputs must
// also declare Options.
type Input struct {
	Name        string   `json:"name"`
	Type        string   `json:"type,omitempty"`
	Description string   `json:"description,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Default     string   `json:"default,omitempty"`
	Options     []string `json:"options,omitempty"`
}

// InputTypes are the supported invocation input types.
var InputTypes = map[string]bool{"string": true, "boolean": true, "integer": true, "enum": true}

// privilegedFields are the job fields a component invocation must never be
// able to set through `with`. Because ValidateInvocation only accepts keys
// that are declared inputs, this list is a second, explicit defense against
// components that (accidentally or maliciously) declare an input named after
// a structural job field.
var privilegedFields = map[string]bool{
	"steps": true, "env": true, "cache": true, "secrets": true, "sandbox": true,
	"image": true, "runtime": true, "network": true, "vm": true, "shell": true,
	"permissions": true, "runner": true, "needs": true, "placement": true,
	"resources": true, "deployment": true, "snapshot": true,
	"component": true, "with": true, "if": true, "timeout": true, "retry": true,
	"services": true, "artifacts": true, "downloads": true, "outputs": true,
	"tests": true, "generate": true, "downstream": true, "matrix": true,
}

// ValidateInvocation checks a `with` map against the component's declared
// inputs: every key must be a declared input (never a privileged structural
// field), values must satisfy the declared type and enum membership, and
// every required input must be present (or have a default).
func ValidateInvocation(spec Spec, with map[string]string) error {
	for key := range with {
		if privilegedFields[key] {
			return fmt.Errorf("component %q: input %q names a privileged job field and cannot be set via with", spec.Name, key)
		}
	}
	declared := map[string]Input{}
	for _, in := range spec.Inputs {
		if strings.TrimSpace(in.Name) == "" {
			return fmt.Errorf("component %q: input with empty name", spec.Name)
		}
		typ := in.Type
		if typ == "" {
			typ = "string"
		}
		if !InputTypes[typ] {
			return fmt.Errorf("component %q: input %q has unknown type %q (want string, boolean, integer or enum)", spec.Name, in.Name, in.Type)
		}
		if typ == "enum" && len(in.Options) == 0 {
			return fmt.Errorf("component %q: enum input %q declares no options", spec.Name, in.Name)
		}
		if _, dup := declared[in.Name]; dup {
			return fmt.Errorf("component %q: duplicate input %q", spec.Name, in.Name)
		}
		declared[in.Name] = in
	}
	for key := range with {
		in, ok := declared[key]
		if !ok {
			return fmt.Errorf("component %q: unknown input %q", spec.Name, key)
		}
		if err := checkValue(in, with[key]); err != nil {
			return fmt.Errorf("component %q: %w", spec.Name, err)
		}
	}
	for _, in := range spec.Inputs {
		if !in.Required {
			continue
		}
		if _, ok := with[in.Name]; ok {
			continue
		}
		if in.Default != "" {
			continue
		}
		return fmt.Errorf("component %q: required input %q not provided", spec.Name, in.Name)
	}
	return nil
}

func checkValue(in Input, v string) error {
	switch in.Type {
	case "", "string":
		return nil
	case "boolean":
		if v != "true" && v != "false" {
			return fmt.Errorf("input %q must be a boolean, got %q", in.Name, v)
		}
	case "integer":
		if _, err := strconv.ParseInt(v, 10, 64); err != nil {
			return fmt.Errorf("input %q must be an integer, got %q", in.Name, v)
		}
	case "enum":
		for _, o := range in.Options {
			if o == v {
				return nil
			}
		}
		return fmt.Errorf("input %q must be one of %v, got %q", in.Name, in.Options, v)
	}
	return nil
}

// Apply validates the invocation and merges the component into the job:
// component steps are prepended to the job's own steps, env is layered
// (component defaults, then job env, then `with` values — the invocation
// always wins), secrets and cache entries are appended, and the component
// sandbox fills the job's sandbox when the job does not declare one. Input
// defaults are applied for declared inputs the invocation did not set.
func Apply(spec Spec, job *pipeline.Job, with map[string]string) error {
	if job == nil {
		return fmt.Errorf("component %q: nil job", spec.Name)
	}
	if err := ValidateInvocation(spec, with); err != nil {
		return err
	}
	effective := map[string]string{}
	for _, in := range spec.Inputs {
		if v, ok := with[in.Name]; ok {
			effective[in.Name] = v
			continue
		}
		if in.Default != "" {
			effective[in.Name] = in.Default
		}
	}
	steps := make([]pipeline.Step, 0, len(spec.Steps)+len(job.Steps))
	steps = append(steps, spec.Steps...)
	steps = append(steps, job.Steps...)
	// Component-declared secrets are scoped to the component's own steps:
	// the job cannot leak them into unrelated steps it added itself.
	for i := range spec.Steps {
		steps[i].Secrets = append(steps[i].Secrets, spec.Secrets...)
	}
	job.Steps = steps
	env := map[string]string{}
	for k, v := range spec.Env {
		env[k] = v
	}
	for k, v := range job.Env {
		env[k] = v
	}
	for k, v := range effective {
		env[k] = v
	}
	job.Env = env
	job.Cache = append(spec.Cache, job.Cache...)
	if spec.Sandbox != nil && job.Sandbox == (pipeline.Sandbox{}) {
		job.Sandbox = *spec.Sandbox
	}
	return nil
}

// Digest computes the content digest of a component spec: the SHA-256 of its
// deterministic JSON form (struct fields in declaration order, maps sorted).
func Digest(spec Spec) (string, error) {
	b, err := canonicalJSON(spec)
	if err != nil {
		return "", err
	}
	sum := sha256Sum(b)
	return sum, nil
}

// InputNames returns the declared input names, sorted, for stable iteration.
func InputNames(spec Spec) []string {
	names := make([]string, 0, len(spec.Inputs))
	for _, in := range spec.Inputs {
		names = append(names, in.Name)
	}
	sort.Strings(names)
	return names
}
