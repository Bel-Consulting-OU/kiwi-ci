package server

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Bel-Consulting-OU/kiwi-ci/internal/components"
	"github.com/Bel-Consulting-OU/kiwi-ci/internal/pipeline"
)

// resolveComponents resolves every job-level component reference in the spec
// server-side and merges the component fragment into the invoking job. The
// resolved pipeline is self-contained: component and with are cleared so the
// canonical pipeline text runners receive never carries a reference.
//
// Resolution is digest-pinned: remote refs must be name@sha256:<hex> and the
// registry must return a spec whose digest matches. The returned map records
// the resolved digest per job key, which enqueue stores on the model job
// (Job.ComponentDigest).
func (s *Server) resolveComponents(ctx context.Context, spec *pipeline.Spec) (map[string]string, error) {
	digests := map[string]string{}
	if s.ComponentRegistry == nil {
		for key, j := range spec.Jobs {
			if j.Component != "" {
				return nil, fmt.Errorf("job %q references component %q but the server has no component registry configured", key, j.Component)
			}
		}
		return digests, nil
	}
	for key, j := range spec.Jobs {
		if j.Component == "" {
			continue
		}
		cspec, digest, err := s.ComponentRegistry.Resolve(ctx, j.Component)
		if err != nil {
			return nil, fmt.Errorf("job %q component %q: %w", key, j.Component, err)
		}
		if err := components.Apply(cspec, &j, j.With); err != nil {
			return nil, fmt.Errorf("job %q component %q: %w", key, j.Component, err)
		}
		j.Component = ""
		j.With = nil
		spec.Jobs[key] = j
		digests[key] = digest
	}
	return digests, nil
}

// validateRunInputs checks the submission's inputs (Metadata keys of the
// form "input.<name>") against the pipeline's declared inputs: unknown
// inputs are rejected, required inputs must be present, and values must
// satisfy the declared type (string, boolean, integer, enum).
func validateRunInputs(spec *pipeline.Spec, meta map[string]string) (map[string]string, error) {
	provided := map[string]string{}
	for k, v := range meta {
		if !strings.HasPrefix(k, "input.") {
			continue
		}
		name := strings.TrimPrefix(k, "input.")
		if _, ok := spec.Inputs[name]; !ok {
			return nil, fmt.Errorf("unknown input %q", name)
		}
		provided[name] = v
	}
	out := map[string]string{}
	for name, in := range spec.Inputs {
		typ := in.Type
		if typ == "" {
			typ = "string"
		}
		v, has := provided[name]
		if !has {
			if in.Required {
				return nil, fmt.Errorf("required input %q not provided", name)
			}
			if in.Default == nil {
				continue
			}
			v = fmt.Sprint(in.Default)
		}
		switch typ {
		case "", "string":
		case "boolean":
			if v != "true" && v != "false" {
				return nil, fmt.Errorf("input %q must be a boolean, got %q", name, v)
			}
		case "integer":
			if _, err := strconv.ParseInt(v, 10, 64); err != nil {
				return nil, fmt.Errorf("input %q must be an integer, got %q", name, v)
			}
		case "enum":
			found := false
			for _, o := range in.Options {
				if o == v {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("input %q must be one of %v, got %q", name, in.Options, v)
			}
		default:
			return nil, fmt.Errorf("input %q has unknown type %q", name, typ)
		}
		out[name] = v
	}
	return out, nil
}
